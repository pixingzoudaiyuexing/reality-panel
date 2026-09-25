// v0.4.3: Repository trait layer.
//
// Domain-specific traits (UserRepository, RuleRepository, ...) define the data
// access contract. The aggregate `Repository` trait combines them so handlers
// take a single `Arc<dyn Repository>` dependency.
//
// PR1: only SqliteRepository implements these traits. PR2 will add
// PgRepository (PostgreSQL) implementing the same traits.
//
// Design principles:
//   - Methods return domain models (User, ForwardRule, ...) — no DB types leak.
//   - Transactions are encapsulated inside methods (e.g. apply_traffic_batch,
//     reset_traffic) — no `begin()` / `Tx` leaks to handlers.
//   - Errors are DbError (unified codes), not raw sqlx::Error.
//   - Service-layer logic (config assembly, protocol derivation, stale sweep)
//     stays in the caller, NOT in the repository.
//
// dead_code: some trait methods in this module are part of the contract but
// not yet wired to a handler in PR1 (e.g. increment_user_traffic,
// delete_rules_by_uid). They're reachable through the trait object and will be
// used by future callers / PgRepository parity tests; silence the lints rather
// than delete the contract.
#![allow(dead_code)]

use async_trait::async_trait;
use relay_shared::models::{
    DeviceGroup, ForwardRule, ForwardRuleTarget, Order, Plan, SharedGroupSummary, Statistic,
    TunnelProfile, User,
};
use relay_shared::protocol::{RuleTargetRequest, TrafficEntry};
use serde::Serialize;

use crate::node_claim::{
    NodeClaimNonceVerifier, NodeClaimSecret, NodeClaimSecretVerifier, NodeClaimantNonce,
};
use crate::node_credential::{
    NodeCredentialDeliveryNonce, NodeCredentialDeliveryNonceVerifier, NodeCredentialSecret,
    NodeCredentialVerifier, PresentedNodeCredentialVerifier,
};
use crate::node_identity::ReuseEligibleNodeId;

use super::error::DbError;

// ── Resource scoping (v0.4.10 multi-user isolation) ──

/// The ownership scope a resource query is restricted to.
///
/// `All` = the caller may see/modify every row (administrators). `Owner(uid)`
/// = only rows whose `uid` column equals `uid`. This is the single type the
/// Repository layer uses to enforce per-user isolation; the API layer builds it
/// from the authenticated user (see `AuthUser::resource_scope` in middleware.rs)
/// and the db layer never imports from the api layer.
///
/// `Owner(uid)` is folded into the SQL WHERE clause (e.g.
/// `WHERE id = ? AND uid = ?`), so a miss — "row doesn't exist" vs "row belongs
/// to someone else" — is indistinguishable to the caller (both return None →
/// 404). That closes a resource-id existence oracle.
#[derive(Debug, Clone, Copy)]
pub enum ResourceScope {
    All,
    Owner(i64),
}

impl ResourceScope {
    /// `Some(uid)` when scoped to one owner, `None` when unscoped (admin).
    /// Repository impls use this to pick the scoped vs unscoped SQL branch.
    pub fn owner_id(&self) -> Option<i64> {
        match self {
            ResourceScope::All => None,
            ResourceScope::Owner(uid) => Some(*uid),
        }
    }
}

/// Scope for tunnel-profile reads. Distinct from [`ResourceScope`] because
/// profile isolation is by usage-context, not ownership:
/// - `AvailableTemplates`: templates available for rule selection (ws/tls_simple,
///   builtin + admin-created custom). Used by `GET /tunnel-profiles` so any
///   logged-in user can select a template for their rules.
/// - `ManageableCustomTemplates`: custom templates the admin can manage
///   (is_builtin = false, ws/tls_simple only). Used by `GET /admin/tunnel-profiles`.
/// - `All`: internal use (config generation, audit, migration).
///
/// v0.4.11 PR1: replaced `BuiltinOnly` with context-based scopes. A regular
/// user may now select any available WS/TLS Simple template (builtin or admin-
/// created custom), not just builtin ones.
#[derive(Debug, Clone, Copy)]
pub enum ProfileScope {
    /// Internal: all profiles (config generation, audit, migration).
    All,
    /// Available for rule selection: ws/tls_simple, builtin + admin custom.
    AvailableTemplates,
    /// Manageable custom templates: is_builtin=false, ws/tls_simple only.
    ManageableCustomTemplates,
}

// ── User ──

#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Login lookup: username must exist AND not be banned.
    async fn find_by_username_not_banned(&self, username: &str) -> Result<Option<User>, DbError>;
    /// Register existing check: username exists (regardless of banned).
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, DbError>;
    /// Load full user by id.
    async fn find_by_id(&self, id: i64) -> Result<Option<User>, DbError>;
    /// Password hash for change_password.
    async fn find_password_by_id(&self, id: i64) -> Result<Option<String>, DbError>;
    /// banned flag for auth extractor. Returns None if user doesn't exist.
    async fn find_banned_by_id(&self, id: i64) -> Result<Option<bool>, DbError>;
    /// v0.4.10 PR4: the auth state the middleware needs in ONE query —
    /// (banned, token_version, must_change_password). None = user deleted.
    /// Replaces three separate lookups per request.
    async fn find_auth_state_by_id(&self, id: i64) -> Result<Option<(bool, i64, bool)>, DbError>;
    /// Check if user is admin (returns None if not found or not admin).
    async fn is_admin(&self, id: i64) -> Result<bool, DbError>;
    /// Check if user exists by id.
    async fn exists_by_id(&self, id: i64) -> Result<bool, DbError>;
    /// Insert a new user (register).
    async fn insert_user(
        &self,
        username: &str,
        password_hash: &str,
        plan_id: i64,
    ) -> Result<(), DbError>;
    /// v0.4.10 PR3: register a user whose quota fields (max_rules,
    /// traffic_limit, speed_limit, ip_limit) are inherited ATOMICALLY from the
    /// plan via `INSERT ... SELECT`. This closes the race where a separate
    /// "validate plan then insert" sequence could see the plan change (or be
    /// deleted) between the two steps. Returns rows_affected: 0 means the plan
    /// does not exist (the SELECT matched no row) and no user was created —
    /// the caller surfaces this as a registration failure. A UNIQUE violation
    /// on username still surfaces as `DbError::UniqueViolation` (→ 409).
    async fn insert_user_from_plan(
        &self,
        username: &str,
        password_hash: &str,
        plan_id: i64,
    ) -> Result<u64, DbError>;
    /// Update password.
    async fn update_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError>;
    /// v0.4.10 PR4: self-service password change. Atomically sets the new hash,
    /// bumps token_version (revoking all the user's existing sessions including
    /// the one making this call), and clears must_change_password. Returns rows
    /// affected (0 = user not found).
    async fn change_own_password(&self, id: i64, new_hash: &str) -> Result<u64, DbError>;
    /// v0.4.10 PR4: admin password reset. Atomically sets the new hash, bumps
    /// token_version (revoking the target's sessions), and sets
    /// must_change_password to the given value (so a temporary password forces
    /// a change on first use). Returns rows affected (0 = user not found).
    async fn admin_reset_password(
        &self,
        id: i64,
        new_hash: &str,
        must_change_password: bool,
    ) -> Result<u64, DbError>;
    /// Dynamic field update (balance/max_rules/traffic_limit/banned).
    /// v0.4.10 PR4: when `banned` is set to `Some(true)`, the same UPDATE also
    /// bumps token_version so the ban instantly revokes the user's JWTs (the
    /// per-request banned check already blocks them, but bumping keeps the
    /// revocation signal uniform with admin-reset / self-change).
    async fn update_user_fields(
        &self,
        id: i64,
        balance: Option<&str>,
        max_rules: Option<i32>,
        traffic_limit: Option<i64>,
        banned: Option<bool>,
        suspended: Option<bool>,
    ) -> Result<u64, DbError>;
    /// v1.0.7: admin directly sets a user's plan association + expiry WITHOUT
    /// charging (the "edit user plan" panel uses this for removing a plan — both
    /// NULL — and for adjusting the expiry). Unconditionally writes both columns;
    /// the caller composes the pair (e.g. keep plan_id, change expiry). Skips
    /// admin users (WHERE admin = false). Returns rows affected (0 = not found
    /// or target is an admin).
    async fn admin_set_user_plan(
        &self,
        id: i64,
        plan_id: Option<i64>,
        plan_expire_at: Option<String>,
    ) -> Result<u64, DbError>;
    /// v1.0.9: remove a user's plan AND revoke device-group authorization AND
    /// pause their now-unauthorized rules, all in ONE transaction — the clear
    /// path used to do these as 4 separate calls, which could half-complete.
    /// Clears plan_id/plan_expire_at, sets all_device_groups=0, deletes the
    /// user's user_device_groups rows, and system-pauses (auto_paused=1) every
    /// active rule. No-op for admins. Returns rows affected on the user row
    /// (0 = not found or admin).
    async fn clear_user_plan(&self, user_id: i64) -> Result<u64, DbError>;
    /// Increment user traffic_used (called inside traffic batch tx).
    async fn increment_user_traffic(&self, id: i64, delta: i64) -> Result<(), DbError>;
    /// Reset traffic_used to 0 for user AND their rules (atomic).
    async fn reset_traffic(&self, id: i64) -> Result<(), DbError>;
    /// Delete user (only if not admin). Returns rows affected (0 = not found or admin).
    async fn delete_non_admin(&self, id: i64) -> Result<u64, DbError>;
    /// Delete a non-admin user AND all their owned resources (rules,
    /// tunnel_profiles, device_groups) in ONE transaction. Returns rows affected
    /// on the users table (0 = not found or admin → nothing deleted, fully rolled
    /// back). Replaces the old non-transactional cascade that missed
    /// tunnel_profiles and could leave a half-deleted account.
    async fn delete_user_cascade(&self, uid: i64) -> Result<u64, DbError>;
    /// List all users (public projection, no password).
    async fn list_users_public(&self) -> Result<Vec<crate::api::admin::UserPublic>, DbError>;
    /// Count users with placeholder admin password (system boot check).
    async fn count_placeholder_admin_password(&self) -> Result<i64, DbError>;
    /// Replace placeholder admin password with a real hash (system boot).
    async fn replace_placeholder_admin_password(&self, hash: &str) -> Result<(), DbError>;
}

// ── Rule (forward_rules) ──

#[async_trait]
pub trait RuleRepository: Send + Sync {
    async fn list_rules(&self, scope: &ResourceScope) -> Result<Vec<ForwardRule>, DbError>;
    /// Look up a single rule by id within the scope. None = no such rule OR a
    /// rule that exists but is outside the caller's scope (indistinguishable,
    /// by design — closes a resource-id existence oracle).
    async fn find_rule_by_id(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<ForwardRule>, DbError>;
    /// List all target rows for a rule (within scope), ordered by position.
    async fn list_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<ForwardRuleTarget>, DbError>;
    /// List enabled target rows for a rule (within scope), ordered by position.
    async fn list_enabled_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<ForwardRuleTarget>, DbError>;
    /// Replace all targets for an existing rule (within scope). Positions are
    /// assigned by input order.
    async fn replace_rule_targets(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        targets: &[RuleTargetRequest],
    ) -> Result<(), DbError>;
    /// Update a rule's load-balancing strategy (within scope). Returns rows affected.
    async fn set_rule_load_balance_strategy(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        strategy: &str,
    ) -> Result<u64, DbError>;
    /// Update a rule's per-rule upload/download Mbps caps (0 = unlimited),
    /// within scope.
    async fn set_rule_rate_limits(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
    ) -> Result<u64, DbError>;
    /// v1.2.0: update a rule's connection cap (0 = unlimited) and scheduled
    /// restart interval in minutes (0 = off), within scope.
    ///
    /// Written together because they are one form section and one semantic
    /// concern — "how this rule sheds load". The caller validates
    /// `auto_restart_minutes` against `MIN_AUTO_RESTART_MINUTES` first; this
    /// layer stores what it is given.
    async fn set_rule_connection_controls(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        max_connections: i32,
        auto_restart_minutes: i32,
    ) -> Result<u64, DbError>;
    /// v1.2.0: rules with a scheduled restart enabled (`auto_restart_minutes >
    /// 0`) that are not paused. Returns (rule_id, device_group_in,
    /// auto_restart_minutes) — everything the scheduler needs to fan a restart
    /// out to the rule's nodes, without loading whole rules every tick.
    async fn list_auto_restart_rules(&self) -> Result<Vec<(i64, i64, i32)>, DbError>;
    /// Bind (or unbind, when profile_id is None) a rule to a tunnel profile,
    /// within scope.
    async fn set_rule_tunnel_profile(
        &self,
        rule_id: i64,
        scope: &ResourceScope,
        profile_id: Option<i64>,
    ) -> Result<u64, DbError>;
    /// v0.4.11 PR4: the (listen_port, protocol) pairs already in use on a
    /// specific inbound group. Used by auto_assign_port to pick a free port
    /// scoped to the rule's device_group_in — different groups (and different
    /// users sharing the same group's pool) are evaluated independently.
    async fn list_group_port_protocols(
        &self,
        device_group_in: i64,
    ) -> Result<Vec<(i32, String, String)>, DbError>;
    /// v1.2.x: the auto-assign port pool configured on a device group
    /// (`device_groups.port_range`, e.g. "10000-65535"). `auto_assign_port`
    /// parses this to bound its search. Returns `None` when the group id
    /// doesn't exist (the caller falls back to the default pool).
    async fn group_port_range(&self, group_id: i64) -> Result<Option<String>, DbError>;
    /// Count rules for a user (quota reporting).
    async fn count_by_uid(&self, uid: i64) -> Result<i64, DbError>;
    /// Get max_rules for a user (quota ceiling; 0 = unlimited).
    async fn max_rules_for_uid(&self, uid: i64) -> Result<i32, DbError>;
    /// Insert a rule with quota guard AND port-conflict guard, in ONE
    /// transaction. The port check is socket-type aware (TCP-bearing rules
    /// conflict with TCP-bearing, UDP-bearing with UDP-bearing) and scoped to
    /// device_group_in.
    ///
    /// Returns `Ok(1)` on success, `Ok(0)` if the user's max_rules quota is
    /// exhausted, `Err(DbError::PortConflict)` if the port is already occupied
    /// on the group by a conflicting socket type, or `Err(DbError::UniqueViolation)`
    /// as the DB-layer backstop (partial unique index) when a concurrent insert
    /// won the race.
    ///
    /// Concurrency: SQLite uses BEGIN IMMEDIATE (acquire the write lock up
    /// front); PostgreSQL takes a per-group advisory xact lock plus the
    /// existing user-row FOR UPDATE quota lock.
    #[allow(clippy::too_many_arguments)]
    async fn insert_quota_guarded(
        &self,
        name: &str,
        uid: i64,
        listen_port: i32,
        protocol: &str,
        public_transport: &str,
        node_transport: &str,
        route_mode: &str,
        entry_transport: &str,
        ws_path: Option<&str>,
        sni: Option<&str>,
        camouflage_enabled: bool,
        send_proxy_protocol: bool,
        device_group_in: i64,
        device_group_out: Option<i64>,
        forward_mode: &str,
        target_addr: &str,
        target_port: i32,
    ) -> Result<u64, DbError>;

    /// v1.2: create a rule AND write its targets / load-balance strategy /
    /// rate limits / tunnel profile in ONE transaction, returning the new
    /// rule's id directly.
    ///
    /// This supersedes the old `insert_quota_guarded`-then-`list_rules`-by-
    /// `listen_port`-lookup dance for `create_rule`. The old lookup keyed only
    /// on `(owner_uid, listen_port)` and ignored `device_group_in`, so when two
    /// inbound groups (both legal owners of the same listen_port under the
    /// per-group partial unique index) reused a port, the lookup returned the
    /// WRONG rule and the targets/LB/limits were written to it. Returning the
    /// id from the INSERT itself closes that bug, and putting every write in
    /// one transaction means a mid-creation failure leaves no half-rule.
    ///
    /// Returns:
    /// - `Ok(Some(id))` — rule created; the id is the freshly inserted row.
    /// - `Ok(None)` — the owner's max_rules quota is exhausted (the
    ///   quota-guarded INSERT matched 0 rows); no row was written.
    /// - `Err(DbError::PortConflict)` — listen_port already occupied on the
    ///   inbound group by a conflicting socket type.
    /// - `Err(DbError::UniqueViolation)` — DB-layer backstop (partial unique
    ///   index) when a concurrent creator won the race.
    ///
    /// `load_balance_strategy` is the stable DB string ("first"/"round_robin"/
    /// "failover"); it is only written when it differs from "first" (mirrors
    /// the service's existing behaviour, since "first" is the column default).
    /// `upload_limit_mbps` / `download_limit_mbps` are only written when either
    /// is non-zero (0 = unlimited = the column default). `tunnel_profile_id` is
    /// only written when `Some`.
    #[allow(clippy::too_many_arguments)]
    async fn create_rule_full(
        &self,
        name: &str,
        uid: i64,
        listen_port: i32,
        protocol: &str,
        public_transport: &str,
        node_transport: &str,
        route_mode: &str,
        entry_transport: &str,
        ws_path: Option<&str>,
        sni: Option<&str>,
        camouflage_enabled: bool,
        send_proxy_protocol: bool,
        device_group_in: i64,
        device_group_out: Option<i64>,
        forward_mode: &str,
        target_addr: &str,
        target_port: i32,
        targets: &[RuleTargetRequest],
        load_balance_strategy: &str,
        upload_limit_mbps: i32,
        download_limit_mbps: i32,
        tunnel_profile_id: Option<i64>,
    ) -> Result<Option<i64>, DbError>;
    /// Find (protocol, public_transport) for effective-combo validation, scoped.
    async fn find_transport_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<(String, String)>, DbError>;
    /// Find device_group_out for update_rule, scoped.
    async fn find_device_group_out_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<Option<i64>>, DbError>;
    /// Dynamic update of legacy rule fields, scoped. Returns rows affected.
    #[allow(clippy::too_many_arguments)]
    async fn update_rule_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        listen_port: Option<i32>,
        protocol: Option<&str>,
        public_transport: Option<&str>,
        node_transport: Option<&str>,
        entry_transport: Option<&str>,
        route_mode: Option<&str>,
        ws_path: Option<Option<&str>>,
        sni: Option<Option<&str>>,
        camouflage_enabled: Option<bool>,
        device_group_in: Option<i64>,
        device_group_out: Option<Option<i64>>,
        forward_mode: Option<&str>,
        target_addr: Option<&str>,
        target_port: Option<i32>,
        paused: Option<bool>,
    ) -> Result<u64, DbError> {
        self.update_rule_fields_with_proxy_protocol(
            id,
            scope,
            name,
            listen_port,
            protocol,
            public_transport,
            node_transport,
            entry_transport,
            route_mode,
            ws_path,
            sni,
            camouflage_enabled,
            None,
            device_group_in,
            device_group_out,
            forward_mode,
            target_addr,
            target_port,
            paused,
        )
        .await
    }

    /// Extended dynamic update used by nginx_sni Rule edits. When
    /// `send_proxy_protocol` is present and the resulting row is nginx_sni, the
    /// whole listener cohort is synchronized in the same database transaction.
    #[allow(clippy::too_many_arguments)]
    async fn update_rule_fields_with_proxy_protocol(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        listen_port: Option<i32>,
        protocol: Option<&str>,
        public_transport: Option<&str>,
        node_transport: Option<&str>,
        entry_transport: Option<&str>,
        route_mode: Option<&str>,
        ws_path: Option<Option<&str>>,
        sni: Option<Option<&str>>,
        camouflage_enabled: Option<bool>,
        send_proxy_protocol: Option<bool>,
        device_group_in: Option<i64>,
        device_group_out: Option<Option<i64>>,
        forward_mode: Option<&str>,
        target_addr: Option<&str>,
        target_port: Option<i32>,
        paused: Option<bool>,
    ) -> Result<u64, DbError>;
    /// Increment rule traffic (upload, download).
    async fn increment_rule_traffic(
        &self,
        id: i64,
        upload: u64,
        download: u64,
    ) -> Result<(), DbError>;
    /// Find rule owner (rule_id, uid) for traffic report ownership check.
    async fn find_rule_owner(
        &self,
        rule_id: i64,
        device_group_in: i64,
    ) -> Result<Option<(i64, i64)>, DbError>;
    /// Delete rule by id, scoped. Returns rows affected.
    async fn delete_rule(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError>;
    /// Delete all rules for a user (cascade cleanup).
    async fn delete_rules_by_uid(&self, uid: i64) -> Result<u64, DbError>;
    /// List active rules for config build (the JOIN+filter query).
    /// This returns raw ForwardRule rows; config assembly is service-layer.
    async fn list_active_for_config(&self, group_id: i64) -> Result<Vec<ForwardRule>, DbError>;
}

// ── Group (device_groups) ──

#[async_trait]
pub trait GroupRepository: Send + Sync {
    /// Returns all groups the caller has access to, scoped by ownership.
    /// Non-admins see only their own groups.
    async fn list_groups(&self, scope: &ResourceScope) -> Result<Vec<DeviceGroup>, DbError>;
    /// v0.4.12 PR1: returns a summary of ADMIN-owned `group_type = 'in'` groups,
    /// available for ANY regular user to attach rules to — independent of
    /// whether the user already has rules. Admins get an empty list (they manage
    /// groups directly, not via shared infrastructure). Never includes sensitive
    /// fields (token, uid, config, fallback_group). The companion node-status
    /// aggregation is done in the handler layer over the `node_status:*` kvs
    /// keys (there is NO node_status table), so it is NOT a Repository method.
    async fn list_shared_groups(
        &self,
        uid: i64,
        is_admin: bool,
    ) -> Result<Vec<SharedGroupSummary>, DbError>;
    async fn find_by_token(&self, token: &str) -> Result<Option<DeviceGroup>, DbError>;
    /// Look up a group by id within the scope. None = no such group OR a group
    /// outside the caller's scope (indistinguishable → 404).
    async fn find_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<DeviceGroup>, DbError>;
    async fn find_name_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<String>, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn insert_group(
        &self,
        name: &str,
        group_type: &str,
        token: &str,
        uid: i64,
        connect_host: &str,
        port_range: &str,
        rate: f64,
        hidden: bool,
    ) -> Result<(), DbError>;
    async fn find_by_token_after_insert(&self, token: &str)
        -> Result<Option<DeviceGroup>, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn update_group_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        group_type: Option<&str>,
        connect_host: Option<&str>,
        port_range: Option<&str>,
        rate: Option<f64>,
        hidden: Option<bool>,
    ) -> Result<u64, DbError>;
    async fn update_group_token(
        &self,
        id: i64,
        scope: &ResourceScope,
        new_token: &str,
    ) -> Result<u64, DbError>;
    /// v1.0.4: count how many forward_rules reference this group via
    /// device_group_in, device_group_out, or fallback_group. Used as a
    /// pre-delete safety check so the admin sees a clear 409 instead of
    /// a cryptic FK violation or orphaned references.
    async fn count_rules_by_group(&self, id: i64) -> Result<i64, DbError>;
    async fn delete_group(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError>;
    async fn delete_groups_by_uid(&self, uid: i64) -> Result<u64, DbError>;
    /// v1.0.8: list all inbound device groups (group_type = 'in'). Used by the
    /// purchase flow to compute the authorized set when grant_all_groups=true
    /// — in that mode the user gains access to every inbound group, so rules
    /// bound to inbound groups are NOT paused.
    async fn list_all_inbound_group_ids(&self) -> Result<Vec<i64>, DbError>;
    /// v1.0.8: resolve device-group NAMES for the given ids, for display (e.g.
    /// the account page's "可用线路" and the shop's plan-grant hint). Unlike
    /// `list_shared_groups`, this is NOT filtered by ownership/authorization —
    /// callers already know the ids are safe to show to the caller (their own
    /// authorized set, or a plan's grant set). Order is not guaranteed; callers
    /// that need it presented in `ids` order should sort client-side.
    async fn list_group_names_by_ids(&self, ids: &[i64]) -> Result<Vec<String>, DbError>;
}

// ── Node Reuse V1 bindings ──

/// Stable identity for one concrete Relay in the current data model. `node_id`
/// alone is insufficient outside its Home Group namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, sqlx::FromRow)]
pub struct ConcreteNodeIdentity {
    pub home_group_id: i64,
    pub node_id: String,
}

/// One explicit authorization for `reusing_group_id` to run on exactly one
/// concrete Home-Group node. This does not transfer node ownership.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct NodeReuseBinding {
    pub reusing_group_id: i64,
    pub home_group_id: i64,
    pub node_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeReuseBindingCreateRejection {
    ReusingGroupMissing,
    HomeGroupMissing,
    ReusingGroupNotInbound,
    HomeGroupNotInbound,
    ActiveCredentialMissing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeReuseBindingCreateResult {
    Created(NodeReuseBinding),
    Existing(NodeReuseBinding),
    Rejected(NodeReuseBindingCreateRejection),
}

#[async_trait]
pub trait NodeReuseRepository: Send + Sync {
    async fn insert_node_reuse_binding(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<(), DbError>;
    /// Atomically admits a new exact-node reuse binding. Implementations must
    /// re-check both Group rows and the exact identity's current ACTIVE
    /// Credential in the same transaction as the INSERT so a concurrent Group
    /// deletion/type change or Credential revocation cannot race admission.
    ///
    /// An already-persisted exact binding returns Existing without requiring
    /// the Credential to still be active: a binding is durable admin history,
    /// while runtime/preview authority is revalidated separately.
    async fn create_node_reuse_binding_if_active(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
    ) -> Result<NodeReuseBindingCreateResult, DbError>;
    async fn find_node_reuse_binding(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<Option<NodeReuseBinding>, DbError>;
    async fn list_reusing_group_ids_for_node(
        &self,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<Vec<i64>, DbError>;
    async fn list_reused_concrete_nodes_for_group(
        &self,
        reusing_group_id: i64,
    ) -> Result<Vec<ConcreteNodeIdentity>, DbError>;
    /// Conservative primitive for future Home-Group deletion guards. Slice 1
    /// deliberately does not wire it into current group deletion behavior.
    async fn count_node_reuse_bindings_for_home_group(
        &self,
        home_group_id: i64,
    ) -> Result<i64, DbError>;
    /// Counts bindings that reference this Group in either role. Used by the
    /// admin Group deletion guard; FK RESTRICT remains the database backstop.
    async fn count_node_reuse_bindings_for_group(&self, group_id: i64) -> Result<i64, DbError>;
    async fn delete_node_reuse_binding(
        &self,
        reusing_group_id: i64,
        home_group_id: i64,
        node_id: &str,
    ) -> Result<u64, DbError>;
}

// ── Node Reuse V1 concrete-node credential registry ──

/// Persisted verifier material for one concrete Node credential generation.
///
/// A row is still NOT proof of a claimed Node or Node Reuse authority. S2-A2A
/// adds only internal cryptographic/lifecycle primitives; no runtime path calls them.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct NodeCredentialRecord {
    /// Public lookup identifier for the verifier record. This is not a bearer secret.
    pub credential_id: String,
    pub home_group_id: i64,
    pub node_id: String,
    /// Monotonic per-(Home Group, node id) generation.
    pub generation: i64,
    pub verifier_format: String,
    pub verifier_version: i64,
    /// Verifier bytes are deliberately redacted from Debug output.
    pub verifier_data: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
    /// Inactive candidates keep this NULL. A non-NULL value means server-active
    /// only; it does not grant Node Reuse authority.
    pub activated_at: Option<String>,
    /// Once set, revocation is irreversible through the Repository contract.
    pub revoked_at: Option<String>,
}

/// S2-A1 storage-shape DTO retained for compatibility/debug regression coverage.
///
/// S2-A2A deliberately removes the Repository write method that accepted this
/// caller-selected generation. New writes must use NewNodeCredentialCandidate
/// so the database layer allocates generations atomically.
#[derive(Clone, PartialEq, Eq)]
pub struct NewNodeCredentialRecord {
    pub credential_id: String,
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub generation: i64,
    pub verifier_format: String,
    pub verifier_version: i64,
    pub verifier_data: Vec<u8>,
}

/// Candidate input for atomic generation allocation. It structurally carries the
/// reviewed V1 verifier rather than arbitrary format/version/data fields.
#[derive(Clone, PartialEq, Eq)]
pub struct NewNodeCredentialCandidate {
    pub credential_id: String,
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub verifier: NodeCredentialVerifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeCredentialMutationResult {
    Applied,
    Rejected,
}

struct RedactedVerifierData;

impl std::fmt::Debug for RedactedVerifierData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Debug for NodeCredentialRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentialRecord")
            .field("credential_id", &self.credential_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("generation", &self.generation)
            .field("verifier_format", &self.verifier_format)
            .field("verifier_version", &self.verifier_version)
            .field("verifier_data", &RedactedVerifierData)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("activated_at", &self.activated_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

impl std::fmt::Debug for NewNodeCredentialRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewNodeCredentialRecord")
            .field("credential_id", &self.credential_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("generation", &self.generation)
            .field("verifier_format", &self.verifier_format)
            .field("verifier_version", &self.verifier_version)
            .field("verifier_data", &RedactedVerifierData)
            .finish()
    }
}

impl std::fmt::Debug for NewNodeCredentialCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewNodeCredentialCandidate")
            .field("credential_id", &self.credential_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("verifier", &self.verifier)
            .finish()
    }
}

#[cfg(test)]
mod node_credential_debug_tests {
    use super::*;

    const VERIFIER_BYTES: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    fn assert_verifier_is_redacted(debug: &str) {
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("[1, 35, 69, 103, 137, 171, 205, 239]"));
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("ASNFZ4mrze8="));
    }

    #[test]
    fn node_credential_record_debug_redacts_verifier_data() {
        let record = NodeCredentialRecord {
            credential_id: "cred-debug-record".into(),
            home_group_id: 42,
            node_id: "Node_A".into(),
            generation: 7,
            verifier_format: "test-format".into(),
            verifier_version: 3,
            verifier_data: VERIFIER_BYTES.to_vec(),
            created_at: "2026-09-23 00:00:00".into(),
            updated_at: "2026-09-23 00:01:00".into(),
            activated_at: None,
            revoked_at: None,
        };

        let debug = format!("{record:?}");
        assert_verifier_is_redacted(&debug);
        assert!(debug.contains("cred-debug-record"));
        assert!(debug.contains("Node_A"));
        assert!(debug.contains("home_group_id: 42"));
        assert!(debug.contains("test-format"));
        assert!(debug.contains("verifier_version: 3"));
    }

    #[test]
    fn new_node_credential_record_debug_redacts_verifier_data() {
        let record = NewNodeCredentialRecord {
            credential_id: "cred-debug-new".into(),
            home_group_id: 84,
            node_id: ReuseEligibleNodeId::parse("Node_B").unwrap(),
            generation: 9,
            verifier_format: "test-format-new".into(),
            verifier_version: 4,
            verifier_data: VERIFIER_BYTES.to_vec(),
        };

        let debug = format!("{record:?}");
        assert_verifier_is_redacted(&debug);
        assert!(debug.contains("cred-debug-new"));
        assert!(debug.contains("Node_B"));
        assert!(debug.contains("home_group_id: 84"));
        assert!(debug.contains("test-format-new"));
        assert!(debug.contains("verifier_version: 4"));
    }
}

#[async_trait]
pub trait NodeCredentialRepository: Send + Sync {
    /// Atomically assigns the next generation for this exact concrete identity
    /// and persists an inactive candidate. Callers cannot supply a generation.
    async fn allocate_node_credential_candidate(
        &self,
        candidate: &NewNodeCredentialCandidate,
    ) -> Result<NodeCredentialRecord, DbError>;

    async fn find_node_credential(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError>;

    /// Runtime-authentication lookup. Returns only the exact credential when it
    /// is the current ACTIVE generation for its concrete Home Group + Node
    /// identity. Historical/revoked/inactive rows are deliberately invisible.
    async fn find_active_node_credential_for_runtime(
        &self,
        credential_id: &str,
    ) -> Result<Option<NodeCredentialRecord>, DbError>;

    /// Identity-scoped form of the current-ACTIVE lookup. Returns exactly the
    /// latest activated generation only when it is still non-revoked.
    async fn find_current_active_node_credential_for_identity(
        &self,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
    ) -> Result<Option<NodeCredentialRecord>, DbError>;

    async fn list_node_credentials_for_identity(
        &self,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
    ) -> Result<Vec<NodeCredentialRecord>, DbError>;

    /// Performs the one-time initial activation of an inactive, non-revoked
    /// candidate. Once this exact identity has any activation history, later
    /// activation must use a separately approved recovery flow, not this method.
    async fn activate_node_credential(
        &self,
        credential_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError>;

    /// Atomically revokes the expected current active generation and activates
    /// an inactive candidate whose generation is strictly newer than both the
    /// current generation and every historically activated generation. Any
    /// mismatch or rollback attempt leaves the old active row unchanged.
    async fn replace_active_node_credential(
        &self,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        expected_active_credential_id: &str,
        expected_active_generation: i64,
        candidate_credential_id: &str,
        candidate_generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError>;

    /// Irreversible through this contract: there is intentionally no method that
    /// clears revoked_at or reactivates a revoked generation.
    async fn revoke_node_credential(
        &self,
        credential_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        generation: i64,
    ) -> Result<NodeCredentialMutationResult, DbError>;
}

// ── Node Reuse V1 one-time Concrete Node Claim registry ──

/// Persisted internal Claim state. A row is authorization workflow state only:
/// it is not proof that a physical machine has been verified and grants no
/// runtime Node Reuse authority.
#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct NodeCredentialClaimRecord {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: String,
    pub secret_verifier_format: String,
    pub secret_verifier_version: i64,
    pub secret_verifier_data: Vec<u8>,
    pub state: String,
    pub expires_at: String,
    pub claimant_nonce_verifier_format: Option<String>,
    pub claimant_nonce_verifier_version: Option<i64>,
    pub claimant_nonce_verifier_data: Option<Vec<u8>>,
    pub approved_by: i64,
    pub approval_ref: String,
    pub created_at: String,
    pub updated_at: String,
    pub claimed_at: Option<String>,
    pub credential_pending_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancelled_at: Option<String>,
    pub expired_at: Option<String>,
}

/// Input for atomically creating an APPROVED Claim.
///
/// It intentionally carries only a verifier, never the raw Claim Secret.
#[derive(Clone, PartialEq, Eq)]
pub struct NewNodeCredentialClaim {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub secret_verifier: NodeClaimSecretVerifier,
    pub approved_by: i64,
    pub approval_ref: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Presented material for one claim attempt. Raw material exists only in memory
/// for constant-time verifier checks and is never part of a persisted DTO.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeCredentialClaimAttempt {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub secret: NodeClaimSecret,
    pub claimant_nonce: NodeClaimantNonce,
    pub now: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCredentialClaimCreateResult {
    Created(NodeCredentialClaimRecord),
    Existing(NodeCredentialClaimRecord),
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCredentialClaimResult {
    Claimed(NodeCredentialClaimRecord),
    Existing(NodeCredentialClaimRecord),
    Expired,
    Cancelled,
    Invalid,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeCredentialClaimMutationResult {
    Applied,
    Rejected,
}

impl std::fmt::Debug for NodeCredentialClaimRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentialClaimRecord")
            .field("claim_id", &self.claim_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("secret_verifier_format", &self.secret_verifier_format)
            .field("secret_verifier_version", &self.secret_verifier_version)
            .field("secret_verifier_data", &RedactedVerifierData)
            .field("state", &self.state)
            .field("expires_at", &self.expires_at)
            .field(
                "claimant_nonce_verifier_format",
                &self.claimant_nonce_verifier_format,
            )
            .field(
                "claimant_nonce_verifier_version",
                &self.claimant_nonce_verifier_version,
            )
            .field(
                "claimant_nonce_verifier_data",
                &self
                    .claimant_nonce_verifier_data
                    .as_ref()
                    .map(|_| RedactedVerifierData),
            )
            .field("approved_by", &self.approved_by)
            .field("approval_ref", &self.approval_ref)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("claimed_at", &self.claimed_at)
            .field("credential_pending_at", &self.credential_pending_at)
            .field("completed_at", &self.completed_at)
            .field("cancelled_at", &self.cancelled_at)
            .field("expired_at", &self.expired_at)
            .finish()
    }
}

impl std::fmt::Debug for NewNodeCredentialClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewNodeCredentialClaim")
            .field("claim_id", &self.claim_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("secret_verifier", &self.secret_verifier)
            .field("approved_by", &self.approved_by)
            .field("approval_ref", &self.approval_ref)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl std::fmt::Debug for NodeCredentialClaimAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentialClaimAttempt")
            .field("claim_id", &self.claim_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("secret", &self.secret)
            .field("claimant_nonce", &self.claimant_nonce)
            .field("now", &self.now)
            .finish()
    }
}

impl NodeCredentialClaimRecord {
    pub fn secret_matches(&self, node_id: &ReuseEligibleNodeId, secret: &NodeClaimSecret) -> bool {
        if self.node_id != node_id.as_str()
            || self.secret_verifier_format != crate::node_claim::NODE_CLAIM_SECRET_VERIFIER_FORMAT
            || self.secret_verifier_version != crate::node_claim::NODE_CLAIM_VERIFIER_VERSION
        {
            return false;
        }
        NodeClaimSecretVerifier::derive(&self.claim_id, self.home_group_id, node_id, secret)
            .verify_data(&self.secret_verifier_data)
    }

    pub fn claimant_nonce_matches(
        &self,
        node_id: &ReuseEligibleNodeId,
        nonce: &NodeClaimantNonce,
    ) -> bool {
        let (Some(format), Some(version), Some(data)) = (
            self.claimant_nonce_verifier_format.as_deref(),
            self.claimant_nonce_verifier_version,
            self.claimant_nonce_verifier_data.as_deref(),
        ) else {
            return false;
        };
        if format != crate::node_claim::NODE_CLAIM_NONCE_VERIFIER_FORMAT
            || version != crate::node_claim::NODE_CLAIM_VERIFIER_VERSION
        {
            return false;
        }
        NodeClaimNonceVerifier::derive(&self.claim_id, self.home_group_id, node_id, nonce)
            .verify_data(data)
    }
}

#[async_trait]
pub trait NodeCredentialClaimRepository: Send + Sync {
    async fn create_node_credential_claim(
        &self,
        claim: &NewNodeCredentialClaim,
    ) -> Result<NodeCredentialClaimCreateResult, DbError>;

    async fn find_node_credential_claim(
        &self,
        claim_id: &str,
    ) -> Result<Option<NodeCredentialClaimRecord>, DbError>;

    async fn list_node_credential_claims_for_identity(
        &self,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
    ) -> Result<Vec<NodeCredentialClaimRecord>, DbError>;

    async fn claim_node_credential(
        &self,
        attempt: &NodeCredentialClaimAttempt,
    ) -> Result<NodeCredentialClaimResult, DbError>;

    async fn cancel_node_credential_claim(
        &self,
        claim_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NodeCredentialClaimMutationResult, DbError>;

    async fn expire_node_credential_claim(
        &self,
        claim_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NodeCredentialClaimMutationResult, DbError>;
}

// ── Node Reuse V1 B2-02A inert credential-delivery state machine ──

pub const NODE_CREDENTIAL_DELIVERY_TTL_SECS: i64 = 10 * 60;

#[derive(Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct NodeCredentialDeliveryRecord {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: String,
    pub credential_id: String,
    pub credential_verifier_format: String,
    pub credential_verifier_version: i64,
    pub credential_verifier_data: Vec<u8>,
    pub delivery_nonce_verifier_format: String,
    pub delivery_nonce_verifier_version: i64,
    pub delivery_nonce_verifier_data: Vec<u8>,
    pub state: String,
    pub authorized_at: String,
    pub expires_at: String,
    pub updated_at: String,
    pub credential_generation: Option<i64>,
    pub proof_verified_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancelled_at: Option<String>,
    pub expired_at: Option<String>,
}

impl std::fmt::Debug for NodeCredentialDeliveryRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentialDeliveryRecord")
            .field("claim_id", &self.claim_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("credential_id", &self.credential_id)
            .field(
                "credential_verifier_format",
                &self.credential_verifier_format,
            )
            .field(
                "credential_verifier_version",
                &self.credential_verifier_version,
            )
            .field("credential_verifier_data", &RedactedVerifierData)
            .field(
                "delivery_nonce_verifier_format",
                &self.delivery_nonce_verifier_format,
            )
            .field(
                "delivery_nonce_verifier_version",
                &self.delivery_nonce_verifier_version,
            )
            .field("delivery_nonce_verifier_data", &RedactedVerifierData)
            .field("state", &self.state)
            .field("authorized_at", &self.authorized_at)
            .field("expires_at", &self.expires_at)
            .field("updated_at", &self.updated_at)
            .field("credential_generation", &self.credential_generation)
            .field("proof_verified_at", &self.proof_verified_at)
            .field("completed_at", &self.completed_at)
            .field("cancelled_at", &self.cancelled_at)
            .field("expired_at", &self.expired_at)
            .finish()
    }
}

impl NodeCredentialDeliveryRecord {
    pub fn delivery_nonce_matches(
        &self,
        node_id: &ReuseEligibleNodeId,
        nonce: &NodeCredentialDeliveryNonce,
    ) -> bool {
        if self.node_id != node_id.as_str()
            || self.delivery_nonce_verifier_format
                != crate::node_credential::NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_FORMAT
            || self.delivery_nonce_verifier_version
                != crate::node_credential::NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_VERSION
        {
            return false;
        }
        NodeCredentialDeliveryNonceVerifier::derive(
            &self.claim_id,
            self.home_group_id,
            node_id,
            nonce,
        )
        .verify_data(&self.delivery_nonce_verifier_data)
    }

    pub fn presented_verifier_matches(&self, presented: &PresentedNodeCredentialVerifier) -> bool {
        self.credential_verifier_format == presented.format()
            && self.credential_verifier_version == presented.version()
            && presented.verify_data(&self.credential_verifier_data)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PrepareInitialNodeCredentialDelivery {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub claim_secret: NodeClaimSecret,
    pub claimant_nonce: NodeClaimantNonce,
    pub delivery_nonce: NodeCredentialDeliveryNonce,
    pub credential_id: String,
    pub presented_verifier: PresentedNodeCredentialVerifier,
    pub now: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for PrepareInitialNodeCredentialDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrepareInitialNodeCredentialDelivery")
            .field("claim_id", &self.claim_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("claim_secret", &self.claim_secret)
            .field("claimant_nonce", &self.claimant_nonce)
            .field("delivery_nonce", &self.delivery_nonce)
            .field("credential_id", &self.credential_id)
            .field("presented_verifier", &self.presented_verifier)
            .field("now", &self.now)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ActivateInitialNodeCredentialFromDelivery {
    pub claim_id: String,
    pub home_group_id: i64,
    pub node_id: ReuseEligibleNodeId,
    pub credential_id: String,
    pub delivery_nonce: NodeCredentialDeliveryNonce,
    pub credential_secret: NodeCredentialSecret,
    pub now: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Debug for ActivateInitialNodeCredentialFromDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivateInitialNodeCredentialFromDelivery")
            .field("claim_id", &self.claim_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("credential_id", &self.credential_id)
            .field("delivery_nonce", &self.delivery_nonce)
            .field("credential_secret", &self.credential_secret)
            .field("now", &self.now)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCredentialDeliveryPrepareResult {
    Prepared(NodeCredentialDeliveryRecord),
    Existing(NodeCredentialDeliveryRecord),
    Expired,
    Cancelled,
    Invalid,
    Replay,
    AlreadyActive,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeCredentialDeliveryActivateResult {
    Activated {
        delivery: NodeCredentialDeliveryRecord,
        credential: NodeCredentialRecord,
    },
    Existing {
        delivery: NodeCredentialDeliveryRecord,
        credential: NodeCredentialRecord,
    },
    Expired,
    Cancelled,
    Invalid,
    InvalidProof,
    AlreadyActive,
    RecoveryRequired,
    CredentialRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeCredentialDeliveryMutationResult {
    Applied,
    Rejected,
}

#[async_trait]
pub trait NodeCredentialDeliveryRepository: Send + Sync {
    async fn find_node_credential_delivery(
        &self,
        claim_id: &str,
    ) -> Result<Option<NodeCredentialDeliveryRecord>, DbError>;

    async fn prepare_initial_node_credential_delivery(
        &self,
        request: &PrepareInitialNodeCredentialDelivery,
    ) -> Result<NodeCredentialDeliveryPrepareResult, DbError>;

    async fn activate_initial_node_credential_from_delivery(
        &self,
        request: &ActivateInitialNodeCredentialFromDelivery,
    ) -> Result<NodeCredentialDeliveryActivateResult, DbError>;

    async fn expire_node_credential_delivery(
        &self,
        claim_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NodeCredentialDeliveryMutationResult, DbError>;
}

// ── Manual bootstrap enrollments ──

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ManualBootstrapEnrollment {
    pub id: String,
    pub secret_verifier: String,
    pub group_id: i64,
    pub profile: String,
    pub state: String,
    pub architecture: Option<String>,
    pub client_nonce_verifier: Option<String>,
    pub session_verifier: Option<String>,
    pub session_expires_at: Option<String>,
    pub node_id: Option<String>,
    pub observed_at: Option<String>,
    pub last_error_category: Option<String>,
    pub created_by: i64,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
    pub claimed_at: Option<String>,
    pub verified_at: Option<String>,
    pub local_committed_at: Option<String>,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewManualBootstrapEnrollment {
    pub id: String,
    pub secret_verifier: String,
    pub group_id: i64,
    pub profile: String,
    pub created_by: i64,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone)]
pub struct ManualBootstrapClaim {
    pub id: String,
    pub secret_verifier: String,
    pub profile: String,
    pub architecture: String,
    pub client_nonce_verifier: String,
    pub session_verifier: String,
    pub session_expires_at: String,
    pub now: String,
}

#[derive(Debug, Clone)]
pub enum ManualBootstrapClaimResult {
    Claimed(ManualBootstrapEnrollment),
    Existing(ManualBootstrapEnrollment),
    Expired,
    Invalid,
    Replay,
}

#[async_trait]
pub trait ManualBootstrapEnrollmentRepository: Send + Sync {
    async fn create_manual_bootstrap_enrollment(
        &self,
        enrollment: &NewManualBootstrapEnrollment,
    ) -> Result<(), DbError>;

    async fn find_manual_bootstrap_enrollment(
        &self,
        id: &str,
    ) -> Result<Option<ManualBootstrapEnrollment>, DbError>;

    async fn claim_manual_bootstrap_enrollment(
        &self,
        claim: &ManualBootstrapClaim,
    ) -> Result<ManualBootstrapClaimResult, DbError>;

    async fn expire_manual_bootstrap_enrollment(&self, id: &str, now: &str)
        -> Result<u64, DbError>;

    async fn record_manual_bootstrap_verification_error(
        &self,
        id: &str,
        session_verifier: &str,
        category: &str,
        now: &str,
    ) -> Result<u64, DbError>;

    async fn mark_manual_bootstrap_verifying(
        &self,
        id: &str,
        session_verifier: &str,
        node_id: &str,
        observed_at: &str,
        now: &str,
    ) -> Result<u64, DbError>;

    async fn mark_manual_bootstrap_local_committed(
        &self,
        id: &str,
        session_verifier: &str,
        node_id: &str,
        now: &str,
    ) -> Result<u64, DbError>;

    async fn complete_manual_bootstrap_enrollment(
        &self,
        id: &str,
        session_verifier: &str,
        now: &str,
    ) -> Result<u64, DbError>;

    async fn fail_manual_bootstrap_enrollment(
        &self,
        id: &str,
        session_verifier: &str,
        category: &str,
        now: &str,
    ) -> Result<u64, DbError>;
}

// ── DNS record ownership bindings ──

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DnsRecordBinding {
    pub id: i64,
    pub rule_id: Option<i64>,
    pub fqdn: String,
    pub zone_id: i64,
    pub zone_name: String,
    pub host: String,
    pub record_type: String,
    /// Exact provider line identity as observed when the binding was created.
    pub line: String,
    /// Stable desired identity (`default` or `dnsmgr:<opaque raw id>`).
    pub line_key: String,
    pub record_id: String,
    pub desired_value: String,
    pub state: String,
    pub last_observed_at: Option<String>,
    pub last_error_category: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct NewDnsRecordBinding {
    pub rule_id: Option<i64>,
    pub fqdn: String,
    pub zone_id: i64,
    pub zone_name: String,
    pub host: String,
    pub record_type: String,
    pub line: String,
    pub line_key: String,
    pub record_id: String,
    pub desired_value: String,
    pub state: String,
    pub last_observed_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct DetachedDnsRecordBindingAdoption {
    pub binding_id: i64,
    pub rule_id: i64,
    pub fqdn: String,
    pub zone_id: i64,
    pub zone_name: String,
    pub host: String,
    pub record_type: String,
    pub line: String,
    pub line_key: String,
    pub record_id: String,
    pub previous_desired_value: String,
    pub desired_value: String,
    pub observed_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct AmbiguousDnsRecordBindingRebind {
    pub binding_id: i64,
    pub rule_id: i64,
    pub fqdn: String,
    pub zone_id: i64,
    pub zone_name: String,
    pub host: String,
    pub record_type: String,
    pub line: String,
    pub line_key: String,
    pub previous_record_id: String,
    pub replacement_record_id: String,
    pub desired_value: String,
    pub observed_at: String,
    pub updated_at: String,
}

#[async_trait]
pub trait DnsRecordBindingRepository: Send + Sync {
    async fn insert_dns_record_binding(
        &self,
        binding: &NewDnsRecordBinding,
    ) -> Result<i64, DbError>;

    async fn find_dns_record_binding_by_record(
        &self,
        zone_id: i64,
        record_id: &str,
    ) -> Result<Option<DnsRecordBinding>, DbError>;

    async fn find_dns_record_binding_for_rule(
        &self,
        rule_id: i64,
        fqdn: &str,
        record_type: &str,
        line_key: &str,
    ) -> Result<Option<DnsRecordBinding>, DbError>;

    async fn update_dns_record_binding_observation(
        &self,
        id: i64,
        state: &str,
        last_observed_at: Option<&str>,
        last_error_category: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError>;

    /// Replace the provider identity/value only after a mutation has been
    /// confirmed by post-write discovery. This is the controlled stale-record
    /// recreation path; discovery alone must never call it.
    async fn rebind_verified_dns_record(
        &self,
        id: i64,
        record_id: &str,
        line: &str,
        desired_value: &str,
        observed_at: &str,
        updated_at: &str,
    ) -> Result<u64, DbError>;

    /// Recover provider identity only for a binding left in the explicit
    /// ambiguous-mutation recoverable state. The transfer deliberately preserves
    /// ERROR + MUTATION_UNKNOWN until normal reconciliation verifies the provider.
    /// Every previous identity field is part of the atomic predicate; a normal
    /// BOUND/MISSING/CONFLICT binding cannot use this path.
    async fn rebind_ambiguous_dns_record_binding(
        &self,
        rebind: &AmbiguousDnsRecordBindingRebind,
    ) -> Result<u64, DbError>;

    /// Atomically transfer preserved Panel ownership to a replacement Rule.
    /// Every identity field remains in the predicate so stale metadata or a
    /// concurrent claimant can never be overwritten.
    async fn adopt_detached_dns_record_binding(
        &self,
        adoption: &DetachedDnsRecordBindingAdoption,
    ) -> Result<u64, DbError>;
}

// ── DNS reconciliation desired state ──

/// Persisted desired/reconciliation state is deliberately separate from
/// `DnsRecordBinding`: a pending or externally-owned record is not Panel
/// ownership evidence.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DnsRecordSync {
    pub rule_id: i64,
    pub fqdn: String,
    pub record_type: String,
    pub expected_value: Option<String>,
    pub line: String,
    pub line_key: String,
    pub desired_action: String,
    pub state: String,
    pub ownership: String,
    pub mutation_verified_at: Option<String>,
    pub last_observed_at: Option<String>,
    pub propagated_at: Option<String>,
    pub last_error_category: Option<String>,
    pub attempt_count: i32,
    pub next_attempt_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct NewDnsRecordSync {
    pub rule_id: i64,
    pub fqdn: String,
    pub record_type: String,
    pub expected_value: Option<String>,
    pub line: String,
    pub line_key: String,
    pub desired_action: String,
    pub state: String,
    pub ownership: String,
    pub last_error_category: Option<String>,
    pub next_attempt_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[allow(clippy::too_many_arguments)] // Repository 参数顺序是 SQLite/PG 共享契约，本次不改 API。
#[async_trait]
pub trait DnsRecordSyncRepository: Send + Sync {
    async fn insert_dns_record_sync(&self, sync: &NewDnsRecordSync) -> Result<(), DbError>;

    async fn find_dns_record_sync(
        &self,
        rule_id: i64,
        line_key: &str,
    ) -> Result<Option<DnsRecordSync>, DbError>;

    async fn list_dns_record_syncs_for_rule(
        &self,
        rule_id: i64,
    ) -> Result<Vec<DnsRecordSync>, DbError>;

    /// Update desired state only when the desired record changed. The caller
    /// supplies a fresh pending state for an explicit rule/settings trigger.
    async fn update_dns_record_sync_desired(
        &self,
        rule_id: i64,
        fqdn: &str,
        record_type: &str,
        expected_value: Option<&str>,
        line: &str,
        line_key: &str,
        desired_action: &str,
        state: &str,
        ownership: &str,
        last_error_category: Option<&str>,
        next_attempt_at: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError>;

    async fn schedule_dns_record_sync(
        &self,
        rule_id: i64,
        line_key: &str,
        state: &str,
        ownership: &str,
        last_error_category: Option<&str>,
        next_attempt_at: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError>;

    async fn delete_dns_record_sync(&self, rule_id: i64, line_key: &str) -> Result<u64, DbError>;

    async fn count_dns_record_syncs(&self) -> Result<i64, DbError>;

    async fn list_due_dns_record_syncs(
        &self,
        now: &str,
        limit: i64,
    ) -> Result<Vec<DnsRecordSync>, DbError>;

    async fn update_dns_record_sync_observation(
        &self,
        expected: &DnsRecordSync,
        expected_state: &str,
        state: &str,
        ownership: &str,
        mutation_verified_at: Option<&str>,
        last_observed_at: Option<&str>,
        propagated_at: Option<&str>,
        last_error_category: Option<&str>,
        attempt_count: i32,
        next_attempt_at: Option<&str>,
        updated_at: &str,
    ) -> Result<u64, DbError>;

    async fn mark_all_dns_record_syncs_disabled(
        &self,
        now: &str,
        error_category: &str,
    ) -> Result<u64, DbError>;

    /// Recover only safely retryable in-flight/transient states after a Panel
    /// restart. Conflict and mutation-unknown rows remain terminal.
    async fn resume_dns_record_syncs_on_startup(&self, now: &str) -> Result<u64, DbError>;
}

// ── v1.0.7: per-user device-group authorization ──
// Replaces the v1.0.4 user-permission-group layer (user → named group →
// device-group allowlist) with a direct user ↔ device_group link plus a
// per-user `all_device_groups` flag. Admins are always treated as all-allowed.

#[async_trait]
pub trait DeviceGroupAuthRepository: Send + Sync {
    /// List the device-group IDs explicitly assigned to this user (the raw
    /// `user_device_groups` rows). Does NOT expand `all_device_groups`; use
    /// `authorized_device_group_ids` for the effective set. For the admin UI.
    async fn list_user_device_groups(&self, user_id: i64) -> Result<Vec<i64>, DbError>;
    /// Replace a user's explicit device-group assignments (clear + re-insert).
    async fn set_user_device_groups(
        &self,
        user_id: i64,
        device_group_ids: &[i64],
    ) -> Result<(), DbError>;
    /// Set the per-user `all_device_groups` flag. Returns rows affected
    /// (0 = user not found).
    async fn set_user_all_device_groups(&self, user_id: i64, all: bool) -> Result<u64, DbError>;
    /// Effective set of inbound ('in') device-group IDs the user may use:
    /// admins and `all_device_groups` users get ALL 'in' groups; everyone else
    /// gets only their explicit assignments. Empty = cannot forward.
    async fn authorized_device_group_ids(&self, user_id: i64) -> Result<Vec<i64>, DbError>;
    /// v1.0.4: pause all of `user_id`'s rules whose device_group_in is NOT in
    /// `allowed_group_ids` (the user lost authorization for that group). Rules
    /// are paused, never deleted, so an admin can re-authorize and resume them.
    /// An empty `allowed_group_ids` pauses ALL the user's rules. Returns the
    /// number of rules newly paused (0 = nothing to do, skip node broadcast).
    async fn pause_rules_outside_groups(
        &self,
        user_id: i64,
        allowed_group_ids: &[i64],
    ) -> Result<u64, DbError>;
    /// Whether the user is subject to device-group restriction — i.e. a
    /// non-admin without `all_device_groups`. The rule API uses this to decide
    /// whether to enforce the allowlist. Admins / all-device-groups users → false.
    async fn is_user_restricted(&self, user_id: i64) -> Result<bool, DbError>;
}

// ── Tunnel Profile ──

#[async_trait]
pub trait TunnelProfileRepository: Send + Sync {
    async fn list_profiles(&self, scope: &ProfileScope) -> Result<Vec<TunnelProfile>, DbError>;
    async fn find_builtin_flag_by_id(
        &self,
        id: i64,
        scope: &ResourceScope,
    ) -> Result<Option<bool>, DbError>;
    async fn find_by_name(&self, name: &str) -> Result<Option<TunnelProfile>, DbError>;
    /// Look up a full profile row by id, scoped by builtin-ness (NOT ownership —
    /// see [`ProfileScope`]). `None` = no such profile OR outside scope
    /// (indistinguishable, so a caller can't tell "exists but foreign" from
    /// "doesn't exist").
    ///
    /// v0.4.10 fix: the scope was previously `ResourceScope` (owner-based), but
    /// tunnel-profile isolation is by builtin-ness per the v0.4.10 roadmap §5:
    /// a regular user may bind ONLY builtin profiles, an admin may bind any.
    /// The scoping decision is made by the CALLER based on the RULE OWNER's
    /// role (not the operator's), so an admin creating a rule on behalf of a
    /// regular user is still restricted to builtin profiles for that rule.
    /// Internal consistency checks (e.g. protocol-vs-bound-profile validation)
    /// and node-config builds use `ProfileScope::All` since they must resolve
    /// the real binding without leaking existence to the user.
    async fn find_profile_by_id(
        &self,
        id: i64,
        scope: &ProfileScope,
    ) -> Result<Option<TunnelProfile>, DbError>;
    /// Count rules currently bound to this profile (for delete-protection),
    /// scoped.
    async fn count_rules_by_profile(
        &self,
        profile_id: i64,
        scope: &ResourceScope,
    ) -> Result<i64, DbError>;
    /// List the stored protocols of rules bound to this profile (for
    /// transport-change validation: a new transport must be compatible with
    /// every referencing rule's protocol), scoped.
    async fn list_rule_protocols_by_profile(
        &self,
        profile_id: i64,
        scope: &ResourceScope,
    ) -> Result<Vec<String>, DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn insert_profile(
        &self,
        name: &str,
        transport: &str,
        tls_mode: &str,
        ws_path: &str,
        host_header: &str,
        sni: &str,
        uid: i64,
    ) -> Result<(), DbError>;
    #[allow(clippy::too_many_arguments)]
    async fn update_profile_fields(
        &self,
        id: i64,
        scope: &ResourceScope,
        name: Option<&str>,
        transport: Option<&str>,
        tls_mode: Option<&str>,
        ws_path: Option<&str>,
        host_header: Option<&str>,
        sni: Option<&str>,
    ) -> Result<u64, DbError>;
    async fn delete_profile(&self, id: i64, scope: &ResourceScope) -> Result<u64, DbError>;
}

// ── Traffic (atomic batch) ──

/// Outcome of a traffic batch.
///
/// SECURITY (v0.4.9): the per-entry result deliberately does NOT distinguish
/// "rule doesn't exist" from "rule belongs to another group". A node holding a
/// valid group token could otherwise enumerate rule_ids and tell, from the
/// response, whether a given id exists in another group (a rule-id existence
/// oracle). Both cases now produce `Unavailable`, which the caller maps to a
/// single uniform 403 with a generic message. The specific reason (missing vs
/// foreign) is logged server-side only.
#[derive(Debug)]
pub enum TrafficEntryResult {
    /// The batch was applied successfully.
    Ok,
    /// At least one entry referenced a rule that is NOT available to this node
    /// — either it does not exist, or it belongs to a different group. The
    /// whole batch is rolled back; the caller returns a uniform 403. The
    /// real rule_id / reason are logged, never returned to the node.
    Unavailable,
    /// At least one entry would overflow an i64 traffic counter (per-rule
    /// cumulative, per-user cumulative, or existing value + delta). The whole
    /// batch is rolled back; the caller returns a uniform 400.
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficBatchScope {
    pub home_group_id: i64,
    pub node_id: String,
    pub credential_id: String,
    pub credential_generation: i64,
    pub batch_id: String,
    pub payload_sha256: String,
    pub config_revision: Option<u64>,
    /// Server-recorded rule source Group for the exact delivered config revision.
    /// Legacy strict batches map every rule to home_group_id.
    pub rule_source_groups: std::collections::BTreeMap<i64, i64>,
    /// Server-recorded rule owner for the exact delivered config revision.
    /// Empty for legacy strict batches and for revisions delivered before this
    /// owner-attribution snapshot was introduced.
    pub rule_owner_uids: std::collections::BTreeMap<i64, i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotentTrafficBatchResult {
    Applied,
    AlreadyApplied,
    PayloadConflict,
    IdentityUnavailable,
    Unavailable,
    Overflow,
}

#[async_trait]
pub trait TrafficRepository: Send + Sync {
    /// Apply a batch of traffic entries atomically in ONE transaction.
    ///
    /// Contract (v0.4.9 hardened):
    ///   - Ownership is checked with a SINGLE query
    ///     `SELECT id, uid FROM forward_rules WHERE id = ? AND device_group_in = ?`.
    ///     A miss (rule missing OR foreign) → `Unavailable`; the whole batch is
    ///     rolled back. There is NO second "does this id exist elsewhere?"
    ///     query — that was the rule-id existence oracle.
    ///   - Duplicate rule_ids in one batch are AGGREGATED first (summed), so
    ///     the per-rule overflow check sees the batch's true cumulative delta.
    ///   - Overflow is checked with checked arithmetic for: each rule's
    ///     (existing traffic_used + batch delta) and each user's
    ///     (existing traffic_used + sum of their rules' deltas). Any overflow →
    ///     `Overflow`, whole batch rolled back.
    ///   - upload/download arrive as u64 but are converted to i64 with an
    ///     overflow guard (values > i64::MAX are rejected before any write).
    ///   - On any rejection the transaction is rolled back — NO partial update
    ///     of rules or users.
    ///
    /// Returns `Ok(vec![result])` even on the rejected paths (the single
    /// result element tells the caller which rejection happened); `Err` only
    /// for a genuine DB failure.
    async fn apply_traffic_batch(
        &self,
        group_id: i64,
        entries: &[TrafficEntry],
    ) -> Result<Vec<TrafficEntryResult>, DbError>;

    /// Strict VerifiedConcreteNode traffic settlement. The dedupe claim and all
    /// rule/user/history accounting MUST commit or roll back in one transaction.
    async fn apply_idempotent_traffic_batch(
        &self,
        scope: &TrafficBatchScope,
        entries: &[TrafficEntry],
    ) -> Result<IdempotentTrafficBatchResult, DbError>;

    // ── v1.2.0: hourly traffic history ──

    /// Aggregated history buckets, oldest first.
    ///
    /// `since` is an inclusive 'YYYY-MM-DD HH:00:00' UTC lower bound. `daily`
    /// collapses hour rows into per-day buckets ('YYYY-MM-DD') — a 30-day
    /// hourly series is 720 points of noise, so 7d/30d views aggregate by day.
    ///
    /// `uid = None` means all users (admin); `rule_id = None` means all rules.
    /// The API layer is responsible for forcing `uid = Some(caller)` on
    /// non-admins — this layer trusts its arguments.
    async fn query_traffic_history(
        &self,
        uid: Option<i64>,
        rule_id: Option<i64>,
        since: &str,
        daily: bool,
    ) -> Result<Vec<TrafficHistoryBucket>, DbError>;

    /// Delete rows with `hour_ts < cutoff`. Returns rows deleted. Called by
    /// the retention sweeper; the table has no FK so this is the ONLY way rows
    /// die.
    async fn prune_traffic_history(&self, cutoff: &str) -> Result<u64, DbError>;

    /// v1.2.4: fold one status report into the node's hourly metrics bucket.
    ///
    /// Called on every report (~10s), so it must be a single UPSERT: sums and
    /// the sample count accumulate, the maxima take whichever is larger. The
    /// average is derived at read time from sum/samples so it stays exact
    /// instead of drifting through repeated incremental updates.
    async fn record_node_metrics(&self, m: &NodeMetricSample) -> Result<(), DbError>;

    /// Hourly (or daily, when `daily`) metric series per node since `since`.
    /// Admin-only data — this layer trusts its arguments.
    async fn query_node_metrics(
        &self,
        since: &str,
        daily: bool,
    ) -> Result<Vec<NodeMetricBucket>, DbError>;

    /// Delete rows with `hour_ts < cutoff`. Returns rows deleted. Same
    /// contract as prune_traffic_history — no FK, so this is the only way
    /// rows die.
    async fn prune_node_metrics(&self, cutoff: &str) -> Result<u64, DbError>;

    /// v1.2.4: append one audit entry. Best-effort at the call site — see
    /// service::audit for why a failure here must not undo the operation that
    /// was just performed.
    async fn record_audit(&self, e: &NewAuditEntry) -> Result<(), DbError>;

    /// Most recent entries first. `action` filters to one action when given.
    /// Admin-only data — this layer trusts its arguments.
    async fn query_audit_log(
        &self,
        action: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEntry>, DbError>;

    /// Total matching rows, for pagination.
    async fn count_audit_log(&self, action: Option<&str>) -> Result<i64, DbError>;

    /// Delete entries older than `cutoff`. The retention sweeper is the only
    /// thing that removes them.
    async fn prune_audit_log(&self, cutoff: &str) -> Result<u64, DbError>;
}

/// v1.2.4: one site announcement.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct Announcement {
    pub id: i64,
    pub title: String,
    pub content: String,
    /// "info" | "success" | "warning" | "error".
    pub kind: String,
    pub pinned: bool,
    pub published_at: String,
    /// None = never auto-hides.
    pub expires_at: Option<String>,
    pub author_id: Option<i64>,
    /// Snapshot of who posted it — survives deletion of that admin account.
    pub author_name: String,
}

/// The writable half, for create and update.
#[derive(Debug, Clone)]
pub struct NewAnnouncement {
    pub title: String,
    pub content: String,
    pub kind: String,
    pub pinned: bool,
    pub published_at: String,
    pub expires_at: Option<String>,
    pub author_id: Option<i64>,
    pub author_name: String,
}

// ── Announcements (v1.2.4) ──

#[async_trait]
pub trait AnnouncementRepository: Send + Sync {
    /// The notice the banner shows, or None.
    ///
    /// Pinned first, then newest, with expired rows excluded. `now` is passed
    /// in rather than read here so one clock decides and tests can pin it.
    async fn active_announcement(&self, now: &str) -> Result<Option<Announcement>, DbError>;

    /// History, newest first. `include_expired` is what separates the user's
    /// archive (true — reading old notices is the point) from callers that
    /// only want live ones.
    async fn list_announcements(
        &self,
        include_expired: bool,
        now: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Announcement>, DbError>;

    async fn count_announcements(&self, include_expired: bool, now: &str) -> Result<i64, DbError>;

    async fn find_announcement(&self, id: i64) -> Result<Option<Announcement>, DbError>;

    async fn create_announcement(&self, a: &NewAnnouncement) -> Result<i64, DbError>;

    /// Returns rows affected: 0 = no such id.
    async fn update_announcement(&self, id: i64, a: &NewAnnouncement) -> Result<u64, DbError>;

    async fn delete_announcement(&self, id: i64) -> Result<u64, DbError>;

    /// Highest announcement id, or 0 when there are none.
    ///
    /// Drives the header bell's unread dot: the client stores the id it last
    /// looked at and compares. Deliberately the id and not a timestamp —
    /// editing an old notice must not re-notify everyone, and only a new row
    /// raises the maximum.
    async fn latest_announcement_id(&self) -> Result<i64, DbError>;
}

/// An audit entry being written.
///
/// `detail` MUST NOT contain secrets. Record that a token was rotated, never
/// the token; that notification settings changed, never the credentials.
#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub ts: String,
    /// None for actions with no authenticated actor (system/scheduler).
    pub actor_id: Option<i64>,
    /// Snapshot of the actor's username — survives deletion of the account.
    pub actor_name: String,
    pub action: String,
    pub target_type: String,
    /// TEXT because targets are not uniformly numeric (rule id vs node id).
    pub target_id: String,
    pub detail: String,
}

/// An audit entry being read back.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub actor_id: Option<i64>,
    pub actor_name: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub detail: String,
}

/// One status report, reduced to the fields the history keeps.
#[derive(Debug, Clone)]
pub struct NodeMetricSample {
    pub node_id: String,
    pub group_id: i64,
    /// 'YYYY-MM-DD HH:00:00' UTC — the bucket this sample lands in.
    pub hour_ts: String,
    pub cpu: f64,
    pub mem: f64,
    pub connections: i64,
}

/// One point of the node-metric series, per (bucket, node).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct NodeMetricBucket {
    /// 'YYYY-MM-DD HH:00:00' (hourly) or 'YYYY-MM-DD' (daily), UTC.
    pub bucket: String,
    pub node_id: String,
    pub group_id: i64,
    /// The group's name at query time, or "#id" once the group is deleted —
    /// resolved in SQL so the chart legend needs no second round trip.
    pub group_name: String,
    pub cpu_avg: f64,
    pub cpu_max: f64,
    pub mem_avg: f64,
    pub mem_max: f64,
    pub conn_avg: f64,
    pub conn_max: i64,
}

/// One point of the traffic-history series, per (bucket, line).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow, serde::Serialize)]
pub struct TrafficHistoryBucket {
    /// 'YYYY-MM-DD HH:00:00' (hourly) or 'YYYY-MM-DD' (daily), UTC.
    pub bucket: String,
    /// v1.2.0: the inbound device group (line) this slice belongs to. 0 =
    /// unknown — pre-column history whose rule has since been deleted, so the
    /// attribution is unrecoverable.
    pub group_id: i64,
    /// The group's name at query time, or "#id" once the group is deleted.
    /// Resolved in SQL so the chart legend needs no second round trip.
    pub group_name: String,
    pub real_upload: i64,
    pub real_download: i64,
    /// What was actually charged against quota in this bucket — the chart's
    /// primary series, so it can never disagree with the quota numbers.
    pub billed_total: i64,
}

// ── KVS (generic key-value) ──

#[async_trait]
pub trait KvsRepository: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, DbError>;
    async fn set(&self, key: &str, value: &str) -> Result<(), DbError>;
    async fn delete(&self, key: &str) -> Result<u64, DbError>;
    async fn scan_prefix(&self, prefix: &str) -> Result<Vec<(String, String)>, DbError>;
}

// ── Statistics ──

#[async_trait]
pub trait StatisticsRepository: Send + Sync {
    async fn query_stats(
        &self,
        stat_type: Option<&str>,
        stat_key: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Vec<Statistic>, DbError>;
}

// ── Plan ──

#[async_trait]
pub trait PlanRepository: Send + Sync {
    async fn list_plans(&self) -> Result<Vec<Plan>, DbError>;
    /// v1.0.8: plans visible to regular users for self-purchase (hidden = 0).
    async fn list_visible_plans(&self) -> Result<Vec<Plan>, DbError>;
    /// Look up a plan's name by id. None = no such plan. Used by /user/me to
    /// project the user's plan_id into a human-readable plan_name without
    /// exposing other plan columns.
    async fn find_plan_name_by_id(&self, id: i64) -> Result<Option<String>, DbError>;
    /// v1.0.8: fetch a full plan row by id (for purchase validation). None =
    /// no such plan (or hidden, when buying — gated by the caller).
    async fn find_plan_by_id(&self, id: i64) -> Result<Option<Plan>, DbError>;
    /// v1.0.8: create a plan. Returns the new row's id.
    #[allow(clippy::too_many_arguments)]
    async fn insert_plan(
        &self,
        name: &str,
        max_rules: i32,
        traffic: i64,
        price: &str,
        plan_type: &str,
        duration_days: i32,
        hidden: bool,
        reset_traffic: bool,
        description: &str,
        grant_all_groups: bool,
    ) -> Result<i64, DbError>;
    /// v1.0.9: insert a plan AND its device-group grant set in ONE transaction,
    /// so a failure mid-way can't leave a plan row with no grants (the two-call
    /// insert_plan + set_plan_device_groups sequence could). Returns the new id.
    #[allow(clippy::too_many_arguments)]
    async fn create_plan_with_groups(
        &self,
        name: &str,
        max_rules: i32,
        traffic: i64,
        price: &str,
        plan_type: &str,
        duration_days: i32,
        hidden: bool,
        reset_traffic: bool,
        description: &str,
        grant_all_groups: bool,
        device_group_ids: &[i64],
    ) -> Result<i64, DbError>;
    /// v1.0.8: update a plan's mutable fields. Returns rows affected (0 = not
    /// found). speed_limit/ip_limit are intentionally NOT updatable here
    /// (placeholders, never enforced) to keep the API surface minimal.
    #[allow(clippy::too_many_arguments)]
    async fn update_plan_fields(
        &self,
        id: i64,
        name: Option<&str>,
        max_rules: Option<i32>,
        traffic: Option<i64>,
        price: Option<&str>,
        plan_type: Option<&str>,
        duration_days: Option<i32>,
        hidden: Option<bool>,
        reset_traffic: Option<bool>,
        description: Option<&str>,
        grant_all_groups: Option<bool>,
    ) -> Result<u64, DbError>;
    /// v1.0.8: delete a plan. Returns rows affected (0 = not found).
    async fn delete_plan(&self, id: i64) -> Result<u64, DbError>;
    /// v1.0.8: count users whose plan_id points at this plan. Used as a
    /// pre-delete safety check (count > 0 → 409).
    async fn count_users_on_plan(&self, plan_id: i64) -> Result<i64, DbError>;

    /// v1.0.9: list the device-group ids this plan grants on purchase.
    async fn list_plan_device_groups(&self, plan_id: i64) -> Result<Vec<i64>, DbError>;
    /// v1.0.9: REPLACE the plan's grant set (delete-then-insert, deduped). Used
    /// by the admin create/update plan handlers.
    async fn set_plan_device_groups(
        &self,
        plan_id: i64,
        device_group_ids: &[i64],
    ) -> Result<(), DbError>;

    /// v1.0.8: atomically purchase a plan in ONE transaction (防双花):
    ///   - lock + read the user's balance
    ///   - refuse if balance < price_cents (returns `BuyPlanError::InsufficientBalance`)
    ///   - balance -= price_cents, traffic_limit += traffic_to_add
    ///   - max_rules = plan_max_rules, plan_id = plan_id
    ///   - reset traffic_used to 0 when `reset_traffic`
    ///   - plan_expire_at = max(now, current expiry) + duration_days (NULL when duration_days=0)
    ///   - insert an orders row (snapshots plan_name + price)
    ///   - v1.0.9: grant device groups in the SAME tx. v1.0.8: purchase REPLACES
    ///     authorization — when `grant_all_groups` set all_device_groups=1 (and
    ///     clear explicit rows); else reset all_device_groups=0 and replace
    ///     user_device_groups with the plan's `device_group_ids`. Rules bound to
    ///     groups outside `new_authorized_group_ids` are paused in the same tx.
    /// All on the same tx handle so a concurrent purchase can't double-spend.
    /// `price_cents` / `traffic_to_add` / `plan_max_rules` / `duration_days` are
    /// resolved by the caller from the plan row (and re-checked hidden=0 there),
    /// so this method trusts them and only owns the atomic money + bookkeeping.
    #[allow(clippy::too_many_arguments)]
    async fn buy_plan(
        &self,
        user_id: i64,
        plan_id: i64,
        plan_name: &str,
        price_cents: i64,
        traffic_to_add: i64,
        plan_max_rules: i32,
        duration_days: i32,
        reset_traffic: bool,
        grant_all_groups: bool,
        device_group_ids: &[i64],
        // v1.0.8: the NEW authorized group set AFTER purchase. Used inside the
        // transaction to pause rules outside this set (replacement semantics).
        // Computed by the caller: all inbound groups if grant_all_groups, else
        // device_group_ids (the plan's grants).
        new_authorized_group_ids: &[i64],
    ) -> Result<(), BuyPlanError>;
}

/// v1.2.0: redeem codes (balance top-up). Its own trait rather than more
/// methods on `PlanRepository` — a code isn't a plan, and the existing repo
/// layer is already split by concern.
#[async_trait]
pub trait RedeemRepository: Send + Sync {
    /// Insert a generated batch in ONE transaction. Returns how many rows
    /// landed. A duplicate `code` (astronomically unlikely, but possible) is
    /// skipped rather than failing the whole batch — an admin asking for 100
    /// codes would rather get 99 than an error.
    async fn create_redeem_codes(&self, codes: &[NewRedeemCode]) -> Result<u64, DbError>;

    /// Redeem `code` for `user_id`, crediting the balance ATOMICALLY.
    ///
    /// The whole thing is one transaction, and the code is claimed with a
    /// CONDITIONAL update (`WHERE status = 'unused'`) whose affected-row count
    /// is checked. That combination is what makes a double-redeem impossible:
    /// two concurrent requests for the same code both try the update, exactly
    /// one sees `rows_affected == 1`, and the loser's transaction rolls back
    /// without touching the balance.
    ///
    /// `now` is passed in (not read from the clock here) so expiry is evaluated
    /// against the same instant the caller used, and so tests can pin it.
    ///
    /// Returns the credited amount and the user's NEW balance, both canonical
    /// strings, for the success message.
    async fn redeem_code(
        &self,
        code: &str,
        user_id: i64,
        now: &str,
    ) -> Result<(String, String), RedeemCodeError>;

    /// v1.2.4: the codes a given user redeemed, newest first.
    ///
    /// Separate from `list_redeem_codes` rather than another filter on it: this
    /// one is reachable by a NON-admin (their own account page), so the uid
    /// filter must be structural, not one more optional field that a future
    /// caller could forget to set.
    async fn list_redeem_codes_by_user(
        &self,
        user_id: i64,
    ) -> Result<Vec<relay_shared::models::RedeemCode>, DbError>;

    /// List codes for the admin UI, newest first.
    async fn list_redeem_codes(
        &self,
        filter: &RedeemCodeFilter,
    ) -> Result<Vec<relay_shared::models::RedeemCode>, DbError>;

    /// Count codes matching a filter (for pagination + batch summaries).
    async fn count_redeem_codes(&self, filter: &RedeemCodeFilter) -> Result<i64, DbError>;

    /// Void an UNUSED code so it can never be redeemed. Returns rows affected;
    /// 0 means it was already used or voided. A used code is never voidable —
    /// the money already moved, and rewriting that row would falsify the audit
    /// trail.
    async fn void_redeem_code(&self, id: i64) -> Result<u64, DbError>;

    /// Delete codes that were never used. Returns rows deleted.
    ///
    /// Deliberately refuses to delete `used` rows: they are the record of money
    /// entering the system. Cleaning up a mis-generated batch is legitimate;
    /// erasing a redemption is not.
    async fn delete_unused_redeem_codes(&self, ids: &[i64]) -> Result<u64, DbError>;
}

/// v1.0.8: errors from the atomic purchase transaction.
#[derive(Debug)]
pub enum BuyPlanError {
    /// User balance < plan price. Caller → 400.
    InsufficientBalance,
    /// DB error. Caller → 500.
    Database(DbError),
}

impl From<DbError> for BuyPlanError {
    fn from(e: DbError) -> Self {
        BuyPlanError::Database(e)
    }
}

/// v1.2.0: outcome of redeeming a top-up code.
#[derive(Debug)]
pub enum RedeemCodeError {
    /// No such code, already used, or voided. ONE variant on purpose — see
    /// `models::RedeemError::NotRedeemable`: distinguishing "doesn't exist"
    /// from "already used" tells a stranger which guesses were real codes.
    NotRedeemable,
    /// Exists and unused, but past `expires_at`.
    Expired,
    /// Crediting would exceed `money::MAX_BALANCE_CENTS`.
    BalanceOverflow,
    /// DB error. Caller → 500.
    Database(DbError),
}

impl From<DbError> for RedeemCodeError {
    fn from(e: DbError) -> Self {
        RedeemCodeError::Database(e)
    }
}

impl From<sqlx::Error> for RedeemCodeError {
    fn from(e: sqlx::Error) -> Self {
        RedeemCodeError::Database(DbError::from(e))
    }
}

/// v1.2.0: one code to insert in a generation batch. `code` is the STORED form
/// (no dashes, upper-case); `amount` is a canonical balance string.
#[derive(Debug, Clone)]
pub struct NewRedeemCode {
    pub code: String,
    pub amount: String,
    pub expires_at: Option<String>,
    pub batch_id: String,
    pub remark: String,
}

/// v1.2.0: filter for listing codes in the admin UI.
#[derive(Debug, Clone, Default)]
pub struct RedeemCodeFilter {
    /// "unused" | "used" | "void"; None = all.
    pub status: Option<String>,
    pub batch_id: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

impl From<sqlx::Error> for BuyPlanError {
    fn from(e: sqlx::Error) -> Self {
        BuyPlanError::Database(DbError::from(e))
    }
}

// ── App settings (registration config) ──

/// The registration settings row (always id=1 in app_settings).
/// v0.4.21 PR2: added allowed_plan_ids for multi-plan registration support.
#[derive(Debug, Clone, Serialize)]
pub struct RegistrationSettings {
    pub registration_enabled: bool,
    pub default_registration_plan_id: i64,
    pub allowed_plan_ids: Vec<i64>,
}

/// v0.4.10 PR3: registration settings stored in the `app_settings` single-row
/// table (NOT env vars, NOT kvs). The env var REGISTRATION_ENABLED only seeds
/// the row once on first boot via [`insert_settings_if_absent`]; after that
/// the admin owns the value via PUT /admin/settings/registration and the env
/// var is never consulted again.
#[async_trait]
pub trait SettingsRepository: Send + Sync {
    /// Read the registration settings row. `None` = the row hasn't been seeded
    /// yet (fresh DB before main.rs's first insert_settings_if_absent pass).
    async fn get_registration_settings(&self) -> Result<Option<RegistrationSettings>, DbError>;
    /// Atomically insert the settings row ONLY if it does not already exist.
    /// If a row is present this is a no-op (the env-var seed value is NOT
    /// applied over an admin-configured row). This is the sole path by which
    /// REGISTRATION_ENABLED enters the database.
    async fn insert_settings_if_absent(
        &self,
        enabled: bool,
        default_plan_id: i64,
        allowed_plan_ids: &[i64],
    ) -> Result<(), DbError>;
    /// Atomic upsert (INSERT ... ON CONFLICT DO UPDATE). Used by the admin
    /// PUT endpoint: creates the row if missing, overwrites if present, with
    /// no observable intermediate state under concurrent admin requests.
    async fn set_registration_settings(
        &self,
        enabled: bool,
        default_plan_id: i64,
        allowed_plan_ids: &[i64],
    ) -> Result<(), DbError>;
}

// ── Aggregate ──

/// v1.0.8: purchase-order history.
#[async_trait]
pub trait OrderRepository: Send + Sync {
    /// List a user's orders, newest first.
    async fn list_orders_by_user(&self, user_id: i64) -> Result<Vec<Order>, DbError>;
    /// v1.2.4: every user's orders, newest first, for the admin view.
    ///
    /// Paginated rather than returning the lot: this table only grows, and the
    /// per-user list it sits beside is naturally small enough not to need it.
    async fn list_all_orders(&self, limit: i64, offset: i64) -> Result<Vec<Order>, DbError>;
    async fn count_all_orders(&self) -> Result<i64, DbError>;
    /// Insert an order row (snapshots plan_name + price). Used inside the
    /// purchase transaction.
    async fn insert_order(
        &self,
        user_id: i64,
        plan_id: Option<i64>,
        plan_name: &str,
        price: &str,
    ) -> Result<(), DbError>;
}

/// The aggregate repository trait. Handlers depend on `Arc<dyn Repository>`
/// and get access to all domain-specific methods.
#[async_trait]
pub trait Repository:
    UserRepository
    + RuleRepository
    + GroupRepository
    + DeviceGroupAuthRepository
    + TunnelProfileRepository
    + TrafficRepository
    + KvsRepository
    + StatisticsRepository
    + PlanRepository
    + SettingsRepository
    + OrderRepository
    + RedeemRepository
    + AnnouncementRepository
    + ManualBootstrapEnrollmentRepository
    + DnsRecordBindingRepository
    + DnsRecordSyncRepository
    + NodeReuseRepository
    + NodeCredentialRepository
    + NodeCredentialClaimRepository
    + NodeCredentialDeliveryRepository
    + Send
    + Sync
{
}
