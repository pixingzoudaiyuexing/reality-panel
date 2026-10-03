# Fresh credential bootstrap and failure retry (v1.4.4 RC)

The Node uses the canonical HTTPS Panel URL and validates TLS normally. HTTPS at the edge may terminate before an HTTP origin hop; X-Forwarded-Proto and a trusted socket-peer list are not claim authorization conditions. Admin auth, exact identity, approved claim secret/expiry, claimant nonce, prepare/activate, replay and revocation rules remain.

For a failed Fresh deployment, the exact deployment claim can cancel only pending material using the existing cancellation transaction. The node-side rollback requires an authenticated terminal-inactive result before removing node-id, the newly created claim directory or matching runtime-auth descriptor. Pre-existing identity/material and unknown paths remain protected. Historical Panel claim/delivery rows remain CANCELLED/EXPIRED; no direct database deletion is needed.

If activation completed (including an ACK loss), cleanup reports ACTIVE_PRESERVED and keeps identity/credential/runtime. Do not create a different UUID over that active identity; resume/recover the exact existing deployment. An unavailable activation/cancellation result reports RECOVERY_REQUIRED and retains material. Only confirmed unactivated failure is eligible for immediate new-UUID Fresh retry.

Bootstrap diagnostics report safe stage, endpoint path, HTTP/business status when available and exception category. Claim/credential secrets, nonces, verifier, headers and raw exception bodies are not printed. Migration mode retains its previous semantics.
