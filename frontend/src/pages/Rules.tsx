import { Table, Button, Modal, Form, Input, InputNumber, Select, Space, message, Popconfirm, Popover, Tag, Alert, Typography, Dropdown, Switch, Tabs, Tooltip, Pagination, Collapse } from 'antd';
import type { MenuProps } from 'antd';
import { PlusOutlined, ReloadOutlined, EditOutlined, ApiOutlined, CopyOutlined, DownloadOutlined, UploadOutlined, PauseCircleOutlined, PlayCircleOutlined, DeleteOutlined, ArrowUpOutlined, ArrowDownOutlined, MedicineBoxOutlined, QuestionCircleOutlined, ThunderboltOutlined, SearchOutlined, MoreOutlined } from '@ant-design/icons';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/client';
import type { ApiEnvelope, ForwardRule, DeviceGroup, User, UserSelf, RuleTargetInput, SharedGroupSummary, RestartResponse, ReapplyResponse, NodeStatus, RuleDnsStatus } from '../api/types';
import { MIN_AUTO_RESTART_MINUTES } from '../api/types';
import { useI18n } from '../i18n/context';
import { formatBytes } from '../utils/format';
import { useAuth } from '../auth/useAuth';
import { asValidatedEntry, buildExportJSON, buildImportedRulePayload, ruleTargets, validateImportEntry } from '../utils/rulesIO';
import {
  camouflageCertificateMessage,
  compactRealityStatus,
  compactRealityStatusDisplay,
  deriveCamouflageStatus,
  dnsOwnershipDisplay,
  dnsSyncStateDisplay,
  isRealityRule,
  normalizeSni,
  runtimeStateDisplay,
  type RuleHealthDisplay,
} from '../utils/realityRuleStatus';
import { RuleDiagnosisModal } from '../components/diagnosis/RuleDiagnosisModal';

const { Text } = Typography;
const { TextArea } = Input;

export const RULE_SELECTION_COLUMN_WIDTH = 48;
export const RULE_TABLE_SCROLL_X = 1320;
export const RULES_PAGE_SIZE = 20;

function RuleEllipsis({ value, mono = true, tooltip = true }: { value: string; mono?: boolean; tooltip?: boolean }) {
  const content = <span className={`rp-rules-ellipsis${mono ? ' rp-mono' : ''}`} title={value}>{value}</span>;
  return tooltip ? <Tooltip title={value}>{content}</Tooltip> : content;
}

function RuleHealthItem({ label, display }: { label: string; display: RuleHealthDisplay }) {
  return (
    <Tooltip title={`${label}: ${display.raw}`}>
      <span className="rp-rule-health-item" data-state={display.tone} data-raw-state={display.raw}>
        <span className="rp-rule-health-dot" aria-hidden="true" />
        <span>{label}</span>
        <strong>{display.label}</strong>
      </span>
    </Tooltip>
  );
}

function RuntimeDetailState({ label, state, t }: { label: string; state: string; t: (key: string) => string }) {
  const display = runtimeStateDisplay(state, t);
  return (
    <Tooltip title={`${label}: ${state}`}>
      <span className="rp-rules-detail-state" data-state={display.tone} data-raw-state={state}>
        {label} {display.label}
      </span>
    </Tooltip>
  );
}

function targetSummary(rule: ForwardRule): string {
  const targets = ruleTargets(rule).filter(t => t.enabled);
  const first = targets[0] ?? ruleTargets(rule)[0];
  if (!first) return '-';
  const suffix = targets.length > 1 ? ` (+${targets.length - 1})` : '';
  return `${first.host}:${first.port}${suffix}`;
}

function formTargets(values: { targets?: RuleTargetInput[]; target_addr?: string; target_port?: number }): RuleTargetInput[] {
  const targets = values.targets ?? [];
  return targets.map(t => ({ host: t.host?.trim() ?? '', port: Number(t.port), enabled: t.enabled !== false }));
}

function payloadWithTargets<T extends Record<string, unknown>>(values: T & { targets?: RuleTargetInput[]; target_addr?: string; target_port?: number }) {
  const targets = formTargets(values);
  if (targets.length < 1) {
    throw new Error('targets must have at least one entry');
  }
  const first = targets[0];
  return {
    ...values,
    target_addr: first.host,
    target_port: first.port,
    targets,
  };
}

export function DnsStatusCell({
  status,
  retrying = false,
  onRetry,
  t,
}: {
  status?: RuleDnsStatus;
  retrying?: boolean;
  onRetry?: () => void;
  t: (key: string) => string;
}) {
  if (!status || !status.eligible || status.sync_state === 'NOT_ELIGIBLE') {
    return <Text type="secondary">-</Text>;
  }
  const display = dnsSyncStateDisplay(status.sync_state, t);
  const color = display.tone === 'normal' ? 'green'
    : display.tone === 'warning' ? 'orange'
      : display.tone === 'error' ? 'red'
        : display.tone === 'waiting' ? 'gold'
          : 'default';
  const retryable = status.automation_enabled
    && ['FAILED', 'CONFLICT', 'DISABLED'].includes(status.sync_state)
    && status.sync_state !== 'MUTATION_OUTCOME_UNKNOWN'
    && !['MUTATION_UNKNOWN', 'POST_WRITE_NOT_VERIFIED'].includes(status.last_error_category ?? '');
  return (
    <Space orientation="vertical" size={2}>
      <Space size={4} wrap>
        <Tooltip title={status.sync_state}>
          <Tag color={color} data-raw-state={status.sync_state}>{display.label}</Tag>
        </Tooltip>
        {!status.automation_enabled && <Tag>{t('dnsAutomationDisabled')}</Tag>}
      </Space>
      {status.fqdn && status.record_type && status.expected_value && (
        <Text className="rp-mono">{status.record_type} {status.fqdn} → {status.expected_value}</Text>
      )}
      <Tooltip title={status.ownership}>
        <Text type="secondary" data-raw-ownership={status.ownership}>
          {t('dnsOwnership')}: {dnsOwnershipDisplay(status.ownership, t)}
        </Text>
      </Tooltip>
      {status.warning_category && <Text type="warning">{status.warning_category}</Text>}
      {status.last_error_category && <Text type="danger">{status.last_error_category}</Text>}
      {retryable && onRetry && (
        <Button size="small" type="text" icon={<ReloadOutlined />} loading={retrying} onClick={onRetry}>
          {t('retryDnsSync')}
        </Button>
      )}
    </Space>
  );
}

export function CamouflageFormFields({
  enabled,
  initialValue,
  isAdmin,
  t,
  compact = false,
}: {
  enabled: boolean;
  initialValue?: boolean;
  isAdmin: boolean;
  t: (key: string) => string;
  compact?: boolean;
}) {
  return (
    <>
      <Form.Item
        name="camouflage_enabled"
        label={t('camouflage')}
        valuePropName="checked"
        initialValue={initialValue}
        extra={!isAdmin ? t('camouflageAdminOnly') : undefined}
      >
        <Switch aria-label={t('camouflage')} disabled={!isAdmin} />
      </Form.Item>
      {compact ? (
        <div className="rp-rule-runtime-summary">
          <Text type="secondary">
            {enabled ? t('ruleRealityRuntimeSummary') : t('ruleRealityProtocolSummary')}
          </Text>
        </div>
      ) : (
        <>
          <Form.Item label={t('camouflageTlsPort')}>
            <InputNumber aria-label={t('camouflageTlsPort')} value={8443} disabled style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item label={t('certificateRenewBefore')}>
            <InputNumber aria-label={t('certificateRenewBefore')} value={30} addonAfter={t('days')} disabled style={{ width: '100%' }} />
          </Form.Item>
        </>
      )}
      {enabled && (
        compact
          ? <Text type="warning" className="rp-rule-conditional-note">{t('remoteRealityFallbackHint')}</Text>
          : <Alert type="info" showIcon title={t('remoteRealityFallbackHint')} style={{ marginBottom: 12 }} />
      )}
    </>
  );
}

export function ProxyProtocolFormField({
  initialValue,
  isAdmin,
  t,
  showHint = true,
}: {
  initialValue?: boolean;
  isAdmin: boolean;
  t: (key: string) => string;
  showHint?: boolean;
}) {
  return (
    <Form.Item
      name="send_proxy_protocol"
      label={t('sendProxyProtocol')}
      valuePropName="checked"
      initialValue={initialValue}
      extra={showHint ? t('sendProxyProtocolHint') : undefined}
    >
      <Switch aria-label={t('sendProxyProtocol')} disabled={!isAdmin} />
    </Form.Item>
  );
}

/** Trigger a browser download of a text file. */
function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function Rules() {
  const { t } = useI18n();
  const { isAdmin, user, refreshCurrentUser } = useAuth();
  const [searchParams] = useSearchParams();
  // v0.4.20: admin can manage another user's rules via /rules?owner_uid=X.
  const filterOwnerUid: number | null = isAdmin
    ? (parseInt(searchParams.get('owner_uid') || '') || null)
    : null;
  const [rules, setRules] = useState<ForwardRule[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  // v0.4.11 PR3: shared inbound groups (admin-owned) for regular users.
  const [sharedGroups, setSharedGroups] = useState<SharedGroupSummary[]>([]);
  // v0.4.12 PR1: true when /groups/shared failed to load (DB error). A regular
  // user then sees a load-failure notice and rule creation is blocked, instead
  // of a misleading empty inbound dropdown.
  const [sharedLoadFailed, setSharedLoadFailed] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [nodeStatuses, setNodeStatuses] = useState<NodeStatus[]>([]);
  const [dnsStatuses, setDnsStatuses] = useState<RuleDnsStatus[]>([]);
  const [dnsRetrying, setDnsRetrying] = useState<number | null>(null);
  // v1.0.7: a regular user's own traffic quota (admins read each owner's quota
  // from `users` instead). Used to flag rules whose owner is out of traffic —
  // those rules stop forwarding even though their `paused` flag stays false.
  const [selfQuota, setSelfQuota] = useState<{ used: number; limit: number } | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [importGroupId, setImportGroupId] = useState<number | undefined>(undefined);
  const [importResults, setImportResults] = useState<string[]>([]);
  const [editing, setEditing] = useState<ForwardRule | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const pendingCreateValues = useRef<Record<string, unknown> | null>(null);
  // v0.4.8: rule diagnosis modal state.
  const [diagnosing, setDiagnosing] = useState<ForwardRule | null>(null);
  // v0.4.9: group-name column + filter. selectedGroup === null means "all".
  // (Explicit null, not !selectedGroup, so a future id of 0 wouldn't be falsy.)
  const [selectedGroup, setSelectedGroup] = useState<number | null>(null);
  // Client-side filter over the already-loaded rules — /rules returns the whole
  // (owner-scoped) set, so searching needs no round-trip.
  const [ruleSearch, setRuleSearch] = useState('');
  const [selectedRowKeys, setSelectedRowKeys] = useState<number[]>([]);
  const [currentPage, setCurrentPage] = useState(1);
  const backgroundRefreshInFlight = useRef(false);

  const ownerUid = filterOwnerUid ?? (isAdmin ? (user?.id ?? null) : null);
  const scopedRulesUrl = ownerUid ? `/rules?owner_uid=${ownerUid}` : '/rules';

  useEffect(() => {
    void refreshCurrentUser();
  }, [refreshCurrentUser]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      // v0.4.10: /admin/users is admin-only and NOT in the main Promise.all —
      // a regular user would 403 and block the whole page load. The owner
      // column / selector are hidden for non-admins (they only ever own their
      // own rules), so the users list is fetched separately and only when
      // isAdmin. A failure here leaves users empty but rules/groups still load.
      // v0.4.20: admin can filter rules by owner_uid.
      // Admin on own page → filter to their own rules; admin viewing another
      // user → use filterOwnerUid; regular user → backend filters automatically.
      const [r, g] = await Promise.all([
        api.get<unknown, ApiEnvelope<ForwardRule[]>>(scopedRulesUrl),
        api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
      ]);
      if (r.code !== 0) throw new Error(r.message || 'rules load failed');
      if (g.code !== 0) throw new Error(g.message || 'groups load failed');
      setRules(r.data || []);
      setGroups(g.data || []);
      if (isAdmin) {
        try {
          const u = await api.get<unknown, ApiEnvelope<User[]>>('/admin/users');
          setUsers(u.data || []);
        } catch {
          // Non-fatal: owner column falls back to "#uid" labels.
          setUsers([]);
        }
        try {
          const n = await api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes');
          setNodeStatuses(n.data || []);
        } catch {
          setNodeStatuses([]);
        }
        try {
          const dns = await api.get<unknown, ApiEnvelope<RuleDnsStatus[]>>('/admin/rules/dns-status');
          setDnsStatuses(dns.data || []);
        } catch {
          setDnsStatuses([]);
        }
        setSelfQuota(null);
      } else {
        setUsers([]);
        setNodeStatuses([]);
        setDnsStatuses([]);
        // v1.0.7: a regular user only ever sees their own rules, so one /user/me
        // read gives the quota needed to flag all of them. Non-fatal on failure.
        try {
          const me = await api.get<unknown, ApiEnvelope<UserSelf>>('/user/me');
          setSelfQuota(me.data ? { used: me.data.traffic_used, limit: me.data.traffic_limit } : null);
        } catch {
          setSelfQuota(null);
        }
      }
      // v0.4.12 PR1: shared inbound groups (admin-owned) for regular users.
      // The endpoint wraps the payload in ApiResponse — a non-zero code is a
      // load failure (NOT an empty "no lines" state), so we flag it and block
      // rule creation rather than show an empty inbound dropdown.
      // Admins get an empty list (they manage groups directly).
      if (!isAdmin) {
        try {
          const sg = await api.get<unknown, ApiEnvelope<SharedGroupSummary[]>>('/groups/shared');
          if (sg.code !== 0) {
            setSharedLoadFailed(true);
            setSharedGroups([]);
          } else {
            setSharedLoadFailed(false);
            setSharedGroups(sg.data || []);
          }
        } catch {
          setSharedLoadFailed(true);
          setSharedGroups([]);
        }
      } else {
        setSharedLoadFailed(false);
        setSharedGroups([]);
      }
      setLoadFailed(false);
    } catch {
      setLoadFailed(true);
    } finally { setLoading(false); }
  }, [isAdmin, scopedRulesUrl]);

  useEffect(() => { load(); }, [load]);

  const backgroundRefresh = useCallback(async () => {
    if (backgroundRefreshInFlight.current) return;
    backgroundRefreshInFlight.current = true;
    try {
      if (isAdmin) {
        const [rulesResult, nodesResult, dnsResult] = await Promise.allSettled([
          api.get<unknown, ApiEnvelope<ForwardRule[]>>(scopedRulesUrl),
          api.get<unknown, ApiEnvelope<NodeStatus[]>>('/nodes'),
          api.get<unknown, ApiEnvelope<RuleDnsStatus[]>>('/admin/rules/dns-status'),
        ]);
        if (rulesResult.status === 'fulfilled' && rulesResult.value.code === 0) {
          setRules(rulesResult.value.data || []);
          setLoadFailed(false);
        } else {
          setLoadFailed(true);
        }
        if (nodesResult.status === 'fulfilled' && nodesResult.value.code === 0) {
          setNodeStatuses(nodesResult.value.data || []);
        }
        if (dnsResult.status === 'fulfilled' && dnsResult.value.code === 0) {
          setDnsStatuses(dnsResult.value.data || []);
        }
      } else {
        const [rulesResult, meResult] = await Promise.allSettled([
          api.get<unknown, ApiEnvelope<ForwardRule[]>>(scopedRulesUrl),
          api.get<unknown, ApiEnvelope<UserSelf>>('/user/me'),
        ]);
        if (rulesResult.status === 'fulfilled' && rulesResult.value.code === 0) {
          setRules(rulesResult.value.data || []);
          setLoadFailed(false);
        } else {
          setLoadFailed(true);
        }
        if (meResult.status === 'fulfilled' && meResult.value.code === 0 && meResult.value.data) {
          setSelfQuota({
            used: meResult.value.data.traffic_used,
            limit: meResult.value.data.traffic_limit,
          });
        }
      }
    } finally {
      backgroundRefreshInFlight.current = false;
    }
  }, [isAdmin, scopedRulesUrl]);

  useEffect(() => {
    const timer = window.setInterval(() => void backgroundRefresh(), 10000);
    return () => window.clearInterval(timer);
  }, [backgroundRefresh]);

  // User lookup map for the "owner" column.
  const userMap = new Map(users.map(u => [u.id, u.username]));
  // v1.0.7: owner-quota lookup for the "traffic exhausted" status tag. Admins
  // resolve each rule's owner from `users`; a regular user uses their own quota
  // (their rules are all self-owned). traffic_limit === 0 means unlimited.
  const userById = useMemo(() => new Map(users.map(u => [u.id, u])), [users]);
  const ruleOverQuota = (r: ForwardRule): boolean => {
    if (isAdmin) {
      const u = userById.get(r.uid);
      return !!u && u.traffic_limit > 0 && u.traffic_used >= u.traffic_limit;
    }
    return !!selfQuota && selfQuota.limit > 0 && selfQuota.used >= selfQuota.limit;
  };
  // v0.4.9: group lookup map for the "group name" column + filter. Memoized so
  // the column render + filter options share one derivation.
  const groupMap = useMemo(() => new Map(groups.map(g => [g.id, g])), [groups]);
  // v1.0.8: group-name + listen-IP lookup for the rule columns. A regular user
  // does NOT own the (admin-owned) device groups, so GET /groups returns none
  // for them and the columns rendered "未知分组 / 未配置". Their AUTHORIZED
  // groups come from /groups/shared (SharedGroupSummary, which carries name +
  // connect_host) — merge both so name/IP resolve for admins and users alike.
  const groupInfo = useMemo(() => {
    const m = new Map<number, { name: string; connect_host: string }>();
    for (const g of groups) m.set(g.id, { name: g.name, connect_host: g.connect_host });
    for (const g of sharedGroups) {
      if (!m.has(g.id)) m.set(g.id, { name: g.name, connect_host: g.connect_host });
    }
    return m;
  }, [groups, sharedGroups]);
  const dnsStatusByRule = useMemo(
    () => new Map(dnsStatuses.map(status => [status.rule_id, status])),
    [dnsStatuses],
  );
  // The rules actually shown: the group filter and the search box compose, so
  // "this group, port 443" works. Computed once so the table + count stay in
  // sync.
  //
  // Search matches name, listen port and target address. Targets are read via
  // ruleTargets() rather than target_addr alone: a multi-target rule keeps the
  // first target in that column, and searching for a backup target should still
  // find the rule.
  const visibleRules = useMemo(() => {
    const q = ruleSearch.trim().toLowerCase();
    return rules.filter(r => {
      if (selectedGroup !== null && r.device_group_in !== selectedGroup) return false;
      if (!q) return true;
      if (r.name.toLowerCase().includes(q)) return true;
      if (String(r.listen_port).includes(q)) return true;
      return ruleTargets(r).some(
        tgt => tgt.host.toLowerCase().includes(q) || String(tgt.port).includes(q),
      );
    });
  }, [rules, selectedGroup, ruleSearch]);

  const totalPages = Math.max(1, Math.ceil(visibleRules.length / RULES_PAGE_SIZE));
  useEffect(() => {
    setCurrentPage(page => Math.min(page, totalPages));
  }, [totalPages]);

  const pagedRules = useMemo(() => {
    const start = (currentPage - 1) * RULES_PAGE_SIZE;
    return visibleRules.slice(start, start + RULES_PAGE_SIZE);
  }, [currentPage, visibleRules]);

  const visibleGroupCounts = useMemo(() => {
    const counts = new Map<number, number>();
    for (const rule of visibleRules) {
      counts.set(rule.device_group_in, (counts.get(rule.device_group_in) ?? 0) + 1);
    }
    return counts;
  }, [visibleRules]);

  const groupedPagedRules = useMemo(() => {
    const grouped = new Map<number, ForwardRule[]>();
    for (const rule of pagedRules) {
      const group = grouped.get(rule.device_group_in);
      if (group) group.push(rule);
      else grouped.set(rule.device_group_in, [rule]);
    }
    return Array.from(grouped.entries());
  }, [pagedRules]);

  const handleCreate = async (values: {
    name: string; listen_port: number | null; protocol: string;
    public_transport?: string;
    ws_path?: string;
    device_group_in: number; device_group_out: number | null;
    forward_mode: string;
    target_addr?: string; target_port?: number; targets?: RuleTargetInput[];
    load_balance_strategy?: string;
    upload_limit_mbps?: number;
    download_limit_mbps?: number;
    tunnel_profile_id?: number | null;
    owner_uid?: number | null;
    sni?: string;
    camouflage_enabled?: boolean;
    send_proxy_protocol?: boolean;
  }) => {
    const transport = values.public_transport === 'nginx_sni' ? 'nginx_sni' : 'raw';
    const sni = normalizeSni(values.sni);
    if (transport === 'nginx_sni' && !sni) {
      message.error(t('sniRequired'));
      return;
    }
    // v0.4.20: WS/TLS tunnel hidden — only raw and reality-SNI are exposed.
    // v0.4.20: forward_mode always direct, no outbound group.
    // v0.4.20: owner determined by entry point (filterOwnerUid from URL).
    const owner_uid = filterOwnerUid ?? undefined;
    // v0.4.20: reject empty targets before payload generation.
    if (formTargets(values).length < 1) {
      message.error(t('targetRequired'));
      return;
    }
    const payload = payloadWithTargets({
      ...values,
      listen_port: values.listen_port || null,
      protocol: transport === 'nginx_sni' ? 'tcp' : values.protocol,
      public_transport: transport,
      sni,
      camouflage_enabled: transport === 'nginx_sni' && values.camouflage_enabled === true,
      send_proxy_protocol: transport === 'nginx_sni' && values.send_proxy_protocol === true,
      tunnel_profile_id: null,
      forward_mode: 'direct',
      route_mode: 'direct',
      device_group_out: null,
      owner_uid,
    });
    try {
      const res = await api.post<unknown, ApiEnvelope<null>>('/rules', payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleCreated'));
      setCreateOpen(false);
      createForm.resetFields();
      load();
    } catch { message.error(t('failedCreateRule')); }
  };

  const handleEdit = (r: ForwardRule) => {
    setEditing(r);
    editForm.setFieldsValue({
      name: r.name, listen_port: r.listen_port, protocol: r.protocol,
      public_transport: r.public_transport === 'nginx_sni' || r.node_transport === 'nginx_sni' ? 'nginx_sni' : 'raw',
      sni: r.sni ?? undefined,
      camouflage_enabled: r.camouflage_enabled === true,
      send_proxy_protocol: r.send_proxy_protocol === true,
      device_group_in: r.device_group_in,
      target_addr: r.target_addr, target_port: r.target_port,
      targets: ruleTargets(r),
      load_balance_strategy: r.load_balance_strategy ?? 'first',
      upload_limit_mbps: r.upload_limit_mbps ?? 0,
      download_limit_mbps: r.download_limit_mbps ?? 0,
      max_connections: r.max_connections ?? 0,
      auto_restart_minutes: r.auto_restart_minutes ?? 0,
    });
    setEditOpen(true);
  };

  /** 复制规则时在 Modal 挂载后再写入表单，避免字段 initialValue 覆盖预填值。 */
  const handleCopy = (r: ForwardRule) => {
    pendingCreateValues.current = {
      name: `${r.name}-copy`,
      listen_port: null,
      protocol: r.public_transport === 'nginx_sni' || r.node_transport === 'nginx_sni' ? 'tcp' : r.protocol,
      public_transport: r.public_transport === 'nginx_sni' || r.node_transport === 'nginx_sni' ? 'nginx_sni' : 'raw',
      sni: r.sni ?? undefined,
      camouflage_enabled: r.camouflage_enabled === true,
      send_proxy_protocol: r.send_proxy_protocol === true,
      device_group_in: r.device_group_in,
      target_addr: r.target_addr,
      target_port: r.target_port,
      targets: ruleTargets(r),
      load_balance_strategy: r.load_balance_strategy ?? 'first',
      upload_limit_mbps: r.upload_limit_mbps ?? 0,
      download_limit_mbps: r.download_limit_mbps ?? 0,
      // max_connections 与 auto_restart_minutes 为仅编辑字段，不复制到新建表单。
    };
    setCreateOpen(true);
    window.setTimeout(() => {
      if (!pendingCreateValues.current) return;
      createForm.setFieldsValue(pendingCreateValues.current);
      pendingCreateValues.current = null;
    }, 0);
  };

  /** Export all rules as JSON download. */
  const handleExportAll = () => {
    downloadText(`relaypanel-rules-${new Date().toISOString().slice(0, 10)}.json`, buildExportJSON(rules));
    message.success(t('exported'));
  };

  /** Export only the currently-selected rules as JSON download. */
  const handleExportSelected = () => {
    const selected = rules.filter(r => selectedRowKeys.includes(r.id));
    if (selected.length === 0) return;
    downloadText(`relaypanel-rules-selected-${new Date().toISOString().slice(0, 10)}.json`, buildExportJSON(selected));
    message.success(t('exported'));
  };

  const handleImport = async () => {
    if (!importGroupId) {
      message.error(t('selectInboundGroup'));
      return;
    }
    let parsed: unknown;
    try { parsed = JSON.parse(importText); } catch {
      message.error(t('importInvalidJson')); return;
    }
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    if (entries.length === 0) {
      message.error(t('importInvalidFormat')); return;
    }
    const results: string[] = [];
    for (const e of entries) {
      const label = (typeof e === 'object' && e !== null && !Array.isArray(e))
        ? String((e as { name?: unknown })['name'] ?? '?')
        : '?';
      const err = validateImportEntry(e);
      if (err) { results.push(`❌ ${label}: ${err}`); continue; }
      const entry = asValidatedEntry(e);
      try {
        const res = await api.post<unknown, ApiEnvelope<null>>('/rules', {
          ...buildImportedRulePayload(entry, importGroupId),
          // v1.0.6: attribute to the target user when an admin imports via the
          // user-management entry (/rules?owner_uid=X); else owner = caller.
          owner_uid: filterOwnerUid ?? undefined,
        });
        if (res.code === 0) results.push(`✅ ${entry.name}:${entry.listen_port}`);
        else results.push(`❌ ${entry.name}: ${res.message}`);
      } catch { results.push(`❌ ${entry.name}: network error`); }
    }
    if (results.length === 0) { message.error(t('importInvalidFormat')); return; }
    setImportResults(results);
    load(); // refresh rules in background
  };
  const handleUpdate = async (values: {
    name?: string; listen_port?: number; protocol?: string;
    device_group_in?: number;
    target_addr?: string; target_port?: number; targets?: RuleTargetInput[];
    load_balance_strategy?: string;
    upload_limit_mbps?: number;
    download_limit_mbps?: number;
    max_connections?: number;
    auto_restart_minutes?: number;
    public_transport?: string;
    sni?: string;
    camouflage_enabled?: boolean;
    send_proxy_protocol?: boolean;
  }) => {
    if (!editing) return;
    const payload: Record<string, unknown> = {};
    const oldTransport = editing.public_transport === 'nginx_sni' || editing.node_transport === 'nginx_sni' ? 'nginx_sni' : 'raw';
    const newTransport = values.public_transport === 'nginx_sni' ? 'nginx_sni' : 'raw';
    const newSni = normalizeSni(values.sni);
    if (newTransport === 'nginx_sni' && !newSni) {
      message.error(t('sniRequired'));
      return;
    }
    if (values.name !== undefined && values.name !== editing.name) payload.name = values.name;
    if (values.listen_port !== undefined && values.listen_port !== editing.listen_port) payload.listen_port = values.listen_port;
    const effectiveProtocol = newTransport === 'nginx_sni' ? 'tcp' : values.protocol;
    if (effectiveProtocol !== undefined && effectiveProtocol !== editing.protocol) payload.protocol = effectiveProtocol;
    if (newTransport !== oldTransport) payload.public_transport = newTransport;
    if (newTransport === 'nginx_sni' && newSni !== normalizeSni(editing.sni)) payload.sni = newSni;
    if (newTransport === 'raw' && oldTransport === 'nginx_sni') payload.sni = null;
    const newCamouflage = newTransport === 'nginx_sni' && values.camouflage_enabled === true;
    if (newCamouflage !== (editing.camouflage_enabled === true)) payload.camouflage_enabled = newCamouflage;
    const newProxyProtocol = newTransport === 'nginx_sni' && values.send_proxy_protocol === true;
    if (newProxyProtocol !== (editing.send_proxy_protocol === true)) payload.send_proxy_protocol = newProxyProtocol;
    if (values.device_group_in !== undefined && values.device_group_in !== editing.device_group_in) payload.device_group_in = values.device_group_in;
    const newTargets = formTargets(values);
    const oldTargets = ruleTargets(editing);
    if (JSON.stringify(newTargets) !== JSON.stringify(oldTargets)) {
      if (newTargets.length < 1) {
        message.error(t('targetRequired'));
        return;
      }
      const first = newTargets[0];
      payload.target_addr = first.host;
      payload.target_port = first.port;
      payload.targets = newTargets;
    }
    if (values.load_balance_strategy !== undefined && values.load_balance_strategy !== (editing.load_balance_strategy ?? 'first')) {
      payload.load_balance_strategy = values.load_balance_strategy;
    }
    const newUp = values.upload_limit_mbps ?? 0;
    const newDown = values.download_limit_mbps ?? 0;
    if (newUp !== (editing.upload_limit_mbps ?? 0) || newDown !== (editing.download_limit_mbps ?? 0)) {
      payload.upload_limit_mbps = newUp;
      payload.download_limit_mbps = newDown;
    }
    // v1.2.0: send both together when either changed. The API defaults an
    // omitted one to the rule's current value, so sending a single field is
    // safe — but sending the pair keeps the request self-describing.
    const newMaxConn = values.max_connections ?? 0;
    const newAutoRestart = values.auto_restart_minutes ?? 0;
    if (newMaxConn !== (editing.max_connections ?? 0) || newAutoRestart !== (editing.auto_restart_minutes ?? 0)) {
      payload.max_connections = newMaxConn;
      payload.auto_restart_minutes = newAutoRestart;
    }
    if (Object.keys(payload).length === 0) { setEditOpen(false); return; }
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${editing.id}`, payload);
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(t('ruleUpdated'));
      setEditOpen(false);
      load();
    } catch { message.error(t('failedUpdateRule')); }
  };

  const handleDelete = async (id: number) => {
    await api.delete(`/rules/${id}`);
    message.success(t('ruleDeleted'));
    load();
  };

  const handleBatchDelete = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    // v1.0.9: tally per-rule success/failure instead of assuming Promise.all
    // means everything worked — a delete can fail (e.g. 404/permission) and the
    // old code still reported the full count as deleted.
    const results = await Promise.all(ids.map(async id => {
      try {
        const res = await api.delete<unknown, ApiEnvelope<null>>(`/rules/${id}`);
        return res.code === 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success(t('batchDeleteSuccess').replace('{count}', String(ok)));
    } else {
      message.warning(t('batchPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
    }
    setSelectedRowKeys([]);
    load();
  };

  /** v1.0.7: batch pause/resume. Each rule goes through PUT /rules/{id}
   *  {paused}. Resume can be rejected per-rule (403) when the rule points at a
   *  device group the user is no longer authorized for, so we tally ok/fail
   *  instead of assuming success. */
  const handleBatchSetPaused = async (paused: boolean) => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    const results = await Promise.all(ids.map(async id => {
      try {
        const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${id}`, { paused });
        return res.code === 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success((paused ? t('batchPauseSuccess') : t('batchResumeSuccess')).replace('{count}', String(ok)));
    } else {
      message.warning(t('batchPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail)));
    }
    setSelectedRowKeys([]);
    load();
  };

  /** v1.2.0: restart one rule — drop its live connections and rebuild its
   *  listeners on every node of its inbound group. The rule's paused state is
   *  untouched; this is not a pause/resume round-trip.
   *
   *  `restarted` (nodes actually reached) drives the message rather than the
   *  HTTP code: the request can succeed while restarting nothing, e.g. every
   *  node is too old to understand the command. Reporting that as success would
   *  hide exactly the case the user needs to act on. */
  const handleRestart = async (r: ForwardRule) => {
    try {
      const res = await api.post<unknown, ApiEnvelope<RestartResponse>>(`/rules/${r.id}/restart`, {});
      if (res.code !== 0) {
        message.error(res.message || t('restartFailed'));
        return;
      }
      const data = res.data;
      const outdated = (data?.nodes ?? []).filter(n => n.state === 'unsupported').length;
      const offline = (data?.nodes ?? []).filter(n => n.state === 'control_channel_offline').length;
      if ((data?.restarted ?? 0) > 0) {
        let msg = t('restartSuccess').replace('{count}', String(data?.restarted ?? 0));
        if (outdated > 0) msg += ` ${t('restartOutdatedSuffix').replace('{count}', String(outdated))}`;
        if (offline > 0) msg += ` ${t('restartOfflineSuffix').replace('{count}', String(offline))}`;
        if (outdated > 0 || offline > 0) message.warning(msg);
        else message.success(msg);
      } else if (outdated > 0) {
        message.warning(t('restartAllOutdated').replace('{count}', String(outdated)));
      } else if (offline > 0) {
        message.warning(t('restartAllOffline').replace('{count}', String(offline)));
      } else {
        message.warning(t('restartNoNodes'));
      }
    } catch {
      message.error(t('restartFailed'));
    }
  };

  /** v1.2.0: batch restart. Per-rule POST like batch pause/resume — there is no
   *  bulk endpoint. A rule can fail individually (paused → 400, or not owned →
   *  404), so tally ok/fail rather than assuming Promise.all means success. */
  const handleBatchRestart = async () => {
    const ids = selectedRowKeys as number[];
    if (ids.length === 0) return;
    const results = await Promise.all(ids.map(async id => {
      const rule = visibleRules.find(item => item.id === id);
      const endpoint = rule && isRealityRule(rule) ? `/rules/${id}/reapply` : `/rules/${id}/restart`;
      try {
        const res = await api.post<unknown, ApiEnvelope<RestartResponse | ReapplyResponse>>(endpoint, {});
        // Reaching zero nodes is not a success worth reporting as one.
        const count = rule && isRealityRule(rule)
          ? (res.data as ReapplyResponse | undefined)?.applied ?? 0
          : (res.data as RestartResponse | undefined)?.restarted ?? 0;
        return res.code === 0 && count > 0;
      } catch { return false; }
    }));
    const ok = results.filter(Boolean).length;
    const fail = results.length - ok;
    if (fail === 0) {
      message.success(t('batchRestartSuccess').replace('{count}', String(ok)));
    } else {
      // NOT batchPartial: that message blames "unauthorized lines can't be
      // resumed", which is the batch-resume failure mode and has nothing to do
      // with a restart. A restart fails when the rule is paused or every node is
      // old/offline — say that instead of pointing at the wrong cause.
      message.warning(
        t('batchRestartPartial').replace('{ok}', String(ok)).replace('{fail}', String(fail))
      );
    }
    setSelectedRowKeys([]);
  };

  const handleDnsRetry = async (ruleId: number) => {
    setDnsRetrying(ruleId);
    try {
      const res = await api.post<unknown, ApiEnvelope<RuleDnsStatus>>(
        `/admin/rules/${ruleId}/dns/retry`,
        {},
      );
      if (res.code !== 0 || !res.data) {
        message.error(res.message || t('dnsRetryFailed'));
        return;
      }
      setDnsStatuses(current => [
        ...current.filter(status => status.rule_id !== ruleId),
        res.data as RuleDnsStatus,
      ]);
      message.success(t('dnsRetryScheduled'));
    } catch {
      message.error(t('dnsRetryFailed'));
    } finally {
      setDnsRetrying(null);
    }
  };

  const handleDiagnose = (r: ForwardRule) => setDiagnosing(r);

  /** Toggle a rule's paused state via the dedicated paused field on the update
   *  API. Paused rules stay in the DB but the node stops forwarding (get_config
   *  filters WHERE paused = 0). This is the only way to pause a rule — before
   *  v0.3.0 the paused column existed but had no API to flip it. */
  const handleTogglePause = async (r: ForwardRule) => {
    const nextPaused = !r.paused;
    try {
      const res = await api.put<unknown, ApiEnvelope<null>>(`/rules/${r.id}`, { paused: nextPaused });
      if (res.code !== 0) { message.error(res.message); return; }
      message.success(nextPaused ? t('rulePaused') : t('ruleResumed'));
      load();
    } catch { message.error(t('failedUpdateRule')); }
  };

  const confirmDeleteRule = (r: ForwardRule) => {
    Modal.confirm({
      title: t('deleteRuleConfirm'),
      okText: t('delete'),
      cancelText: t('cancel'),
      okButtonProps: { danger: true },
      onOk: () => handleDelete(r.id),
    });
  };

  const confirmRuntimeAction = (r: ForwardRule) => {
    Modal.confirm({
      title: t('restartConfirmTitle'),
      content: t('restartConfirmDesc'),
      okText: t('restart'),
      cancelText: t('cancel'),
      okButtonProps: { danger: true },
      onOk: () => handleRestart(r),
    });
  };

  const protoTags = (p: string) => {
    if (p === 'tcp_udp') return <><Tag color="blue">TCP</Tag><Tag color="purple">UDP</Tag></>;
    if (p === 'udp') return <Tag color="purple">UDP</Tag>;
    return <Tag color="blue">TCP</Tag>;
  };
  const transportTag = (r: ForwardRule) => {
    const transport = r.public_transport ?? r.node_transport ?? 'raw';
    if (transport === 'nginx_sni') return <Tag color="gold">{t('entryTransportNginxSni')}</Tag>;
    return <Tag>{t('entryTransportRaw')}</Tag>;
  };

  const renderStatus = (r: ForwardRule) => {
    const stateTags = (
      <Space size={4} className="rp-rules-status-flags">
        {r.paused ? <Tag color="red">{t('paused')}</Tag> : null}
        {!r.paused && ruleOverQuota(r) ? (
          <Tooltip title={t('quotaExhaustedHint')}>
            <Tag color="orange">{t('quotaExhausted')}</Tag>
          </Tooltip>
        ) : null}
      </Space>
    );
    const traffic = <Text type="secondary" className="rp-rules-traffic">{t('traffic')} {formatBytes(r.traffic_used)}</Text>;
    if (!isRealityRule(r)) {
      return (
        <div className="rp-rules-status-cell">
          <Text type="secondary">{t('runtimeHealthy')}</Text>
          {stateTags}
          {traffic}
        </div>
      );
    }

    const view = deriveCamouflageStatus(r, nodeStatuses);
    const dns = dnsStatusByRule.get(r.id);
    const summary = compactRealityStatus(r, dns, view);
    const summaryDisplay = compactRealityStatusDisplay(summary, t);
    const dnsDetails = (
      <DnsStatusCell status={dns} retrying={dnsRetrying === r.id} onRetry={() => handleDnsRetry(r.id)} t={t} />
    );
    const details = (
      <Space orientation="vertical" size={8} style={{ minWidth: 320, maxWidth: 460 }}>
        <Typography.Text strong>{t('dns')}</Typography.Text>
        {dnsDetails}
        <Typography.Text strong>{t('routeDetails')}</Typography.Text>
        <Text>{t('activeRelays')}: {view.activeCount}/{view.totalCount}</Text>
        {view.nodes.map(node => (
          <div key={`${node.relayIp ?? ''}:${node.nodeId ?? ''}`} className="rp-rules-node-state">
            <Text className="rp-mono">{node.relayIp ?? t('routeUnknown')}</Text>
            <Space size={8} wrap>
              <RuntimeDetailState label={t('diagnosisListener')} state={node.listenerState} t={t} />
              <RuntimeDetailState label={t('diagnosisCamouflage')} state={node.siteState} t={t} />
              <RuntimeDetailState label={t('diagnosisCertificate')} state={node.certificateState} t={t} />
            </Space>
            {node.lastError ? <Text type="warning">{camouflageCertificateMessage(node.certificateState, node.lastError, t)}</Text> : null}
          </div>
        ))}
        <Typography.Text strong>{t('certificateDetails')}</Typography.Text>
        {view.certificate?.issuer && <Text>{view.certificate.issuer}</Text>}
        {view.certificate?.valid_until && <Text>{t('expires')}: {new Date(view.certificate.valid_until).toLocaleString()}</Text>}
        {view.certificate?.last_success && <Text>{t('lastCertificateSuccess')}: {new Date(view.certificate.last_success).toLocaleString()}</Text>}
        {view.certificate?.last_error && <Text type="warning">{camouflageCertificateMessage(view.certificate.certificate_status, view.certificate.last_error, t)}</Text>}
      </Space>
    );
    return (
      <div className="rp-rules-status-cell">
        <Popover title={t('statusDetails')} content={details} trigger="click">
          <Button type="text" size="small" className="rp-compact-status" aria-label={t('statusDetails')}>
            <span className="rp-rule-health-row">
              <RuleHealthItem label={t('dns')} display={summaryDisplay.dns} />
              <RuleHealthItem label={t('routeDetails')} display={summaryDisplay.route} />
            </span>
            <span className="rp-rule-health-row">
              <RuleHealthItem label={t('certificateDetails')} display={summaryDisplay.certificate} />
            </span>
          </Button>
        </Popover>
        {stateTags}
        {traffic}
      </div>
    );
  };

  const moreMenuItems = (r: ForwardRule): MenuProps['items'] => {
    const items: MenuProps['items'] = [
      {
        key: 'toggle',
        label: r.paused ? t('resume') : t('pause'),
        icon: r.paused ? <PlayCircleOutlined /> : <PauseCircleOutlined />,
        onClick: () => void handleTogglePause(r),
      },
      { key: 'copy', label: t('copy'), icon: <CopyOutlined />, onClick: () => handleCopy(r) },
    ];
    if (!isRealityRule(r)) {
      items.push(
        { type: 'divider' },
        {
          key: 'runtime',
          label: t('restart'),
          icon: <ThunderboltOutlined />,
          disabled: r.paused,
          onClick: () => confirmRuntimeAction(r),
        },
      );
    }
    items.push(
      { type: 'divider' },
      { key: 'delete', label: t('delete'), icon: <DeleteOutlined />, danger: true, onClick: () => confirmDeleteRule(r) },
    );
    return items;
  };

  const allColumns = [
    {
      title: t('ruleColumn'), key: 'rule', width: 220,
      render: (_: unknown, r: ForwardRule) => {
        const owner = userMap.get(r.uid) ?? `#${r.uid}`;
        const meta = isAdmin ? `#${r.id} · ${owner}` : `#${r.id}`;
        return (
          <div className="rp-rules-rule-cell">
            <RuleEllipsis value={r.name} mono={false} />
            <Text type="secondary" className="rp-rules-rule-meta" title={meta}>{meta}</Text>
          </div>
        );
      },
    },
    {
      title: t('ruleEntry'), key: 'entry', width: 210,
      render: (_: unknown, r: ForwardRule) => {
        const sni = normalizeSni(r.sni);
        if (isRealityRule(r) && sni) return <RuleEllipsis value={`${sni}:${r.listen_port}`} />;
        const host = groupInfo.get(r.device_group_in)?.connect_host?.trim() ?? '';
        if (!isRealityRule(r) && host) return <RuleEllipsis value={`${host}:${r.listen_port}`} />;
        return <Text className="rp-mono rp-rules-nowrap">{t('port')} {r.listen_port}</Text>;
      },
    },
    {
      title: t('protocolForward'), dataIndex: 'protocol', key: 'protocol', width: 190,
      render: (p: string, r: ForwardRule) => (
        <div className="rp-rules-protocol-cell">
          <Space size={4} className="rp-rules-nowrap">{protoTags(p)}</Space>
          <div>{transportTag(r)}</div>
        </div>
      ),
    },
    {
      title: t('target'), key: 'target', width: 220,
      render: (_: unknown, r: ForwardRule) => {
        // v1.0.9: a multi-target rule shows "first (+N)"; hovering lists every
        // enabled target IP so the admin can see the failover/round-robin pool.
        const all = ruleTargets(r).filter(t => t.enabled).map(t => `${t.host}:${t.port}`);
        const summary = <RuleEllipsis value={targetSummary(r)} tooltip={all.length <= 1} />;
        return (
          <div className="rp-rules-target-cell">
            {all.length > 1 ? (
              <Tooltip title={<div>{all.map((s, i) => <div key={i} className="rp-mono">{s}</div>)}</div>}>
                <span className="rp-rules-target-tooltip" data-target-pool={all.join(',')}>{summary}</span>
              </Tooltip>
            ) : summary}
            {r.load_balance_strategy && r.load_balance_strategy !== 'first' && (
              <div><Tag color="cyan">{r.load_balance_strategy === 'round_robin' ? t('lbRoundRobin') : t('lbFailover')}</Tag></div>
            )}
          </div>
        );
      },
    },
    {
      title: t('status'), key: 'status', width: 240,
      render: (_: unknown, r: ForwardRule) => renderStatus(r),
    },
    {
      title: t('action'), key: 'action', width: 170, fixed: 'right' as const,
      render: (_: unknown, r: ForwardRule) => (
        <Space size={0} className="rp-rules-actions">
          <Button size="small" type="text" icon={<EditOutlined />} onClick={() => handleEdit(r)}>{t('edit')}</Button>
          <Button size="small" type="text" icon={<MedicineBoxOutlined />} disabled={r.protocol === 'udp'} onClick={() => handleDiagnose(r)} title={r.protocol === 'udp' ? t('diagnoseUdpUnsupported') : t('diagnose')}>{t('diagnose')}</Button>
          <Dropdown menu={{ items: moreMenuItems(r) }} trigger={['click']}>
            <Button size="small" type="text" icon={<MoreOutlined />} aria-label={t('moreActions')} title={t('moreActions')} />
          </Dropdown>
        </Space>
      ),
    },
  ];
  const columns = allColumns;

  const inGroups = groups.filter(g => g.group_type === 'in');
  // v0.4.12 PR1: inbound group selection. Admins pick from their OWN 'in'
  // groups. Regular users pick ONLY from admin-owned shared 'in' groups
  // (/groups/shared) — never their own historical groups, which the backend
  // also rejects. This keeps the UI and the API invariant in lock-step.
  const sharedInGroups = sharedGroups.filter(g => g.group_type === 'in');
  const allInGroups = isAdmin ? inGroups : sharedInGroups;
  const protocolOptions = [
    { value: 'tcp_udp', label: t('tcpUdp') },
    { value: 'tcp', label: 'TCP' },
    { value: 'udp', label: 'UDP' },
  ];
  const strategyOptions = [
    { value: 'first', label: t('lbFirst') },
    { value: 'round_robin', label: t('lbRoundRobin') },
    { value: 'failover', label: t('lbFailover') },
  ];
  const isUdp = (p?: string) => p === 'udp' || p === 'tcp_udp';

  const createGroupId = Form.useWatch('device_group_in', createForm);
  const editGroupId = Form.useWatch('device_group_in', { form: editForm, preserve: true });
  const createProto = Form.useWatch('protocol', createForm);
  const editProto = Form.useWatch('protocol', { form: editForm, preserve: true });
  const createTransport = Form.useWatch('public_transport', createForm);
  const editTransport = Form.useWatch('public_transport', { form: editForm, preserve: true });
  const createIsSni = createTransport === 'nginx_sni';
  const editIsSni = editTransport === 'nginx_sni';
  const createCamouflage = Form.useWatch('camouflage_enabled', createForm) === true;
  const editCamouflage = Form.useWatch('camouflage_enabled', { form: editForm, preserve: true }) === true;
  const createProxyProtocol = Form.useWatch('send_proxy_protocol', { form: createForm, preserve: true }) === true;
  const editProxyProtocol = Form.useWatch('send_proxy_protocol', { form: editForm, preserve: true }) === true;
  const createTargets = Form.useWatch('targets', { form: createForm, preserve: true }) as RuleTargetInput[] | undefined;
  const editTargets = Form.useWatch('targets', { form: editForm, preserve: true }) as RuleTargetInput[] | undefined;
  const createStrategy = Form.useWatch('load_balance_strategy', { form: createForm, preserve: true }) as string | undefined;
  const editStrategy = Form.useWatch('load_balance_strategy', { form: editForm, preserve: true }) as string | undefined;
  const createUploadLimit = Number(Form.useWatch('upload_limit_mbps', { form: createForm, preserve: true }) ?? 0);
  const createDownloadLimit = Number(Form.useWatch('download_limit_mbps', { form: createForm, preserve: true }) ?? 0);
  const editUploadLimit = Number(Form.useWatch('upload_limit_mbps', { form: editForm, preserve: true }) ?? 0);
  const editDownloadLimit = Number(Form.useWatch('download_limit_mbps', { form: editForm, preserve: true }) ?? 0);
  const editMaxConnections = Number(Form.useWatch('max_connections', { form: editForm, preserve: true }) ?? 0);
  const editAutoRestart = Number(Form.useWatch('auto_restart_minutes', { form: editForm, preserve: true }) ?? 0);

  const showCreateStrategy = (createTargets?.length ?? 0) > 1 || (createStrategy ?? 'first') !== 'first';
  const showEditStrategy = (editTargets?.length ?? 0) > 1 || (editStrategy ?? 'first') !== 'first';
  const createForwardingAdvancedLabels = [
    createUploadLimit > 0 || createDownloadLimit > 0 ? t('rateLimits') : null,
  ].filter((label): label is string => label !== null);
  const forwardingAdvancedLabels = [
    editUploadLimit > 0 || editDownloadLimit > 0 ? t('rateLimits') : null,
    editMaxConnections > 0 ? t('maxConnections') : null,
    editAutoRestart > 0 ? t('autoRestart') : null,
  ].filter((label): label is string => label !== null);
  const createBasicAdvancedSummary = createProxyProtocol
    ? t('ruleAdvancedProxyEnabled')
    : t('ruleAdvancedNone');
  const editBasicAdvancedSummary = editProxyProtocol
    ? t('ruleAdvancedProxyEnabled')
    : t('ruleAdvancedNone');
  const createForwardingAdvancedSummary = createForwardingAdvancedLabels.length > 0
    ? t('ruleAdvancedConfiguredCount').replace('{count}', String(createForwardingAdvancedLabels.length))
    : t('ruleAdvancedNone');
  const forwardingAdvancedSummary = forwardingAdvancedLabels.length > 0
    ? t('ruleAdvancedConfiguredCount').replace('{count}', String(forwardingAdvancedLabels.length))
    : t('ruleAdvancedNone');

  const advancedLabel = (title: string, summary: string, details?: string[]) => (
    <span className="rp-rule-advanced-label">
      <span>{title} · {summary}</span>
      {details && details.length > 0 ? <Text type="secondary">{details.join(' · ')}</Text> : null}
    </span>
  );

  const hostForForm = (gid?: number) => {
    if (!gid) return '';
    // v1.0.7: a regular user doesn't own the admin device groups, so `groups`
    // is empty for them — resolve the connect host from the merged groupInfo
    // (which also folds in their authorized shared groups) instead.
    return groupInfo.get(gid)?.connect_host ?? '';
  };
  const hostHint = (gid?: number) => t('currentInboundHost').replace(
    '{host}',
    hostForForm(gid) || t('notConfigured'),
  );

  const handleCreateTransportChange = (v: string) => {
    if (v === 'nginx_sni') {
      createForm.setFieldsValue({ protocol: 'tcp', listen_port: createForm.getFieldValue('listen_port') ?? 443 });
    } else {
      createForm.setFieldValue('camouflage_enabled', false);
      createForm.setFieldValue('send_proxy_protocol', false);
    }
  };

  const handleEditTransportChange = (v: string) => {
    if (v === 'nginx_sni') {
      editForm.setFieldsValue({ protocol: 'tcp', listen_port: editForm.getFieldValue('listen_port') ?? 443 });
    } else {
      editForm.setFieldValue('camouflage_enabled', false);
      editForm.setFieldValue('send_proxy_protocol', false);
    }
  };

  const transportOptions = [
    { value: 'raw', label: t('entryTransportRaw') },
    { value: 'nginx_sni', label: t('entryTransportNginxSni') },
  ];

  /** v1.2.0：连接数限制和定时重启仅供编辑表单使用。
   *
   *  两个字段均以 0 表示关闭。连接数限制按节点计数，因此通过 `extra`
   *  明确告知用户，避免把多节点规则误解为共享一个总上限。
   *
   *  纯 UDP 规则没有 accept() 阶段，因此禁用该字段；tcp_udp 规则仍保留，
   *  由它的 TCP 部分使用。 */
  const renderConnectionControls = (proto?: string) => {
    const udpOnly = proto === 'udp';
    return (
    <>
      <Form.Item
        name="max_connections"
        label={t('maxConnections')}
        extra={udpOnly ? t('maxConnectionsUdpUnsupported') : t('maxConnectionsHint')}
        initialValue={0}
      >
        <InputNumber min={0} style={{ width: '100%', maxWidth: 252 }} placeholder="0" disabled={udpOnly} />
      </Form.Item>
      <Form.Item
        name="auto_restart_minutes"
        label={t('autoRestart')}
        extra={t('autoRestartHint').replace('{min}', String(MIN_AUTO_RESTART_MINUTES))}
        initialValue={0}
        rules={[{
          // 与 API 最小值保持一致：0 表示关闭，1 到最小值之间不允许保存。
          validator: (_, value) => {
            const v = Number(value ?? 0);
            if (v === 0 || v >= MIN_AUTO_RESTART_MINUTES) return Promise.resolve();
            return Promise.reject(new Error(
              t('autoRestartTooSmall').replace('{min}', String(MIN_AUTO_RESTART_MINUTES))
            ));
          },
        }]}
      >
        <InputNumber min={0} style={{ width: '100%' }} addonAfter={t('minutes')} placeholder="0" />
      </Form.Item>
    </>
    );
  };

  // 负载策略说明放在标签帮助入口中，避免长期占用表单空间。
  const renderStrategyField = () => (
    <Form.Item
      name="load_balance_strategy"
      initialValue="first"
      label={
        <span>
          {t('loadBalanceStrategy')}{' '}
          <Tooltip
            overlayStyle={{ maxWidth: 360 }}
            title={
              <div style={{ fontSize: 12 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>{t('lbStrategyBlockTitle')}</div>
                <div>• {t('lbFirstDesc')}</div>
                <div>• {t('lbRoundRobinDesc')}</div>
                <div>• {t('lbFailoverDesc')}</div>
                <div style={{ marginTop: 8, opacity: 0.75 }}>{t('lbStrategyBlockFooter')}</div>
              </div>
            }
          >
            <QuestionCircleOutlined style={{ color: '#999' }} />
          </Tooltip>
        </span>
      }
    >
      <Select options={strategyOptions} style={{ maxWidth: 252 }} />
    </Form.Item>
  );

  const renderTargetsEditor = (realityRelay = false) => (
    <Form.List name="targets" initialValue={[{ host: '', port: undefined as unknown as number, enabled: true }]}>
      {(fields, { add, remove, move }) => (
        <Space orientation="vertical" style={{ width: '100%' }}>
          <Text strong>{realityRelay ? t('remoteRealityBackend') : t('targets')}</Text>
          {fields.map(({ key, ...field }, index) => (
            <Space key={key} align="baseline" wrap>
              <Form.Item
                {...field}
                name={[field.name, 'host']}
                label={realityRelay ? t('remoteRealityAddress') : t('address')}
                rules={[{ required: true }]}
                style={{ marginBottom: 8 }}
              >
                {/* Wide enough for a full IPv6 literal (up to 39 chars) — 180px
                    truncated them mid-address. */}
                <Input placeholder={t('targetAddress')} style={{ width: 320, maxWidth: 320 }} />
              </Form.Item>
              <Form.Item
                {...field}
                name={[field.name, 'port']}
                label={realityRelay ? t('remoteRealityPort') : t('port')}
                rules={[
                  { required: true, message: t('targetPortInvalid') },
                  {
                    validator: (_, v) => {
                      if (v == null || v === '' || !Number.isFinite(Number(v)) || Number(v) < 1 || Number(v) > 65535) {
                        return Promise.reject(new Error(t('targetPortInvalid')));
                      }
                      return Promise.resolve();
                    },
                  },
                ]}
                style={{ marginBottom: 8 }}
              >
                <InputNumber min={1} max={65535} placeholder={t('targetPort')} style={{ width: 110 }} />
              </Form.Item>
              <Form.Item
                {...field}
                name={[field.name, 'enabled']}
                valuePropName="checked"
                initialValue={true}
                style={{ marginBottom: 8 }}
              >
                <Switch size="small" />
              </Form.Item>
              <Button size="small" icon={<ArrowUpOutlined />} aria-label={t('moveTargetUp')} disabled={index === 0} onClick={() => move(index, index - 1)} />
              <Button size="small" icon={<ArrowDownOutlined />} aria-label={t('moveTargetDown')} disabled={index === fields.length - 1} onClick={() => move(index, index + 1)} />
              <Button size="small" danger icon={<DeleteOutlined />} aria-label={t('deleteTarget')} disabled={fields.length <= 1} onClick={() => remove(field.name)} />
            </Space>
          ))}
          <Button size="small" icon={<PlusOutlined />} onClick={() => add({ host: '', port: undefined as unknown as number, enabled: true })}>{t('addTarget')}</Button>
        </Space>
      )}
    </Form.List>
  );

  const exportMenuItems: MenuProps['items'] = [
    { key: 'export-all', label: t('exportAll'), icon: <DownloadOutlined />, onClick: handleExportAll },
    { key: 'import', label: t('import'), icon: <UploadOutlined />, onClick: () => setImportOpen(true) },
  ];

  const rowSelectionFor = (groupRules: ForwardRule[]) => ({
    selectedRowKeys,
    preserveSelectedRowKeys: true,
    columnWidth: RULE_SELECTION_COLUMN_WIDTH,
    onSelect: (record: ForwardRule, selected: boolean) => {
      setSelectedRowKeys(current => selected
        ? Array.from(new Set([...current, record.id]))
        : current.filter(key => key !== record.id));
    },
    onSelectAll: (selected: boolean, _selectedRows: ForwardRule[], changedRows: ForwardRule[]) => {
      const changedKeys = changedRows.map(rule => rule.id);
      setSelectedRowKeys(current => selected
        ? Array.from(new Set([...current, ...changedKeys]))
        : current.filter(key => !changedKeys.includes(key)));
    },
    selections: false,
    hideSelectAll: groupRules.length === 0,
  });

  const groupLabel = (groupId: number) => groupInfo.get(groupId)?.name ?? `${t('unknownGroup')} (#${groupId})`;

  return (
    <>
      <div className="rp-page-header rp-rules-header">
        <h2 className="rp-page-title"><ApiOutlined /> {t('forwardRules')}</h2>
        <Space className="rp-rules-page-actions" size={8} wrap>
          <Button icon={<ReloadOutlined />} onClick={load}>{t('refresh')}</Button>
          <Dropdown menu={{ items: exportMenuItems }}>
            <Button icon={<DownloadOutlined />}>{t('exportImport')}</Button>
          </Dropdown>
          <Button type="primary" icon={<PlusOutlined />} disabled={!isAdmin && sharedLoadFailed} onClick={() => { createForm.resetFields(); setCreateOpen(true); }}>{t('addRule')}</Button>
        </Space>
      </div>
      <div className="rp-rules-toolbar" data-testid="rules-toolbar">
        <Space size={8} wrap>
          <Input
            className="rp-rules-search"
            allowClear
            prefix={<SearchOutlined />}
            placeholder={t('searchRulePlaceholder')}
            value={ruleSearch}
            onChange={(e) => { setRuleSearch(e.target.value); setSelectedRowKeys([]); setCurrentPage(1); }}
            style={{ width: 220 }}
          />
          {/* v0.4.9: filter by inbound group. Only groups that actually have
              rules are offered, so the list stays short for large fleets. */}
          <Select
            className="rp-rules-group-filter"
            style={{ minWidth: 180 }}
            allowClear
            placeholder={t('filterByGroup')}
            value={selectedGroup ?? undefined}
            onChange={(v: number | undefined) => { setSelectedGroup(v ?? null); setSelectedRowKeys([]); setCurrentPage(1); }}
            options={Array.from(new Set(rules.map(r => r.device_group_in)))
              .map(gid => {
                const g = groupMap.get(gid);
                return { value: gid, label: g ? g.name : `${t('unknownGroup')} (#${gid})` };
              })}
          />
        </Space>
      </div>
      {selectedRowKeys.length > 0 ? (
        <div className="rp-rules-batchbar" data-testid="rules-batchbar" data-selected-count={selectedRowKeys.length}>
          <Space size={8} wrap>
            <Text strong>{t('selectedCount').replace('{count}', String(selectedRowKeys.length))}</Text>
            <Button icon={<PlayCircleOutlined />} onClick={() => handleBatchSetPaused(false)}>{t('batchResume')}</Button>
            <Button icon={<PauseCircleOutlined />} onClick={() => handleBatchSetPaused(true)}>{t('batchPause')}</Button>
            <Popconfirm
              title={t('batchRestartConfirm').replace('{count}', String(selectedRowKeys.length))}
              description={t('restartConfirmDesc')}
              onConfirm={handleBatchRestart}
              okButtonProps={{ danger: true }}
            >
              <Button icon={<ThunderboltOutlined />}>{t('batchRestart')}</Button>
            </Popconfirm>
            <Button icon={<DownloadOutlined />} onClick={handleExportSelected}>{t('batchExport')}</Button>
            <Popconfirm
              title={t('batchDeleteConfirm').replace('{count}', String(selectedRowKeys.length))}
              onConfirm={handleBatchDelete}
              okButtonProps={{ danger: true }}
            >
              <Button danger icon={<DeleteOutlined />}>{t('batchDelete')}</Button>
            </Popconfirm>
          </Space>
          <Button type="text" onClick={() => setSelectedRowKeys([])}>{t('cancelSelection')}</Button>
        </div>
      ) : null}
      {/* v0.4.20: admin viewing another user's rules — show who. */}
      {filterOwnerUid && (
        <Alert type="info" showIcon style={{ marginBottom: 12 }}
          title={t('viewingUserRules').replace('{user}', userMap.get(filterOwnerUid) ?? `#${filterOwnerUid}`)}
        />
      )}
      {/* v0.4.12 PR1: a regular user whose shared-lines fetch failed sees a
          load-failure notice; rule creation is disabled above so they can't
          submit against an empty/unknown inbound list. */}
      {!isAdmin && sharedLoadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={t('loadFailed')}
          description={t('loadFailedRetry')}
        />
      )}
      {loadFailed && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          title={t('rulesLoadFailed')}
          description={t('loadFailedRetry')}
          action={<Button size="small" onClick={() => void load()}>{t('retry')}</Button>}
        />
      )}
      {groupedPagedRules.length === 0 && (!loadFailed || rules.length > 0) ? (
        <Table
          rowSelection={rowSelectionFor([])}
          dataSource={[]}
          columns={columns}
          rowKey="id"
          loading={loading}
          locale={{ emptyText: t('rulesEmpty') }}
          pagination={false}
          className="rp-rules-table"
          scroll={{ x: RULE_TABLE_SCROLL_X }}
        />
      ) : groupedPagedRules.map(([groupId, groupRules]) => (
        <section className="rp-rules-group-section" data-testid={`rules-group-${groupId}`} key={groupId}>
          <div className="rp-rules-group-header">
            <Text strong className="rp-rules-group-title" title={groupLabel(groupId)}>{groupLabel(groupId)}</Text>
            <Text type="secondary">
              {t('ruleCount').replace('{count}', String(visibleGroupCounts.get(groupId) ?? groupRules.length))}
            </Text>
          </div>
          <Table
            rowSelection={rowSelectionFor(groupRules)}
            dataSource={groupRules}
            columns={columns}
            rowKey="id"
            loading={loading}
            locale={{ emptyText: t('rulesEmpty') }}
            pagination={false}
            className="rp-rules-table"
            scroll={{ x: RULE_TABLE_SCROLL_X }}
          />
        </section>
      ))}
      {visibleRules.length > RULES_PAGE_SIZE ? (
        <div className="rp-rules-pagination" data-testid="rules-pagination">
          <Pagination
            current={currentPage}
            pageSize={RULES_PAGE_SIZE}
            total={visibleRules.length}
            showSizeChanger={false}
            onChange={setCurrentPage}
          />
        </div>
      ) : null}

      <Modal
        title={t('addRule')}
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => createForm.submit()}
        okText={t('create')}
        cancelText={t('cancel')}
        width={620}
        className="rp-rule-editor-modal"
      >
        <Form form={createForm} onFinish={handleCreate} layout="vertical" className="rp-rule-form">
          <Tabs items={[
            {
              key: 'basic',
              label: t('tabBasic'),
              children: (<>
                <Form.Item name="name" label={t('name')} rules={[{ required: true }]}><Input placeholder="my-rule" /></Form.Item>
                {/* v0.4.20: owner is determined by the entry point — admins use
                    /rules?owner_uid=X from the user management page; regular
                    users always own their own rules. */}
                {filterOwnerUid && (
                  <Alert type="info" showIcon style={{ marginBottom: 12 }}
                    title={t('creatingRuleFor').replace('{user}', userMap.get(filterOwnerUid) ?? `#${filterOwnerUid}`)}
                  />
                )}
                <Form.Item name="device_group_in" label={t('inboundGroup')} rules={[{ required: true }]} extra={hostHint(createGroupId)}>
                  <Select options={allInGroups.map(g => ({ value: g.id, label: g.name }))} placeholder={allInGroups.length ? t('select') : t('createGroupFirst')} />
                </Form.Item>
                <Form.Item name="public_transport" label={t('transportMethod')} initialValue="raw">
                  <Select options={transportOptions} onChange={handleCreateTransportChange} />
                </Form.Item>
                <Form.Item name="listen_port" label={t('listenPort')} extra={createIsSni ? t('sniListenPortHint') : t('listenPortHint')}>
                  <InputNumber min={1} max={65535} style={{ width: '100%' }} placeholder={createIsSni ? '443' : 'auto'} />
                </Form.Item>
                {createIsSni && (
                  <>
                    <Form.Item
                      name="sni"
                      label={t('sni')}
                      extra={t('sniHint')}
                      rules={[{ required: true, message: t('sniRequired') }]}
                    >
                      <Input placeholder="op1.example.com" />
                    </Form.Item>
                    <CamouflageFormFields
                      enabled={createCamouflage}
                      initialValue={false}
                      isAdmin={isAdmin}
                      t={t}
                      compact
                    />
                  </>
                )}
                {!createIsSni ? (
                  <Form.Item name="protocol" label={t('protocol')} rules={[{ required: true }]} initialValue="tcp_udp"
                    extra={isUdp(createProto) ? t('entryTransportUdpOnlyRaw') : undefined}>
                    <Select options={protocolOptions} />
                  </Form.Item>
                ) : null}
                {/* v0.4.20: forward_mode always direct. */}
                <Form.Item name="forward_mode" hidden initialValue="direct"><Input /></Form.Item>
                {createIsSni ? (
                  <Collapse
                    className="rp-rule-advanced"
                    ghost
                    size="small"
                    items={[{
                      key: 'basic-advanced',
                      forceRender: true,
                      label: advancedLabel(t('ruleAdvancedSettings'), createBasicAdvancedSummary),
                      children: <ProxyProtocolFormField initialValue={false} isAdmin={isAdmin} t={t} showHint={createProxyProtocol} />,
                    }]}
                  />
                ) : null}
              </>),
            },
            {
              key: 'forward',
              forceRender: true,
              label: t('tabForward'),
              children: (<>
                {renderTargetsEditor(createIsSni)}
                {showCreateStrategy ? renderStrategyField() : (
                  <Form.Item name="load_balance_strategy" initialValue="first" hidden><Input /></Form.Item>
                )}
                <Collapse
                  className="rp-rule-advanced"
                  ghost
                  size="small"
                  items={[{
                    key: 'forward-advanced',
                    forceRender: true,
                    label: advancedLabel(
                      t('ruleForwardAdvancedSettings'),
                      createForwardingAdvancedSummary,
                      createForwardingAdvancedLabels,
                    ),
                    children: (
                      <Form.Item
                        label={<span>{t('rateLimits')} <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{t('rateLimitsTooltip')}</span>} overlayStyle={{ maxWidth: 340 }}><QuestionCircleOutlined style={{ color: '#999' }} /></Tooltip></span>}
                        extra={t('rateLimitsHint')}
                      >
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <Form.Item name="upload_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('uploadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                          <Form.Item name="download_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('downloadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                        </Space>
                      </Form.Item>
                    ),
                  }]}
                />
              </>),
            },
          ]} />
        </Form>
      </Modal>

      <Modal
        title={t('editRule')}
        open={editOpen}
        onCancel={() => setEditOpen(false)}
        onOk={() => editForm.submit()}
        okText={t('save')}
        cancelText={t('cancel')}
        width={620}
        className="rp-rule-editor-modal"
      >
        <Form form={editForm} onFinish={handleUpdate} layout="vertical" className="rp-rule-form">
          <Tabs items={[
            {
              key: 'basic',
              label: t('tabBasic'),
              children: (<>
                <Form.Item name="name" label={t('name')}><Input /></Form.Item>
                <Form.Item name="device_group_in" label={t('inboundGroup')} extra={hostHint(editGroupId)}>
                  <Select options={allInGroups.map(g => ({ value: g.id, label: g.name }))} />
                </Form.Item>
                <Form.Item name="public_transport" label={t('transportMethod')} initialValue="raw">
                  <Select options={transportOptions} onChange={handleEditTransportChange} />
                </Form.Item>
                <Form.Item name="listen_port" label={t('listenPort')} extra={editIsSni ? t('sniListenPortHint') : undefined}>
                  <InputNumber min={1} max={65535} style={{ width: '100%' }} />
                </Form.Item>
                {editIsSni && (
                  <>
                    <Form.Item
                      name="sni"
                      label={t('sni')}
                      extra={t('sniHint')}
                      rules={[{ required: true, message: t('sniRequired') }]}
                    >
                      <Input placeholder="op1.example.com" />
                    </Form.Item>
                    <CamouflageFormFields
                      enabled={editCamouflage}
                      isAdmin={isAdmin}
                      t={t}
                      compact
                    />
                  </>
                )}
                {!editIsSni ? (
                  <Form.Item name="protocol" label={t('protocol')}
                    extra={isUdp(editProto) ? t('entryTransportUdpOnlyRaw') : undefined}>
                    <Select options={protocolOptions} />
                  </Form.Item>
                ) : null}
                {/* v0.4.20: forward_mode always direct. */}
                <Form.Item name="forward_mode" hidden initialValue="direct"><Input /></Form.Item>
                {editIsSni ? (
                  <Collapse
                    className="rp-rule-advanced"
                    ghost
                    size="small"
                    items={[{
                      key: 'basic-advanced',
                      forceRender: true,
                      label: advancedLabel(t('ruleAdvancedSettings'), editBasicAdvancedSummary),
                      children: (
                        <ProxyProtocolFormField
                          isAdmin={isAdmin}
                          t={t}
                          showHint={editProxyProtocol}
                        />
                      ),
                    }]}
                  />
                ) : null}
              </>),
            },
            {
              key: 'forward',
              // v1.0.9: force-render so the targets Form.List mounts even while
              // the Basic tab is active. Without this, editing only a Basic field
              // (e.g. listen_port) and submitting without opening this tab left
              // `values.targets` unregistered — handleUpdate then read it as
              // "targets cleared" and rejected with "add at least one target".
              forceRender: true,
              label: t('tabForward'),
              children: (<>
                {renderTargetsEditor(editIsSni)}
                {showEditStrategy ? renderStrategyField() : null}
                <Collapse
                  className="rp-rule-advanced"
                  ghost
                  size="small"
                  items={[{
                    key: 'forward-advanced',
                    forceRender: true,
                    label: advancedLabel(
                      t('ruleForwardAdvancedSettings'),
                      forwardingAdvancedSummary,
                      forwardingAdvancedLabels,
                    ),
                    children: (
                      <>
                        <Form.Item
                          label={<span>{t('rateLimits')} <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{t('rateLimitsTooltip')}</span>} overlayStyle={{ maxWidth: 340 }}><QuestionCircleOutlined style={{ color: '#999' }} /></Tooltip></span>}
                          extra={t('rateLimitsHint')}
                        >
                          <Space orientation="vertical" style={{ width: '100%' }}>
                            <Form.Item name="upload_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('uploadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                            <Form.Item name="download_limit_mbps" noStyle initialValue={0}><InputNumber min={0} addonBefore={t('downloadLimit')} addonAfter="Mbps" style={{ width: '100%' }} placeholder="0" /></Form.Item>
                          </Space>
                        </Form.Item>
                        {renderConnectionControls(editProto)}
                      </>
                    ),
                  }]}
                />
              </>),
            },
          ]} />
        </Form>
      </Modal>

      <Modal title={t('import')} open={importOpen} onCancel={() => { setImportOpen(false); setImportText(''); setImportResults([]); }}
        onOk={importResults.length > 0 ? undefined : handleImport}
        okText={importResults.length > 0 ? t('close') : t('import')}
        cancelText={t('cancel')} width={600}
        footer={importResults.length > 0 ? <Button onClick={() => { setImportOpen(false); setImportText(''); setImportResults([]); }}>{t('close')}</Button> : undefined}
      >
        {importResults.length === 0 ? (
          <>
            <Form.Item label={t('selectInboundGroup')}>
              <Select value={importGroupId} onChange={setImportGroupId}
                options={(isAdmin ? groups.filter(g => g.group_type === 'in') : sharedGroups)
                  .map(g => ({ value: g.id, label: `${g.name} (#${g.id})` }))}
                placeholder={t('selectDeviceGroups')} style={{ width: '100%' }} />
            </Form.Item>
            <Alert type="info" showIcon style={{ marginBottom: 12 }}
              title={t('importHint')} />
            <TextArea value={importText} onChange={e => setImportText(e.target.value)}
              rows={10} placeholder='[{"dest":["1.2.3.4:55443"],"listen_port":443,"name":"op1","public_transport":"nginx_sni","sni":"op1.example.com"}]' />
          </>
        ) : (
          <div style={{ maxHeight: 300, overflowY: 'auto' }} aria-live="polite" aria-label={t('import')}>
            {importResults.map((r, i) => <div key={i} style={{ fontFamily: 'var(--rp-font-mono)', fontSize: 13, lineHeight: 1.8 }}>{r}</div>)}
          </div>
        )}
      </Modal>

      <RuleDiagnosisModal
        rule={diagnosing}
        open={diagnosing !== null}
        onClose={() => setDiagnosing(null)}
        isAdmin={isAdmin}
        t={t}
      />
    </>
  );
}
