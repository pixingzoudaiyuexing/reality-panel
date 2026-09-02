/* eslint-disable react-refresh/only-export-components */
import { Space, Tag, Tooltip, Typography } from 'antd';
import type { Tfn } from './types';
import type { NodeDisplayRow, RelayReadyNode } from '../../api/types';
import { CountryFlag } from './CountryFlag';

const { Text } = Typography;

/** Dual-stack network cell — IPv4 line + IPv6 line. Each line shows the
 *  CountryFlag pill (SVG, no Emoji) followed by the IP. No country name and
 *  no regionUnknown text: unknown regions render "--". */
export function NetworkCell({ row }: { row: NodeDisplayRow; t: Tfn }) {
  const v4 = row.public_ipv4 ?? row.public_ip;
  const v6 = row.public_ipv6;
  if (!v4 && !v6) return <Text type="secondary">-</Text>;
  const line = (ip: string, code: string | null | undefined) => (
    <div key={ip} style={{ fontSize: 12, lineHeight: '18px', display: 'flex', alignItems: 'center', gap: 6 }}>
      <CountryFlag code={code} />
      <span className="rp-mono" style={{ whiteSpace: 'nowrap' }}>{ip}</span>
    </div>
  );
  return (
    <>
      {v4 ? line(v4, row.ipv4_country_code) : null}
      {v6 ? line(v6, row.ipv6_country_code) : null}
    </>
  );
}

/** Status tag with protocol-mismatch detection. */
export function statusTag(r: NodeDisplayRow, t: Tfn, panelProtocol: number) {
  const v = r.config_protocol_version;
  if (v != null && panelProtocol > 0 && v !== panelProtocol) {
    return <Tag color="red">{t('protocolIncompatible')}</Tag>;
  }
  return r.online ? <Tag color="green">{t('online')}</Tag> : <Tag>{t('offline')}</Tag>;
}

export function relayReadyReasonLabel(reason: string, t: Tfn): string {
  const [code, detail] = reason.split(':', 2);
  const labels: Record<string, Parameters<Tfn>[0]> = {
    STATUS_MISSING: 'relayReadyStatusMissing',
    STATUS_INVALID: 'relayReadyStatusInvalid',
    STALE_STATUS: 'relayReadyStaleStatus',
    LAST_SEEN_MISSING: 'relayReadyLastSeenMissing',
    CONTROL_CHANNEL_OFFLINE: 'relayReadyControlOffline',
    CONFIG_PROTOCOL_MISMATCH: 'relayReadyProtocolMismatch',
    PUBLIC_IPV4_INVALID: 'relayReadyIpv4Invalid',
    PUBLIC_IPV4_MISSING: 'relayReadyIpv4Missing',
    RECONCILIATION_NOT_CONVERGED: 'relayReadyNotConverged',
    ACTIVE_RULES_MISSING: 'relayReadyActiveRulesMissing',
    ACTIVE_RULE_MISSING: 'relayReadyActiveRuleMissing',
    CAMOUFLAGE_SITE_NOT_ACTIVE: 'relayReadyCamouflageInactive',
    CERTIFICATE_NOT_ACTIVE: 'relayReadyCertificateInactive',
    LISTENER_ERROR: 'relayReadyListenerError',
  };
  const key = labels[code];
  if (!key) return reason;
  return detail ? `${t(key)} (${detail})` : t(key);
}

export function RelayReadyStatus({ node, t }: { node?: RelayReadyNode; t: Tfn }) {
  if (!node) return <Text type="secondary">-</Text>;
  if (node.ready) return <Tag color="green">{t('relayReady')}</Tag>;

  const reasons = node.ready_reasons.map((reason) => relayReadyReasonLabel(reason, t));
  const summary = reasons.length > 1
    ? `${reasons[0]} · ${t('relayReadyMoreReasons').replace('{count}', String(reasons.length - 1))}`
    : reasons[0];
  return (
    <Space orientation="vertical" size={1} className="rp-node-ready-state">
      <Tag color="red">{t('relayNotReady')}</Tag>
      {summary ? (
        <Tooltip title={reasons.join('；')}>
          <Text type="danger" className="rp-node-ready-reason">{summary}</Text>
        </Tooltip>
      ) : null}
    </Space>
  );
}
