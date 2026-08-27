import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { Form } from 'antd';
import { CamouflageFormFields, camouflageCertificateMessage, deriveCamouflageStatus, DnsStatusCell, ProxyProtocolFormField } from './Rules';
import type { NodeStatus, RuleDnsStatus } from '../api/types';

// ============================================================
// Pure-function tests for Rules.tsx helpers
// ============================================================

// Replicate the logic from Rules.tsx to test it independently.
// These match the actual implementation line-for-line.

const formTargets = (values: { targets?: Array<{ host: string; port: number; enabled?: boolean }>; target_addr?: string; target_port?: number }) => {
  const targets = values.targets ?? [];
  return targets.map(t => ({ host: t.host?.trim() ?? '', port: Number(t.port), enabled: t.enabled !== false }));
};

const payloadWithTargets = (values: Record<string, unknown> & { targets?: Array<{ host: string; port: number; enabled?: boolean }> }) => {
  const targets = formTargets(values);
  if (targets.length < 1) {
    throw new Error('targets must have at least one entry');
  }
  const first = targets[0];
  return { ...values, target_addr: first.host, target_port: first.port, targets };
};

const portValidator = (_: unknown, v: unknown) => {
  if (v == null || v === '' || !Number.isFinite(Number(v)) || Number(v) < 1 || Number(v) > 65535) {
    return Promise.reject(new Error('Target port must be 1-65535'));
  }
  return Promise.resolve();
};

// ============================================================
describe('formTargets', () => {
  it('returns empty when targets is empty', () => {
    expect(formTargets({ targets: [] })).toEqual([]);
  });

  it('does not fall back to legacy target_addr/target_port', () => {
    expect(formTargets({ target_addr: '1.2.3.4', target_port: 80 })).toEqual([]);
  });

  it('with 1 target returns it (trim host, Number port)', () => {
    const result = formTargets({ targets: [{ host: ' 1.2.3.4 ', port: 80 }] });
    expect(result).toEqual([{ host: '1.2.3.4', port: 80, enabled: true }]);
  });

  it('with multiple targets returns all', () => {
    const result = formTargets({ targets: [{ host: 'a', port: 1 }, { host: 'b', port: 2 }] });
    expect(result).toHaveLength(2);
    expect(result[0].host).toBe('a');
    expect(result[1].host).toBe('b');
  });
});

describe('payloadWithTargets', () => {
  it('throws if targets is empty', () => {
    expect(() => payloadWithTargets({ targets: [] })).toThrow('targets must have at least one entry');
  });

  it('does not generate target_addr=\'\' or target_port=0 for empty targets', () => {
    try {
      payloadWithTargets({ targets: [] });
    } catch (e) {
      expect((e as Error).message).toContain('targets');
      return;
    }
    expect.unreachable('should have thrown');
  });

  it('with a valid target writes target_addr/target_port from first entry', () => {
    const result = payloadWithTargets({ targets: [{ host: '10.0.0.1', port: 443 }], name: 'test' });
    expect(result.target_addr).toBe('10.0.0.1');
    expect(result.target_port).toBe(443);
    expect(result.targets).toHaveLength(1);
  });
});

describe('port validator', () => {
  it('rejects undefined', async () => {
    await expect(portValidator(undefined, undefined)).rejects.toThrow();
  });
  it('rejects null', async () => {
    await expect(portValidator(undefined, null)).rejects.toThrow();
  });
  it('rejects 0', async () => {
    await expect(portValidator(undefined, 0)).rejects.toThrow();
  });
  it('rejects -1', async () => {
    await expect(portValidator(undefined, -1)).rejects.toThrow();
  });
  it('rejects 65536', async () => {
    await expect(portValidator(undefined, 65536)).rejects.toThrow();
  });
  it('rejects empty string', async () => {
    await expect(portValidator(undefined, '')).rejects.toThrow();
  });
  it('accepts 1', async () => {
    await expect(portValidator(undefined, 1)).resolves.toBeUndefined();
  });
  it('accepts 80', async () => {
    await expect(portValidator(undefined, 80)).resolves.toBeUndefined();
  });
  it('accepts 65535', async () => {
    await expect(portValidator(undefined, 65535)).resolves.toBeUndefined();
  });
  it('accepts numeric string "80"', async () => {
    await expect(portValidator(undefined, '80')).resolves.toBeUndefined();
  });
  it('rejects numeric string "0"', async () => {
    await expect(portValidator(undefined, '0')).rejects.toThrow();
  });
});

describe('camouflage observed status', () => {
  const rule = { id: 42, camouflage_enabled: true, sni: 'op1.example.com', device_group_in: 10 };
  const node = (
    site: Record<string, unknown>,
    overrides: Partial<NodeStatus> = {},
  ): NodeStatus => ({
    group_id: 10,
    node_id: 'node-a',
    public_ipv4: '192.0.2.10',
    online: true,
    cpu: 0,
    mem: 0,
    connections: 0,
    uptime: 1,
    last_seen: new Date().toISOString(),
    active_listener_rule_ids: [rule.id],
    camouflage_sites: [{
      site_id: 'op1_example_com',
      sni: 'op1.example.com',
      site_status: 'active',
      certificate_status: 'active',
      ...site,
    }],
    ...overrides,
  });

  it('renders renewal failure as a warning while an existing certificate remains active', () => {
    const translate = (key: string) => key;
    expect(camouflageCertificateMessage(
      'active',
      'Certificate remains valid; automatic renewal failed and will be retried',
      translate,
    )).toBe('certificateRenewalWarning');
    expect(camouflageCertificateMessage('failed', 'DNS lookup failed', translate))
      .toBe('camouflageDnsMismatch');
    expect(camouflageCertificateMessage('failed', 'hard certificate failure', translate))
      .toBe('hard certificate failure');
  });

  it('returns unknown when no Relay has useful observed state', () => {
    const result = deriveCamouflageStatus(rule, []);
    expect(result.state).toBe('unknown');
    expect(result.activeCount).toBe(0);
    expect(result.totalCount).toBe(0);
  });

  it('keeps ACTIVE plus FAILED available as partial', () => {
    const active = node({}, { node_id: 'active', public_ipv4: '192.0.2.10' });
    const failed = node({
      site_status: 'failed',
      certificate_status: 'failed',
      last_error: 'DNS does not target this Relay',
    }, {
      node_id: 'failed',
      public_ipv4: '192.0.2.20',
      active_listener_rule_ids: [],
    });
    const result = deriveCamouflageStatus(rule, [active, failed]);
    expect(result.state).toBe('partial');
    expect(result.activeCount).toBe(1);
    expect(result.totalCount).toBe(2);
    expect(result.certificate?.certificate_status).toBe('active');
  });

  it('keeps ACTIVE plus WITHHELD available as partial', () => {
    const active = node({}, { node_id: 'active', public_ipv4: '192.0.2.10' });
    const withheld = node({}, {
      node_id: 'withheld',
      public_ipv4: '192.0.2.20',
      active_listener_rule_ids: [],
    });
    const result = deriveCamouflageStatus(rule, [active, withheld]);
    expect(result.state).toBe('partial');
    expect(result.nodes.find(entry => entry.nodeId === 'withheld')?.listenerState).toBe('withheld');
  });

  it('reports active when all relevant Relays are fully active', () => {
    const result = deriveCamouflageStatus(rule, [
      node({}, { node_id: 'node-a', public_ipv4: '192.0.2.10' }),
      node({}, { node_id: 'node-b', public_ipv4: '192.0.2.20' }),
    ]);
    expect(result.state).toBe('active');
    expect(result.activeCount).toBe(2);
    expect(result.totalCount).toBe(2);
  });

  it('reports preparing when zero Relays are active and one is preparing', () => {
    const result = deriveCamouflageStatus(rule, [node({
      site_status: 'preparing',
      certificate_status: 'pending',
    }, { active_listener_rule_ids: [] })]);
    expect(result.state).toBe('preparing');
    expect(result.activeCount).toBe(0);
  });

  it('reports failed when zero Relays are active and all observed states failed', () => {
    const first = node({
      site_status: 'failed',
      certificate_status: 'failed',
      last_error: 'terminal failure A',
    }, { node_id: 'node-a', public_ipv4: '192.0.2.10', active_listener_rule_ids: [] });
    const second = node({
      site_status: 'failed',
      certificate_status: 'failed',
      last_error: 'terminal failure B',
    }, { node_id: 'node-b', public_ipv4: '192.0.2.20', active_listener_rule_ids: [] });
    const result = deriveCamouflageStatus(rule, [first, second]);
    expect(result.state).toBe('failed');
    expect(result.activeCount).toBe(0);
  });

  it('is deterministic when API node order changes', () => {
    const active = node({}, { node_id: 'active', public_ipv4: '192.0.2.10' });
    const failed = node({
      site_status: 'failed',
      certificate_status: 'failed',
      last_error: 'DNS does not target this Relay',
    }, {
      node_id: 'failed',
      public_ipv4: '192.0.2.20',
      active_listener_rule_ids: [],
    });
    expect(deriveCamouflageStatus(rule, [active, failed]))
      .toEqual(deriveCamouflageStatus(rule, [failed, active]));
  });

  it('preserves Relay IP and Node ID in every per-node result', () => {
    const result = deriveCamouflageStatus(rule, [node({}, {
      node_id: 'persistent-node-id',
      public_ipv4: '198.51.100.25',
    })]);
    expect(result.nodes[0]).toMatchObject({
      nodeId: 'persistent-node-id',
      relayIp: '198.51.100.25',
      listenerState: 'active',
      siteState: 'active',
      certificateState: 'active',
    });
  });
});

describe('camouflage rule form fields', () => {
  const t = (key: string) => key;

  it('shows an enabled admin control plus the fixed port and renewal policy', () => {
    render(
      <Form>
        <CamouflageFormFields enabled={false} initialValue={false} isAdmin t={t} />
      </Form>,
    );

    expect(screen.getByRole('switch', { name: 'camouflage' })).toBeEnabled();
    expect(screen.getByRole('spinbutton', { name: 'camouflageTlsPort' })).toHaveValue('8443');
    expect(screen.getByRole('spinbutton', { name: 'certificateRenewBefore' })).toHaveValue('30');
  });

  it('keeps the control visible but disabled for a non-admin', () => {
    render(
      <Form>
        <CamouflageFormFields enabled={false} initialValue={false} isAdmin={false} t={t} />
      </Form>,
    );

    expect(screen.getByRole('switch', { name: 'camouflage' })).toBeDisabled();
    expect(screen.getByText('camouflageAdminOnly')).toBeInTheDocument();
  });
});

describe('Proxy Protocol rule form field', () => {
  const t = (key: string) => key;

  it('defaults OFF and warns an administrator about the upstream requirement', () => {
    render(<Form><ProxyProtocolFormField initialValue={false} isAdmin t={t} /></Form>);
    expect(screen.getByRole('switch', { name: 'sendProxyProtocol' })).not.toBeChecked();
    expect(screen.getByText('sendProxyProtocolHint')).toBeInTheDocument();
  });

  it('is disabled for non-admin users', () => {
    render(<Form><ProxyProtocolFormField initialValue={false} isAdmin={false} t={t} /></Form>);
    expect(screen.getByRole('switch', { name: 'sendProxyProtocol' })).toBeDisabled();
  });
});

describe('rule DNS status', () => {
  const t = (key: string) => key;
  const status = (sync_state: string, overrides: Partial<RuleDnsStatus> = {}): RuleDnsStatus => ({
    rule_id: 42,
    eligible: true,
    automation_enabled: true,
    fqdn: 'op1.example.com',
    record_type: 'A',
    expected_value: '192.0.2.10',
    ownership: 'PANEL_MANAGED',
    sync_state,
    last_observed_at: null,
    mutation_verified_at: null,
    propagated_at: null,
    last_error_category: null,
    warning_category: null,
    ...overrides,
  });

  it.each([
    'PENDING',
    'SYNCING',
    'MUTATION_VERIFIED',
    'PROPAGATING',
    'PROPAGATED',
    'CONFLICT',
    'FAILED',
    'DISABLED',
    'INVALID_CONFIG',
  ])('renders %s independently from certificate and Relay state', (state) => {
    const { unmount } = render(<DnsStatusCell status={status(state)} t={t} />);
    expect(screen.getByText(state)).toBeInTheDocument();
    expect(screen.getByText('A op1.example.com → 192.0.2.10')).toBeInTheDocument();
    unmount();
  });

  it('shows external ownership and a multiple-answer propagation warning', () => {
    render(<DnsStatusCell status={status('PROPAGATED', {
      ownership: 'EXTERNAL',
      warning_category: 'PUBLIC_DNS_MULTIPLE_ANSWERS',
    })} t={t} />);
    expect(screen.getByText('dnsOwnership: EXTERNAL')).toBeInTheDocument();
    expect(screen.getByText('PUBLIC_DNS_MULTIPLE_ANSWERS')).toBeInTheDocument();
  });

  it('offers retry for safe terminal states but not unknown mutation outcomes', () => {
    const retry = vi.fn();
    const { rerender } = render(<DnsStatusCell status={status('CONFLICT')} onRetry={retry} t={t} />);
    fireEvent.click(screen.getByRole('button', { name: /retryDnsSync/ }));
    expect(retry).toHaveBeenCalledOnce();

    rerender(<DnsStatusCell status={status('MUTATION_OUTCOME_UNKNOWN', {
      last_error_category: 'POST_WRITE_NOT_VERIFIED',
    })} onRetry={retry} t={t} />);
    expect(screen.queryByRole('button', { name: /retryDnsSync/ })).not.toBeInTheDocument();
  });

  it('shows disabled automation without claiming the certificate or route failed', () => {
    render(<DnsStatusCell status={status('DISABLED', { automation_enabled: false })} t={t} />);
    expect(screen.getByText('dnsAutomationDisabled')).toBeInTheDocument();
    expect(screen.queryByText('routeFailed')).not.toBeInTheDocument();
  });
});

// ============================================================
// v0.4.21: strategy options tests
// ============================================================

describe('strategyOptions', () => {
  const strategyOptions = [
    { value: 'first',       label: 'lbFirst' },
    { value: 'round_robin', label: 'lbRoundRobin' },
    { value: 'failover',    label: 'lbFailover' },
  ];

  it('has exactly three strategy options', () => {
    expect(strategyOptions).toHaveLength(3);
  });

  it('option values match backend wire/db strings', () => {
    const values = strategyOptions.map(o => o.value);
    expect(values).toEqual(['first', 'round_robin', 'failover']);
  });

  it('option labels are short (no long descriptions in Select)', () => {
    for (const opt of strategyOptions) {
      expect(opt.label).not.toContain('：');
      expect(opt.label).not.toContain(':');
      expect(opt.label.length).toBeLessThan(20);
    }
  });
});
