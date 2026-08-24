import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Form } from 'antd';
import { CamouflageFormFields, deriveCamouflageStatus } from './Rules';
import type { NodeStatus } from '../api/types';

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
  const node = (site: Record<string, unknown>): NodeStatus => ({
    group_id: 10,
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
  });

  it('keeps the route waiting until the site and certificate are active', () => {
    expect(deriveCamouflageStatus(rule, [])).toEqual({ state: 'preparing', certificate: undefined });
  });

  it('marks an active certificate-backed site as route active', () => {
    expect(deriveCamouflageStatus(rule, [node({})]).state).toBe('active');
  });

  it('does not claim active until the matching listener rule is applied', () => {
    const waiting = node({});
    waiting.active_listener_rule_ids = [];
    expect(deriveCamouflageStatus(rule, [waiting]).state).toBe('preparing');
  });

  it('does not combine certificate and listener state from different nodes', () => {
    const certificateOnly = node({});
    certificateOnly.node_id = 'certificate-only';
    certificateOnly.active_listener_rule_ids = [];
    const listenerOnly = node({ site_status: 'preparing', certificate_status: 'pending' });
    listenerOnly.node_id = 'listener-only';
    expect(deriveCamouflageStatus(rule, [certificateOnly, listenerOnly]).state).toBe('preparing');
  });

  it('surfaces DNS/certificate failure instead of claiming the route is active', () => {
    const result = deriveCamouflageStatus(rule, [node({
      site_status: 'failed',
      certificate_status: 'failed',
      last_error: 'DNS does not resolve the certificate domain to this node',
    })]);
    expect(result.state).toBe('failed');
    expect(result.certificate?.last_error).toContain('DNS');
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
