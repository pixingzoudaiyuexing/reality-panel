import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CarrierAffinityView, CarrierLineCatalog, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';

const { mockGet, mockPut } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPut: vi.fn() }));
vi.mock('../../api/client', () => ({ default: { get: mockGet, put: mockPut } }));

import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { assignCarrierLines } from './carrierCatalog';

const t = ((key: string) => key) as Tfn;
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const nodes: RelayReadyNode[] = [
  { node_id: 'node-a', public_ipv4: '203.0.113.5', online: true, ready: true, ready_reasons: [], preferred: true },
  { node_id: 'node-b', public_ipv4: '203.0.113.6', online: false, ready: false, ready_reasons: ['CONTROL_CHANNEL_OFFLINE'], preferred: false },
];
const catalog: CarrierLineCatalog = {
  stale: false,
  lines: [
    { id: 'default', name: '全网默认', parent: null },
    { id: 'Dianxin', name: '电信', parent: null },
    { id: 'Liantong', name: '联通', parent: null },
  ],
};
const view: CarrierAffinityView = {
  group_id: 7,
  default_node_id: 'node-a',
  active_policy: { bindings: [
    { line_id: 'default', mode: 'node', node_id: 'node-a' },
    { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
  ] },
  pending_policy: null,
  transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
  bindings: [],
  catalog_stale: false,
};

function arrange(over: Partial<CarrierAffinityView> = {}) {
  const response = { ...view, ...over };
  mockGet.mockImplementation((url: string) => Promise.resolve(ok(url.endsWith('/carrier-lines') ? catalog : response)));
  mockPut.mockResolvedValue(ok(response));
  render(<CarrierAffinityPanel groupId={7} nodes={nodes} t={t} />);
}

describe('CarrierAffinityPanel node-oriented editor', () => {
  beforeEach(() => vi.clearAllMocks());

  it('shows every Relay and keeps an offline Relay editable', async () => {
    arrange();
    expect(await screen.findByTestId('carrier-node-node-a')).toHaveTextContent('203.0.113.5');
    expect(screen.getByTestId('carrier-node-node-b')).toHaveTextContent('offline');
    expect(screen.getByLabelText('node-b carrierLine')).toBeEnabled();
  });

  it('moves one unique line between Relays', () => {
    expect(assignCarrierLines(view.active_policy.bindings, 'node-a', ['default', 'Dianxin'])).toEqual([
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-a' },
      { line_id: 'default', mode: 'node', node_id: 'node-a' },
    ]);
  });

  it('exposes default as an ordinary assignable line', async () => {
    arrange();
    expect(await screen.findByTestId('carrier-node-node-a')).toHaveTextContent('全网默认');
  });

  it('locks edits while the existing DNS transaction is active', async () => {
    arrange({ transaction: { kind: 'carrier_policy_apply', state: 'switching', started_at: 'now', last_error: null, rollback_error: null } });
    expect(await screen.findByText('carrierBusy')).toBeInTheDocument();
    expect(screen.getByLabelText('node-a carrierLine')).toBeDisabled();
  });
});
