import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CarrierAffinityView, CarrierLineCatalog, RelayReadyNode } from '../../api/types';
import type { Tfn } from './types';

const { mockGet, mockPut } = vi.hoisted(() => ({ mockGet: vi.fn(), mockPut: vi.fn() }));
vi.mock('../../api/client', () => ({ default: { get: mockGet, put: mockPut } }));

import { CarrierAffinityPanel } from './CarrierAffinityPanel';
import { assignCarrierLines, buildCarrierLineOptions, carrierLineMatchesSearch } from './carrierCatalog';

const t = ((key: string) => key === 'carrierAllNetworkDefault' ? '全网默认' : key) as Tfn;
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
    { id: 'Dianxin_Shanghai', name: '电信_上海', parent: 'Dianxin' },
    { id: 'Liantong_Shanghai', name: '联通_上海', parent: 'Liantong' },
    { id: 'Yidong_Shanghai', name: '移动_上海', parent: null },
    { id: 'Yidong_Sichuan', name: '移动_四川', parent: null },
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
    expect(assignCarrierLines(view.active_policy.bindings, 'node-a', ['default', 'Dianxin'], view.default_node_id)).toEqual([
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-a' },
      { line_id: 'default', mode: 'node', node_id: 'node-a' },
    ]);
  });

  it('removes a deselected legacy FollowDefault line from the default Relay', () => {
    expect(assignCarrierLines([
      { line_id: 'default', mode: 'follow_default', node_id: null },
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
    ], 'node-a', [], 'node-a')).toEqual([
      { line_id: 'Dianxin', mode: 'node', node_id: 'node-b' },
    ]);
  });

  it('exposes default as an ordinary assignable line', async () => {
    arrange();
    expect(await screen.findByTestId('carrier-node-node-a')).toHaveTextContent('全网默认');
  });

  it('keeps the all-network default first and supports keyword AND search', async () => {
    const names = new Map([
      ['Yidong', '移动'],
      ['default', '全网默认'],
      ['Dianxin', '电信'],
      ['Liantong', '联通'],
      ['Dianxin_Shanghai', '电信_上海'],
      ['Liantong_Shanghai', '联通_上海'],
      ['Yidong_Shanghai', '移动_上海'],
      ['Yidong_Sichuan', '移动_四川'],
    ]);
    const options = buildCarrierLineOptions(names.keys(), names);
    expect(options[0]).toEqual({ value: 'default', label: '全网默认' });

    const labels = (query: string) => options
      .filter((option) => carrierLineMatchesSearch(query, option))
      .map((option) => option.label);
    expect(labels('电信')).toEqual(['电信', '电信_上海']);
    expect(labels('上海')).toHaveLength(3);
    expect(labels('上海')).toEqual(expect.arrayContaining(['电信_上海', '联通_上海', '移动_上海']));
    expect(labels('移动   四川')).toEqual(['移动_四川']);
    expect(labels('默认')).toEqual(['全网默认']);
    expect(labels('全网')).toEqual(['全网默认']);
    expect(labels('上海')).not.toContain('全网默认');
    expect(labels('DIANXIN')).toEqual(['电信', '电信_上海']);

    arrange();
    const input = await screen.findByLabelText('node-a carrierLine');
    fireEvent.mouseDown(input);
    fireEvent.change(input, { target: { value: '移动 四川' } });
    expect(await screen.findByText('移动_四川')).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: '全网默认' })).not.toBeInTheDocument();
  });

  it('locks edits while the existing DNS transaction is active', async () => {
    arrange({ transaction: { kind: 'carrier_policy_apply', state: 'switching', started_at: 'now', last_error: null, rollback_error: null } });
    expect(await screen.findByText('carrierBusy')).toBeInTheDocument();
    expect(screen.getByLabelText('node-a carrierLine')).toBeDisabled();
  });
});
