import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import type { DeviceGroup, NodeReusePreview, NodeReuseRuntimeStatus } from '../../api/types';

const { mockGet, mockPost, mockDelete } = vi.hoisted(() => ({
  mockGet: vi.fn(), mockPost: vi.fn(), mockDelete: vi.fn(),
}));
vi.mock('../../api/client', () => ({
  default: { get: mockGet, post: mockPost, delete: mockDelete },
}));

import { NodeReusePanel } from './NodeReusePanel';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const groups = [
  { id: 10, name: 'Home', group_type: 'in' },
  { id: 20, name: 'Bound', group_type: 'in' },
  { id: 30, name: 'Candidate', group_type: 'in' },
  { id: 40, name: 'Outbound', group_type: 'out' },
  { id: 50, name: 'Alternative', group_type: 'in' },
] as DeviceGroup[];

const runtime = (overrides: Partial<NodeReuseRuntimeStatus> = {}): NodeReuseRuntimeStatus => ({
  ready: true,
  bindings: [{
    binding: { reusing_group_id: 20, home_group_id: 10, node_id: 'NODE_A', created_at: '2026-09-27' },
    current_active_credential: true, home_group_inbound: true,
    reusing_group_inbound: true, preview_eligible: true, blockers: [],
  }],
  sync_state: 'WAITING',
  expected_fingerprint: 'a'.repeat(64),
  expected_revision: 3,
  preview: {
    home_group_id: 10, node_id: 'NODE_A', source_group_ids: [10, 20],
    sources: [{ group_id: 20, is_home: false, rule_ids: [2], listener_count: 1, camouflage_site_count: 0 }],
    listeners: [], conflicts: [], known_runtime_prerequisites_satisfied: true,
  },
  blockers: [],
  ...overrides,
});

const candidatePreview = (conflict = false): NodeReusePreview => ({
  home_group_id: 10, node_id: 'NODE_A', source_group_ids: [10, 20, 30],
  sources: [
    { group_id: 10, is_home: true, rule_ids: [1], listener_count: 1, camouflage_site_count: 0 },
    { group_id: 20, is_home: false, rule_ids: [2], listener_count: 1, camouflage_site_count: 0 },
    { group_id: 30, is_home: false, rule_ids: [3], listener_count: 1, camouflage_site_count: 0 },
  ],
  listeners: [{ source_group_id: 30, rule_id: 3, port: 443, protocol: 'TCP' }],
  conflicts: conflict ? [{
    kind: 'TCP_PORT_COLLISION', source_group_id: 30, rule_id: 3,
    other_source_group_id: 10, other_rule_id: 1, message: 'internal conflict',
  }] : [],
  known_runtime_prerequisites_satisfied: !conflict,
});

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockDelete.mockReset();
  mockGet.mockImplementation((url: string) => Promise.resolve(ok(url === '/groups' ? groups : runtime())));
});

async function selectCandidate() {
  fireEvent.click(screen.getByText('nodeReuseAdd'));
  fireEvent.mouseDown(screen.getByRole('combobox'));
  const listbox = await screen.findByRole('listbox');
  expect(within(listbox).queryByRole('option', { name: 'Home' })).not.toBeInTheDocument();
  expect(within(listbox).queryByRole('option', { name: 'Bound' })).not.toBeInTheDocument();
  expect(within(listbox).queryByRole('option', { name: 'Outbound' })).not.toBeInTheDocument();
  expect(within(listbox).getByRole('option', { name: 'Candidate' })).toBeInTheDocument();
  fireEvent.click(screen.getByText('Candidate'));
}

describe('NodeReusePanel', () => {
  it('uses the server sync state, not generic reconciliation supplied by the drawer', async () => {
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    expect(await screen.findByText('nodeReuseState_WAITING')).toBeInTheDocument();
    expect(screen.queryByText('nodeReuseState_SYNCED')).not.toBeInTheDocument();
  });

  it('filters the picker, previews impact, then creates only after a passing check', async () => {
    mockPost.mockImplementation((url: string) => Promise.resolve(ok(
      url.endsWith('/preview') ? candidatePreview() : { outcome: 'CREATED' },
    )));
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    await screen.findByText('nodeReuseState_WAITING');
    await selectCandidate();
    fireEvent.click(screen.getByText('nodeReuseCheck'));
    expect(await screen.findByText('nodeReuseCheckPassed')).toBeInTheDocument();
    expect(screen.getByText('nodeReuseImpact')).toBeInTheDocument();
    fireEvent.click(screen.getByText('nodeReuseConfirm'));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/node-reuse/bindings', {
      reusing_group_id: 30, home_group_id: 10, node_id: 'NODE_A',
    }));
  });

  it('blocks conflicting preflight with human-readable impact and no create request', async () => {
    mockPost.mockResolvedValue(ok(candidatePreview(true)));
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    await screen.findByText('nodeReuseState_WAITING');
    await selectCandidate();
    fireEvent.click(screen.getByText('nodeReuseCheck'));
    expect(await screen.findByText('nodeReuseCheckBlocked')).toBeInTheDocument();
    expect(screen.getByText('nodeReusePortConflict')).toBeInTheDocument();
    expect(screen.getByText('nodeReuseNoChangeNext')).toBeInTheDocument();
    expect(screen.getByText('nodeReuseConfirm').closest('button')).toBeDisabled();
    expect(screen.queryByText('TCP_PORT_COLLISION')).not.toBeInTheDocument();
    expect(mockPost).toHaveBeenCalledTimes(1);
  });

  it('discards an old preflight response after the candidate selection changes', async () => {
    let resolvePreview!: (value: ReturnType<typeof ok<NodeReusePreview>>) => void;
    mockPost.mockImplementation(() => new Promise((resolve) => { resolvePreview = resolve; }));
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    await screen.findByText('nodeReuseState_WAITING');
    await selectCandidate();
    fireEvent.click(screen.getByText('nodeReuseCheck'));
    await waitFor(() => expect(mockPost).toHaveBeenCalledOnce());
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(screen.getByText('Alternative'));
    resolvePreview(ok(candidatePreview()));
    await waitFor(() => expect(screen.queryByText('nodeReuseCheckPassed')).not.toBeInTheDocument());
    expect(screen.queryByText('nodeReuseConfirm')).not.toBeInTheDocument();
    expect(mockPost).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['OFFLINE', 'nodeReuseOfflineImpact'],
    ['SYNCED', null],
    ['APPLY_FAILED', 'nodeReuseApplyFailureImpact'],
    ['CONFLICT', 'nodeReuseConflictImpact'],
    ['DEGRADED', 'nodeReuseDegradedImpact'],
  ] as const)('renders authoritative %s state and its impact', async (syncState, impact) => {
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(
      url === '/groups' ? groups : runtime({ sync_state: syncState }),
    )));
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    expect(await screen.findByText(`nodeReuseState_${syncState}`)).toBeInTheDocument();
    if (impact) expect(screen.getByText(impact)).toBeInTheDocument();
  });

  it('keeps a legacy-authenticated status row unready even when an active credential exists', async () => {
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(
      url === '/groups' ? groups : runtime({
        ready: false, sync_state: 'NOT_READY', blockers: ['NODE_NOT_VERIFIED_IN_LAST_REPORT'],
      }),
    )));
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    expect(await screen.findByText('nodeReuseState_NOT_READY')).toBeInTheDocument();
    fireEvent.click(screen.getByText('nodeReuseRequirements'));
    expect(screen.getByText('nodeReuseVerifiedRequired')).toBeInTheDocument();
    expect(screen.getByText('nodeReuseAdd').closest('button')).toBeDisabled();
  });

  it('removes the binding row while keeping node-level offline sync warning', async () => {
    let deleted = false;
    mockGet.mockImplementation((url: string) => Promise.resolve(ok(
      url === '/groups' ? groups : runtime({
        sync_state: 'OFFLINE', bindings: deleted ? [] : runtime().bindings,
      }),
    )));
    mockDelete.mockImplementation(() => { deleted = true; return Promise.resolve(ok({ outcome: 'DELETED' })); });
    render(<NodeReusePanel homeGroupId={10} nodeId="NODE_A" open />);
    await screen.findByText('nodeReuseState_OFFLINE');
    fireEvent.click(screen.getByText('nodeReuseRemove'));
    expect(await screen.findByText('nodeReuseRemovedOffline')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(mockDelete).toHaveBeenCalledOnce());
    await waitFor(() => expect(screen.getByText('nodeReuseNoBindings')).toBeInTheDocument());
    expect(screen.getByText('nodeReuseState_OFFLINE')).toBeInTheDocument();
  });
});
