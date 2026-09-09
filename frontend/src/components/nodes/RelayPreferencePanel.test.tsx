import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { message, Modal } from 'antd';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  ApiEnvelope,
  CarrierAffinityView,
  RelayPreferenceView,
  RelayReadyNode,
  RoutingApplyRequest,
  RoutingApplyResult,
} from '../../api/types';
import type { Tfn } from './types';

const { mockGet, mockPut } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
}));

vi.mock('../../api/client', () => ({ default: { get: mockGet, put: mockPut } }));
vi.mock('./CarrierAffinityPanel', async () => {
  const React = await import('react');
  return {
    CarrierAffinityPanel: ({ onApply, onDirtyChange, onViewChange }: {
      onApply: (request: RoutingApplyRequest) => Promise<RoutingApplyResult | null>;
      onDirtyChange: (dirty: boolean) => void;
      onViewChange: (view: CarrierAffinityView) => void;
    }) => {
      React.useEffect(() => {
        onViewChange({
          group_id: 10,
          default_node_id: 'node-a',
          active_policy: { default_node_id: 'node-a', bindings: [] },
          pending_policy: null,
          transaction: { kind: null, state: 'idle', started_at: null, last_error: null, rollback_error: null },
          bindings: [],
          catalog_stale: false,
        });
      }, [onViewChange]);
      return <>
        <button onClick={() => onDirtyChange(true)}>carrier-dirty</button>
        <button onClick={() => void onApply({ mode: 'carrier', default_node_id: 'node-a', bindings: [] })}>carrier-apply</button>
      </>;
    },
  };
});
vi.mock('./RelaySchedulePanel', () => ({
  RelaySchedulePanel: ({ onActivate }: { onActivate: () => Promise<RoutingApplyResult | null> }) => (
    <button onClick={() => void onActivate()}>schedule-activate</button>
  ),
}));
vi.mock('./RelayFailoverPanel', () => ({
  RelayFailoverPanel: ({ onApply, onDirtyChange }: {
    onApply: (request: RoutingApplyRequest) => Promise<RoutingApplyResult | null>;
    onDirtyChange: (dirty: boolean) => void;
  }) => <>
    <button onClick={() => onDirtyChange(true)}>failover-dirty</button>
    <button onClick={() => void onApply({ mode: 'failover', health_check_port: 443, failure_after_seconds: 5 })}>failover-apply</button>
  </>,
}));

import { RelayPreferencePanel } from './RelayPreferencePanel';

const t = ((key: string) => key) as Tfn;
const ok = <T,>(data: T): ApiEnvelope<T> => ({ code: 0, message: 'ok', data });

function relayNode(nodeId: string, over: Partial<RelayReadyNode> = {}): RelayReadyNode {
  return {
    node_id: nodeId,
    public_ipv4: `203.0.113.${nodeId.charCodeAt(nodeId.length - 1)}`,
    online: true,
    ready: true,
    ready_reasons: [],
    preferred: false,
    ...over,
  };
}

function preference(over: Partial<RelayPreferenceView> = {}): RelayPreferenceView {
  return {
    group_id: 10,
    active_routing_mode: 'normal',
    pending_routing_mode: null,
    routing_mode_conflict: [],
    normal_default_node_id: 'node-a',
    preferred_node_id: 'node-a',
    preferred_node_public_ipv4: '203.0.113.97',
    pending_node_id: null,
    state: 'idle',
    started_at: null,
    last_error: null,
    rollback_error: null,
    dns_records: [],
    nodes: [relayNode('node-a', { preferred: true }), relayNode('node-b'), relayNode('node-c')],
    ...over,
  };
}

function applied(over: Partial<RoutingApplyResult> = {}): RoutingApplyResult {
  return {
    config_saved: true,
    activation_requested: false,
    activation_succeeded: true,
    active_mode: 'normal',
    target_mode: 'normal',
    transition_state: 'idle',
    business_error_code: null,
    message: 'ok',
    ...over,
  };
}

async function renderPanel(view = preference()) {
  mockGet.mockResolvedValue(ok(view));
  render(<RelayPreferencePanel groupId={10} t={t} />);
  await screen.findByTestId('routing-mode-control');
}

async function confirmModeChange() {
  const dialog = await screen.findByRole('dialog', { name: 'routingModeConfirmTitle' });
  fireEvent.click(within(dialog).getByRole('button', { name: 'routingModeConfirm' }));
}

beforeEach(() => {
  mockGet.mockReset();
  mockPut.mockReset();
  mockPut.mockResolvedValue(ok(applied()));
});

afterEach(() => Modal.destroyAll());

describe('RelayPreferencePanel routing function UX', () => {
  it.each([
    ['normal', 'routingFunctionNormal'],
    ['carrier', 'routingFunctionCarrier'],
    ['schedule', 'routingFunctionSchedule'],
    ['failover', 'routingFunctionFailover'],
  ] as const)('uses %s as view-only navigation with zero routing mutation', async (_mode, label) => {
    await renderPanel();
    fireEvent.click(screen.getByRole('tab', { name: label }));
    expect(mockPut).not.toHaveBeenCalled();
  });

  it('initially opens the active mode and keeps selected Tab separate from active truth', async () => {
    await renderPanel(preference({ active_routing_mode: 'carrier' }));
    expect(screen.getByRole('tab', { name: 'routingFunctionCarrier' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('routing-mode-control')).toHaveTextContent('routingMode_carrier');
    fireEvent.click(screen.getByRole('tab', { name: 'routingFunctionSchedule' }));
    expect(screen.getByRole('tab', { name: 'routingFunctionSchedule' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByTestId('routing-mode-control')).toHaveTextContent('routingMode_carrier');
    expect(mockPut).not.toHaveBeenCalled();
  });

  it('changes NORMAL selection locally and saves active NORMAL without mode confirmation', async () => {
    await renderPanel();
    fireEvent.click(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: 'routingSetNormalDefault' }));
    expect(screen.getByTestId('default-line-candidate-node-b')).toHaveTextContent('routingNormalSelected');
    expect(mockPut).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId('normal-routing-apply'));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/groups/10/routing-apply', {
      mode: 'normal', default_node_id: 'node-b',
    }));
    expect(screen.queryByRole('dialog', { name: 'routingModeConfirmTitle' })).toBeNull();
  });

  it('confirms once before activating inactive NORMAL', async () => {
    await renderPanel(preference({ active_routing_mode: 'carrier' }));
    fireEvent.click(screen.getByRole('tab', { name: 'routingFunctionNormal' }));
    fireEvent.click(within(await screen.findByTestId('default-line-candidate-node-b')).getByRole('button', { name: 'routingSetNormalDefault' }));
    fireEvent.click(screen.getByTestId('normal-routing-apply'));
    expect(mockPut).not.toHaveBeenCalled();
    await confirmModeChange();
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/groups/10/routing-apply', {
      mode: 'normal', default_node_id: 'node-b',
    }));
  });

  it.each([
    ['routingFunctionCarrier', 'carrier-apply', { mode: 'carrier', default_node_id: 'node-a', bindings: [] }],
    ['routingFunctionSchedule', 'schedule-activate', { mode: 'schedule' }],
    ['routingFunctionFailover', 'failover-apply', { mode: 'failover', health_check_port: 443, failure_after_seconds: 5 }],
  ] as const)('activates inactive function %s only after confirmation', async (tab, action, payload) => {
    await renderPanel();
    fireEvent.click(screen.getByRole('tab', { name: tab }));
    fireEvent.click(screen.getByRole('button', { name: action }));
    expect(mockPut).not.toHaveBeenCalled();
    await confirmModeChange();
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/groups/10/routing-apply', payload));
  });

  it('saves an active function without mode confirmation', async () => {
    await renderPanel(preference({ active_routing_mode: 'carrier' }));
    fireEvent.click(screen.getByRole('button', { name: 'carrier-apply' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/groups/10/routing-apply', {
      mode: 'carrier', default_node_id: 'node-a', bindings: [],
    }));
    expect(screen.queryByRole('dialog', { name: 'routingModeConfirmTitle' })).toBeNull();
  });

  it.each([
    ['normal', 'routingFunctionNormal', 'routingSetNormalDefault'],
    ['carrier', 'routingFunctionCarrier', 'carrier-dirty'],
    ['failover', 'routingFunctionFailover', 'failover-dirty'],
  ] as const)('warns before leaving dirty %s draft', async (mode, tab, dirtyAction) => {
    await renderPanel(preference({ active_routing_mode: mode }));
    if (mode === 'normal') {
      fireEvent.click(within(screen.getByTestId('default-line-candidate-node-b')).getByRole('button', { name: dirtyAction }));
    } else {
      fireEvent.click(screen.getByRole('button', { name: dirtyAction }));
    }
    fireEvent.click(screen.getByRole('tab', { name: mode === 'carrier' ? 'routingFunctionSchedule' : 'routingFunctionCarrier' }));
    expect(await screen.findByRole('dialog', { name: 'routingUnsavedTitle' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: tab })).toHaveAttribute('aria-selected', 'true');
  });

  it('shows partial success with the mapped reason and keeps backend active truth', async () => {
    const warning = vi.spyOn(message, 'warning');
    const view = preference({ active_routing_mode: 'schedule' });
    mockGet.mockResolvedValue(ok(view));
    mockPut.mockRejectedValue({ response: { data: ok(applied({
      config_saved: true,
      activation_requested: true,
      activation_succeeded: false,
      active_mode: 'schedule',
      target_mode: 'carrier',
      business_error_code: 'DNS_PROVIDER_PREFLIGHT_FAILED',
    })) } });
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByTestId('routing-mode-control');
    fireEvent.click(screen.getByRole('tab', { name: 'routingFunctionCarrier' }));
    fireEvent.click(screen.getByRole('button', { name: 'carrier-apply' }));
    await confirmModeChange();
    await waitFor(() => expect(warning).toHaveBeenCalledWith(expect.stringContaining('routingPartialFailure')));
    expect(warning).toHaveBeenCalledWith(expect.stringContaining('routingErrorProviderPreflight'));
    expect(screen.getByTestId('routing-mode-control')).toHaveTextContent('routingMode_schedule');
  });

  it('maps missing Schedule configuration without mislabeling it as DNSMgr failure', async () => {
    const error = vi.spyOn(message, 'error');
    mockGet.mockResolvedValue(ok(preference()));
    mockPut.mockRejectedValue({ response: { data: ok(applied({
      config_saved: false,
      activation_requested: true,
      activation_succeeded: false,
      active_mode: 'normal',
      target_mode: 'schedule',
      business_error_code: 'SCHEDULE_ENABLED_RULE_REQUIRED',
    })) } });
    render(<RelayPreferencePanel groupId={10} t={t} />);
    await screen.findByTestId('routing-mode-control');
    fireEvent.click(screen.getByRole('tab', { name: 'routingFunctionSchedule' }));
    fireEvent.click(screen.getByRole('button', { name: 'schedule-activate' }));
    await confirmModeChange();
    await waitFor(() => expect(error).toHaveBeenCalledWith('routingErrorScheduleRequired'));
    expect(error).not.toHaveBeenCalledWith('routingErrorDnsMgrUnavailable');
  });

  it('renders active, pending and rollback state only from backend truth', async () => {
    await renderPanel(preference({
      active_routing_mode: 'carrier',
      pending_routing_mode: 'schedule',
      pending_node_id: 'node-b',
      state: 'rolling_back',
      last_error: 'DNS_PROVIDER_FAILED',
      dns_records: [{
        rule_id: 1,
        fqdn: 'op1.example.com',
        line_id: 'Dianxin',
        line_key: 'dnsmgr:Dianxin',
        rollback_value: '203.0.113.5',
        target_value: '203.0.113.6',
        expected_value: '203.0.113.5',
        sync_state: 'PROPAGATED',
        position: 'rollback',
        last_error: null,
      }],
    }));
    const status = screen.getByTestId('routing-mode-control');
    expect(status).toHaveTextContent('routingMode_carrier');
    expect(status).toHaveTextContent('routingModeRollingBack: routingMode_schedule');
    expect(screen.getByTestId('relay-dns-record-1-dnsmgr-Dianxin')).toHaveTextContent('relayPreferenceDnsAtPrevious');
  });

  it('fails closed on legacy authority conflict without exposing a mode mutation control', async () => {
    await renderPanel(preference({
      active_routing_mode: null,
      routing_mode_conflict: ['carrier', 'schedule'],
    }));
    expect(screen.getByText('routingModeConflict')).toBeInTheDocument();
    expect(screen.queryByLabelText('routingModeCurrent')).toBeNull();
    expect(screen.getByTestId('normal-routing-apply')).toBeDisabled();
  });
});
