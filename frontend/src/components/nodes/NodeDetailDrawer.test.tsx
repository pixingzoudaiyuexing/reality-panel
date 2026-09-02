import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { NodeDisplayRow, ReconciliationState } from '../../api/types';

// NodeDetailDrawer calls api.delete on the admin "delete status" action, so the
// client must be mocked before importing the component.
vi.mock('../../api/client', () => ({
  default: { delete: vi.fn().mockResolvedValue({ code: 0 }) },
}));

import { NodeDetailDrawer } from './NodeDetailDrawer';

const baseRow: NodeDisplayRow = {
  group_id: 1,
  group_name: 'g1',
  node_id: 'node-abc',
  online: true,
  cpu: 10,
  mem: 20,
  network_interface: 'eth0',
  config_protocol_version: 2,
};

describe('NodeDetailDrawer desensitization', () => {
  it('shows admin-only sensitive fields when isAdmin is true', () => {
    render(<NodeDetailDrawer row={baseRow} open onClose={vi.fn()} isAdmin={true} panelProtocol={2} />);
    // node_id value + admin-only labels are present
    expect(screen.getByText('node-abc')).toBeInTheDocument();
    expect(screen.getByText('configProtocolVersion')).toBeInTheDocument();
    expect(screen.getByText('networkInterface')).toBeInTheDocument();
    // 在线状态来自实时数据，不能通过清除筛选条件隐藏。
    expect(screen.queryByText('nodeStatusDelete')).not.toBeInTheDocument();
  });

  it('offers clear status only for an offline node', () => {
    render(<NodeDetailDrawer row={{ ...baseRow, online: false }} open onClose={vi.fn()} isAdmin panelProtocol={2} />);
    expect(screen.getByText('nodeStatusDelete')).toBeInTheDocument();
  });

  it('hides node_id and all admin-only fields when isAdmin is false', () => {
    const row = {
      ...baseRow,
      reconciliation: {
        state: 'APPLY_FAILED' as const,
        recovery_source: 'PANEL' as const,
        last_error: 'runtime reconciliation failed',
      },
    };
    render(<NodeDetailDrawer row={row} open onClose={vi.fn()} isAdmin={false} panelProtocol={2} />);
    // the raw node_id must never reach a regular user's DOM
    expect(screen.queryByText('node-abc')).not.toBeInTheDocument();
    expect(screen.queryByText('configProtocolVersion')).not.toBeInTheDocument();
    expect(screen.queryByText('networkInterface')).not.toBeInTheDocument();
    expect(screen.queryByText('nodeStatusDelete')).not.toBeInTheDocument();
    expect(screen.queryByText('reconciliationState_APPLY_FAILED')).not.toBeInTheDocument();
    expect(screen.queryByText('runtime reconciliation failed')).not.toBeInTheDocument();
    // safe metrics are still rendered (sanity: the drawer did open)
    expect(screen.getByText('nodeVersion')).toBeInTheDocument();
  });

  it.each<ReconciliationState>([
    'CONVERGED',
    'RECONCILING',
    'REPAIRING',
    'DEGRADED_LOCAL_RECOVERY',
    'APPLY_FAILED',
    'DEPENDENCY_WITHHELD',
    'WAITING_FOR_AUTHORITY',
  ])('renders reconciliation state %s distinctly for administrators', (state) => {
    const row: NodeDisplayRow = {
      ...baseRow,
      reconciliation: {
        state,
        desired_fingerprint: 'a'.repeat(64),
        applied_fingerprint: 'b'.repeat(64),
        observed_fingerprint: 'c'.repeat(64),
        last_success_at: '2026-08-26T00:00:00Z',
        last_error: state === 'APPLY_FAILED' ? 'runtime reconciliation failed' : null,
        recovery_source: state === 'DEGRADED_LOCAL_RECOVERY' ? 'LKG_PRIMARY' : 'PANEL',
      },
    };
    render(<NodeDetailDrawer row={row} open onClose={vi.fn()} isAdmin panelProtocol={2} />);

    expect(screen.getByText(`reconciliationState_${state}`)).toBeInTheDocument();
    expect(screen.getByText('aaaaaaaaaaaa...')).toHaveAttribute('title', 'a'.repeat(64));
    expect(screen.getByText('bbbbbbbbbbbb...')).toHaveAttribute('title', 'b'.repeat(64));
    expect(screen.getByText('cccccccccccc...')).toHaveAttribute('title', 'c'.repeat(64));
    if (state === 'APPLY_FAILED') {
      expect(screen.getByText('runtime reconciliation failed')).toBeInTheDocument();
    }
  });
});
