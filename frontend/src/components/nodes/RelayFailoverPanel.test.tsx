import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiEnvelope, RelayFailoverView, RoutingApplyResult } from '../../api/types';
import { zhCN } from '../../i18n/zh-CN';
import type { Tfn } from './types';

const { mockGet, mockPost, mockApply } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockApply: vi.fn(),
}));

vi.mock('../../api/client', () => ({
  default: { get: mockGet, post: mockPost },
}));

import { RelayFailoverPanel } from './RelayFailoverPanel';

const t = ((key: keyof typeof zhCN) => zhCN[key]) as Tfn;
const ok = <T,>(data: T): ApiEnvelope<T> => ({ code: 0, message: 'ok', data });

function failover(over: Partial<RelayFailoverView> = {}): RelayFailoverView {
  return {
    model_version: 1,
    enabled: false,
    health_check_port: 443,
    failure_after_seconds: 5,
    excluded_failed_node_ids: ['node-c'],
    last_switch_at: null,
    last_from_node_id: null,
    last_to_node_id: null,
    last_result: null,
    last_error: null,
    group_id: 10,
    current_node_id: 'node-a',
    nodes: [
      {
        node_id: 'node-a',
        public_ipv4: '64.118.154.53',
        ready: true,
        ready_reasons: [],
        current: true,
        excluded: false,
        probe_status: 'healthy',
        last_probed_at: '2026-09-06T00:00:00Z',
      },
      {
        node_id: 'node-b',
        public_ipv4: '64.118.144.159',
        ready: false,
        ready_reasons: ['STALE_STATUS'],
        current: false,
        excluded: false,
        probe_status: 'unhealthy',
        last_probed_at: '2026-09-06T00:00:00Z',
      },
      {
        node_id: 'node-c',
        public_ipv4: '64.118.135.54',
        ready: true,
        ready_reasons: [],
        current: false,
        excluded: true,
        probe_status: 'healthy',
        last_probed_at: '2026-09-06T00:00:00Z',
      },
    ],
    ...over,
  };
}

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockApply.mockReset();
  mockGet.mockResolvedValue(ok(failover()));
  mockPost.mockResolvedValue(ok(failover({ excluded_failed_node_ids: [] })));
  mockApply.mockResolvedValue({
    config_saved: true,
    activation_requested: true,
    activation_succeeded: true,
    active_mode: 'failover',
    target_mode: 'failover',
    transition_state: 'idle',
    business_error_code: null,
    message: 'ok',
  } satisfies RoutingApplyResult);
});

async function renderPanel(active = false) {
  render(<RelayFailoverPanel groupId={10} t={t} active={active} onApply={mockApply} />);
  await screen.findByTestId('relay-failover-10');
}

describe('RelayFailoverPanel', () => {
  it('renders current, standby readiness, TCP probe, and sticky exclusion states', async () => {
    await renderPanel();
    const current = screen.getByTestId('relay-failover-node-node-a');
    expect(current).toHaveTextContent('当前使用');
    expect(current).toHaveTextContent('探测正常');
    const unready = screen.getByTestId('relay-failover-node-node-b');
    expect(unready).toHaveTextContent('未就绪');
    expect(unready).toHaveTextContent('探测异常');
    expect(unready).toHaveTextContent('节点状态已过期');
    const excluded = screen.getByTestId('relay-failover-node-node-c');
    expect(excluded).toHaveTextContent('已淘汰');
    expect(within(excluded).getByRole('button', { name: /重新纳入备选/ })).toBeEnabled();
  });

  it('shows read-only inactive status and no independent authority switch', async () => {
    await renderPanel();
    expect(screen.getByText('未启用')).toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: '自动故障切换' })).toBeNull();
    expect(screen.getByText(/同组已就绪且检查正常的可用节点/)).toBeInTheDocument();
    expect(screen.queryByText(/随机选择/)).toBeNull();
  });

  it('saves and activates failover with the current validated settings', async () => {
    await renderPanel();
    fireEvent.click(screen.getByRole('button', { name: /保存并启用/ }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledWith({
      mode: 'failover', health_check_port: 443, failure_after_seconds: 5,
    }));
  });

  it('saves a custom TCP port and continuous failure threshold', async () => {
    await renderPanel();
    fireEvent.change(screen.getByLabelText('健康检查端口'), { target: { value: '8443' } });
    fireEvent.change(screen.getByLabelText('故障判定时间'), { target: { value: '13' } });
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledWith({
      mode: 'failover', health_check_port: 8443, failure_after_seconds: 13,
    }));
  });

  it('reincludes only through the dedicated health-checked endpoint', async () => {
    await renderPanel();
    fireEvent.click(within(screen.getByTestId('relay-failover-node-node-c')).getByRole('button', { name: /重新纳入备选/ }));
    await waitFor(() => expect(mockPost).toHaveBeenCalledWith(
      '/groups/10/relay-failover/reinclude',
      { node_id: 'node-c' },
    ));
  });

  it('shows the backend reason when a node is still unhealthy', async () => {
    mockPost.mockRejectedValue({
      response: { data: { message: '当前节点仍未通过健康检查，无法重新纳入备选。' } },
    });
    await renderPanel();
    fireEvent.click(within(screen.getByTestId('relay-failover-node-node-c')).getByRole('button', { name: /重新纳入备选/ }));
    expect(await screen.findByText(/当前节点仍未通过健康检查/)).toBeInTheDocument();
  });

  it('uses Save changes without an independent mode switch while active', async () => {
    await renderPanel(true);
    expect(screen.getByText('当前生效')).toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: '自动故障切换' })).toBeNull();
    fireEvent.change(screen.getByLabelText('健康检查端口'), { target: { value: '8443' } });
    fireEvent.click(screen.getByRole('button', { name: /保存修改/ }));
    await waitFor(() => expect(mockApply).toHaveBeenCalledWith({
      mode: 'failover', health_check_port: 8443, failure_after_seconds: 5,
    }));
  });

  it('does not present a started Relay transaction as failover success', async () => {
    mockGet.mockResolvedValue(ok(failover({
      last_from_node_id: 'node-a',
      last_to_node_id: 'node-b',
      last_result: 'started',
    })));
    await renderPanel();
    expect(screen.getByText('切换处理中')).toBeInTheDocument();
    expect(screen.queryByText('切换成功')).toBeNull();
  });

  it('shows success only after the backend reports a committed preference', async () => {
    mockGet.mockResolvedValue(ok(failover({
      current_node_id: 'node-b',
      last_from_node_id: 'node-a',
      last_to_node_id: 'node-b',
      last_result: 'success',
      last_switch_at: '2026-09-06T01:00:00Z',
    })));
    await renderPanel();
    expect(screen.getByText('切换成功')).toBeInTheDocument();
  });

  it('renders exhausted as an explicit no-candidate failure', async () => {
    mockGet.mockResolvedValue(ok(failover({
      last_result: 'exhausted',
      last_error: 'NO_AVAILABLE_CANDIDATES',
    })));
    await renderPanel();
    expect(screen.getAllByText('故障切换失败').length).toBeGreaterThan(0);
    expect(screen.getAllByText('无可用备选节点').length).toBeGreaterThan(0);
  });
});
