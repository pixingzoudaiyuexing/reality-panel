import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { CarrierLineCatalog, CarrierPolicy, RelayReadyNode, RelaySchedule } from '../../api/types';
import { zhCN } from '../../i18n/zh-CN';
import type { Tfn } from './types';

const { mockGet, mockPost, mockPut, mockDelete } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockPut: vi.fn(),
  mockDelete: vi.fn(),
}));

vi.mock('../../api/client', () => ({
  default: { get: mockGet, post: mockPost, put: mockPut, delete: mockDelete },
}));

import { RelaySchedulePanel } from './RelaySchedulePanel';
import { formatUtcOffset, utcOffsetOptions } from './relayScheduleTime';

const t = ((key: keyof typeof zhCN) => zhCN[key]) as Tfn;
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });

function node(nodeId: string, ip: string, ready = true): RelayReadyNode {
  return {
    node_id: nodeId,
    public_ipv4: ip,
    online: ready,
    ready,
    ready_reasons: ready ? [] : ['STALE_STATUS'],
    preferred: nodeId === 'node-a',
  };
}

function schedule(over: Partial<RelaySchedule> = {}): RelaySchedule {
  return {
    id: 'schedule-1',
    group_id: 10,
    target_node_id: 'node-a',
    schedule_type: 'daily',
    enabled: true,
    created_at: '2026-08-30T00:00:00Z',
    updated_at: '2026-08-30T00:00:00Z',
    execute_at: null,
    time: '08:00',
    utc_offset_minutes: 480,
    weekdays: [],
    last_run_at: null,
    last_run_slot: null,
    last_result: null,
    last_error: null,
    ...over,
  };
}

const nodes = [node('node-a', '64.118.154.53'), node('node-b', '64.118.144.159', false)];

beforeEach(() => {
  mockGet.mockReset();
  mockPost.mockReset();
  mockPut.mockReset();
  mockDelete.mockReset();
  mockGet.mockResolvedValue(ok([]));
  mockPost.mockResolvedValue(ok(schedule()));
  mockPut.mockResolvedValue(ok(schedule()));
  mockDelete.mockResolvedValue(ok(null));
});

const carrierPolicy: CarrierPolicy = { bindings: [
  { line_id: 'Dianxin', mode: 'follow_default', node_id: null },
  { line_id: 'Liantong', mode: 'node', node_id: 'node-b' },
] };
const carrierCatalog: CarrierLineCatalog = { stale: false, lines: [
  { id: 'Dianxin', name: '电信', parent: null },
  { id: 'Liantong', name: '联通', parent: null },
] };

async function renderPanel(items: RelaySchedule[] = [], props: { topologyState?: 'failed_manual_intervention'; withPolicy?: boolean } = {}) {
  mockGet.mockResolvedValue(ok(items));
  render(<RelaySchedulePanel groupId={10} nodes={nodes} t={t} carrierPolicy={props.withPolicy ? carrierPolicy : undefined} carrierCatalog={props.withPolicy ? carrierCatalog : undefined} topologyState={props.topologyState} />);
  await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/admin/relay-schedules'));
}

async function choose(label: string, optionText: RegExp | string) {
  const input = screen.getByLabelText(label);
  await userEvent.click(input.parentElement ?? input);
  fireEvent.click(await screen.findByText(optionText));
}

async function chooseOffset(label: string) {
  const input = screen.getByLabelText('时区');
  await userEvent.click(input.parentElement ?? input);
  await userEvent.type(input, label);
  const matches = await screen.findAllByText(label);
  fireEvent.click(matches[matches.length - 1]);
}

async function openCreate() {
  fireEvent.click(screen.getByRole('button', { name: /新建定时切换/ }));
  await screen.findByRole('dialog');
}

describe('RelaySchedulePanel', () => {
  it('shows only this group schedules and formats one-time, daily, and weekly', async () => {
    await renderPanel([
      schedule({ id: 'once', schedule_type: 'one_time', execute_at: '2026-09-01T08:00:00Z', time: null, utc_offset_minutes: null }),
      schedule({ id: 'daily', time: '08:00', utc_offset_minutes: 480 }),
      schedule({ id: 'weekly', schedule_type: 'weekly', time: '20:00', utc_offset_minutes: -300, weekdays: [1, 3, 5] }),
      schedule({ id: 'other', group_id: 99 }),
    ]);

    expect(screen.getByTestId('relay-schedule-once')).toHaveTextContent('一次');
    expect(screen.getByTestId('relay-schedule-daily')).toHaveTextContent('每天 · 08:00 · UTC+08:00');
    expect(screen.getByTestId('relay-schedule-weekly')).toHaveTextContent('每周 · 周一、周三、周五 · 20:00 · UTC-05:00');
    expect(screen.queryByTestId('relay-schedule-other')).toBeNull();
  });

  it('shows target IP as primary while keeping node_id as identity', async () => {
    await renderPanel([schedule()]);
    const row = screen.getByTestId('relay-schedule-schedule-1');
    expect(within(row).getByText('64.118.154.53')).toBeInTheDocument();
    expect(within(row).getByText('node-a')).toBeInTheDocument();
  });

  it('creates a one-time schedule with RFC3339 execute_at and node_id', async () => {
    await renderPanel();
    await openCreate();
    await choose('目标线路', /64\.118\.144\.159 · node-b/);
    fireEvent.change(screen.getByLabelText('执行时间'), { target: { value: '2026-09-01T08:00' } });
    fireEvent.click(screen.getByRole('button', { name: '保 存' }));

    await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/admin/relay-schedules', expect.objectContaining({
      group_id: 10,
      target_node_id: 'node-b',
      schedule_type: 'one_time',
      execute_at: new Date('2026-09-01T08:00').toISOString(),
      enabled: true,
    })));
  });

  it('creates daily and weekly payloads with fixed offset fields', async () => {
    await renderPanel();
    await openCreate();
    await choose('目标线路', /64\.118\.154\.53 · node-a/);
    await choose('计划类型', '每天');
    fireEvent.change(await screen.findByLabelText('时间'), { target: { value: '08:30' } });
    await chooseOffset('UTC+08:00');
    fireEvent.click(screen.getByRole('button', { name: '保 存' }));
    await waitFor(() => expect(mockPost).toHaveBeenLastCalledWith('/admin/relay-schedules', expect.objectContaining({
      schedule_type: 'daily', time: '08:30', utc_offset_minutes: 480,
    })));

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    fireEvent.click(screen.getByRole('button', { name: /新建定时切换/ }));
    await choose('目标线路', /64\.118\.154\.53 · node-a/);
    await choose('计划类型', '每周');
    fireEvent.change(await screen.findByLabelText('时间'), { target: { value: '20:00' } });
    await chooseOffset('UTC-05:00');
    fireEvent.click(screen.getByLabelText('周一'));
    fireEvent.click(screen.getByLabelText('周五'));
    fireEvent.click(screen.getByRole('button', { name: '保 存' }));
    await waitFor(() => expect(mockPost).toHaveBeenLastCalledWith('/admin/relay-schedules', expect.objectContaining({
      schedule_type: 'weekly', time: '20:00', utc_offset_minutes: -300, weekdays: [1, 5],
    })));
  });

  it('maps whole-hour and quarter-hour UTC offsets to the existing minute model', () => {
    expect(formatUtcOffset(480)).toBe('UTC+08:00');
    expect(formatUtcOffset(330)).toBe('UTC+05:30');
    expect(formatUtcOffset(345)).toBe('UTC+05:45');
    expect(formatUtcOffset(570)).toBe('UTC+09:30');
    expect(utcOffsetOptions().find((option) => option.label === 'UTC+05:45')?.value).toBe(345);
  });

  it('shows policy impact from FollowDefault only and keeps unconfigured lines out', async () => {
    await renderPanel([schedule()], { withPolicy: true });
    const impact = screen.getByTestId('relay-schedule-impact-schedule-1');
    expect(impact).toHaveTextContent('按当前策略预计');
    expect(impact).toHaveTextContent('跟随默认线路: 电信');
    expect(impact).toHaveTextContent('指定线路保持不变: 联通');
    expect(impact).toHaveTextContent('未单独配置的线路不参与本次切换');
    expect(impact).not.toHaveTextContent('移动');
  });

  it('does not describe an unavailable Carrier policy as an empty policy', async () => {
    await renderPanel([schedule()]);
    const impact = screen.getByTestId('relay-schedule-impact-schedule-1');
    expect(impact).toHaveTextContent('运营商线路策略暂时无法读取');
    expect(impact).not.toHaveTextContent('跟随默认线路: 无');
    expect(impact).not.toHaveTextContent('指定线路保持不变: 无');
  });

  it('shows split risk without disabling create, edit, enable, disable, or delete', async () => {
    await renderPanel([
      schedule({ id: 'enabled', enabled: true }),
      schedule({ id: 'disabled', enabled: false }),
    ], { topologyState: 'failed_manual_intervention' });
    expect(screen.getByText('当前 DNS 状态不一致')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /新建定时切换/ })).toBeEnabled();
    for (const id of ['enabled', 'disabled']) {
      const row = screen.getByTestId(`relay-schedule-${id}`);
      expect(within(row).getByRole('button', { name: /编辑/ })).toBeEnabled();
      expect(within(row).getByRole('button', { name: /删除/ })).toBeEnabled();
    }
    expect(within(screen.getByTestId('relay-schedule-enabled')).getByRole('button', { name: /停\s*用/ })).toBeEnabled();
    expect(within(screen.getByTestId('relay-schedule-disabled')).getByRole('button', { name: /启\s*用/ })).toBeEnabled();
  });

  it('shows a Not Ready schedule target and its reason without blocking editing', async () => {
    await renderPanel([schedule({ target_node_id: 'node-b' })]);
    const row = screen.getByTestId('relay-schedule-schedule-1');
    expect(row).toHaveTextContent('未就绪');
    expect(row).toHaveTextContent('节点状态已过期');
    expect(within(row).getByRole('button', { name: /编辑/ })).toBeEnabled();
  });

  it('renders a never-run schedule once as Last run dash', async () => {
    await renderPanel([schedule()]);
    const row = screen.getByTestId('relay-schedule-schedule-1');
    expect(row).toHaveTextContent('最近执行: -');
    expect(row).not.toHaveTextContent('尚未执行');
  });

  it('edits through PUT without changing group or execution state', async () => {
    await renderPanel([schedule()]);
    fireEvent.click(within(screen.getByTestId('relay-schedule-schedule-1')).getByRole('button', { name: /编辑/ }));
    fireEvent.change(await screen.findByLabelText('时间'), { target: { value: '09:15' } });
    fireEvent.click(screen.getByRole('button', { name: '保 存' }));
    await waitFor(() => expect(mockPut).toHaveBeenCalledWith('/admin/relay-schedules/schedule-1', expect.objectContaining({
      target_node_id: 'node-a', schedule_type: 'daily', time: '09:15', utc_offset_minutes: 480,
    })));
    const payload = mockPut.mock.calls[0][1];
    expect(payload).not.toHaveProperty('group_id');
    expect(payload).not.toHaveProperty('last_run_at');
  });

  it('uses dedicated enable and disable endpoints', async () => {
    await renderPanel([
      schedule({ id: 'enabled', enabled: true }),
      schedule({ id: 'disabled', enabled: false }),
    ]);
    fireEvent.click(within(screen.getByTestId('relay-schedule-enabled')).getByRole('button', { name: /停\s*用/ }));
    fireEvent.click(within(screen.getByTestId('relay-schedule-disabled')).getByRole('button', { name: /启\s*用/ }));
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith('/admin/relay-schedules/enabled/disable');
      expect(mockPost).toHaveBeenCalledWith('/admin/relay-schedules/disabled/enable');
    });
  });

  it('confirms deletion before calling DELETE', async () => {
    await renderPanel([schedule()]);
    fireEvent.click(within(screen.getByTestId('relay-schedule-schedule-1')).getByRole('button', { name: /删除/ }));
    expect(screen.getByText('确定删除这条定时切换计划吗？')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'OK' }));
    await waitFor(() => expect(mockDelete).toHaveBeenCalledWith('/admin/relay-schedules/schedule-1'));
  });

  it('maps every stable scheduler result without claiming switch success', async () => {
    await renderPanel([
      schedule({ id: 'started', last_result: 'started' }),
      schedule({ id: 'preferred', last_result: 'already_preferred' }),
      schedule({ id: 'busy', last_result: 'busy' }),
      schedule({ id: 'not-ready', last_result: 'target_not_ready' }),
      schedule({ id: 'failed', last_result: 'failed' }),
      schedule({ id: 'missed', last_result: 'missed' }),
    ]);
    expect(screen.getByText('已触发切换')).toBeInTheDocument();
    expect(screen.queryByText('切换成功')).toBeNull();
    for (const label of ['已是当前默认线路', '切换忙', '目标未就绪', '执行失败', '已错过']) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it('contains load failure locally and supports manual refresh', async () => {
    mockGet.mockRejectedValueOnce(new Error('network')).mockResolvedValueOnce(ok([]));
    render(<RelaySchedulePanel groupId={10} nodes={nodes} t={t} />);
    const alert = (await screen.findByText('定时切换计划加载失败')).closest('[role="alert"]') as HTMLElement;
    expect(screen.getByTestId('relay-schedules-10')).toBeInTheDocument();
    fireEvent.click(within(alert).getByRole('button', { name: /刷\s*新/ }));
    await waitFor(() => expect(mockGet).toHaveBeenCalledTimes(2));
  });

  it('warns before re-enabling a consumed one-time schedule', async () => {
    await renderPanel([schedule({
      schedule_type: 'one_time',
      enabled: false,
      execute_at: '2026-09-01T08:00:00Z',
      time: null,
      utc_offset_minutes: null,
      last_run_slot: 'one_time:2026-09-01T08:00:00Z',
    })]);
    fireEvent.click(within(screen.getByTestId('relay-schedule-schedule-1')).getByRole('button', { name: /启\s*用/ }));
    expect(screen.getByText(/该执行时间已被处理/)).toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
  });
});
