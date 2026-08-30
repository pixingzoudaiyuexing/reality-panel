import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Checkbox,
  Divider,
  Empty,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd';
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import api from '../../api/client';
import type {
  ApiEnvelope,
  CreateRelayScheduleRequest,
  RelayReadyNode,
  RelaySchedule,
  RelayScheduleType,
  UpdateRelayScheduleRequest,
} from '../../api/types';
import type { Tfn } from './types';

const { Text } = Typography;

interface Props {
  groupId: number;
  nodes: RelayReadyNode[];
  t: Tfn;
}

interface ScheduleFormValues {
  target_node_id: string;
  schedule_type: RelayScheduleType;
  execute_at?: string;
  time?: string;
  utc_offset_minutes?: number;
  weekdays?: number[];
  enabled: boolean;
}

const WEEKDAYS = [1, 2, 3, 4, 5, 6, 7] as const;

function pad(value: number): string {
  return String(value).padStart(2, '0');
}

function formatLocalDateTime(value: string | null, includeSeconds = false): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const base = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  return includeSeconds ? `${base}:${pad(date.getSeconds())}` : base;
}

function toLocalDateTimeInput(value: string | null): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return undefined;
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function formatOffset(minutes: number | null): string {
  if (minutes === null) return 'UTC+00:00';
  const sign = minutes < 0 ? '-' : '+';
  const absolute = Math.abs(minutes);
  return `UTC${sign}${pad(Math.floor(absolute / 60))}:${pad(absolute % 60)}`;
}

function weekdayLabel(day: number, t: Tfn): string {
  const keys = [
    'relayScheduleMonday',
    'relayScheduleTuesday',
    'relayScheduleWednesday',
    'relayScheduleThursday',
    'relayScheduleFriday',
    'relayScheduleSaturday',
    'relayScheduleSunday',
  ] as const;
  return t(keys[day - 1] ?? 'relayScheduleMonday');
}

function scheduleDescription(schedule: RelaySchedule, t: Tfn): string {
  if (schedule.schedule_type === 'one_time') {
    return `${t('relayScheduleOneTime')} · ${formatLocalDateTime(schedule.execute_at)}`;
  }
  if (schedule.schedule_type === 'daily') {
    return `${t('relayScheduleDaily')} · ${schedule.time ?? '-'} · ${formatOffset(schedule.utc_offset_minutes)}`;
  }
  const days = schedule.weekdays
    .map((day) => weekdayLabel(day, t))
    .join(t('relayScheduleWeekdaySeparator'));
  return `${t('relayScheduleWeekly')} · ${days} · ${schedule.time ?? '-'} · ${formatOffset(schedule.utc_offset_minutes)}`;
}

function resultLabel(result: string | null, t: Tfn): string {
  const keys: Record<string, Parameters<Tfn>[0]> = {
    started: 'relayScheduleResultStarted',
    already_preferred: 'relayScheduleResultAlreadyPreferred',
    busy: 'relayScheduleResultBusy',
    target_not_ready: 'relayScheduleResultTargetNotReady',
    failed: 'relayScheduleResultFailed',
    missed: 'relayScheduleResultMissed',
  };
  return result ? t(keys[result] ?? 'relayScheduleResultFailed') : t('relayScheduleNeverRun');
}

function requestError(error: unknown, fallback: string): string {
  const message = (error as { response?: { data?: { message?: string } } }).response?.data?.message;
  return message ? `${fallback}: ${message}` : fallback;
}

export function RelaySchedulePanel({ groupId, nodes, t }: Props) {
  const [schedules, setSchedules] = useState<RelaySchedule[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<RelaySchedule | null>(null);
  const [saving, setSaving] = useState(false);
  const [actionId, setActionId] = useState<string | null>(null);
  const [form] = Form.useForm<ScheduleFormValues>();
  const scheduleType = Form.useWatch('schedule_type', form) ?? 'one_time';
  const offsetMinutes = Form.useWatch('utc_offset_minutes', form);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get<unknown, ApiEnvelope<RelaySchedule[]>>('/admin/relay-schedules');
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setSchedules(response.data.filter((schedule) => schedule.group_id === groupId));
      setLoadError(false);
    } catch {
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [groupId]);

  useEffect(() => {
    void load();
  }, [load]);

  const nodeById = useMemo(
    () => new Map(nodes.map((node) => [node.node_id, node])),
    [nodes],
  );
  const nodeOptions = nodes.map((node) => ({
    value: node.node_id,
    label: `${node.public_ipv4 ?? node.node_id}${node.public_ipv4 ? ` · ${node.node_id}` : ''} · ${node.ready ? t('relayReady') : t('relayNotReady')}`,
  }));

  const openCreate = () => {
    setEditing(null);
    form.resetFields();
    form.setFieldsValue({
      schedule_type: 'one_time',
      enabled: true,
      utc_offset_minutes: -new Date().getTimezoneOffset(),
      weekdays: [],
    });
    setModalOpen(true);
  };

  const openEdit = (schedule: RelaySchedule) => {
    setEditing(schedule);
    form.setFieldsValue({
      target_node_id: schedule.target_node_id,
      schedule_type: schedule.schedule_type,
      execute_at: toLocalDateTimeInput(schedule.execute_at),
      time: schedule.time ?? undefined,
      utc_offset_minutes: schedule.utc_offset_minutes ?? undefined,
      weekdays: schedule.weekdays,
      enabled: schedule.enabled,
    });
    setModalOpen(true);
  };

  const submit = async (values: ScheduleFormValues) => {
    setSaving(true);
    const common = {
      target_node_id: values.target_node_id,
      schedule_type: values.schedule_type,
      enabled: values.enabled,
    };
    const payload: UpdateRelayScheduleRequest = values.schedule_type === 'one_time'
      ? { ...common, execute_at: new Date(values.execute_at as string).toISOString() }
      : values.schedule_type === 'daily'
        ? { ...common, time: values.time, utc_offset_minutes: values.utc_offset_minutes }
        : { ...common, time: values.time, utc_offset_minutes: values.utc_offset_minutes, weekdays: values.weekdays };
    try {
      const response = editing
        ? await api.put<unknown, ApiEnvelope<RelaySchedule>>(`/admin/relay-schedules/${editing.id}`, payload)
        : await api.post<unknown, ApiEnvelope<RelaySchedule>>('/admin/relay-schedules', {
          group_id: groupId,
          ...payload,
        } satisfies CreateRelayScheduleRequest);
      if (response.code !== 0) throw new Error(response.message);
      message.success(t(editing ? 'relayScheduleUpdated' : 'relayScheduleCreated'));
      setModalOpen(false);
      await load();
    } catch (error) {
      message.error(requestError(error, t('relayScheduleSaveFailed')));
    } finally {
      setSaving(false);
    }
  };

  const setEnabled = async (schedule: RelaySchedule, enabled: boolean) => {
    setActionId(schedule.id);
    try {
      const action = enabled ? 'enable' : 'disable';
      const response = await api.post<unknown, ApiEnvelope<RelaySchedule>>(
        `/admin/relay-schedules/${schedule.id}/${action}`,
      );
      if (response.code !== 0) throw new Error(response.message);
      await load();
    } catch (error) {
      message.error(requestError(error, t('relayScheduleActionFailed')));
    } finally {
      setActionId(null);
    }
  };

  const remove = async (schedule: RelaySchedule) => {
    setActionId(schedule.id);
    try {
      const response = await api.delete<unknown, ApiEnvelope<null>>(`/admin/relay-schedules/${schedule.id}`);
      if (response.code !== 0) throw new Error(response.message);
      await load();
    } catch (error) {
      message.error(requestError(error, t('relayScheduleDeleteFailed')));
    } finally {
      setActionId(null);
    }
  };

  return (
    <div data-testid={`relay-schedules-${groupId}`} style={{ padding: '0 12px 12px' }}>
      <Divider style={{ margin: '12px 0' }} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 10 }}>
        <Text strong>{t('relayScheduleTitle')}</Text>
        <Space size={4}>
          <Button size="small" icon={<PlusOutlined />} onClick={openCreate}>{t('relayScheduleCreate')}</Button>
          <Tooltip title={t('refresh')}>
            <Button
              size="small"
              type="text"
              icon={<ReloadOutlined />}
              aria-label={t('relayScheduleRefresh')}
              loading={loading}
              onClick={() => void load()}
            />
          </Tooltip>
        </Space>
      </div>

      {loadError ? <Alert type="warning" showIcon title={t('relayScheduleLoadFailed')} action={<Button size="small" onClick={() => void load()}>{t('refresh')}</Button>} /> : null}
      {loading && schedules.length === 0 && !loadError ? <div style={{ textAlign: 'center', padding: 12 }}><Spin size="small" /></div> : null}
      {!loading && !loadError && schedules.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('relayScheduleEmpty')} /> : null}

      {schedules.map((schedule) => {
        const target = nodeById.get(schedule.target_node_id);
        const targetPrimary = target?.public_ipv4 ?? schedule.target_node_id;
        const consumedOneTime = schedule.schedule_type === 'one_time' && schedule.last_run_slot !== null;
        const toggleButton = (confirmFirst: boolean) => (
          <Button
            size="small"
            loading={actionId === schedule.id}
            onClick={confirmFirst ? undefined : () => void setEnabled(schedule, !schedule.enabled)}
          >
            {t(schedule.enabled ? 'relayScheduleDisable' : 'relayScheduleEnable')}
          </Button>
        );
        return (
          <div
            key={schedule.id}
            data-testid={`relay-schedule-${schedule.id}`}
            style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid var(--rp-border)' }}
          >
            <div style={{ flex: '1 1 420px', minWidth: 0 }}>
              <Space size={6} wrap>
                <Text strong className="rp-mono">{targetPrimary}</Text>
                <Tag color={schedule.enabled ? 'green' : undefined}>{t(schedule.enabled ? 'relayScheduleEnabled' : 'relayScheduleDisabled')}</Tag>
              </Space>
              {target?.public_ipv4 ? <div><Text type="secondary" code>{schedule.target_node_id}</Text></div> : null}
              <div><Text>{scheduleDescription(schedule, t)}</Text></div>
              <Space size={6} wrap>
                <Text type="secondary">{schedule.last_run_at ? `${t('relayScheduleLastRun')}: ${formatLocalDateTime(schedule.last_run_at, true)}` : t('relayScheduleNeverRun')}</Text>
                <Tag>{resultLabel(schedule.last_result, t)}</Tag>
                {schedule.last_error ? <Tooltip title={schedule.last_error}><Text type="danger" ellipsis style={{ maxWidth: 280 }}>{schedule.last_error}</Text></Tooltip> : null}
              </Space>
            </div>
            <Space size={4} wrap>
              <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(schedule)}>{t('edit')}</Button>
              {!schedule.enabled && consumedOneTime ? (
                <Popconfirm title={t('relayScheduleConsumedWarning')} onConfirm={() => void setEnabled(schedule, true)}>
                  {toggleButton(true)}
                </Popconfirm>
              ) : toggleButton(false)}
              <Popconfirm title={t('relayScheduleDeleteConfirm')} onConfirm={() => void remove(schedule)} okButtonProps={{ danger: true }}>
                <Button size="small" danger icon={<DeleteOutlined />} loading={actionId === schedule.id}>{t('delete')}</Button>
              </Popconfirm>
            </Space>
          </div>
        );
      })}

      <Modal
        title={t(editing ? 'relayScheduleEdit' : 'relayScheduleCreate')}
        open={modalOpen}
        confirmLoading={saving}
        okText={t('save')}
        cancelText={t('cancel')}
        onCancel={() => setModalOpen(false)}
        onOk={() => form.submit()}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" onFinish={submit}>
          <Form.Item name="target_node_id" label={t('relayScheduleTarget')} rules={[{ required: true }]}>
            <Select options={nodeOptions} />
          </Form.Item>
          <Form.Item name="schedule_type" label={t('relayScheduleType')} rules={[{ required: true }]}>
            <Select options={[
              { value: 'one_time', label: t('relayScheduleOneTime') },
              { value: 'daily', label: t('relayScheduleDaily') },
              { value: 'weekly', label: t('relayScheduleWeekly') },
            ]} />
          </Form.Item>
          {scheduleType === 'one_time' ? (
            <Form.Item name="execute_at" label={t('relayScheduleExecuteAt')} rules={[{ required: true }]}>
              <Input type="datetime-local" />
            </Form.Item>
          ) : (
            <>
              <Form.Item name="time" label={t('relayScheduleTime')} rules={[{ required: true }]}>
                <Input type="time" />
              </Form.Item>
              <Form.Item
                name="utc_offset_minutes"
                label={t('relayScheduleUtcOffset')}
                extra={offsetMinutes !== undefined ? formatOffset(offsetMinutes) : undefined}
                rules={[{ required: true }]}
              >
                <InputNumber min={-840} max={840} step={30} style={{ width: '100%' }} />
              </Form.Item>
            </>
          )}
          {scheduleType === 'weekly' ? (
            <Form.Item name="weekdays" label={t('relayScheduleWeekdays')} rules={[{ required: true, type: 'array', min: 1 }]}>
              <Checkbox.Group options={WEEKDAYS.map((day) => ({ label: weekdayLabel(day, t), value: day }))} />
            </Form.Item>
          ) : null}
          <Form.Item name="enabled" label={t('relayScheduleStatus')} valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
