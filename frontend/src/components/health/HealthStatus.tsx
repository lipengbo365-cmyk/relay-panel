import { Alert, Progress, Space, Tag, Typography } from 'antd';
import type {
  HealthJob,
  HealthJobItemState,
  HealthJobStatus,
  HealthStatus as HealthStatusValue,
  SafeError,
} from '../../api/health';
import { healthJobProgress } from '../../api/health';

const JOB_COLORS: Record<HealthJobStatus, string> = {
  QUEUED: 'default',
  RUNNING: 'processing',
  CANCEL_REQUESTED: 'warning',
  SUCCEEDED: 'success',
  FAILED: 'error',
  PARTIAL: 'orange',
  CANCELLED: 'default',
  PARTIAL_CANCELLED: 'gold',
};

const ITEM_COLORS: Record<HealthJobItemState, string> = {
  QUEUED: 'default',
  LEASED: 'cyan',
  DISPATCHING: 'blue',
  IN_FLIGHT: 'processing',
  RETRY_WAIT: 'warning',
  SUCCEEDED: 'success',
  FAILED: 'error',
  CANCELLED: 'default',
};

const HEALTH_COLORS: Record<HealthStatusValue, string> = {
  ONLINE: 'success',
  OFFLINE: 'error',
  AUTH_FAILED: 'magenta',
  TIMEOUT: 'orange',
  CONNECT_FAILED: 'volcano',
  DISABLED: 'default',
  UNKNOWN: 'default',
};

export function JobStatusTag({ status }: { status: HealthJobStatus }) {
  return <Tag color={JOB_COLORS[status]}>{status}</Tag>;
}

export function ItemStateTag({ state }: { state: HealthJobItemState }) {
  return <Tag color={ITEM_COLORS[state]}>{state}</Tag>;
}

export function HealthStatusTag({ status }: { status: HealthStatusValue | null }) {
  return status
    ? <Tag color={HEALTH_COLORS[status]}>{status}</Tag>
    : <Typography.Text type="secondary">—</Typography.Text>;
}

export function TimestampDisplay({ value }: { value: number | null }) {
  if (value === null) return <Typography.Text type="secondary">—</Typography.Text>;
  return <span style={{ whiteSpace: 'nowrap' }}>{new Date(value).toLocaleString()}</span>;
}

export function SafeHealthError({ error }: { error: SafeError }) {
  return (
    <Alert
      type="warning"
      showIcon
      title={error.code}
      description={error.message}
      data-testid="safe-health-error"
    />
  );
}

export function HealthJobProgress({ job }: { job: HealthJob }) {
  const percent = healthJobProgress(job);
  return (
    <Space orientation="vertical" size={2} style={{ width: '100%', minWidth: 150 }}>
      <Progress percent={percent} size="small" status={job.status === 'FAILED' ? 'exception' : undefined} />
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {job.succeeded_count + job.failed_count + job.cancelled_count}/{job.total_items}
      </Typography.Text>
    </Space>
  );
}
