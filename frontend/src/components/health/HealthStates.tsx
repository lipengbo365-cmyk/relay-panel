import { Button, Empty, Result, Skeleton, Space, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import type { SafeError } from '../../api/health';
import { SafeHealthError } from './HealthStatus';

export type HealthEmptyKind =
  | 'jobs'
  | 'filtered-jobs'
  | 'items'
  | 'resources'
  | 'nodes'
  | 'failed-items'
  | 'history';

const EMPTY_COPY: Record<HealthEmptyKind, { title: string; detail: string }> = {
  jobs: { title: 'No health jobs', detail: 'Create controls will be enabled in the actions phase.' },
  'filtered-jobs': { title: 'No jobs match these filters', detail: 'Clear a filter or return to the first page.' },
  items: { title: 'No job items', detail: 'This job has no items matching the current filter.' },
  resources: { title: 'No SOCKS5 resources', detail: 'Add resources before creating a health job.' },
  nodes: { title: 'No Relay Nodes', detail: 'A health job requires at least one enabled Relay Node.' },
  'failed-items': { title: 'No execution failures', detail: 'Retry applies only to items whose execution state is FAILED.' },
  history: { title: 'No health history', detail: 'This resource has not produced health history yet.' },
};

export function HealthLoadingState({ rows = 4 }: { rows?: number }) {
  return <Skeleton active paragraph={{ rows }} />;
}

export function HealthEmptyState({ kind }: { kind: HealthEmptyKind }) {
  const copy = EMPTY_COPY[kind];
  return (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={null}>
      <Space orientation="vertical" size={2}>
        <Typography.Text strong>{copy.title}</Typography.Text>
        <Typography.Text type="secondary">{copy.detail}</Typography.Text>
      </Space>
    </Empty>
  );
}

export function HealthErrorState({ error, onRetry }: { error: SafeError; onRetry?: () => void }) {
  return (
    <Result
      status="warning"
      title="Health data could not be loaded"
      subTitle={<SafeHealthError error={error} />}
      extra={onRetry ? <Button icon={<ReloadOutlined />} onClick={onRetry}>Retry safely</Button> : undefined}
    />
  );
}
