import { Button, Empty, Result, Skeleton, Space, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import type { SafeError } from '../../api/health';
import { SafeHealthError } from './HealthStatus';
import { useHealthLocale } from './healthLocale';

export type HealthEmptyKind =
  | 'jobs'
  | 'filtered-jobs'
  | 'items'
  | 'resources'
  | 'nodes'
  | 'failed-items'
  | 'history';

export function HealthLoadingState({ rows = 4 }: { rows?: number }) {
  return <Skeleton active paragraph={{ rows }} />;
}

export function HealthEmptyState({ kind }: { kind: HealthEmptyKind }) {
  const { copy: c } = useHealthLocale();
  const copy: Record<HealthEmptyKind, { title: string; detail: string }> = {
    jobs: { title: c.noHealthJobs, detail: c.noHealthJobsDetail },
    'filtered-jobs': { title: c.noFilteredJobs, detail: c.noFilteredJobsDetail },
    items: { title: c.noItems, detail: c.noItemsDetail },
    resources: { title: c.noResources, detail: c.noResourcesDetail },
    nodes: { title: c.noNodes, detail: c.noNodesDetail },
    'failed-items': { title: c.noFailedItems, detail: c.noFailedItemsDetail },
    history: { title: c.noHistory, detail: c.noHistoryDetail },
  };
  const selected = copy[kind];
  return (
    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={null}>
      <Space orientation="vertical" size={2}>
        <Typography.Text strong>{selected.title}</Typography.Text>
        <Typography.Text type="secondary">{selected.detail}</Typography.Text>
      </Space>
    </Empty>
  );
}

export function HealthErrorState({ error, onRetry }: { error: SafeError; onRetry?: () => void }) {
  const { copy: c } = useHealthLocale();
  return (
    <Result
      status="warning"
      title={c.healthLoadFailed}
      subTitle={<SafeHealthError error={error} />}
      extra={onRetry ? <Button icon={<ReloadOutlined />} onClick={onRetry}>{c.retrySafely}</Button> : undefined}
    />
  );
}
