import { Button, Space, Typography } from 'antd';
import { ExperimentOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';

interface HealthCenterHeaderProps {
  title: string;
  createLabel: string;
  refreshLabel: string;
  lastRefreshLabel: string;
  lastRefreshAt: number | null;
  refreshing?: boolean;
  onCreate: () => void;
  onRefresh: () => void;
}
export function HealthCenterHeader({
  title,
  createLabel,
  refreshLabel,
  lastRefreshLabel,
  lastRefreshAt,
  refreshing = false,
  onCreate,
  onRefresh,
}: HealthCenterHeaderProps) {
  return (
    <div className="rp-page-header" style={{ gap: 16, flexWrap: 'wrap' }}>
      <div>
        <Typography.Title level={2} className="rp-page-title" style={{ marginBottom: 2 }}>
          <ExperimentOutlined /> {title}
        </Typography.Title>
        <Typography.Text type="secondary">
          {lastRefreshLabel}: {lastRefreshAt === null ? '—' : new Date(lastRefreshAt).toLocaleString()}
        </Typography.Text>
      </div>
      <Space wrap>
        <Button icon={<ReloadOutlined spin={refreshing} />} loading={refreshing} onClick={onRefresh}>
          {refreshLabel}
        </Button>
        <Button type="primary" icon={<PlusOutlined />} onClick={onCreate}>
          {createLabel}
        </Button>
      </Space>
    </div>
  );
}
