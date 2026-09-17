import { Alert, Card, Col, Row, Space, Statistic, Table, Typography } from 'antd';
import type { HealthJob, HealthStatus } from '../../api/health';
import { HealthJobProgress, JobStatusTag, TimestampDisplay } from './HealthStatus';
import { HealthEmptyState, HealthLoadingState } from './HealthStates';

interface HealthOverviewProps {
  loading?: boolean;
  resourceTotal?: number;
  healthTotals?: Partial<Record<HealthStatus, number>>;
  nodeOnline?: number;
  nodeTotal?: number;
  supportedNodes?: number;
  recentJobs?: HealthJob[];
  onOpenJob?: (jobId: string) => void;
}

const unavailable = '—';

export function HealthOverview({
  loading = false,
  resourceTotal,
  healthTotals = {},
  nodeOnline,
  nodeTotal,
  supportedNodes,
  recentJobs = [],
  onOpenJob,
}: HealthOverviewProps) {
  if (loading) return <HealthLoadingState rows={6} />;

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="SOCKS5 Resources" value={resourceTotal ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="ONLINE" value={healthTotals.ONLINE ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="Abnormal Health" value={
            healthTotals.OFFLINE === undefined
              ? unavailable
              : (healthTotals.OFFLINE ?? 0)
                + (healthTotals.AUTH_FAILED ?? 0)
                + (healthTotals.TIMEOUT ?? 0)
                + (healthTotals.CONNECT_FAILED ?? 0)
          } /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="Relay Nodes Online" value={
            nodeOnline === undefined || nodeTotal === undefined ? unavailable : `${nodeOnline}/${nodeTotal}`
          } /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card title="Node Readiness" style={{ height: '100%' }}>
            <Statistic title="Supports SOCKS5 Check" value={supportedNodes ?? unavailable} />
            <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
              Online and protocol capability remain separate signals. Eligibility is not inferred in this skeleton.
            </Typography.Paragraph>
          </Card>
        </Col>
        <Col xs={24} lg={16}>
          <Card title="Recent Jobs">
            {recentJobs.length === 0 ? <HealthEmptyState kind="jobs" /> : (
              <Table
                size="small"
                rowKey="id"
                pagination={false}
                dataSource={recentJobs.slice(0, 5)}
                onRow={(job) => ({ onClick: () => onOpenJob?.(job.id), style: { cursor: 'pointer' } })}
                columns={[
                  { title: 'Job', dataIndex: 'id', render: (id: string) => <span className="rp-mono">{id}</span> },
                  { title: 'Status', dataIndex: 'status', render: (status: HealthJob['status']) => <JobStatusTag status={status} /> },
                  { title: 'Progress', render: (_value: unknown, job: HealthJob) => <HealthJobProgress job={job} /> },
                  { title: 'Created', dataIndex: 'created_at', render: (value: number) => <TimestampDisplay value={value} /> },
                ]}
              />
            )}
          </Card>
        </Col>
      </Row>

      <Alert
        type="info"
        showIcon
        title="Stale and coverage metrics are not available"
        description="The backend does not expose an authoritative aggregate contract yet. This page does not estimate them from browser timestamps."
      />
    </Space>
  );
}
