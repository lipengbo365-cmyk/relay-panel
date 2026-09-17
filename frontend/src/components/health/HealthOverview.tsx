import { Alert, Card, Col, Row, Space, Statistic, Table, Typography } from 'antd';
import type { HealthJob, HealthStatus, SafeError } from '../../api/health';
import type { RelayNode } from '../../api/types';
import { HealthJobProgress, JobStatusTag, TimestampDisplay } from './HealthStatus';
import { HealthEmptyState, HealthErrorState, HealthLoadingState } from './HealthStates';

interface HealthOverviewProps {
  loading?: boolean;
  resourceTotal?: number;
  healthTotals?: Partial<Record<HealthStatus, number>>;
  nodeOnline?: number;
  nodeTotal?: number;
  supportedNodes?: number;
  recentJobs?: HealthJob[];
  nodes?: RelayNode[];
  resourceError?: SafeError | null;
  nodeError?: SafeError | null;
  jobsError?: SafeError | null;
  stale?: boolean;
  onRetry?: () => void;
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
  nodes = [],
  resourceError = null,
  nodeError = null,
  jobsError = null,
  stale = false,
  onRetry,
  onOpenJob,
}: HealthOverviewProps) {
  if (loading) return <HealthLoadingState rows={6} />;

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      {stale ? <Alert type="warning" showIcon title="Data may be stale" description="The latest refresh failed. Last successful data remains visible." /> : null}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="SOCKS5 Resources" value={resourceTotal ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="ONLINE" value={healthTotals.ONLINE ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="OFFLINE" value={healthTotals.OFFLINE ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title="Relay Nodes Online" value={
            nodeOnline === undefined || nodeTotal === undefined ? unavailable : `${nodeOnline}/${nodeTotal}`
          } /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        {(['AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'UNKNOWN'] as HealthStatus[]).map((status) => (
          <Col xs={24} sm={12} xl={6} key={status}>
            <Card className="rp-stat-card"><Statistic title={status} value={healthTotals[status] ?? unavailable} /></Card>
          </Col>
        ))}
      </Row>

      {resourceError ? <HealthErrorState error={resourceError} onRetry={onRetry} /> : null}

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card title="Node Readiness" style={{ height: '100%' }}>
            {nodeError ? <HealthErrorState error={nodeError} onRetry={onRetry} /> : <>
            <Statistic title="Supports SOCKS5 Check" value={supportedNodes ?? unavailable} />
            <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
              Online and protocol capability are separate backend signals. Eligibility is not inferred in the browser.
            </Typography.Paragraph>
            <Table
              size="small"
              rowKey="id"
              pagination={false}
              dataSource={nodes}
              style={{ marginTop: 12 }}
              columns={[
                { title: 'Node', dataIndex: 'name' },
                { title: 'Online', dataIndex: 'online', render: (value: boolean) => value ? 'Yes' : 'No' },
                { title: 'Protocol', dataIndex: 'config_protocol_version', render: (value: number | null) => value ?? '—' },
                { title: 'Queue', dataIndex: 'socks5_check_queue', render: (value: number | null) => value ?? '—' },
              ]}
            />
            </>}
          </Card>
        </Col>
        <Col xs={24} lg={16}>
          <Card title="Recent Jobs">
            {jobsError ? <HealthErrorState error={jobsError} onRetry={onRetry} /> : recentJobs.length === 0 ? <HealthEmptyState kind="jobs" /> : (
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
