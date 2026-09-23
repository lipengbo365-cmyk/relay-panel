import { Alert, Card, Col, Row, Space, Statistic, Table, Typography } from 'antd';
import type { HealthJob, HealthStatus, SafeError } from '../../api/health';
import type { RelayNode } from '../../api/types';
import { HealthJobProgress, JobStatusTag, TimestampDisplay } from './HealthStatus';
import { HealthEmptyState, HealthErrorState, HealthLoadingState } from './HealthStates';
import { useHealthLocale } from './healthLocale';

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
  const { copy: c, healthStatus } = useHealthLocale();
  if (loading) return <HealthLoadingState rows={6} />;

  return (
    <Space orientation="vertical" size="large" style={{ width: '100%' }}>
      {stale ? <Alert type="warning" showIcon title={c.dataMayBeStale} description={c.dataMayBeStaleDescription} /> : null}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title={c.socks5Resources} value={resourceTotal ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title={healthStatus('ONLINE')} value={healthTotals.ONLINE ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title={healthStatus('OFFLINE')} value={healthTotals.OFFLINE ?? unavailable} /></Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card className="rp-stat-card"><Statistic title={c.relayNodesOnline} value={
            nodeOnline === undefined || nodeTotal === undefined ? unavailable : `${nodeOnline}/${nodeTotal}`
          } /></Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        {(['AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'UNKNOWN'] as HealthStatus[]).map((status) => (
          <Col xs={24} sm={12} xl={6} key={status}>
            <Card className="rp-stat-card"><Statistic title={healthStatus(status)} value={healthTotals[status] ?? unavailable} /></Card>
          </Col>
        ))}
      </Row>

      {resourceError ? <HealthErrorState error={resourceError} onRetry={onRetry} /> : null}

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card title={c.nodeReadiness} style={{ height: '100%' }}>
            {nodeError ? <HealthErrorState error={nodeError} onRetry={onRetry} /> : null}
            {!nodeError || nodes.length > 0 ? <>
              <Statistic title={c.supportsSocks5Check} value={supportedNodes ?? unavailable} />
              <Typography.Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 0 }}>
                {c.readinessSignals}
              </Typography.Paragraph>
              <Table
                size="small"
                rowKey="id"
                pagination={false}
                dataSource={nodes}
                style={{ marginTop: 12 }}
                columns={[
                  { title: c.node, dataIndex: 'name' },
                  { title: c.online, dataIndex: 'online', render: (value: boolean) => value ? c.yes : c.no },
                  { title: c.protocol, dataIndex: 'config_protocol_version', render: (value: number | null) => value ?? '—' },
                  { title: c.queue, dataIndex: 'socks5_check_queue', render: (value: number | null) => value ?? '—' },
                ]}
              />
            </> : null}
          </Card>
        </Col>
        <Col xs={24} lg={16}>
          <Card title={c.recentJobs}>
            {jobsError ? <HealthErrorState error={jobsError} onRetry={onRetry} /> : null}
            {!jobsError && recentJobs.length === 0 ? <HealthEmptyState kind="jobs" /> : null}
            {recentJobs.length > 0 ? (
              <Table
                size="small"
                rowKey="id"
                pagination={false}
                dataSource={recentJobs.slice(0, 5)}
                onRow={(job) => ({ onClick: () => onOpenJob?.(job.id), style: { cursor: 'pointer' } })}
                columns={[
                  { title: c.job, dataIndex: 'id', render: (id: string) => <span className="rp-mono">{id}</span> },
                  { title: c.status, dataIndex: 'status', render: (status: HealthJob['status']) => <JobStatusTag status={status} /> },
                  { title: c.progress, render: (_value: unknown, job: HealthJob) => <HealthJobProgress job={job} /> },
                  { title: c.created, dataIndex: 'created_at', render: (value: number) => <TimestampDisplay value={value} /> },
                ]}
              />
            ) : null}
          </Card>
        </Col>
      </Row>

      <Alert
        type="info"
        showIcon
        title={c.aggregateUnavailable}
        description={c.aggregateUnavailableDescription}
      />
    </Space>
  );
}
