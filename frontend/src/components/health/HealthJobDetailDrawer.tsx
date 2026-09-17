import {
  Alert,
  Badge,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Space,
  Table,
  Tooltip,
  Typography,
} from 'antd';
import type { HealthJob, HealthJobItem, SafeError } from '../../api/health';
import {
  HealthJobProgress,
  HealthStatusTag,
  ItemStateTag,
  JobStatusTag,
  TimestampDisplay,
} from './HealthStatus';
import { nodeDisplayName, resourceDisplayName } from './healthDisplay';
import { HealthErrorState, HealthLoadingState } from './HealthStates';

interface HealthJobDetailDrawerProps {
  open: boolean;
  jobId: string | null;
  job?: HealthJob | null;
  items?: HealthJobItem[];
  loading?: boolean;
  error?: SafeError | null;
  resourceNames?: ReadonlyMap<number, string>;
  nodeNames?: ReadonlyMap<number, string>;
  onClose: () => void;
}

function selectorText(value: object): string {
  return JSON.stringify(value, null, 2);
}

export function HealthJobDetailDrawer({
  open,
  jobId,
  job = null,
  items = [],
  loading = false,
  error = null,
  resourceNames = new Map<number, string>(),
  nodeNames = new Map<number, string>(),
  onClose,
}: HealthJobDetailDrawerProps) {
  return (
    <Drawer
      title={<Space>Health Job <Typography.Text code>{jobId ?? '—'}</Typography.Text></Space>}
      open={open}
      onClose={onClose}
      size="min(1120px, 96vw)"
      destroyOnHidden
    >
      {loading ? <HealthLoadingState rows={8} /> : error ? <HealthErrorState error={error} /> : !job ? (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description="Job data wiring is reserved for F2 Read-only Data Views."
        />
      ) : (
        <Space orientation="vertical" size="large" style={{ width: '100%' }}>
          <Descriptions
            bordered
            size="small"
            column={{ xs: 1, sm: 2, lg: 3 }}
            items={[
              { key: 'source', label: 'Source', children: job.source },
              { key: 'status', label: 'Status', children: <JobStatusTag status={job.status} /> },
              { key: 'parent', label: 'Parent Job', children: job.parent_job_id ? <Typography.Text code>{job.parent_job_id}</Typography.Text> : '—' },
              { key: 'semantics', label: 'Snapshot Semantics', children: job.snapshot_semantics },
              { key: 'matrix', label: 'Matrix Mode', children: job.matrix_mode },
              { key: 'policy', label: 'Retry Policy', children: job.retry_policy_version },
              { key: 'hash', label: 'Snapshot Hash', span: 3, children: <Typography.Text code copyable>{job.snapshot_hash}</Typography.Text> },
              { key: 'created', label: 'Created', children: <TimestampDisplay value={job.created_at} /> },
              { key: 'started', label: 'Started', children: <TimestampDisplay value={job.started_at} /> },
              { key: 'finished', label: 'Finished', children: <TimestampDisplay value={job.finished_at} /> },
            ]}
          />

          {job.snapshot_semantics === 'EXACT_PAIRS' ? (
            <Alert
              type="info"
              showIcon
              title="Exact failed-pair snapshot"
              description={job.selectors_reconstruct_snapshot
                ? 'Contract mismatch: EXACT_PAIRS must not be reconstructed from selectors.'
                : 'selectors_reconstruct_snapshot = false. The UI will not infer a Resource × Node Cartesian matrix.'}
            />
          ) : null}

          <div>
            <Typography.Title level={5}>Progress from backend counters</Typography.Title>
            <HealthJobProgress job={job} />
            <Space wrap style={{ marginTop: 8 }}>
              <Badge count={job.queued_count} showZero color="#8c8c8c" title="Queued" /> Queued
              <Badge count={job.running_count} showZero color="#1677ff" title="Running" /> Running
              <Badge count={job.succeeded_count} showZero color="#059669" title="Succeeded" /> Succeeded
              <Badge count={job.failed_count} showZero color="#ef4444" title="Failed" /> Failed
              <Badge count={job.cancelled_count} showZero color="#6b7280" title="Cancelled" /> Cancelled
            </Space>
          </div>

          <div>
            <Typography.Title level={5}>Selectors</Typography.Title>
            <Space align="start" wrap style={{ width: '100%' }}>
              <pre className="rp-health-selector">{selectorText(job.resource_selector)}</pre>
              <pre className="rp-health-selector">{selectorText(job.node_selector)}</pre>
            </Space>
          </div>

          <Alert
            type="warning"
            showIcon
            title="Exact per-Job exit IP and latency are unavailable"
            description="Items show execution state and health result separately. Current Resource health is never substituted for this historical Job result."
          />

          <Space wrap>
            <Tooltip title="Enabled in F3 Actions/State Handling">
              <Button disabled>Cancel Job</Button>
            </Tooltip>
            <Tooltip title="Retries execution failures only; it does not recheck every unhealthy proxy.">
              <Button disabled>Retry Execution Failures</Button>
            </Tooltip>
          </Space>

          <Table
            size="small"
            rowKey="id"
            dataSource={items}
            pagination={false}
            scroll={{ x: 1450 }}
            locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No job items" /> }}
            columns={[
              { title: 'Item', dataIndex: 'id', width: 80 },
              { title: 'Resource', width: 150, render: (_value: unknown, item: HealthJobItem) => resourceDisplayName(item.resource_id_snapshot, resourceNames) },
              { title: 'Relay Node', width: 150, render: (_value: unknown, item: HealthJobItem) => nodeDisplayName(item.relay_node_id_snapshot, nodeNames) },
              { title: 'Execution State', dataIndex: 'state', width: 145, render: (state: HealthJobItem['state']) => <ItemStateTag state={state} /> },
              { title: 'Health Result', dataIndex: 'health_status', width: 145, render: (status: HealthJobItem['health_status']) => <HealthStatusTag status={status} /> },
              { title: 'Attempts', dataIndex: 'attempt_count', width: 90 },
              { title: 'Retries', dataIndex: 'retry_count', width: 80 },
              { title: 'Safe Error', width: 230, render: (_value: unknown, item: HealthJobItem) => item.safe_error_code ? <span>{item.safe_error_code}: {item.safe_error_message ?? '—'}</span> : '—' },
              { title: 'After Cancel', width: 120, render: (_value: unknown, item: HealthJobItem) => item.completed_after_cancel ? <Badge status="warning" text="Completed" /> : '—' },
              { title: 'Started', dataIndex: 'last_started_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
              { title: 'Finished', dataIndex: 'finished_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
            ]}
          />
        </Space>
      )}
    </Drawer>
  );
}
