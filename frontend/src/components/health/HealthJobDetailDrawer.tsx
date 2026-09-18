import { useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Modal,
  Space,
  Table,
  Tooltip,
  Typography,
} from 'antd';
import {
  isTerminalHealthJob,
  type HealthJob,
  type HealthJobItem,
  type HealthJobItemState,
  type SafeError,
} from '../../api/health';
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
  itemsLoading?: boolean;
  itemsError?: SafeError | null;
  nextItemsCursor?: string | null;
  canPreviousItems?: boolean;
  itemState?: HealthJobItemState;
  safeErrorCode?: string;
  onItemStateChange?: (state?: HealthJobItemState) => void;
  onSafeErrorCodeChange?: (code: string) => void;
  onNextItems?: () => void;
  onPreviousItems?: () => void;
  onRetry?: () => void;
  cancelLoading?: boolean;
  retryLoading?: boolean;
  cancelOutcomeUnknown?: boolean;
  retryOutcomeUnknown?: boolean;
  actionError?: SafeError | null;
  onCancelJob?: () => void;
  onRetryFailed?: () => void;
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
  itemsLoading = false,
  itemsError = null,
  nextItemsCursor = null,
  canPreviousItems = false,
  itemState,
  safeErrorCode = '',
  onItemStateChange,
  onSafeErrorCodeChange,
  onNextItems,
  onPreviousItems,
  onRetry,
  cancelLoading = false,
  retryLoading = false,
  cancelOutcomeUnknown = false,
  retryOutcomeUnknown = false,
  actionError = null,
  onCancelJob,
  onRetryFailed,
}: HealthJobDetailDrawerProps) {
  const [cancelConfirm, setCancelConfirm] = useState(false);
  const [retryConfirm, setRetryConfirm] = useState(false);
  const terminal = job ? isTerminalHealthJob(job.status) : false;
  const canCancel = Boolean(job && !terminal && !job.cancel_requested && job.status !== 'CANCEL_REQUESTED');
  const canRetry = Boolean(job && terminal && job.failed_count > 0);

  return (
    <>
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
              { key: 'cancel', label: 'Cancel Requested', children: job.cancel_requested ? 'Yes' : 'No' },
              { key: 'failure', label: 'Failure Code', children: job.failure_code ?? '—' },
              { key: 'hash', label: 'Snapshot Hash', children: <Typography.Text code copyable>{job.snapshot_hash}</Typography.Text> },
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

          {job.status === 'CANCEL_REQUESTED' || job.cancel_requested ? (
            <Alert
              type="warning"
              showIcon
              title="Cancellation in progress"
              description="The backend is cancelling work that has not started. In-flight checks may still complete and record a health result."
            />
          ) : null}

          {actionError ? <Alert type="error" showIcon title={actionError.code} description={actionError.message} /> : null}
          {cancelOutcomeUnknown ? (
            <Alert
              type="warning"
              showIcon
              title="Cancel outcome unknown"
              description="Refresh or retry the same cancellation request; backend state remains authoritative."
            />
          ) : null}
          {retryOutcomeUnknown ? (
            <Alert
              type="warning"
              showIcon
              title="Retry outcome unknown"
              description="Retry the same request to discover the original child Job without creating a duplicate."
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
            <Tooltip title={canCancel ? 'Request cancellation; in-flight checks may still finish.' : 'Available only while a Job is non-terminal.'}>
              <Button
                danger
                loading={cancelLoading}
                disabled={(!canCancel && !cancelOutcomeUnknown) || cancelLoading}
                onClick={() => setCancelConfirm(true)}
              >
                {cancelOutcomeUnknown ? 'Retry Cancel Request' : job.cancel_requested ? 'Cancellation Requested' : 'Cancel Job'}
              </Button>
            </Tooltip>
            <Tooltip title="Retries execution failures only; it does not recheck every unhealthy proxy.">
              <Button
                loading={retryLoading}
                disabled={(!canRetry && !retryOutcomeUnknown) || retryLoading}
                onClick={() => setRetryConfirm(true)}
              >
                {retryOutcomeUnknown ? 'Retry Same Request' : 'Retry Execution Failures'}
              </Button>
            </Tooltip>
          </Space>

          <Table
            size="small"
            rowKey="id"
            dataSource={itemsError ? [] : items}
            loading={itemsLoading}
            pagination={false}
            scroll={{ x: 1450 }}
            title={() => <Space wrap>
              <Typography.Text strong>Job Items</Typography.Text>
              <select aria-label="Item state filter" value={itemState ?? ''} onChange={(event) => onItemStateChange?.((event.target.value || undefined) as HealthJobItemState | undefined)}>
                <option value="">All states</option>
                {['QUEUED', 'LEASED', 'DISPATCHING', 'IN_FLIGHT', 'RETRY_WAIT', 'SUCCEEDED', 'FAILED', 'CANCELLED'].map((value) => <option key={value} value={value}>{value}</option>)}
              </select>
              <input aria-label="Safe error code filter" placeholder="Safe error code" value={safeErrorCode} onChange={(event) => onSafeErrorCodeChange?.(event.target.value)} />
            </Space>}
            locale={{ emptyText: itemsError ? <HealthErrorState error={itemsError} onRetry={onRetry} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No job items" /> }}
            columns={[
              { title: 'Item', dataIndex: 'id', width: 80 },
              { title: 'Resource', width: 150, render: (_value: unknown, item: HealthJobItem) => resourceDisplayName(item.resource_id_snapshot, resourceNames) },
              { title: 'Relay Node', width: 150, render: (_value: unknown, item: HealthJobItem) => nodeDisplayName(item.relay_node_id_snapshot, nodeNames) },
              { title: 'Execution State', dataIndex: 'state', width: 145, render: (state: HealthJobItem['state']) => <ItemStateTag state={state} /> },
              { title: 'Health Result', dataIndex: 'health_status', width: 145, render: (status: HealthJobItem['health_status']) => <HealthStatusTag status={status} /> },
              { title: 'Attempts', dataIndex: 'attempt_count', width: 90 },
              { title: 'Retries', dataIndex: 'retry_count', width: 80 },
              { title: 'Safe Error', width: 230, render: (_value: unknown, item: HealthJobItem) => item.safe_error_code ? <span>{item.safe_error_code}: {item.safe_error_message ?? '—'}</span> : '—' },
              { title: 'After Cancel', width: 170, render: (_value: unknown, item: HealthJobItem) => item.completed_after_cancel ? <Tooltip title="The check completed after cancellation was requested."><Badge status="warning" text="Completed after cancel" /></Tooltip> : '—' },
              { title: 'Started', dataIndex: 'last_started_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
              { title: 'Finished', dataIndex: 'finished_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
            ]}
          />
          <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
            <Button disabled={!canPreviousItems} onClick={onPreviousItems}>Previous items</Button>
            <Button disabled={!nextItemsCursor} onClick={onNextItems}>Next items</Button>
          </Space>
        </Space>
      )}
      </Drawer>

      <Modal
        title="Cancel this health Job?"
        open={cancelConfirm}
        okText={cancelOutcomeUnknown ? 'Retry Cancel Request' : 'Request Cancellation'}
        okButtonProps={{ danger: true }}
        confirmLoading={cancelLoading}
        onCancel={() => setCancelConfirm(false)}
        onOk={() => {
          setCancelConfirm(false);
          onCancelJob?.();
        }}
      >
        Cancellation stops checks that have not started or can still be cancelled. Checks already in flight may finish and legally record health results.
      </Modal>

      <Modal
        title="Retry execution failures?"
        open={retryConfirm}
        okText={retryOutcomeUnknown ? 'Retry Same Request' : 'Retry Execution Failures'}
        confirmLoading={retryLoading}
        onCancel={() => setRetryConfirm(false)}
        onOk={() => {
          setRetryConfirm(false);
          onRetryFailed?.();
        }}
      >
        Only orchestration Items in the FAILED execution state are retried. Health results such as OFFLINE, AUTH_FAILED, or CONNECT_FAILED are not automatically rechecked.
      </Modal>
    </>
  );
}
