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
import { useHealthLocale } from './healthLocale';

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

function selectorText(value: object, chinese: boolean): string {
  if (!chinese) return JSON.stringify(value, null, 2);
  const keys: Record<string, string> = {
    ids: 'ID', enabled: '启用状态', country_codes: '国家代码', statuses: '健康状态',
    tags: '标签', tag_match: '标签匹配',
  };
  const localize = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map(localize);
    if (input && typeof input === 'object') {
      return Object.fromEntries(Object.entries(input).map(([key, child]) => [keys[key] ?? key, localize(child)]));
    }
    if (input === true) return '是';
    if (input === false) return '否';
    if (input === 'ALL') return '全部匹配';
    if (input === 'ANY') return '任一匹配';
    return input;
  };
  return JSON.stringify(localize(value), null, 2);
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
  const { chinese, copy: c, itemState: itemStateLabel, matrix, semantics, source } = useHealthLocale();
  const [cancelConfirm, setCancelConfirm] = useState(false);
  const [retryConfirm, setRetryConfirm] = useState(false);
  const terminal = job ? isTerminalHealthJob(job.status) : false;
  const canCancel = Boolean(job && !terminal && !job.cancel_requested && job.status !== 'CANCEL_REQUESTED');
  const canRetry = Boolean(job && terminal && job.failed_count > 0);

  return (
    <>
      <Drawer
        title={<Space>{c.healthJob} <Typography.Text code>{jobId ?? '—'}</Typography.Text></Space>}
        open={open}
        onClose={onClose}
        size="min(1120px, 96vw)"
        destroyOnHidden
      >
      {loading ? <HealthLoadingState rows={8} /> : error ? <HealthErrorState error={error} /> : !job ? (
        <Empty
          image={Empty.PRESENTED_IMAGE_SIMPLE}
          description={c.noHealthJobs}
        />
      ) : (
        <Space orientation="vertical" size="large" style={{ width: '100%' }}>
          <Descriptions
            bordered
            size="small"
            column={{ xs: 1, sm: 2, lg: 3 }}
            items={[
              { key: 'source', label: c.source, children: source(job.source) },
              { key: 'status', label: c.status, children: <JobStatusTag status={job.status} /> },
              { key: 'parent', label: c.parentJob, children: job.parent_job_id ? <Typography.Text code>{job.parent_job_id}</Typography.Text> : '—' },
              { key: 'semantics', label: c.snapshotSemantics, children: semantics(job.snapshot_semantics) },
              { key: 'matrix', label: c.matrixMode, children: matrix(job.matrix_mode) },
              { key: 'policy', label: c.retryPolicy, children: job.retry_policy_version },
              { key: 'cancel', label: c.cancelRequested, children: job.cancel_requested ? c.yes : c.no },
              { key: 'failure', label: c.failureCode, children: job.failure_code ?? '—' },
              { key: 'hash', label: c.snapshotHash, children: <Typography.Text code copyable>{job.snapshot_hash}</Typography.Text> },
              { key: 'created', label: c.created, children: <TimestampDisplay value={job.created_at} /> },
              { key: 'started', label: c.started, children: <TimestampDisplay value={job.started_at} /> },
              { key: 'finished', label: c.finished, children: <TimestampDisplay value={job.finished_at} /> },
            ]}
          />

          {job.snapshot_semantics === 'EXACT_PAIRS' ? (
            <Alert
              type="info"
              showIcon
              title={c.exactSnapshot}
              description={job.selectors_reconstruct_snapshot
                ? c.exactSnapshotMismatch
                : c.exactSnapshotDescription}
            />
          ) : null}

          {job.status === 'CANCEL_REQUESTED' ? (
            <Alert
              type="warning"
              showIcon
              title={c.cancellationInProgress}
              description={c.cancellationInProgressDescription}
            />
          ) : null}

          {actionError ? <Alert type="error" showIcon title={actionError.code} description={actionError.message} /> : null}
          {cancelOutcomeUnknown ? (
            <Alert
              type="warning"
              showIcon
              title={c.cancelOutcomeUnknown}
              description={c.cancelOutcomeUnknownDescription}
            />
          ) : null}
          {retryOutcomeUnknown ? (
            <Alert
              type="warning"
              showIcon
              title={c.retryOutcomeUnknown}
              description={c.retryOutcomeUnknownDescription}
            />
          ) : null}

          <div>
            <Typography.Title level={5}>{c.progressCounters}</Typography.Title>
            <HealthJobProgress job={job} />
            <Space wrap style={{ marginTop: 8 }}>
              <Badge count={job.queued_count} showZero color="#8c8c8c" title={c.queued} /> {c.queued}
              <Badge count={job.running_count} showZero color="#1677ff" title={c.running} /> {c.running}
              <Badge count={job.succeeded_count} showZero color="#059669" title={c.succeeded} /> {c.succeeded}
              <Badge count={job.failed_count} showZero color="#ef4444" title={c.failed} /> {c.failed}
              <Badge count={job.cancelled_count} showZero color="#6b7280" title={c.cancelled} /> {c.cancelled}
            </Space>
          </div>

          <div>
            <Typography.Title level={5}>{c.selectors}</Typography.Title>
            <Space align="start" wrap style={{ width: '100%' }}>
              <pre className="rp-health-selector">{selectorText(job.resource_selector, chinese)}</pre>
              <pre className="rp-health-selector">{selectorText(job.node_selector, chinese)}</pre>
            </Space>
          </div>

          <Alert
            type="warning"
            showIcon
            title={c.exactResultUnavailable}
            description={c.exactResultUnavailableDescription}
          />

          <Space wrap>
            <Tooltip title={canCancel ? c.cancelTooltip : c.cancelUnavailableTooltip}>
              <Button
                danger
                loading={cancelLoading}
                disabled={(!canCancel && !cancelOutcomeUnknown) || cancelLoading}
                onClick={() => setCancelConfirm(true)}
              >
                {cancelOutcomeUnknown ? c.retryCancelRequest : job.cancel_requested ? c.cancellationRequested : c.cancelJob}
              </Button>
            </Tooltip>
            <Tooltip title={c.retryTooltip}>
              <Button
                loading={retryLoading}
                disabled={(!canRetry && !retryOutcomeUnknown) || retryLoading}
                onClick={() => setRetryConfirm(true)}
              >
                {retryOutcomeUnknown ? c.retrySameRequest : c.retryExecutionFailures}
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
              <Typography.Text strong>{c.jobItems}</Typography.Text>
              <select aria-label={c.itemStateFilter} value={itemState ?? ''} onChange={(event) => onItemStateChange?.((event.target.value || undefined) as HealthJobItemState | undefined)}>
                <option value="">{c.allStates}</option>
                {(['QUEUED', 'LEASED', 'DISPATCHING', 'IN_FLIGHT', 'RETRY_WAIT', 'SUCCEEDED', 'FAILED', 'CANCELLED'] as HealthJobItemState[]).map((value) => <option key={value} value={value}>{itemStateLabel(value)}</option>)}
              </select>
              <input aria-label={c.safeErrorFilter} placeholder={c.safeErrorCode} value={safeErrorCode} onChange={(event) => onSafeErrorCodeChange?.(event.target.value)} />
            </Space>}
            locale={{ emptyText: itemsError ? <HealthErrorState error={itemsError} onRetry={onRetry} /> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={c.noJobItems} /> }}
            columns={[
              { title: c.item, dataIndex: 'id', width: 80 },
              { title: c.resource, width: 150, render: (_value: unknown, item: HealthJobItem) => resourceDisplayName(item.resource_id_snapshot, resourceNames) },
              { title: c.relayNode, width: 150, render: (_value: unknown, item: HealthJobItem) => nodeDisplayName(item.relay_node_id_snapshot, nodeNames) },
              { title: c.executionState, dataIndex: 'state', width: 145, render: (state: HealthJobItem['state']) => <ItemStateTag state={state} /> },
              { title: c.healthResult, dataIndex: 'health_status', width: 145, render: (status: HealthJobItem['health_status']) => <HealthStatusTag status={status} /> },
              { title: c.attempts, dataIndex: 'attempt_count', width: 90 },
              { title: c.retries, dataIndex: 'retry_count', width: 80 },
              { title: c.safeError, width: 230, render: (_value: unknown, item: HealthJobItem) => item.safe_error_code ? <span>{item.safe_error_code}: {item.safe_error_message ?? '—'}</span> : '—' },
              { title: c.afterCancel, width: 170, render: (_value: unknown, item: HealthJobItem) => item.completed_after_cancel ? <Tooltip title={c.completedAfterCancel}><Badge status="warning" text={c.completedAfterCancel} /></Tooltip> : '—' },
              { title: c.started, dataIndex: 'last_started_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
              { title: c.finished, dataIndex: 'finished_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
            ]}
          />
          <Space style={{ width: '100%', justifyContent: 'flex-end' }}>
            <Button disabled={!canPreviousItems} onClick={onPreviousItems}>{c.previousItems}</Button>
            <Button disabled={!nextItemsCursor} onClick={onNextItems}>{c.nextItems}</Button>
          </Space>
        </Space>
      )}
      </Drawer>

      <Modal
        title={c.cancelConfirmTitle}
        open={cancelConfirm}
        okText={cancelOutcomeUnknown ? c.retryCancelRequest : c.requestCancellation}
        okButtonProps={{ danger: true }}
        confirmLoading={cancelLoading}
        onCancel={() => setCancelConfirm(false)}
        onOk={() => {
          setCancelConfirm(false);
          onCancelJob?.();
        }}
      >
        {c.cancelConfirmDescription}
      </Modal>

      <Modal
        title={c.retryConfirmTitle}
        open={retryConfirm}
        okText={retryOutcomeUnknown ? c.retrySameRequest : c.retryExecutionFailures}
        confirmLoading={retryLoading}
        onCancel={() => setRetryConfirm(false)}
        onOk={() => {
          setRetryConfirm(false);
          onRetryFailed?.();
        }}
      >
        {c.retryConfirmDescription}
      </Modal>
    </>
  );
}
