import { useState } from 'react';
import { Button, Card, Select, Space, Table, Typography } from 'antd';
import { LeftOutlined, RightOutlined } from '@ant-design/icons';
import type {
  HealthJob,
  HealthJobFilters,
  HealthJobSource,
  HealthJobStatus,
  SafeError,
} from '../../api/health';
import {
  HealthJobProgress,
  JobStatusTag,
  TimestampDisplay,
} from './HealthStatus';
import { HealthEmptyState, HealthErrorState } from './HealthStates';
import { useHealthLocale } from './healthLocale';

const JOB_STATUSES: HealthJobStatus[] = [
  'QUEUED', 'RUNNING', 'CANCEL_REQUESTED', 'SUCCEEDED',
  'FAILED', 'PARTIAL', 'CANCELLED', 'PARTIAL_CANCELLED',
];

const JOB_SOURCES: HealthJobSource[] = [
  'MANUAL', 'SCHEDULED', 'RETRY_FAILED', 'POLICY_RUN_NOW',
];

interface HealthJobListProps {
  jobs: HealthJob[];
  loading?: boolean;
  nextCursor?: string | null;
  onOpenJob: (jobId: string) => void;
  onFiltersChange?: (filters: HealthJobFilters) => void;
  onCursorChange?: (cursor: string | undefined) => void;
  onCursorReset?: () => void;
  error?: SafeError | null;
  stale?: boolean;
  onRetry?: () => void;
}

export function HealthJobList({
  jobs,
  loading = false,
  nextCursor = null,
  onOpenJob,
  onFiltersChange,
  onCursorChange,
  onCursorReset,
  error = null,
  stale = false,
  onRetry,
}: HealthJobListProps) {
  const { copy: c, jobStatus, source } = useHealthLocale();
  const [filters, setFilters] = useState<HealthJobFilters>({});
  const [cursorStack, setCursorStack] = useState<string[]>([]);

  const changeFilters = (next: HealthJobFilters) => {
    setFilters(next);
    setCursorStack([]);
    onCursorReset?.();
    onCursorChange?.(undefined);
    onFiltersChange?.(next);
  };

  const moveNext = () => {
    if (!nextCursor) return;
    setCursorStack((current) => [...current, nextCursor]);
    onCursorChange?.(nextCursor);
  };

  const movePrevious = () => {
    setCursorStack((current) => {
      const next = current.slice(0, -1);
      onCursorChange?.(next.at(-1));
      return next;
    });
  };

  const resetToFirstPage = () => {
    setCursorStack([]);
    onCursorReset?.();
    onCursorChange?.(undefined);
    onRetry?.();
  };

  return (
    <Card>
      {stale ? <Typography.Paragraph type="warning">{c.dataMayBeStale}；{c.dataMayBeStaleDescription}</Typography.Paragraph> : null}
      <Space wrap style={{ marginBottom: 16 }}>
        <Select<HealthJobStatus>
          allowClear
          aria-label={c.jobStatusFilter}
          placeholder={c.filterStatus}
          style={{ width: 210 }}
          value={filters.status}
          options={JOB_STATUSES.map((value) => ({ value, label: jobStatus(value) }))}
          onChange={(status) => changeFilters({ ...filters, status })}
        />
        <Select<HealthJobSource>
          allowClear
          aria-label={c.jobSourceFilter}
          placeholder={c.filterSource}
          style={{ width: 190 }}
          value={filters.source}
          options={JOB_SOURCES.map((value) => ({ value, label: source(value) }))}
          onChange={(source) => changeFilters({ ...filters, source })}
        />
        <Typography.Text type="secondary">
          {c.cursorHint}
        </Typography.Text>
      </Space>

      {error ? <HealthErrorState error={error} onRetry={error.code === 'INVALID_CURSOR' ? resetToFirstPage : onRetry} /> : <Table
        rowKey="id"
        loading={loading}
        dataSource={jobs}
        pagination={false}
        scroll={{ x: 1550 }}
        locale={{ emptyText: <HealthEmptyState kind={filters.status || filters.source ? 'filtered-jobs' : 'jobs'} /> }}
        columns={[
          { title: c.jobId, dataIndex: 'id', width: 220, render: (id: string) => <Typography.Link className="rp-mono" onClick={() => onOpenJob(id)}>{id}</Typography.Link> },
          { title: c.source, dataIndex: 'source', width: 130, render: (value: HealthJobSource) => source(value) },
          { title: c.status, dataIndex: 'status', width: 170, render: (status: HealthJobStatus) => <JobStatusTag status={status} /> },
          { title: c.progress, width: 190, render: (_value: unknown, job: HealthJob) => <HealthJobProgress job={job} /> },
          { title: c.queued, dataIndex: 'queued_count', width: 85 },
          { title: c.running, dataIndex: 'running_count', width: 85 },
          { title: c.succeeded, dataIndex: 'succeeded_count', width: 100 },
          { title: c.failed, dataIndex: 'failed_count', width: 80 },
          { title: c.cancelled, dataIndex: 'cancelled_count', width: 95 },
          { title: c.created, dataIndex: 'created_at', width: 180, render: (value: number) => <TimestampDisplay value={value} /> },
          { title: c.started, dataIndex: 'started_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
          { title: c.finished, dataIndex: 'finished_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
          { title: c.actions, fixed: 'right', width: 100, render: (_value: unknown, job: HealthJob) => <Button size="small" onClick={() => onOpenJob(job.id)}>{c.detail}</Button> },
        ]}
      />}

      <Space style={{ width: '100%', justifyContent: 'flex-end', marginTop: 16 }}>
        <Button icon={<LeftOutlined />} disabled={cursorStack.length === 0} onClick={movePrevious}>{c.previous}</Button>
        <Button icon={<RightOutlined />} iconPlacement="end" disabled={!nextCursor} onClick={moveNext}>{c.next}</Button>
      </Space>
    </Card>
  );
}
