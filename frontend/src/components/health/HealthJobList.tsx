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
      {stale ? <Typography.Paragraph type="warning">Data may be stale; the latest refresh failed.</Typography.Paragraph> : null}
      <Space wrap style={{ marginBottom: 16 }}>
        <Select<HealthJobStatus>
          allowClear
          aria-label="Job status filter"
          placeholder="Status"
          style={{ width: 210 }}
          value={filters.status}
          options={JOB_STATUSES.map((value) => ({ value, label: value }))}
          onChange={(status) => changeFilters({ ...filters, status })}
        />
        <Select<HealthJobSource>
          allowClear
          aria-label="Job source filter"
          placeholder="Source"
          style={{ width: 190 }}
          value={filters.source}
          options={JOB_SOURCES.map((value) => ({ value, label: value }))}
          onChange={(source) => changeFilters({ ...filters, source })}
        />
        <Typography.Text type="secondary">
          Cursors are opaque and reset when filters change.
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
          { title: 'Job ID', dataIndex: 'id', width: 220, render: (id: string) => <Typography.Link className="rp-mono" onClick={() => onOpenJob(id)}>{id}</Typography.Link> },
          { title: 'Source', dataIndex: 'source', width: 130 },
          { title: 'Status', dataIndex: 'status', width: 170, render: (status: HealthJobStatus) => <JobStatusTag status={status} /> },
          { title: 'Progress', width: 190, render: (_value: unknown, job: HealthJob) => <HealthJobProgress job={job} /> },
          { title: 'Queued', dataIndex: 'queued_count', width: 85 },
          { title: 'Running', dataIndex: 'running_count', width: 85 },
          { title: 'Succeeded', dataIndex: 'succeeded_count', width: 100 },
          { title: 'Failed', dataIndex: 'failed_count', width: 80 },
          { title: 'Cancelled', dataIndex: 'cancelled_count', width: 95 },
          { title: 'Created', dataIndex: 'created_at', width: 180, render: (value: number) => <TimestampDisplay value={value} /> },
          { title: 'Started', dataIndex: 'started_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
          { title: 'Finished', dataIndex: 'finished_at', width: 180, render: (value: number | null) => <TimestampDisplay value={value} /> },
          { title: 'Actions', fixed: 'right', width: 100, render: (_value: unknown, job: HealthJob) => <Button size="small" onClick={() => onOpenJob(job.id)}>Detail</Button> },
        ]}
      />}

      <Space style={{ width: '100%', justifyContent: 'flex-end', marginTop: 16 }}>
        <Button icon={<LeftOutlined />} disabled={cursorStack.length === 0} onClick={movePrevious}>Previous</Button>
        <Button icon={<RightOutlined />} iconPlacement="end" disabled={!nextCursor} onClick={moveNext}>Next</Button>
      </Space>
    </Card>
  );
}
