import { useState } from 'react';
import { Button, Card, Descriptions, Drawer, Input, Select, Space, Table, Tag, Typography } from 'antd';
import type { HealthStatus, ResourceHealthHistoryRecord } from '../../api/health';
import type { Socks5Health, Socks5Resource } from '../../api/types';
import { useResourceHealthDetail, useResourcePage } from '../../hooks/useHealthReadModel';
import { HealthEmptyState, HealthErrorState, HealthLoadingState } from './HealthStates';
import { HealthStatusTag } from './HealthStatus';
import { nodeDisplayName } from './healthDisplay';

const HEALTH_STATUSES: HealthStatus[] = [
  'ONLINE', 'OFFLINE', 'AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'DISABLED', 'UNKNOWN',
];

interface ResourceHealthViewProps {
  refreshKey?: number;
  nodeNames?: ReadonlyMap<number, string>;
}

function latency(value: number | null) {
  return value === null ? '—' : `${value} ms`;
}

export function ResourceHealthView({
  refreshKey = 0,
  nodeNames = new Map<number, string>(),
}: ResourceHealthViewProps) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState<HealthStatus | undefined>();
  const [selected, setSelected] = useState<Socks5Resource | null>(null);
  const resources = useResourcePage(page, search, status, refreshKey);
  const detail = useResourceHealthDetail(selected?.id ?? null, refreshKey);
  const pageSize = resources.data.page_size || 50;
  const hasNext = page * pageSize < resources.data.total;

  const applySearch = (value: string) => {
    setPage(1);
    setSearch(value.trim());
  };

  return (
    <Card>
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search placeholder="Search Resource" allowClear style={{ width: 260 }} onSearch={applySearch} />
        <Select<HealthStatus>
          allowClear
          aria-label="Resource health status"
          placeholder="Health Status"
          style={{ width: 190 }}
          options={HEALTH_STATUSES.map((value) => ({ value, label: value }))}
          onChange={(value) => { setPage(1); setStatus(value); }}
        />
        <Typography.Text type="secondary">Current Health uses the paged Resource projection.</Typography.Text>
      </Space>

      {resources.error ? <HealthErrorState error={resources.error} onRetry={() => void resources.reload()} /> : <>
        <Table
          rowKey="id"
          loading={resources.loading}
          dataSource={resources.data.items}
          pagination={false}
          scroll={{ x: 1200 }}
          locale={{ emptyText: <HealthEmptyState kind="resources" /> }}
          onRow={(resource) => ({ onClick: () => setSelected(resource), style: { cursor: 'pointer' } })}
          columns={[
            { title: 'Resource', dataIndex: 'name', width: 180 },
            { title: 'Current Health', dataIndex: 'status', width: 150, render: (value: HealthStatus) => <HealthStatusTag status={value} /> },
            { title: 'Latest Node', dataIndex: 'last_relay_node_id', width: 160, render: (value: number | null, row: Socks5Resource) => row.last_relay_node_name ?? (value ? nodeDisplayName(value, nodeNames) : '—') },
            { title: 'Exit IP', dataIndex: 'detected_exit_ip', width: 150, render: (value: string | null) => value ?? '—' },
            { title: 'Country', dataIndex: 'detected_country', width: 100, render: (value: string | null) => value ?? '—' },
            { title: 'Latency', dataIndex: 'latency_ms', width: 100, render: latency },
            { title: 'Failure Streak', dataIndex: 'consecutive_failures', width: 120 },
            { title: 'Last Checked', dataIndex: 'last_check_at', width: 190, render: (value: string | null) => value ?? '—' },
            { title: 'Truth Scope', width: 130, render: () => <Tag color="blue">CURRENT</Tag> },
          ]}
        />
        <Space style={{ width: '100%', justifyContent: 'space-between', marginTop: 16 }}>
          <Typography.Text type="secondary">{resources.data.total} Resources · page {page}</Typography.Text>
          <Space>
            <Button disabled={page === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>Previous</Button>
            <Button disabled={!hasNext} onClick={() => setPage((value) => value + 1)}>Next</Button>
          </Space>
        </Space>
      </>}

      <Drawer
        title={`Current Health · ${selected?.name ?? ''}`}
        open={selected !== null}
        onClose={() => setSelected(null)}
        size="min(920px, 96vw)"
        destroyOnHidden
      >
        {selected ? (
          <Space orientation="vertical" size="large" style={{ width: '100%' }}>
            <Typography.Text type="secondary">
              Current Health Truth for this Resource. These values are not substituted into historical Job Items.
            </Typography.Text>
            {detail.health.loading ? <HealthLoadingState /> : detail.health.error ? (
              <HealthErrorState error={detail.health.error} onRetry={() => void detail.reload()} />
            ) : detail.health.data.length === 0 ? <HealthEmptyState kind="nodes" /> : (
              <Table<Socks5Health>
                rowKey="relay_node_id"
                size="small"
                pagination={false}
                scroll={{ x: 1050 }}
                dataSource={detail.health.data}
                columns={[
                  { title: 'Relay Node', dataIndex: 'relay_node_id', render: (value: number) => nodeDisplayName(value, nodeNames) },
                  { title: 'Current Health', dataIndex: 'status', render: (value: HealthStatus) => <HealthStatusTag status={value} /> },
                  { title: 'Exit IP', dataIndex: 'exit_ip', render: (value: string | null) => value ?? '—' },
                  { title: 'Country', dataIndex: 'country', render: (value: string | null) => value ?? '—' },
                  { title: 'TCP', dataIndex: 'tcp_latency_ms', render: latency },
                  { title: 'Handshake', dataIndex: 'handshake_latency_ms', render: latency },
                  { title: 'Connect', dataIndex: 'connect_latency_ms', render: latency },
                  { title: 'Total', dataIndex: 'total_latency_ms', render: latency },
                  { title: 'Failure Streak', dataIndex: 'consecutive_failures' },
                  { title: 'Checked At', dataIndex: 'checked_at' },
                ]}
              />
            )}

            <Descriptions bordered size="small" column={1} items={[
              { key: 'resource', label: 'Resource', children: selected.name },
              { key: 'projection', label: 'List Projection', children: <HealthStatusTag status={selected.status} /> },
              { key: 'checked', label: 'Projection Checked At', children: selected.last_check_at ?? '—' },
            ]} />

            <Typography.Title level={5}>Check History · latest 50</Typography.Title>
            {detail.history.loading ? <HealthLoadingState /> : detail.history.error ? (
              <HealthErrorState error={detail.history.error} onRetry={() => void detail.reload()} />
            ) : detail.history.data.length === 0 ? <HealthEmptyState kind="history" /> : (
              <Table<ResourceHealthHistoryRecord>
                rowKey="id"
                size="small"
                pagination={false}
                scroll={{ x: 1000 }}
                dataSource={detail.history.data}
                columns={[
                  { title: 'Relay Node', dataIndex: 'relay_node_id', render: (value: number) => nodeDisplayName(value, nodeNames) },
                  { title: 'Health', dataIndex: 'status', render: (value: HealthStatus) => <HealthStatusTag status={value} /> },
                  { title: 'Exit IP', dataIndex: 'exit_ip', render: (value: string | null) => value ?? '—' },
                  { title: 'Country', dataIndex: 'country', render: (value: string | null) => value ?? '—' },
                  { title: 'Total Latency', dataIndex: 'total_latency_ms', render: latency },
                  { title: 'Error', render: (_: unknown, row: ResourceHealthHistoryRecord) => row.error_code ? `${row.error_code}: ${row.safe_error_message ?? '—'}` : '—' },
                  { title: 'Checked At', dataIndex: 'checked_at' },
                ]}
              />
            )}
          </Space>
        ) : null}
      </Drawer>
    </Card>
  );
}
