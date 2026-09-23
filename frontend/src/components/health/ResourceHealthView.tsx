import { useState } from 'react';
import { Button, Card, Descriptions, Drawer, Input, Select, Space, Table, Tag, Typography } from 'antd';
import type { HealthStatus, ResourceHealthHistoryRecord } from '../../api/health';
import type { Socks5Health, Socks5Resource } from '../../api/types';
import { useResourceHealthDetail, useResourcePage } from '../../hooks/useHealthReadModel';
import { HealthEmptyState, HealthErrorState, HealthLoadingState } from './HealthStates';
import { HealthStatusTag } from './HealthStatus';
import { nodeDisplayName } from './healthDisplay';
import { useHealthLocale } from './healthLocale';

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
  const { copy: c, healthStatus } = useHealthLocale();
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
        <Input.Search placeholder={c.searchResource} allowClear style={{ width: 260 }} onSearch={applySearch} />
        <Select<HealthStatus>
          allowClear
          aria-label={c.resourceHealthStatus}
          placeholder={c.healthStatuses}
          style={{ width: 190 }}
          options={HEALTH_STATUSES.map((value) => ({ value, label: healthStatus(value) }))}
          onChange={(value) => { setPage(1); setStatus(value); }}
        />
        <Typography.Text type="secondary">{c.currentProjectionHint}</Typography.Text>
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
            { title: c.resource, dataIndex: 'name', width: 180 },
            { title: c.currentHealth, dataIndex: 'status', width: 150, render: (value: HealthStatus) => <HealthStatusTag status={value} /> },
            { title: c.latestNode, dataIndex: 'last_relay_node_id', width: 160, render: (value: number | null, row: Socks5Resource) => row.last_relay_node_name ?? (value ? nodeDisplayName(value, nodeNames) : '—') },
            { title: c.exitIp, dataIndex: 'detected_exit_ip', width: 150, render: (value: string | null) => value ?? '—' },
            { title: c.country, dataIndex: 'detected_country', width: 100, render: (value: string | null) => value ?? '—' },
            { title: c.latency, dataIndex: 'latency_ms', width: 100, render: latency },
            { title: c.failureStreak, dataIndex: 'consecutive_failures', width: 120 },
            { title: c.lastChecked, dataIndex: 'last_check_at', width: 190, render: (value: string | null) => value ?? '—' },
            { title: c.truthScope, width: 130, render: () => <Tag color="blue">{c.current}</Tag> },
          ]}
        />
        <Space style={{ width: '100%', justifyContent: 'space-between', marginTop: 16 }}>
          <Typography.Text type="secondary">{resources.data.total} {c.resourcePageSummary} {page} {c.pageSuffix}</Typography.Text>
          <Space>
            <Button disabled={page === 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>{c.previous}</Button>
            <Button disabled={!hasNext} onClick={() => setPage((value) => value + 1)}>{c.next}</Button>
          </Space>
        </Space>
      </>}

      <Drawer
        title={`${c.currentHealthTitle} · ${selected?.name ?? ''}`}
        open={selected !== null}
        onClose={() => setSelected(null)}
        size="min(920px, 96vw)"
        destroyOnHidden
      >
        {selected ? (
          <Space orientation="vertical" size="large" style={{ width: '100%' }}>
            <Typography.Text type="secondary">
              {c.currentHealthDescription}
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
                  { title: c.relayNode, dataIndex: 'relay_node_id', render: (value: number) => nodeDisplayName(value, nodeNames) },
                  { title: c.currentHealth, dataIndex: 'status', render: (value: HealthStatus) => <HealthStatusTag status={value} /> },
                  { title: c.exitIp, dataIndex: 'exit_ip', render: (value: string | null) => value ?? '—' },
                  { title: c.country, dataIndex: 'country', render: (value: string | null) => value ?? '—' },
                  { title: c.tcp, dataIndex: 'tcp_latency_ms', render: latency },
                  { title: c.handshake, dataIndex: 'handshake_latency_ms', render: latency },
                  { title: c.connect, dataIndex: 'connect_latency_ms', render: latency },
                  { title: c.total, dataIndex: 'total_latency_ms', render: latency },
                  { title: c.failureStreak, dataIndex: 'consecutive_failures' },
                  { title: c.checkedAt, dataIndex: 'checked_at' },
                ]}
              />
            )}

            <Descriptions bordered size="small" column={1} items={[
              { key: 'resource', label: c.resource, children: selected.name },
              { key: 'projection', label: c.listProjection, children: <HealthStatusTag status={selected.status} /> },
              { key: 'checked', label: c.projectionCheckedAt, children: selected.last_check_at ?? '—' },
            ]} />

            <Typography.Title level={5}>{c.checkHistory}</Typography.Title>
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
                  { title: c.relayNode, dataIndex: 'relay_node_id', render: (value: number) => nodeDisplayName(value, nodeNames) },
                  { title: c.health, dataIndex: 'status', render: (value: HealthStatus) => <HealthStatusTag status={value} /> },
                  { title: c.exitIp, dataIndex: 'exit_ip', render: (value: string | null) => value ?? '—' },
                  { title: c.country, dataIndex: 'country', render: (value: string | null) => value ?? '—' },
                  { title: c.totalLatency, dataIndex: 'total_latency_ms', render: latency },
                  { title: c.error, render: (_: unknown, row: ResourceHealthHistoryRecord) => row.error_code ? `${row.error_code}: ${row.safe_error_message ?? '—'}` : '—' },
                  { title: c.checkedAt, dataIndex: 'checked_at' },
                ]}
              />
            )}
          </Space>
        ) : null}
      </Drawer>
    </Card>
  );
}
