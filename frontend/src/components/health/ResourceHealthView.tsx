import { useState } from 'react';
import { Card, Descriptions, Drawer, Input, Select, Space, Table, Tag, Typography } from 'antd';
import type { HealthStatus } from '../../api/health';
import type { Socks5Resource } from '../../api/types';
import { HealthEmptyState } from './HealthStates';
import { HealthStatusTag } from './HealthStatus';

interface ResourceHealthViewProps {
  resources: Socks5Resource[];
  loading?: boolean;
}

export function ResourceHealthView({ resources, loading = false }: ResourceHealthViewProps) {
  const [selected, setSelected] = useState<Socks5Resource | null>(null);

  return (
    <Card>
      <Space wrap style={{ marginBottom: 16 }}>
        <Input.Search placeholder="Search Resource" disabled style={{ width: 260 }} />
        <Select<HealthStatus> placeholder="Health Status" disabled style={{ width: 190 }} />
        <Typography.Text type="secondary">Filters and current Health Truth data are connected in F2.</Typography.Text>
      </Space>
      <Table
        rowKey="id"
        loading={loading}
        dataSource={resources}
        pagination={false}
        scroll={{ x: 1200 }}
        locale={{ emptyText: <HealthEmptyState kind="resources" /> }}
        onRow={(resource) => ({ onClick: () => setSelected(resource), style: { cursor: 'pointer' } })}
        columns={[
          { title: 'Resource', dataIndex: 'name', width: 180 },
          { title: 'Current Health', dataIndex: 'status', width: 150, render: (status: HealthStatus) => <HealthStatusTag status={status} /> },
          { title: 'Latest Node', dataIndex: 'last_relay_node_name', width: 160, render: (value: string | null, row: Socks5Resource) => value ?? (row.last_relay_node_id ? `Node #${row.last_relay_node_id}` : '—') },
          { title: 'Exit IP', dataIndex: 'detected_exit_ip', width: 150, render: (value: string | null) => value ?? '—' },
          { title: 'Country', dataIndex: 'detected_country', width: 100, render: (value: string | null) => value ?? '—' },
          { title: 'Latency', dataIndex: 'latency_ms', width: 100, render: (value: number | null) => value === null ? '—' : `${value} ms` },
          { title: 'Failure Streak', dataIndex: 'consecutive_failures', width: 120 },
          { title: 'Last Checked', dataIndex: 'last_check_at', width: 190, render: (value: string | null) => value ?? '—' },
          { title: 'Truth Scope', width: 130, render: () => <Tag color="blue">CURRENT</Tag> },
        ]}
      />

      <Drawer
        title={`Resource Health · ${selected?.name ?? ''}`}
        open={selected !== null}
        onClose={() => setSelected(null)}
        size="min(760px, 96vw)"
        destroyOnHidden
      >
        {selected ? (
          <Space orientation="vertical" size="large" style={{ width: '100%' }}>
            <Typography.Text type="secondary">
              This is the current Resource Health Truth, not an exact historical Job result.
            </Typography.Text>
            <Descriptions bordered size="small" column={1} items={[
              { key: 'status', label: 'Current Health', children: <HealthStatusTag status={selected.status} /> },
              { key: 'node', label: 'Latest Node', children: selected.last_relay_node_name ?? (selected.last_relay_node_id ? `Node #${selected.last_relay_node_id}` : '—') },
              { key: 'exit', label: 'Exit IP', children: selected.detected_exit_ip ?? '—' },
              { key: 'country', label: 'Country', children: selected.detected_country ?? '—' },
              { key: 'latency', label: 'Latency', children: selected.latency_ms === null ? '—' : `${selected.latency_ms} ms` },
              { key: 'checked', label: 'Last Checked', children: selected.last_check_at ?? '—' },
            ]} />
            <HealthEmptyState kind="history" />
          </Space>
        ) : null}
      </Drawer>
    </Card>
  );
}
