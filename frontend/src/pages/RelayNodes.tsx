import { useEffect, useMemo, useState } from 'react';
import { Button, Card, Form, Input, InputNumber, message, Modal, Space, Switch, Table, Tag, Typography } from 'antd';
import { CloudServerOutlined, EditOutlined, ReloadOutlined } from '@ant-design/icons';
import api from '../api/client';
import type { ApiEnvelope, RelayNode } from '../api/types';

type NodeForm = {
  name: string;
  country: string;
  country_code: string;
  region: string;
  city: string;
  provider: string;
  bandwidth_mbps: number;
  remark: string;
  tags_text: string;
  enabled: boolean;
};

export default function RelayNodes() {
  const [rows, setRows] = useState<RelayNode[]>([]);
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState<RelayNode | null>(null);
  const [form] = Form.useForm<NodeForm>();

  const load = async () => {
    setLoading(true);
    try {
      const response = await api.get<unknown, ApiEnvelope<RelayNode[]>>('/admin/relay-nodes');
      if (response.code !== 0) throw new Error(response.message);
      setRows(response.data ?? []);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '加载 Relay Nodes 失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const columns = useMemo(() => [
    { title: 'Name', dataIndex: 'name' },
    { title: 'Country', render: (_: unknown, row: RelayNode) => [row.country_code, row.country].filter(Boolean).join(' · ') || '-' },
    { title: 'Node-reported IP', dataIndex: 'public_ip', render: (value: string) => value || '-' },
    { title: 'Provider', dataIndex: 'provider', render: (value: string) => value || '-' },
    { title: 'Online', render: (_: unknown, row: RelayNode) => <Tag color={row.online ? 'green' : 'red'}>{row.online ? 'ONLINE' : 'OFFLINE'}</Tag> },
    { title: 'Last Seen', dataIndex: 'last_seen_at' },
    { title: 'CPU', dataIndex: 'cpu', render: (value: number | null) => value == null ? '-' : `${value.toFixed(1)}%` },
    { title: 'RAM', dataIndex: 'ram', render: (value: number | null) => value == null ? '-' : `${value.toFixed(1)}%` },
    { title: 'Connections', dataIndex: 'connections', render: (value: number | null) => value ?? '-' },
    { title: 'Node / Protocol', render: (_: unknown, row: RelayNode) => `${row.node_version || '-'} · v${row.config_protocol_version ?? '-'}` },
    { title: 'SOCKS5 Check Queue', render: (_: unknown, row: RelayNode) => row.supports_socks5_check ? row.socks5_check_queue ?? 0 : <Tag color="orange">Upgrade required</Tag> },
    { title: 'Tags', render: (_: unknown, row: RelayNode) => row.tags.length ? row.tags.map((tag) => <Tag key={tag}>{tag}</Tag>) : '-' },
    {
      title: 'Actions', fixed: 'right' as const,
      render: (_: unknown, row: RelayNode) => (
        <Button size="small" icon={<EditOutlined />} onClick={() => {
          setEditing(row);
          form.setFieldsValue({
            name: row.name, country: row.country, country_code: row.country_code,
            region: row.region, city: row.city, provider: row.provider,
            bandwidth_mbps: row.bandwidth_mbps, remark: row.remark,
            tags_text: row.tags.join(', '), enabled: row.enabled,
          });
        }}>Edit</Button>
      ),
    },
  ], [form]);

  const save = async (values: NodeForm) => {
    if (!editing) return;
    const response = await api.put<unknown, ApiEnvelope<RelayNode>>(`/admin/relay-nodes/${editing.id}`, {
      ...values,
      tags: values.tags_text.split(',').map((tag) => tag.trim()).filter(Boolean),
      tags_text: undefined,
    });
    if (response.code !== 0) return message.error(response.message);
    message.success('Relay Node metadata updated');
    setEditing(null);
    form.resetFields();
    await load();
  };

  return (
    <div>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Title level={2} className="rp-page-title" style={{ margin: 0 }}>
          <CloudServerOutlined /> Relay Nodes
        </Typography.Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>Refresh</Button>
      </Space>
      <Card>
        <Table rowKey="id" loading={loading} dataSource={rows} columns={columns} scroll={{ x: 1500 }} pagination={{ pageSize: 50 }} />
      </Card>
      <Modal title={`Edit Relay Node${editing ? ` · ${editing.name}` : ''}`} open={editing !== null}
        onCancel={() => { setEditing(null); form.resetFields(); }} onOk={() => form.submit()} destroyOnHidden>
        <Form form={form} layout="vertical" onFinish={(values) => void save(values)}>
          <Form.Item name="name" label="Name" rules={[{ required: true }]}><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="country" label="Country" style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="country_code" label="Country Code" style={{ width: 130 }}><Input maxLength={2} /></Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="region" label="Region" style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="city" label="City" style={{ flex: 1 }}><Input /></Form.Item>
          </Space.Compact>
          <Form.Item name="provider" label="Provider"><Input /></Form.Item>
          <Form.Item name="bandwidth_mbps" label="Bandwidth (Mbps)"><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="tags_text" label="Tags" extra="Comma separated"><Input /></Form.Item>
          <Form.Item name="remark" label="Remark"><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="enabled" label="Enabled" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
