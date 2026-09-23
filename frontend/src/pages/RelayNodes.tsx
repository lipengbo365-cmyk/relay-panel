import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button, Card, Form, Input, InputNumber, message, Modal, Space, Switch, Table, Tag, Typography } from 'antd';
import { CloudServerOutlined, EditOutlined, ReloadOutlined } from '@ant-design/icons';
import api from '../api/client';
import type { ApiEnvelope, RelayNode } from '../api/types';
import { useI18n } from '../i18n/context';

type NodeForm = {
  name: string;
  country: string;
  country_code: string;
  region: string;
  city: string;
  provider: string;
  advertise_host: string;
  bandwidth_mbps: number;
  remark: string;
  tags_text: string;
  enabled: boolean;
};

export default function RelayNodes() {
  const { lang } = useI18n();
  const l = useMemo(() => lang === 'zh-CN' ? {
    loadFailed: '加载中转节点失败', name: '名称', country: '国家/地区', reportedIp: '节点上报 IP',
    advertisedHost: '客户端连接地址', provider: '服务商', online: '在线状态', onlineValue: '在线', offlineValue: '离线',
    lastSeen: '最后在线时间', connections: '连接数', nodeProtocol: '节点版本 / 协议', checkQueue: 'SOCKS5 检测队列',
    upgradeRequired: '需要升级', tags: '标签', actions: '操作', edit: '编辑', updated: '中转节点信息已更新',
    title: '中转节点', refresh: '刷新', editTitle: '编辑中转节点', countryCode: '国家代码', region: '地区', city: '城市',
    bandwidth: '带宽（Mbps）', remark: '备注', enabled: '启用', commaSeparated: '使用英文逗号分隔',
    advertisedHostHint: '客户端实际连接的 IPv4、IPv6 或域名；留空时使用节点上报的公网 IP。',
  } : {
    loadFailed: 'Failed to load Relay Nodes', name: 'Name', country: 'Country', reportedIp: 'Node-reported IP',
    advertisedHost: 'Advertised Host', provider: 'Provider', online: 'Online', onlineValue: 'ONLINE', offlineValue: 'OFFLINE',
    lastSeen: 'Last Seen', connections: 'Connections', nodeProtocol: 'Node / Protocol', checkQueue: 'SOCKS5 Check Queue',
    upgradeRequired: 'Upgrade required', tags: 'Tags', actions: 'Actions', edit: 'Edit', updated: 'Relay Node metadata updated',
    title: 'Relay Nodes', refresh: 'Refresh', editTitle: 'Edit Relay Node', countryCode: 'Country Code', region: 'Region', city: 'City',
    bandwidth: 'Bandwidth (Mbps)', remark: 'Remark', enabled: 'Enabled', commaSeparated: 'Comma separated',
    advertisedHostHint: 'Client-facing IPv4, IPv6, or DNS name. Leave blank to use the node-reported public IP.',
  }, [lang]);
  const [rows, setRows] = useState<RelayNode[]>([]);
  const [loading, setLoading] = useState(false);
  const [editing, setEditing] = useState<RelayNode | null>(null);
  const [form] = Form.useForm<NodeForm>();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get<unknown, ApiEnvelope<RelayNode[]>>('/admin/relay-nodes');
      if (response.code !== 0) throw new Error(response.message);
      setRows(response.data ?? []);
    } catch (error) {
      message.error(error instanceof Error ? error.message : l.loadFailed);
    } finally {
      setLoading(false);
    }
  }, [l.loadFailed]);

  useEffect(() => { void load(); }, [load]);

  const columns = useMemo(() => [
    { title: l.name, dataIndex: 'name' },
    { title: l.country, render: (_: unknown, row: RelayNode) => [row.country_code, row.country].filter(Boolean).join(' · ') || '-' },
    { title: l.reportedIp, dataIndex: 'public_ip', render: (value: string) => value || '-' },
    { title: l.advertisedHost, dataIndex: 'advertise_host', render: (value: string) => value || '-' },
    { title: l.provider, dataIndex: 'provider', render: (value: string) => value || '-' },
    { title: l.online, render: (_: unknown, row: RelayNode) => <Tag color={row.online ? 'green' : 'red'}>{row.online ? l.onlineValue : l.offlineValue}</Tag> },
    { title: l.lastSeen, dataIndex: 'last_seen_at' },
    { title: 'CPU', dataIndex: 'cpu', render: (value: number | null) => value == null ? '-' : `${value.toFixed(1)}%` },
    { title: 'RAM', dataIndex: 'ram', render: (value: number | null) => value == null ? '-' : `${value.toFixed(1)}%` },
    { title: l.connections, dataIndex: 'connections', render: (value: number | null) => value ?? '-' },
    { title: l.nodeProtocol, render: (_: unknown, row: RelayNode) => `${row.node_version || '-'} · v${row.config_protocol_version ?? '-'}` },
    { title: l.checkQueue, render: (_: unknown, row: RelayNode) => row.supports_socks5_check ? row.socks5_check_queue ?? 0 : <Tag color="orange">{l.upgradeRequired}</Tag> },
    { title: l.tags, render: (_: unknown, row: RelayNode) => row.tags.length ? row.tags.map((tag) => <Tag key={tag}>{tag}</Tag>) : '-' },
    {
      title: l.actions, fixed: 'right' as const,
      render: (_: unknown, row: RelayNode) => (
        <Button size="small" icon={<EditOutlined />} onClick={() => {
          setEditing(row);
          form.setFieldsValue({
            name: row.name, country: row.country, country_code: row.country_code,
            region: row.region, city: row.city, provider: row.provider,
            advertise_host: row.advertise_host,
            bandwidth_mbps: row.bandwidth_mbps, remark: row.remark,
            tags_text: row.tags.join(', '), enabled: row.enabled,
          });
        }}>{l.edit}</Button>
      ),
    },
  ], [form, l]);

  const save = async (values: NodeForm) => {
    if (!editing) return;
    const response = await api.put<unknown, ApiEnvelope<RelayNode>>(`/admin/relay-nodes/${editing.id}`, {
      ...values,
      tags: values.tags_text.split(',').map((tag) => tag.trim()).filter(Boolean),
      tags_text: undefined,
    });
    if (response.code !== 0) return message.error(response.message);
    message.success(l.updated);
    setEditing(null);
    form.resetFields();
    await load();
  };

  return (
    <div>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Title level={2} className="rp-page-title" style={{ margin: 0 }}>
          <CloudServerOutlined /> {l.title}
        </Typography.Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>{l.refresh}</Button>
      </Space>
      <Card>
        <Table rowKey="id" loading={loading} dataSource={rows} columns={columns} scroll={{ x: 1500 }} pagination={{ pageSize: 50 }} />
      </Card>
      <Modal title={`${l.editTitle}${editing ? ` · ${editing.name}` : ''}`} open={editing !== null}
        onCancel={() => { setEditing(null); form.resetFields(); }} onOk={() => form.submit()} destroyOnHidden>
        <Form form={form} layout="vertical" onFinish={(values) => void save(values)}>
          <Form.Item name="name" label={l.name} rules={[{ required: true }]}><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="country" label={l.country} style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="country_code" label={l.countryCode} style={{ width: 130 }}><Input maxLength={2} /></Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="region" label={l.region} style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="city" label={l.city} style={{ flex: 1 }}><Input /></Form.Item>
          </Space.Compact>
          <Form.Item name="provider" label={l.provider}><Input /></Form.Item>
          <Form.Item name="advertise_host" label={l.advertisedHost} extra={l.advertisedHostHint}><Input placeholder="proxy-us.example.com" /></Form.Item>
          <Form.Item name="bandwidth_mbps" label={l.bandwidth}><InputNumber min={0} style={{ width: '100%' }} /></Form.Item>
          <Form.Item name="tags_text" label={l.tags} extra={l.commaSeparated}><Input /></Form.Item>
          <Form.Item name="remark" label={l.remark}><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="enabled" label={l.enabled} valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
