import { useEffect, useMemo, useState } from 'react';
import {
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  message,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import { ApiOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import api from '../api/client';
import type {
  ApiEnvelope,
  DeviceGroup,
  Socks5RelayRule,
  Socks5Resource,
} from '../api/types';
import { formatBytes } from '../utils/format';

type ResourceForm = {
  name: string;
  host: string;
  port: number;
  username?: string;
  password?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  isp?: string;
  remark?: string;
  enabled: boolean;
};

type RuleForm = {
  name: string;
  device_group_in: number;
  listen_port?: number;
  socks5_resource_id: number;
  relay_username?: string;
  relay_password?: string;
  remote_dns: boolean;
  enabled: boolean;
};

export default function Socks5() {
  const [resources, setResources] = useState<Socks5Resource[]>([]);
  const [rules, setRules] = useState<Socks5RelayRule[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [resourceOpen, setResourceOpen] = useState(false);
  const [ruleOpen, setRuleOpen] = useState(false);
  const [editing, setEditing] = useState<Socks5Resource | null>(null);
  const [editingRule, setEditingRule] = useState<Socks5RelayRule | null>(null);
  const [credentialRule, setCredentialRule] = useState<Socks5RelayRule | null>(null);
  const [resourceForm] = Form.useForm<ResourceForm>();
  const [ruleForm] = Form.useForm<RuleForm>();
  const [credentialForm] = Form.useForm<{ username: string; password: string }>();

  const load = async () => {
    setLoading(true);
    try {
      const [resourceResponse, ruleResponse, groupResponse] = await Promise.all([
        api.get<unknown, ApiEnvelope<Socks5Resource[]>>('/admin/socks5-resources'),
        api.get<unknown, ApiEnvelope<Socks5RelayRule[]>>('/admin/socks5-rules'),
        api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
      ]);
      if (resourceResponse.code !== 0) throw new Error(resourceResponse.message);
      if (ruleResponse.code !== 0) throw new Error(ruleResponse.message);
      if (groupResponse.code !== 0) throw new Error(groupResponse.message);
      setResources(resourceResponse.data ?? []);
      setRules(ruleResponse.data ?? []);
      setGroups((groupResponse.data ?? []).filter((group) => group.group_type === 'in'));
    } catch (error) {
      message.error(error instanceof Error ? error.message : '加载 SOCKS5 数据失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const groupNames = useMemo(
    () => new Map(groups.map((group) => [group.id, group.name])),
    [groups],
  );

  const saveResource = async (values: ResourceForm) => {
    const payload: Record<string, unknown> = {
      ...values,
      password: values.password || undefined,
    };
    if (!editing || values.username?.trim()) payload.username = values.username?.trim() || null;
    const response = editing
      ? await api.put<unknown, ApiEnvelope<Socks5Resource>>(
          `/admin/socks5-resources/${editing.id}`,
          payload,
        )
      : await api.post<unknown, ApiEnvelope<Socks5Resource>>(
          '/admin/socks5-resources',
          payload,
        );
    if (response.code !== 0) throw new Error(response.message);
    message.success(editing ? 'SOCKS5 资源已更新' : 'SOCKS5 资源已创建');
    setResourceOpen(false);
    setEditing(null);
    resourceForm.resetFields();
    await load();
  };

  const saveRule = async (values: RuleForm) => {
    const response = editingRule
      ? await api.put<unknown, ApiEnvelope<Socks5RelayRule>>(
          `/admin/socks5-rules/${editingRule.rule_id}`,
          {
            name: values.name,
            device_group_in: values.device_group_in,
            listen_port: values.listen_port,
            socks5_resource_id: values.socks5_resource_id,
            remote_dns: values.remote_dns,
            enabled: values.enabled,
          },
        )
      : await api.post<unknown, ApiEnvelope<Socks5RelayRule>>(
          '/admin/socks5-rules',
          { ...values, allow_no_auth: false },
        );
    if (response.code !== 0) throw new Error(response.message);
    message.success(editingRule ? 'SOCKS5 中转规则已更新' : 'SOCKS5 中转规则已创建');
    setRuleOpen(false);
    setEditingRule(null);
    ruleForm.resetFields();
    await load();
  };

  const toggleResource = async (record: Socks5Resource, enabled: boolean) => {
    const response = await api.post<unknown, ApiEnvelope<null>>(
      `/admin/socks5-resources/${record.id}/enabled/${enabled}`,
    );
    if (response.code !== 0) return message.error(response.message);
    await load();
  };

  const toggleRule = async (record: Socks5RelayRule, enabled: boolean) => {
    const response = await api.post<unknown, ApiEnvelope<null>>(
      `/admin/socks5-rules/${record.rule_id}/enabled/${enabled}`,
    );
    if (response.code !== 0) return message.error(response.message);
    await load();
  };

  const deleteResource = async (id: number) => {
    const response = await api.delete<unknown, ApiEnvelope<null>>(
      `/admin/socks5-resources/${id}`,
    );
    if (response.code !== 0) return message.error(response.message);
    message.success('SOCKS5 资源已删除');
    await load();
  };

  const deleteRule = async (id: number) => {
    const response = await api.delete<unknown, ApiEnvelope<null>>(
      `/admin/socks5-rules/${id}`,
    );
    if (response.code !== 0) return message.error(response.message);
    message.success('SOCKS5 中转规则已删除');
    await load();
  };

  const resetCredential = async (values: { username: string; password: string }) => {
    if (!credentialRule) return;
    const response = await api.put<unknown, ApiEnvelope<null>>(
      `/admin/socks5-rules/${credentialRule.rule_id}/credential`,
      values,
    );
    if (response.code !== 0) return message.error(response.message);
    message.success('入口凭据已重置');
    setCredentialRule(null);
    credentialForm.resetFields();
    await load();
  };

  const resourceColumns = [
    { title: '名称', dataIndex: 'name' },
    {
      title: 'SOCKS5 地址',
      render: (_: unknown, row: Socks5Resource) => `${row.host}:${row.port}`,
    },
    {
      title: '上游认证',
      render: (_: unknown, row: Socks5Resource) =>
        row.username_masked ? `${row.username_masked} / ••••••••` : '无认证',
    },
    {
      title: '地区',
      render: (_: unknown, row: Socks5Resource) =>
        [row.country_code, row.region, row.city].filter(Boolean).join(' · ') || '-',
    },
    {
      title: '检测状态',
      render: (_: unknown, row: Socks5Resource) => (
        <Tag color={row.status === 'ONLINE' ? 'green' : row.status === 'UNKNOWN' ? 'default' : 'red'}>
          {row.status}
        </Tag>
      ),
    },
    { title: '出口 IP', dataIndex: 'detected_exit_ip', render: (value: string | null) => value || '-' },
    {
      title: '启用',
      render: (_: unknown, row: Socks5Resource) => (
        <Switch checked={row.enabled} onChange={(value) => void toggleResource(row, value)} />
      ),
    },
    {
      title: '操作',
      render: (_: unknown, row: Socks5Resource) => (
        <Space>
          <Button
            size="small"
            onClick={() => {
              setEditing(row);
              resourceForm.setFieldsValue({
                name: row.name,
                host: row.host,
                port: row.port,
                country: row.country,
                country_code: row.country_code,
                region: row.region,
                city: row.city,
                isp: row.isp,
                remark: row.remark,
                enabled: row.enabled,
              });
              setResourceOpen(true);
            }}
          >
            编辑
          </Button>
          <Popconfirm title="确定删除该资源？" onConfirm={() => void deleteResource(row.id)}>
            <Button size="small" danger>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const ruleColumns = [
    { title: '规则名称', dataIndex: 'name' },
    {
      title: '入口',
      render: (_: unknown, row: Socks5RelayRule) =>
        `${groupNames.get(row.device_group_in) ?? `#${row.device_group_in}`} · ${row.proxy_address}`,
    },
    { title: '上游资源', dataIndex: 'resource_name' },
    { title: '出口 IP', dataIndex: 'detected_exit_ip', render: (value: string | null) => value || '-' },
    { title: '入口账号', dataIndex: 'relay_username_masked', render: (value: string | null) => value || '-' },
    { title: '流量', dataIndex: 'traffic_used', render: (value: number) => formatBytes(value) },
    {
      title: '启用',
      render: (_: unknown, row: Socks5RelayRule) => (
        <Switch checked={!row.paused} onChange={(value) => void toggleRule(row, value)} />
      ),
    },
    {
      title: '操作',
      render: (_: unknown, row: Socks5RelayRule) => (
        <Space>
          <Button size="small" onClick={() => {
            setEditingRule(row);
            ruleForm.setFieldsValue({
              name: row.name,
              device_group_in: row.device_group_in,
              listen_port: row.listen_port,
              socks5_resource_id: row.socks5_resource_id,
              remote_dns: row.remote_dns,
              enabled: !row.paused,
            });
            setRuleOpen(true);
          }}>编辑</Button>
          <Button size="small" onClick={() => {
            setCredentialRule(row);
            credentialForm.setFieldsValue({ username: '', password: '' });
          }}>重置凭据</Button>
          <Popconfirm title="确定删除该规则？" onConfirm={() => void deleteRule(row.rule_id)}>
            <Button size="small" danger>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Title level={2} className="rp-page-title" style={{ margin: 0 }}>
          <ApiOutlined /> SOCKS5 中转
        </Typography.Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>刷新</Button>
      </Space>
      <Card>
        <Tabs
          items={[
            {
              key: 'resources',
              label: 'SOCKS5 资源',
              children: (
                <>
                  <Button
                    type="primary"
                    icon={<PlusOutlined />}
                    style={{ marginBottom: 16 }}
                    onClick={() => {
                      setEditing(null);
                      resourceForm.resetFields();
                      resourceForm.setFieldsValue({ enabled: true });
                      setResourceOpen(true);
                    }}
                  >
                    添加资源
                  </Button>
                  <Table rowKey="id" loading={loading} dataSource={resources} columns={resourceColumns} scroll={{ x: 1100 }} />
                </>
              ),
            },
            {
              key: 'rules',
              label: 'SOCKS5 中转规则',
              children: (
                <>
                  <Button
                    type="primary"
                    icon={<PlusOutlined />}
                    style={{ marginBottom: 16 }}
                    onClick={() => {
                      setEditingRule(null);
                      ruleForm.resetFields();
                      ruleForm.setFieldsValue({ remote_dns: true, enabled: true });
                      setRuleOpen(true);
                    }}
                  >
                    添加规则
                  </Button>
                  <Table rowKey="rule_id" loading={loading} dataSource={rules} columns={ruleColumns} scroll={{ x: 900 }} />
                </>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        title={editing ? '编辑 SOCKS5 资源' : '添加 SOCKS5 资源'}
        open={resourceOpen}
        onCancel={() => {
          resourceForm.resetFields();
          setEditing(null);
          setResourceOpen(false);
        }}
        onOk={() => resourceForm.submit()}
        destroyOnHidden
      >
        <Form form={resourceForm} layout="vertical" onFinish={(values) => void saveResource(values)}>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="host" label="主机" rules={[{ required: true }]} style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="port" label="端口" rules={[{ required: true }]}><InputNumber min={1} max={65535} /></Form.Item>
          </Space.Compact>
          <Form.Item name="username" label="上游用户名"><Input placeholder={editing?.username_masked ?? '留空表示无认证'} /></Form.Item>
          <Form.Item name="password" label="上游密码" extra={editing ? '留空保留原密码' : undefined}><Input.Password autoComplete="new-password" /></Form.Item>
          <Space.Compact block>
            <Form.Item name="country" label="国家" style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="country_code" label="国家代码" style={{ width: 120 }}><Input maxLength={2} /></Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="region" label="地区" style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="city" label="城市" style={{ flex: 1 }}><Input /></Form.Item>
          </Space.Compact>
          <Form.Item name="isp" label="ISP"><Input /></Form.Item>
          <Form.Item name="remark" label="备注"><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal
        title={editingRule ? '编辑 SOCKS5 中转规则' : '添加 SOCKS5 中转规则'}
        open={ruleOpen}
        onCancel={() => {
          ruleForm.resetFields();
          setEditingRule(null);
          setRuleOpen(false);
        }}
        onOk={() => ruleForm.submit()}
        destroyOnHidden
      >
        <Form form={ruleForm} layout="vertical" onFinish={(values) => void saveRule(values)}>
          <Form.Item name="name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="device_group_in" label="入口节点分组" rules={[{ required: true }]}>
            <Select options={groups.map((group) => ({ value: group.id, label: group.name }))} />
          </Form.Item>
          <Form.Item
            name="listen_port"
            label="入口端口"
            extra={editingRule ? undefined : '留空时从该节点分组端口池自动分配'}
            rules={editingRule ? [{ required: true }] : undefined}
          >
            <InputNumber min={1} max={65535} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="socks5_resource_id" label="上游 SOCKS5" rules={[{ required: true }]}>
            <Select options={resources.filter((item) => item.enabled).map((item) => ({ value: item.id, label: `${item.name} (${item.host}:${item.port})` }))} />
          </Form.Item>
          {!editingRule && (
            <>
              <Form.Item name="relay_username" label="客户端入口用户名" rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
              <Form.Item name="relay_password" label="客户端入口密码" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
            </>
          )}
          <Form.Item name="remote_dns" label="域名交由上游 SOCKS5 解析" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="立即启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
      <Modal
        title={`重置入口凭据${credentialRule ? ` · ${credentialRule.name}` : ''}`}
        open={credentialRule !== null}
        onCancel={() => {
          credentialForm.resetFields();
          setCredentialRule(null);
        }}
        onOk={() => credentialForm.submit()}
        destroyOnHidden
      >
        <Form form={credentialForm} layout="vertical" onFinish={(values) => void resetCredential(values)}>
          <Form.Item name="username" label="新用户名" rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="password" label="新密码" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
