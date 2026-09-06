import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  InputNumber,
  message,
  Modal,
  Popconfirm,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  Upload,
  Row,
} from 'antd';
import { ApiOutlined, PlusOutlined, ReloadOutlined, ThunderboltOutlined, UploadOutlined } from '@ant-design/icons';
import api from '../api/client';
import type {
  ApiEnvelope,
  DeviceGroup,
  RelayNode,
  Socks5CheckResponse,
  Socks5Health,
  Socks5ImportPreview,
  Socks5RelayRule,
  Socks5Resource,
  Socks5ResourcePage,
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

type ResourceChoice = {
  value: number;
  label: string;
};

const countryMismatch = (declared?: string | null, detected?: string | null) =>
  Boolean(
    declared
      && detected
      && declared.length === 2
      && detected.length === 2
      && declared.toUpperCase() !== detected.toUpperCase(),
  );

export default function Socks5() {
  const [resources, setResources] = useState<Socks5Resource[]>([]);
  const [rules, setRules] = useState<Socks5RelayRule[]>([]);
  const [groups, setGroups] = useState<DeviceGroup[]>([]);
  const [relayNodes, setRelayNodes] = useState<RelayNode[]>([]);
  const [loading, setLoading] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>();
  const [countryFilter, setCountryFilter] = useState('');
  const [detectedFilter, setDetectedFilter] = useState('');
  const [tagFilter, setTagFilter] = useState('');
  const [enabledFilter, setEnabledFilter] = useState<boolean>();
  const [selectedIds, setSelectedIds] = useState<React.Key[]>([]);
  const [tagOpen, setTagOpen] = useState(false);
  const [tagText, setTagText] = useState('');
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [importPreview, setImportPreview] = useState<Socks5ImportPreview | null>(null);
  const [importing, setImporting] = useState(false);
  const [importStrategy, setImportStrategy] = useState('SKIP_DUPLICATE');
  const [checkOpen, setCheckOpen] = useState(false);
  const [checkIds, setCheckIds] = useState<number[]>([]);
  const [checkAll, setCheckAll] = useState(false);
  const [checkNodeId, setCheckNodeId] = useState<number>();
  const [checking, setChecking] = useState(false);
  const [checkResults, setCheckResults] = useState<Socks5CheckResponse[]>([]);
  const [detail, setDetail] = useState<Socks5Resource | null>(null);
  const [detailHealth, setDetailHealth] = useState<Socks5Health[]>([]);
  const [detailHistory, setDetailHistory] = useState<Socks5Health[]>([]);
  const [resourceOpen, setResourceOpen] = useState(false);
  const [ruleOpen, setRuleOpen] = useState(false);
  const [editing, setEditing] = useState<Socks5Resource | null>(null);
  const [editingRule, setEditingRule] = useState<Socks5RelayRule | null>(null);
  const [credentialRule, setCredentialRule] = useState<Socks5RelayRule | null>(null);
  const [resourceChoices, setResourceChoices] = useState<ResourceChoice[]>([]);
  const resourceChoiceRequest = useRef(0);
  const [resourceForm] = Form.useForm<ResourceForm>();
  const [ruleForm] = Form.useForm<RuleForm>();
  const [credentialForm] = Form.useForm<{ username: string; password: string }>();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
      if (search) params.set('search', search);
      if (statusFilter) params.set('status', statusFilter);
      if (countryFilter) params.set('country', countryFilter);
      if (detectedFilter) params.set('detected_country', detectedFilter);
      if (tagFilter) params.set('tag', tagFilter);
      if (enabledFilter != null) params.set('enabled', String(enabledFilter));
      const [resourceResponse, ruleResponse, groupResponse, nodeResponse] = await Promise.all([
        api.get<unknown, ApiEnvelope<Socks5ResourcePage>>(`/admin/socks5-resources/page?${params}`),
        api.get<unknown, ApiEnvelope<Socks5RelayRule[]>>('/admin/socks5-rules'),
        api.get<unknown, ApiEnvelope<DeviceGroup[]>>('/groups'),
        api.get<unknown, ApiEnvelope<RelayNode[]>>('/admin/relay-nodes'),
      ]);
      if (resourceResponse.code !== 0) throw new Error(resourceResponse.message);
      if (ruleResponse.code !== 0) throw new Error(ruleResponse.message);
      if (groupResponse.code !== 0) throw new Error(groupResponse.message);
      if (nodeResponse.code !== 0) throw new Error(nodeResponse.message);
      setResources(resourceResponse.data?.items ?? []);
      setTotal(resourceResponse.data?.total ?? 0);
      setRules(ruleResponse.data ?? []);
      setGroups((groupResponse.data ?? []).filter((group) => group.group_type === 'in'));
      setRelayNodes(nodeResponse.data ?? []);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '加载 SOCKS5 数据失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, statusFilter, countryFilter, detectedFilter, tagFilter, enabledFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const groupNames = useMemo(
    () => new Map(groups.map((group) => [group.id, group.name])),
    [groups],
  );

  const searchResourceChoices = useCallback(async (value: string) => {
    const requestId = ++resourceChoiceRequest.current;
    const params = new URLSearchParams({ page: '1', page_size: '50', enabled: 'true' });
    if (value.trim()) params.set('search', value.trim());
    const response = await api.get<unknown, ApiEnvelope<Socks5ResourcePage>>(
      `/admin/socks5-resources/page?${params}`,
    );
    if (requestId !== resourceChoiceRequest.current || response.code !== 0) return;
    setResourceChoices((response.data?.items ?? []).map((item) => ({
      value: item.id,
      label: `${item.name} (${item.host}:${item.port})`,
    })));
  }, []);

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

  const previewImport = async () => {
    setImporting(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<Socks5ImportPreview>>(
        '/admin/socks5-resources/import/preview', { text: importText },
      );
      if (response.code !== 0) throw new Error(response.message);
      setImportPreview(response.data);
    } catch (error) {
      message.error(error instanceof Error ? error.message : '导入预览失败');
    } finally {
      setImporting(false);
    }
  };

  const confirmImport = async () => {
    setImporting(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<{ created: number; updated: number; skipped: number; failed: number }>>(
        '/admin/socks5-resources/import/confirm', { text: importText, strategy: importStrategy },
      );
      if (response.code !== 0) throw new Error(response.message);
      const result = response.data;
      message.success(`导入完成：新增 ${result?.created ?? 0}，更新 ${result?.updated ?? 0}，跳过 ${result?.skipped ?? 0}，失败 ${result?.failed ?? 0}`);
      setImportOpen(false);
      setImportText('');
      setImportPreview(null);
      setPage(1);
      await load();
    } catch (error) {
      message.error(error instanceof Error ? error.message : '批量导入失败');
    } finally {
      setImporting(false);
    }
  };

  const runChecks = async () => {
    if (!checkNodeId || (!checkAll && checkIds.length === 0)) return;
    setChecking(true);
    try {
      const endpoint = checkAll
        ? '/admin/socks5-resources/check-all'
        : checkIds.length === 1
        ? `/admin/socks5-resources/${checkIds[0]}/check`
        : '/admin/socks5-resources/check-batch';
      const payload = checkAll
        ? {
            relay_node_id: checkNodeId,
            search: search || undefined,
            status: statusFilter,
            country: countryFilter || undefined,
            detected_country: detectedFilter || undefined,
            tag: tagFilter || undefined,
            enabled: enabledFilter,
          }
        : checkIds.length === 1
        ? { relay_node_id: checkNodeId }
        : { relay_node_id: checkNodeId, resource_ids: checkIds };
      const response = !checkAll && checkIds.length === 1
        ? await api.post<unknown, ApiEnvelope<Socks5CheckResponse>>(endpoint, payload)
        : await api.post<unknown, ApiEnvelope<Socks5CheckResponse[]>>(endpoint, payload);
      if (response.code !== 0) throw new Error(response.message);
      const data = response.data;
      setCheckResults(Array.isArray(data) ? data : data ? [data] : []);
      await load();
    } catch (error) {
      message.error(error instanceof Error ? error.message : '健康检测失败');
    } finally {
      setChecking(false);
    }
  };

  const runBulkAction = async (action: 'ENABLE' | 'DISABLE' | 'DELETE') => {
    if (selectedIds.length === 0) return;
    const response = await api.post<unknown, ApiEnvelope<{ affected: number; blockers: Array<{ resource_id: number; rule_id: number; reason: string }> }>>(
      '/admin/socks5-resources/bulk-action', { ids: selectedIds, action },
    );
    if (response.code !== 0) return message.error(response.message);
    if (response.data?.blockers.length) {
      message.warning(`${response.data.blockers.length} 个引用中的资源未删除`);
    } else {
      message.success(`已处理 ${response.data?.affected ?? 0} 条资源`);
    }
    setSelectedIds([]);
    await load();
  };

  const setBulkTags = async () => {
    const response = await api.post<unknown, ApiEnvelope<{ affected: number }>>(
      '/admin/socks5-resources/bulk-action', {
        ids: selectedIds,
        action: 'SET_TAGS',
        tags: tagText.split(',').map((tag) => tag.trim()).filter(Boolean),
      },
    );
    if (response.code !== 0) return message.error(response.message);
    message.success(`已更新 ${response.data?.affected ?? 0} 条资源的标签`);
    setTagOpen(false);
    setTagText('');
    await load();
  };

  const openDetail = async (resource: Socks5Resource) => {
    setDetail(resource);
    const [health, history] = await Promise.all([
      api.get<unknown, ApiEnvelope<Socks5Health[]>>(`/admin/socks5-resources/${resource.id}/health`),
      api.get<unknown, ApiEnvelope<Socks5Health[]>>(`/admin/socks5-resources/${resource.id}/check-history?limit=50`),
    ]);
    if (health.code === 0) setDetailHealth(health.data ?? []);
    if (history.code === 0) setDetailHistory(history.data ?? []);
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
        <Tag color={row.status === 'ONLINE' ? 'green' : row.status === 'UNKNOWN' ? 'default' : row.status === 'TIMEOUT' ? 'orange' : 'red'}>
          {row.status}
        </Tag>
      ),
    },
    { title: '出口 IP', dataIndex: 'detected_exit_ip', render: (value: string | null) => value || '-' },
    { title: 'Detected', render: (_: unknown, row: Socks5Resource) => (
      <Space size={4}>
        <span>{row.detected_country || '-'}</span>
        {countryMismatch(row.country_code, row.detected_country) ? <Tag color="orange">MISMATCH</Tag> : null}
      </Space>
    ) },
    { title: 'Latency', dataIndex: 'latency_ms', render: (value: number | null) => value == null ? '-' : `${value} ms` },
    { title: 'Relay Node', dataIndex: 'last_relay_node_name', render: (value: string | null) => value || '-' },
    { title: 'Last Check', dataIndex: 'last_check_at', render: (value: string | null) => value || '-' },
    { title: 'Tags', render: (_: unknown, row: Socks5Resource) => row.tags?.map((tag) => <Tag key={tag}>{tag}</Tag>) },
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
          <Button size="small" icon={<ThunderboltOutlined />} onClick={() => {
            setCheckAll(false); setCheckIds([row.id]); setCheckResults([]); setCheckOpen(true);
          }}>Test</Button>
          <Button size="small" onClick={() => void openDetail(row)}>详情</Button>
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
            setResourceChoices([{
              value: row.socks5_resource_id,
              label: `${row.resource_name} (#${row.socks5_resource_id})`,
            }]);
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
                  <Space wrap style={{ marginBottom: 16 }}>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => {
                      setEditing(null);
                      resourceForm.resetFields();
                      resourceForm.setFieldsValue({ enabled: true });
                      setResourceOpen(true);
                    }}>添加资源</Button>
                    <Button icon={<UploadOutlined />} onClick={() => setImportOpen(true)}>批量导入</Button>
                    <Input.Search allowClear placeholder="名称 / Host / Exit IP" style={{ width: 260 }}
                      onSearch={(value) => { setPage(1); setSearch(value.trim()); }} />
                    <Select allowClear placeholder="状态" style={{ width: 160 }} value={statusFilter}
                      onChange={(value) => { setPage(1); setStatusFilter(value); }}
                      options={['ONLINE', 'OFFLINE', 'AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'DISABLED', 'UNKNOWN'].map((value) => ({ value, label: value }))} />
                    <Input.Search allowClear placeholder="Country Code" style={{ width: 150 }} onSearch={(value) => { setPage(1); setCountryFilter(value.trim()); }} />
                    <Input.Search allowClear placeholder="Detected Country" style={{ width: 170 }} onSearch={(value) => { setPage(1); setDetectedFilter(value.trim()); }} />
                    <Input.Search allowClear placeholder="Tag" style={{ width: 130 }} onSearch={(value) => { setPage(1); setTagFilter(value.trim()); }} />
                    <Select allowClear placeholder="Enabled" style={{ width: 120 }} value={enabledFilter}
                      onChange={(value) => { setPage(1); setEnabledFilter(value); }}
                      options={[{ value: true, label: 'Enabled' }, { value: false, label: 'Disabled' }]} />
                    <Button disabled={!selectedIds.length} onClick={() => void runBulkAction('ENABLE')}>批量启用</Button>
                    <Button disabled={!selectedIds.length} onClick={() => void runBulkAction('DISABLE')}>批量禁用</Button>
                    <Button disabled={!selectedIds.length} onClick={() => setTagOpen(true)}>批量标签</Button>
                    <Popconfirm title="删除未被规则引用的选中资源？" onConfirm={() => void runBulkAction('DELETE')}>
                      <Button danger disabled={!selectedIds.length}>批量删除</Button>
                    </Popconfirm>
                    <Button icon={<ThunderboltOutlined />} disabled={!selectedIds.length} onClick={() => {
                      setCheckAll(false); setCheckIds(selectedIds.map(Number)); setCheckResults([]); setCheckOpen(true);
                    }}>批量检测</Button>
                    <Button icon={<ThunderboltOutlined />} disabled={total === 0 || total > 10000} onClick={() => {
                      setCheckAll(true); setCheckIds([]); setCheckResults([]); setCheckOpen(true);
                    }}>检测全部筛选结果 ({total})</Button>
                  </Space>
                  <Table rowKey="id" loading={loading} dataSource={resources} columns={resourceColumns} scroll={{ x: 1700 }}
                    rowSelection={{ selectedRowKeys: selectedIds, onChange: setSelectedIds }}
                    pagination={{ current: page, pageSize, total, showSizeChanger: true, pageSizeOptions: [20, 50, 100, 200],
                      onChange: (next, size) => { setPage(next); setPageSize(size); } }} />
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
                      void searchResourceChoices('');
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
            <Select
              showSearch
              filterOption={false}
              onSearch={(value) => void searchResourceChoices(value)}
              options={resourceChoices}
              placeholder="输入名称、Host 或 Exit IP 搜索"
            />
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

      <Modal title="批量导入 SOCKS5" width={820} open={importOpen} confirmLoading={importing}
        okText={importPreview ? '确认导入' : '生成预览'}
        onOk={() => void (importPreview ? confirmImport() : previewImport())}
        onCancel={() => { setImportOpen(false); setImportPreview(null); setImportText(''); }} destroyOnHidden>
        <Typography.Paragraph type="secondary">
          支持 host:port、host:port:user:password、user:password@host:port、socks5://user:password@host:port；单次最多 10000 条。
        </Typography.Paragraph>
        <Upload
          accept=".txt,.csv,text/plain"
          showUploadList={false}
          beforeUpload={(file) => {
            void file.text().then((text) => {
              setImportText(text);
              setImportPreview(null);
            });
            return false;
          }}
        >
          <Button icon={<UploadOutlined />} style={{ marginBottom: 12 }}>读取文本文件</Button>
        </Upload>
        <Input.TextArea rows={10} value={importText} onChange={(event) => {
          setImportText(event.target.value); setImportPreview(null);
        }} placeholder="每行一个 SOCKS5" />
        {importPreview ? (
          <>
            <Row gutter={12} style={{ marginTop: 16 }}>
              <Col span={4}><Statistic title="Total" value={importPreview.total} /></Col>
              <Col span={4}><Statistic title="Valid" value={importPreview.valid} /></Col>
              <Col span={4}><Statistic title="Invalid" value={importPreview.invalid} /></Col>
              <Col span={4}><Statistic title="Duplicate" value={importPreview.duplicate} /></Col>
              <Col span={4}><Statistic title="New" value={importPreview.new} /></Col>
            </Row>
            <Select value={importStrategy} onChange={setImportStrategy} style={{ width: 240, margin: '12px 0' }}
              options={[{ value: 'SKIP_DUPLICATE', label: '跳过重复' }, { value: 'UPDATE_CREDENTIAL', label: '更新重复项凭据' }]} />
            {importPreview.invalid_lines.length ? (
              <Table size="small" rowKey="line_number" pagination={{ pageSize: 5 }} dataSource={importPreview.invalid_lines}
                columns={[{ title: 'Line', dataIndex: 'line_number' }, { title: 'Masked', dataIndex: 'raw_masked' }, { title: 'Reason', dataIndex: 'error_reason' }]} />
            ) : null}
          </>
        ) : null}
      </Modal>

      <Modal title="批量设置标签" open={tagOpen} onOk={() => void setBulkTags()}
        onCancel={() => setTagOpen(false)} destroyOnHidden>
        <Input value={tagText} onChange={(event) => setTagText(event.target.value)} placeholder="例如 residential, us, provider-a" />
      </Modal>

      <Modal title={`SOCKS5 健康检测 · ${checkAll ? `全部筛选结果 (${total})` : `${checkIds.length} 个资源`}`} width={860} open={checkOpen}
        confirmLoading={checking} okText="Run" onOk={() => void runChecks()}
        onCancel={() => { setCheckOpen(false); setCheckResults([]); setCheckAll(false); }} destroyOnHidden>
        <Select style={{ width: '100%', marginBottom: 16 }} placeholder="选择执行检测的 Relay Node"
          value={checkNodeId} onChange={setCheckNodeId}
          options={relayNodes.map((node) => ({ value: node.id, disabled: !node.online || !node.enabled || !node.supports_socks5_check,
            label: `${node.name} · ${node.public_ip || '-'} · ${node.online ? node.supports_socks5_check ? 'ONLINE' : 'UPGRADE REQUIRED' : 'OFFLINE'}` }))} />
        {checkResults.length ? (
          <Table size="small" rowKey="resource_id" pagination={{ pageSize: 10 }} dataSource={checkResults}
            columns={[
              { title: 'Resource', dataIndex: 'resource_id' },
              { title: 'Outcome', dataIndex: 'outcome' },
              { title: 'Status', render: (_: unknown, row: Socks5CheckResponse) => row.result?.status ?? '-' },
              { title: 'TCP', render: (_: unknown, row: Socks5CheckResponse) => row.result?.tcp_latency_ms == null ? '-' : `${row.result.tcp_latency_ms} ms` },
              { title: 'Handshake', render: (_: unknown, row: Socks5CheckResponse) => row.result?.handshake_latency_ms == null ? '-' : `${row.result.handshake_latency_ms} ms` },
              { title: 'CONNECT', render: (_: unknown, row: Socks5CheckResponse) => row.result?.connect_latency_ms == null ? '-' : `${row.result.connect_latency_ms} ms` },
              { title: 'Exit IP', render: (_: unknown, row: Socks5CheckResponse) => row.result?.exit_ip ?? '-' },
              { title: 'Country', render: (_: unknown, row: Socks5CheckResponse) => row.result?.detected_country ?? '-' },
              { title: 'Error', render: (_: unknown, row: Socks5CheckResponse) => row.result?.error_code ?? '-' },
            ]} />
        ) : null}
      </Modal>

      <Modal title={`SOCKS5 Resource · ${detail?.name ?? ''}`} width={960} open={detail !== null} footer={null}
        onCancel={() => { setDetail(null); setDetailHealth([]); setDetailHistory([]); }} destroyOnHidden>
        {detail ? <Descriptions bordered size="small" column={2} items={[
          { key: 'endpoint', label: 'Endpoint', children: `${detail.host}:${detail.port}` },
          { key: 'credential', label: 'Credential', children: detail.username_masked ? `${detail.username_masked} / ••••••••` : 'No auth' },
          { key: 'country', label: 'Country', children: detail.country_code || detail.country || '-' },
          { key: 'detected', label: 'Detected', children: <Space>{detail.detected_country || '-'}{countryMismatch(detail.country_code, detail.detected_country) ? <Tag color="orange">MISMATCH</Tag> : null}</Space> },
          { key: 'rules', label: 'Rules', children: rules.filter((rule) => rule.socks5_resource_id === detail.id).map((rule) => rule.name).join(', ') || '-' },
          { key: 'remark', label: 'Remark', children: detail.remark || '-' },
        ]} /> : null}
        <Typography.Title level={5}>Node Health Matrix</Typography.Title>
        <Table size="small" pagination={false} rowKey="relay_node_id" dataSource={detailHealth} columns={[
          { title: 'Relay Node', render: (_: unknown, row: Socks5Health) => relayNodes.find((node) => node.id === row.relay_node_id)?.name ?? `#${row.relay_node_id}` },
          { title: 'Status', dataIndex: 'status' }, { title: 'Latency', dataIndex: 'total_latency_ms', render: (value: number | null) => value == null ? '-' : `${value} ms` },
          { title: 'Exit IP', dataIndex: 'exit_ip' }, { title: 'Country', render: (_: unknown, row: Socks5Health) => <Space>{row.country || '-'}{countryMismatch(detail?.country_code, row.country) ? <Tag color="orange">MISMATCH</Tag> : null}</Space> },
          { title: 'Failures', dataIndex: 'consecutive_failures' }, { title: 'Last Check', dataIndex: 'checked_at' },
        ]} />
        <Typography.Title level={5}>Check History</Typography.Title>
        <Table size="small" rowKey={(row) => `${row.relay_node_id}-${row.checked_at}`} dataSource={detailHistory} pagination={{ pageSize: 10 }} columns={[
          { title: 'Relay Node', render: (_: unknown, row: Socks5Health) => relayNodes.find((node) => node.id === row.relay_node_id)?.name ?? `#${row.relay_node_id}` },
          { title: 'Status', dataIndex: 'status' }, { title: 'Latency', dataIndex: 'total_latency_ms' },
          { title: 'Exit IP', dataIndex: 'exit_ip' }, { title: 'Error', dataIndex: 'error_code' }, { title: 'Checked At', dataIndex: 'checked_at' },
        ]} />
      </Modal>
    </div>
  );
}
