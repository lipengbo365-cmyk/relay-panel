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
import SmartRelayWizard from '../components/SmartRelayWizard';
import { useI18n } from '../i18n/context';
import { socks5DisplayText, socks5HealthStatusText, socks5SelectionModeText } from './socks5Locale';

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
  const { lang } = useI18n();
  const text = useCallback((zh: string, en: string) => socks5DisplayText(lang, zh, en), [lang]);
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
  const [smartRelayResource, setSmartRelayResource] = useState<Socks5Resource | null>(null);
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
      message.error(error instanceof Error ? error.message : text('加载 SOCKS5 数据失败', 'Failed to load SOCKS5 data'));
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search, statusFilter, countryFilter, detectedFilter, tagFilter, enabledFilter, text]);

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
    message.success(editing ? text('SOCKS5 资源已更新', 'SOCKS5 resource updated') : text('SOCKS5 资源已创建', 'SOCKS5 resource created'));
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
    message.success(editingRule ? text('SOCKS5 中转规则已更新', 'SOCKS5 relay rule updated') : text('SOCKS5 中转规则已创建', 'SOCKS5 relay rule created'));
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
    message.success(text('SOCKS5 资源已删除', 'SOCKS5 resource deleted'));
    await load();
  };

  const deleteRule = async (id: number) => {
    const response = await api.delete<unknown, ApiEnvelope<null>>(
      `/admin/socks5-rules/${id}`,
    );
    if (response.code !== 0) return message.error(response.message);
    message.success(text('SOCKS5 中转规则已删除', 'SOCKS5 relay rule deleted'));
    await load();
  };

  const resetCredential = async (values: { username: string; password: string }) => {
    if (!credentialRule) return;
    const response = await api.put<unknown, ApiEnvelope<null>>(
      `/admin/socks5-rules/${credentialRule.rule_id}/credential`,
      values,
    );
    if (response.code !== 0) return message.error(response.message);
    message.success(text('入口凭据已重置', 'Ingress credentials reset'));
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
      message.error(error instanceof Error ? error.message : text('导入预览失败', 'Import preview failed'));
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
      message.success(text(
        `导入完成：新增 ${result?.created ?? 0}，更新 ${result?.updated ?? 0}，跳过 ${result?.skipped ?? 0}，失败 ${result?.failed ?? 0}`,
        `Import complete: ${result?.created ?? 0} created, ${result?.updated ?? 0} updated, ${result?.skipped ?? 0} skipped, ${result?.failed ?? 0} failed`,
      ));
      setImportOpen(false);
      setImportText('');
      setImportPreview(null);
      setPage(1);
      await load();
    } catch (error) {
      message.error(error instanceof Error ? error.message : text('批量导入失败', 'Batch import failed'));
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
      message.error(error instanceof Error ? error.message : text('健康检测失败', 'Health check failed'));
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
      message.warning(text(`${response.data.blockers.length} 个引用中的资源未删除`, `${response.data.blockers.length} referenced resources were not deleted`));
    } else {
      message.success(text(`已处理 ${response.data?.affected ?? 0} 条资源`, `${response.data?.affected ?? 0} resources processed`));
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
    message.success(text(`已更新 ${response.data?.affected ?? 0} 条资源的标签`, `Tags updated for ${response.data?.affected ?? 0} resources`));
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
    { title: text('名称', 'Name'), dataIndex: 'name' },
    {
      title: text('SOCKS5 地址', 'SOCKS5 Endpoint'),
      render: (_: unknown, row: Socks5Resource) => `${row.host}:${row.port}`,
    },
    {
      title: text('上游认证', 'Upstream Authentication'),
      render: (_: unknown, row: Socks5Resource) =>
        row.username_masked ? `${row.username_masked} / ••••••••` : text('无认证', 'No authentication'),
    },
    {
      title: text('地区', 'Region'),
      render: (_: unknown, row: Socks5Resource) =>
        [row.country_code, row.region, row.city].filter(Boolean).join(' · ') || '-',
    },
    {
      title: text('最近一次检测', 'Latest Check'),
      render: (_: unknown, row: Socks5Resource) => (
        <Tag color={row.status === 'ONLINE' ? 'green' : row.status === 'UNKNOWN' ? 'default' : row.status === 'TIMEOUT' ? 'orange' : 'red'}>
          {socks5HealthStatusText(lang, row.status)}
        </Tag>
      ),
    },
    { title: text('出口 IP', 'Exit IP'), dataIndex: 'detected_exit_ip', render: (value: string | null) => value || '-' },
    { title: text('检测出口国家', 'Detected Country'), render: (_: unknown, row: Socks5Resource) => (
      <Space size={4}>
        <span>{row.detected_country || '-'}</span>
        {countryMismatch(row.country_code, row.detected_country) ? <Tag color="orange">{text('国家不一致', 'Country mismatch')}</Tag> : null}
      </Space>
    ) },
    { title: text('延迟', 'Latency'), dataIndex: 'latency_ms', render: (value: number | null) => value == null ? '-' : `${value} ms` },
    { title: text('检测节点', 'Check Node'), dataIndex: 'last_relay_node_name', render: (value: string | null) => value || '-' },
    { title: text('最近检测时间', 'Last Checked'), dataIndex: 'last_check_at', render: (value: string | null) => value || '-' },
    { title: text('标签', 'Tags'), render: (_: unknown, row: Socks5Resource) => row.tags?.map((tag) => <Tag key={tag}>{tag}</Tag>) },
    {
      title: text('启用', 'Enabled'),
      render: (_: unknown, row: Socks5Resource) => (
        <Switch checked={row.enabled} onChange={(value) => void toggleResource(row, value)} />
      ),
    },
    {
      title: text('操作', 'Actions'),
      render: (_: unknown, row: Socks5Resource) => (
        <Space>
          <Button size="small" icon={<ThunderboltOutlined />} onClick={() => {
            setCheckAll(false); setCheckIds([row.id]); setCheckResults([]); setCheckOpen(true);
          }}>{text('检测', 'Test')}</Button>
          <Button size="small" type="primary" disabled={!row.enabled} onClick={() => setSmartRelayResource(row)}>{text('创建中转', 'Create Relay')}</Button>
          <Button size="small" onClick={() => void openDetail(row)}>{text('详情', 'Details')}</Button>
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
            {text('编辑', 'Edit')}
          </Button>
          <Popconfirm title={text('确定删除该资源？', 'Delete this resource?')} onConfirm={() => void deleteResource(row.id)}>
            <Button size="small" danger>{text('删除', 'Delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const ruleColumns = [
    { title: text('规则名称', 'Rule Name'), dataIndex: 'name' },
    {
      title: text('入口', 'Ingress'),
      render: (_: unknown, row: Socks5RelayRule) =>
        `${groupNames.get(row.device_group_in) ?? `#${row.device_group_in}`} · ${row.proxy_address}`,
    },
    { title: text('上游资源', 'Upstream Resource'), dataIndex: 'resource_name' },
    { title: text('中转节点', 'Relay Node'), render: (_: unknown, row: Socks5RelayRule) => row.relay_node_name || (row.relay_node_id ? `#${row.relay_node_id}` : text('兼容模式 / 分组', 'Legacy / Group')) },
    { title: text('节点国家', 'Node Country'), dataIndex: 'relay_node_country_code', render: (value: string | null) => value || '-' },
    { title: text('选择方式', 'Selection'), dataIndex: 'selection_mode', render: (value: Socks5RelayRule['selection_mode']) => <Tag color={value === 'RECOMMENDED' ? 'blue' : undefined}>{socks5SelectionModeText(lang, value)}</Tag> },
    { title: text('出口 IP', 'Exit IP'), dataIndex: 'detected_exit_ip', render: (value: string | null) => value || '-' },
    { title: text('出口国家', 'Exit Country'), dataIndex: 'detected_country', render: (value: string | null) => value || '-' },
    { title: text('入口账号', 'Ingress Account'), dataIndex: 'relay_username_masked', render: (value: string | null) => value || '-' },
    { title: text('流量', 'Traffic'), dataIndex: 'traffic_used', render: (value: number) => formatBytes(value) },
    {
      title: text('启用', 'Enabled'),
      render: (_: unknown, row: Socks5RelayRule) => (
        <Space><Switch checked={!row.paused} onChange={(value) => void toggleRule(row, value)} />{row.relay_node_enabled === false ? <Tag color="red">{text('不可用：节点已禁用', 'Unavailable: Node disabled')}</Tag> : row.paused ? <Tag>{text('已暂停', 'Paused')}</Tag> : <Tag color="green">{text('已创建', 'Created')}</Tag>}</Space>
      ),
    },
    {
      title: text('操作', 'Actions'),
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
          }}>{text('编辑', 'Edit')}</Button>
          <Button size="small" onClick={() => {
            setCredentialRule(row);
            credentialForm.setFieldsValue({ username: '', password: '' });
          }}>{text('重置凭据', 'Reset Credentials')}</Button>
          <Popconfirm title={text('确定删除该规则？', 'Delete this rule?')} onConfirm={() => void deleteRule(row.rule_id)}>
            <Button size="small" danger>{text('删除', 'Delete')}</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Space style={{ width: '100%', justifyContent: 'space-between', marginBottom: 16 }}>
        <Typography.Title level={2} className="rp-page-title" style={{ margin: 0 }}>
          <ApiOutlined /> {text('SOCKS5 中转', 'SOCKS5 Relay')}
        </Typography.Title>
        <Button icon={<ReloadOutlined />} onClick={() => void load()}>{text('刷新', 'Refresh')}</Button>
      </Space>
      <Card>
        <Tabs
          items={[
            {
              key: 'resources',
              label: text('SOCKS5 资源', 'SOCKS5 Resources'),
              children: (
                <>
                  <Space wrap style={{ marginBottom: 16 }}>
                    <Button type="primary" icon={<PlusOutlined />} onClick={() => {
                      setEditing(null);
                      resourceForm.resetFields();
                      resourceForm.setFieldsValue({ enabled: true });
                      setResourceOpen(true);
                    }}>{text('添加资源', 'Add Resource')}</Button>
                    <Button icon={<UploadOutlined />} onClick={() => setImportOpen(true)}>{text('批量导入', 'Batch Import')}</Button>
                    <Input.Search allowClear placeholder={text('名称 / Host / Exit IP', 'Name / Host / Exit IP')} style={{ width: 260 }}
                      onSearch={(value) => { setPage(1); setSearch(value.trim()); }} />
                    <Select allowClear placeholder={text('状态', 'Status')} style={{ width: 160 }} value={statusFilter}
                      onChange={(value) => { setPage(1); setStatusFilter(value); }}
                      options={['ONLINE', 'OFFLINE', 'AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'DISABLED', 'UNKNOWN'].map((value) => ({ value, label: value }))} />
                    <Input.Search allowClear placeholder={text('国家代码', 'Country Code')} style={{ width: 150 }} onSearch={(value) => { setPage(1); setCountryFilter(value.trim()); }} />
                    <Input.Search allowClear placeholder={text('检测出口国家', 'Detected Country')} style={{ width: 170 }} onSearch={(value) => { setPage(1); setDetectedFilter(value.trim()); }} />
                    <Input.Search allowClear placeholder={text('标签', 'Tag')} style={{ width: 130 }} onSearch={(value) => { setPage(1); setTagFilter(value.trim()); }} />
                    <Select allowClear placeholder={text('启用状态', 'Enabled')} style={{ width: 120 }} value={enabledFilter}
                      onChange={(value) => { setPage(1); setEnabledFilter(value); }}
                      options={[{ value: true, label: text('已启用', 'Enabled') }, { value: false, label: text('已禁用', 'Disabled') }]} />
                    <Button disabled={!selectedIds.length} onClick={() => void runBulkAction('ENABLE')}>{text('批量启用', 'Enable Selected')}</Button>
                    <Button disabled={!selectedIds.length} onClick={() => void runBulkAction('DISABLE')}>{text('批量禁用', 'Disable Selected')}</Button>
                    <Button disabled={!selectedIds.length} onClick={() => setTagOpen(true)}>{text('批量标签', 'Set Tags')}</Button>
                    <Popconfirm title={text('删除未被规则引用的选中资源？', 'Delete selected resources that are not referenced by rules?')} onConfirm={() => void runBulkAction('DELETE')}>
                      <Button danger disabled={!selectedIds.length}>{text('批量删除', 'Delete Selected')}</Button>
                    </Popconfirm>
                    <Button icon={<ThunderboltOutlined />} disabled={!selectedIds.length} onClick={() => {
                      setCheckAll(false); setCheckIds(selectedIds.map(Number)); setCheckResults([]); setCheckOpen(true);
                    }}>{text('批量检测', 'Test Selected')}</Button>
                    <Button icon={<ThunderboltOutlined />} disabled={total === 0 || total > 10000} onClick={() => {
                      setCheckAll(true); setCheckIds([]); setCheckResults([]); setCheckOpen(true);
                    }}>{text(`检测全部筛选结果 (${total})`, `Test All Filtered (${total})`)}</Button>
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
              label: text('SOCKS5 中转规则', 'SOCKS5 Relay Rules'),
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
                    {text('添加规则', 'Add Rule')}
                  </Button>
                  <Table rowKey="rule_id" loading={loading} dataSource={rules} columns={ruleColumns} scroll={{ x: 1500 }} />
                </>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        title={editing ? text('编辑 SOCKS5 资源', 'Edit SOCKS5 Resource') : text('添加 SOCKS5 资源', 'Add SOCKS5 Resource')}
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
          <Form.Item name="name" label={text('名称', 'Name')} rules={[{ required: true }]}><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="host" label={text('主机', 'Host')} rules={[{ required: true }]} style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="port" label={text('端口', 'Port')} rules={[{ required: true }]}><InputNumber min={1} max={65535} /></Form.Item>
          </Space.Compact>
          <Form.Item name="username" label={text('上游用户名', 'Upstream Username')}><Input placeholder={editing?.username_masked ?? text('留空表示无认证', 'Leave blank for no authentication')} /></Form.Item>
          <Form.Item name="password" label={text('上游密码', 'Upstream Password')} extra={editing ? text('留空保留原密码', 'Leave blank to keep the current password') : undefined}><Input.Password autoComplete="new-password" /></Form.Item>
          <Space.Compact block>
            <Form.Item name="country" label={text('国家', 'Country')} style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="country_code" label={text('国家代码', 'Country Code')} style={{ width: 120 }}><Input maxLength={2} /></Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="region" label={text('地区', 'Region')} style={{ flex: 1 }}><Input /></Form.Item>
            <Form.Item name="city" label={text('城市', 'City')} style={{ flex: 1 }}><Input /></Form.Item>
          </Space.Compact>
          <Form.Item name="isp" label="ISP"><Input /></Form.Item>
          <Form.Item name="remark" label={text('备注', 'Remark')}><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="enabled" label={text('启用', 'Enabled')} valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal
        title={editingRule ? text('编辑 SOCKS5 中转规则', 'Edit SOCKS5 Relay Rule') : text('添加 SOCKS5 中转规则', 'Add SOCKS5 Relay Rule')}
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
          <Form.Item name="name" label={text('规则名称', 'Rule Name')} rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="device_group_in" label={text('入口节点分组', 'Ingress Node Group')} rules={[{ required: true }]}>
            <Select options={groups.map((group) => ({ value: group.id, label: group.name }))} />
          </Form.Item>
          <Form.Item
            name="listen_port"
            label={text('入口端口', 'Ingress Port')}
            extra={editingRule ? undefined : text('留空时从该节点分组端口池自动分配', 'Leave blank to allocate from the Node group port pool')}
            rules={editingRule ? [{ required: true }] : undefined}
          >
            <InputNumber min={1} max={65535} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="socks5_resource_id" label={text('上游 SOCKS5', 'Upstream SOCKS5')} rules={[{ required: true }]}>
            <Select
              showSearch
              filterOption={false}
              onSearch={(value) => void searchResourceChoices(value)}
              options={resourceChoices}
              placeholder={text('输入名称、Host 或 Exit IP 搜索', 'Search by Name, Host, or Exit IP')}
            />
          </Form.Item>
          {!editingRule && (
            <>
              <Form.Item name="relay_username" label={text('客户端入口用户名', 'Client Ingress Username')} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
              <Form.Item name="relay_password" label={text('客户端入口密码', 'Client Ingress Password')} rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
            </>
          )}
          <Form.Item name="remote_dns" label={text('域名交由上游 SOCKS5 解析', 'Resolve DNS through upstream SOCKS5')} valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label={text('立即启用', 'Enable Immediately')} valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
      <Modal
        title={`${text('重置入口凭据', 'Reset Ingress Credentials')}${credentialRule ? ` · ${credentialRule.name}` : ''}`}
        open={credentialRule !== null}
        onCancel={() => {
          credentialForm.resetFields();
          setCredentialRule(null);
        }}
        onOk={() => credentialForm.submit()}
        destroyOnHidden
      >
        <Form form={credentialForm} layout="vertical" onFinish={(values) => void resetCredential(values)}>
          <Form.Item name="username" label={text('新用户名', 'New Username')} rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="password" label={text('新密码', 'New Password')} rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
        </Form>
      </Modal>

      <Modal title={text('批量导入 SOCKS5', 'Batch Import SOCKS5')} width={820} open={importOpen} confirmLoading={importing}
        okText={importPreview ? text('确认导入', 'Confirm Import') : text('生成预览', 'Generate Preview')}
        onOk={() => void (importPreview ? confirmImport() : previewImport())}
        onCancel={() => { setImportOpen(false); setImportPreview(null); setImportText(''); }} destroyOnHidden>
        <Typography.Paragraph type="secondary">
          {text(
            '支持 host:port、host:port:user:password、user:password@host:port、socks5://user:password@host:port；单次最多 10000 条。',
            'Supports host:port, host:port:user:password, user:password@host:port, and socks5://user:password@host:port; maximum 10,000 entries per import.',
          )}
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
          <Button icon={<UploadOutlined />} style={{ marginBottom: 12 }}>{text('读取文本文件', 'Read Text File')}</Button>
        </Upload>
        <Input.TextArea rows={10} value={importText} onChange={(event) => {
          setImportText(event.target.value); setImportPreview(null);
        }} placeholder={text('每行一个 SOCKS5', 'One SOCKS5 entry per line')} />
        {importPreview ? (
          <>
            <Row gutter={12} style={{ marginTop: 16 }}>
              <Col span={4}><Statistic title={text('总数', 'Total')} value={importPreview.total} /></Col>
              <Col span={4}><Statistic title={text('有效', 'Valid')} value={importPreview.valid} /></Col>
              <Col span={4}><Statistic title={text('无效', 'Invalid')} value={importPreview.invalid} /></Col>
              <Col span={4}><Statistic title={text('重复', 'Duplicate')} value={importPreview.duplicate} /></Col>
              <Col span={4}><Statistic title={text('新增', 'New')} value={importPreview.new} /></Col>
            </Row>
            <Select value={importStrategy} onChange={setImportStrategy} style={{ width: 240, margin: '12px 0' }}
              options={[{ value: 'SKIP_DUPLICATE', label: text('跳过重复', 'Skip Duplicates') }, { value: 'UPDATE_CREDENTIAL', label: text('更新重复项凭据', 'Update Duplicate Credentials') }]} />
            {importPreview.invalid_lines.length ? (
              <Table size="small" rowKey="line_number" pagination={{ pageSize: 5 }} dataSource={importPreview.invalid_lines}
                columns={[{ title: text('行号', 'Line'), dataIndex: 'line_number' }, { title: text('脱敏内容', 'Masked Input'), dataIndex: 'raw_masked' }, { title: text('原因', 'Reason'), dataIndex: 'error_reason' }]} />
            ) : null}
          </>
        ) : null}
      </Modal>

      <Modal title={text('批量设置标签', 'Set Tags for Selected Resources')} open={tagOpen} onOk={() => void setBulkTags()}
        onCancel={() => setTagOpen(false)} destroyOnHidden>
        <Input value={tagText} onChange={(event) => setTagText(event.target.value)} placeholder={text('例如 residential, us, provider-a', 'For example: residential, us, provider-a')} />
      </Modal>

      <Modal title={`${text('SOCKS5 健康检测', 'SOCKS5 Health Check')} · ${checkAll ? text(`全部筛选结果 (${total})`, `All Filtered (${total})`) : text(`${checkIds.length} 个资源`, `${checkIds.length} Resources`)}`} width={860} open={checkOpen}
        confirmLoading={checking} okText={text('开始检测', 'Run')} onOk={() => void runChecks()}
        onCancel={() => { setCheckOpen(false); setCheckResults([]); setCheckAll(false); }} destroyOnHidden>
        <Select style={{ width: '100%', marginBottom: 16 }} placeholder={text('选择执行检测的中转节点', 'Select a Relay Node for the check')}
          value={checkNodeId} onChange={setCheckNodeId}
          options={relayNodes.map((node) => ({ value: node.id, disabled: !node.online || !node.enabled || !node.supports_socks5_check,
            label: `${node.name} · ${node.public_ip || '-'} · ${node.online ? node.supports_socks5_check ? text('在线', 'Online') : text('需要升级', 'Upgrade required') : text('离线', 'Offline')}` }))} />
        {checkResults.length ? (
          <Table size="small" rowKey="resource_id" pagination={{ pageSize: 10 }} dataSource={checkResults}
            columns={[
              { title: text('资源', 'Resource'), dataIndex: 'resource_id' },
              { title: text('执行结果', 'Outcome'), dataIndex: 'outcome' },
              { title: text('健康状态', 'Health Status'), render: (_: unknown, row: Socks5CheckResponse) => row.result?.status ? socks5HealthStatusText(lang, row.result.status) : '-' },
              { title: 'TCP', render: (_: unknown, row: Socks5CheckResponse) => row.result?.tcp_latency_ms == null ? '-' : `${row.result.tcp_latency_ms} ms` },
              { title: text('SOCKS5 握手', 'SOCKS5 Handshake'), render: (_: unknown, row: Socks5CheckResponse) => row.result?.handshake_latency_ms == null ? '-' : `${row.result.handshake_latency_ms} ms` },
              { title: text('连接目标', 'Connect Target'), render: (_: unknown, row: Socks5CheckResponse) => row.result?.connect_latency_ms == null ? '-' : `${row.result.connect_latency_ms} ms` },
              { title: text('出口 IP', 'Exit IP'), render: (_: unknown, row: Socks5CheckResponse) => row.result?.exit_ip ?? '-' },
              { title: text('出口国家', 'Exit Country'), render: (_: unknown, row: Socks5CheckResponse) => row.result?.detected_country ?? '-' },
              { title: text('错误代码', 'Error Code'), render: (_: unknown, row: Socks5CheckResponse) => row.result?.error_code ?? '-' },
            ]} />
        ) : null}
      </Modal>

      <Modal title={`${text('SOCKS5 资源', 'SOCKS5 Resource')} · ${detail?.name ?? ''}`} width={960} open={detail !== null} footer={null}
        onCancel={() => { setDetail(null); setDetailHealth([]); setDetailHistory([]); }} destroyOnHidden>
        {detail ? <><Button type="primary" icon={<ThunderboltOutlined />} disabled={!detail.enabled} onClick={() => setSmartRelayResource(detail)} style={{ marginBottom: 12 }}>{text('创建中转', 'Create Relay')}</Button><Descriptions bordered size="small" column={2} items={[
          { key: 'endpoint', label: text('SOCKS5 地址', 'SOCKS5 Endpoint'), children: `${detail.host}:${detail.port}` },
          { key: 'credential', label: text('认证信息', 'Credentials'), children: detail.username_masked ? `${detail.username_masked} / ••••••••` : text('无认证', 'No authentication') },
          { key: 'country', label: text('标注国家', 'Declared Country'), children: detail.country_code || detail.country || '-' },
          { key: 'detected', label: text('检测出口国家', 'Detected Country'), children: <Space>{detail.detected_country || '-'}{countryMismatch(detail.country_code, detail.detected_country) ? <Tag color="orange">{text('国家不一致', 'Country mismatch')}</Tag> : null}</Space> },
          { key: 'rules', label: text('关联规则', 'Rules'), children: rules.filter((rule) => rule.socks5_resource_id === detail.id).map((rule) => rule.name).join(', ') || '-' },
          { key: 'remark', label: text('备注', 'Remark'), children: detail.remark || '-' },
        ]} /></> : null}
        <Typography.Title level={5}>{text('节点健康矩阵', 'Node Health Matrix')}</Typography.Title>
        <Table size="small" pagination={false} rowKey="relay_node_id" dataSource={detailHealth} columns={[
          { title: text('中转节点', 'Relay Node'), render: (_: unknown, row: Socks5Health) => relayNodes.find((node) => node.id === row.relay_node_id)?.name ?? `#${row.relay_node_id}` },
          { title: text('健康状态', 'Health Status'), dataIndex: 'status', render: (value: string) => socks5HealthStatusText(lang, value) }, { title: text('延迟', 'Latency'), dataIndex: 'total_latency_ms', render: (value: number | null) => value == null ? '-' : `${value} ms` },
          { title: text('出口 IP', 'Exit IP'), dataIndex: 'exit_ip' }, { title: text('出口国家', 'Exit Country'), render: (_: unknown, row: Socks5Health) => <Space>{row.country || '-'}{countryMismatch(detail?.country_code, row.country) ? <Tag color="orange">{text('国家不一致', 'Country mismatch')}</Tag> : null}</Space> },
          { title: text('连续失败次数', 'Consecutive Failures'), dataIndex: 'consecutive_failures' }, { title: text('最近检测时间', 'Last Checked'), dataIndex: 'checked_at' },
        ]} />
        <Typography.Title level={5}>{text('检测历史', 'Check History')}</Typography.Title>
        <Table size="small" rowKey={(row) => `${row.relay_node_id}-${row.checked_at}`} dataSource={detailHistory} pagination={{ pageSize: 10 }} columns={[
          { title: text('中转节点', 'Relay Node'), render: (_: unknown, row: Socks5Health) => relayNodes.find((node) => node.id === row.relay_node_id)?.name ?? `#${row.relay_node_id}` },
          { title: text('健康状态', 'Health Status'), dataIndex: 'status', render: (value: string) => socks5HealthStatusText(lang, value) }, { title: text('延迟', 'Latency'), dataIndex: 'total_latency_ms' },
          { title: text('出口 IP', 'Exit IP'), dataIndex: 'exit_ip' }, { title: text('错误代码', 'Error Code'), dataIndex: 'error_code' }, { title: text('检测时间', 'Checked At'), dataIndex: 'checked_at' },
        ]} />
      </Modal>
      <SmartRelayWizard
        open={smartRelayResource !== null}
        resource={smartRelayResource}
        onClose={() => setSmartRelayResource(null)}
        onCreated={() => void load()}
      />
    </div>
  );
}
