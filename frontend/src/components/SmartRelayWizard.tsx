import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Input,
  InputNumber,
  message,
  Modal,
  Progress,
  Radio,
  Row,
  Segmented,
  Space,
  Steps,
  Tag,
  Typography,
} from 'antd';
import { CheckCircleOutlined, CopyOutlined, ThunderboltOutlined } from '@ant-design/icons';
import api from '../api/client';
import type {
  ApiEnvelope,
  RelayCandidate,
  RelayRecommendation,
  SmartRelayCreated,
  SmartRelayPreview,
  Socks5Resource,
} from '../api/types';
import { copyText } from '../utils/clipboard';
import { buildSocksUrl, formatRelayEndpoint } from '../utils/smartRelayEndpoint';
import { useI18n } from '../i18n/context';
import { countryMatchDisplay } from './smartRelayLocale';

type Props = {
  open: boolean;
  resource: Socks5Resource | null;
  onClose: () => void;
  onCreated: () => void;
};

type PortMode = 'AUTO' | 'MANUAL';

type CandidateGroup = 'recommended' | 'available' | 'crossCountry' | 'unknown' | 'unavailable';

const groupLabel = (candidate: RelayCandidate): CandidateGroup => {
  if (!candidate.eligible) return 'unavailable';
  if (candidate.recommended) return 'recommended';
  if (candidate.country_match === 'MATCHED') return 'available';
  if (candidate.country_match === 'CROSS_COUNTRY') return 'crossCountry';
  return 'unknown';
};

function CandidateCard({ candidate, selected, onSelect, chinese }: {
  candidate: RelayCandidate;
  selected: boolean;
  onSelect: () => void;
  chinese: boolean;
}) {
  const text = (zh: string, en: string) => chinese ? zh : en;
  const load = Math.max(candidate.node_cpu ?? 0, candidate.node_memory ?? 0);
  return (
    <Card
      size="small"
      hoverable={candidate.eligible}
      onClick={candidate.eligible ? onSelect : undefined}
      style={{ marginBottom: 10, borderColor: selected ? '#1677ff' : undefined, opacity: candidate.eligible ? 1 : 0.72 }}
    >
      <Row gutter={[12, 8]} align="middle">
        <Col flex="28px"><Radio checked={selected} disabled={!candidate.eligible} /></Col>
        <Col flex="auto">
          <Space wrap>
            <Typography.Text strong>#{candidate.rank} {candidate.relay_node_name}</Typography.Text>
            {candidate.recommended ? <Tag color="blue">{text('推荐', 'Recommended')}</Tag> : null}
            <Tag color={candidate.eligible ? 'green' : 'red'}>{candidate.eligible ? text('可用', 'Eligible') : text('不可用', 'Unavailable')}</Tag>
            <Tag color={candidate.country_match === 'MATCHED' ? 'cyan' : candidate.country_match === 'CROSS_COUNTRY' ? 'orange' : undefined}>{countryMatchDisplay(candidate.country_match, chinese)}</Tag>
            <Tag>{candidate.health_status}</Tag>
          </Space>
          <div style={{ marginTop: 8 }}>
            <Space wrap size={[16, 4]}>
              <span>{candidate.country_code || '??'} · {candidate.region || '-'} · {candidate.city || '-'}</span>
              <span>{candidate.latency_ms == null ? text('延迟 -', 'Latency -') : `${candidate.latency_ms} ms`}</span>
              <span>{candidate.health_age_seconds == null ? text('健康数据时效 -', 'Health age -') : text(`${candidate.health_age_seconds} 秒前检测`, `Health ${candidate.health_age_seconds}s ago`)}</span>
              <span>{text('最近检测', 'Last Check')} {candidate.health_checked_at || '-'}</span>
              <span>{text('端口', 'Ports')} {candidate.port_available}/{candidate.port_total}</span>
              <span>{text('连接地址', 'Endpoint')} {candidate.endpoint_host || '-'}</span>
              <span>{text('评分', 'Score')} {candidate.score}</span>
            </Space>
          </div>
          <Progress percent={Math.min(100, load)} size="small" showInfo={false} status={load >= 95 ? 'exception' : 'normal'} />
          <Typography.Text type="secondary">{candidate.reasons.join(' · ') || text('暂无正向信号', 'No positive signals')}</Typography.Text>
          {candidate.warnings.length ? (
            <div style={{ marginTop: 4 }}><Typography.Text type="warning">{candidate.warnings.join(' · ')}</Typography.Text></div>
          ) : null}
        </Col>
      </Row>
    </Card>
  );
}

export default function SmartRelayWizard({ open, resource, onClose, onCreated }: Props) {
  const { lang } = useI18n();
  const chinese = lang === 'zh-CN';
  const text = (zh: string, en: string) => chinese ? zh : en;
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [recommendation, setRecommendation] = useState<RelayRecommendation | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<number>();
  const [ruleName, setRuleName] = useState('');
  const [portMode, setPortMode] = useState<PortMode>('AUTO');
  const [manualPort, setManualPort] = useState<number | null>(null);
  const [preview, setPreview] = useState<SmartRelayPreview | null>(null);
  const [idempotencyKey, setIdempotencyKey] = useState('');
  const [created, setCreated] = useState<SmartRelayCreated | null>(null);

  const selected = recommendation?.candidates.find((candidate) => candidate.relay_node_id === selectedNodeId);
  const groups = useMemo(() => {
    const result = new Map<CandidateGroup, RelayCandidate[]>();
    for (const candidate of recommendation?.candidates ?? []) {
      const label = groupLabel(candidate);
      result.set(label, [...(result.get(label) ?? []), candidate]);
    }
    return result;
  }, [recommendation]);

  const reset = () => {
    setStep(0);
    setLoading(false);
    setRecommendation(null);
    setSelectedNodeId(undefined);
    setRuleName('');
    setPortMode('AUTO');
    setManualPort(null);
    setPreview(null);
    setIdempotencyKey('');
    setCreated(null);
  };

  useEffect(() => {
    if (open && resource) {
      reset();
      setRuleName(`${resource.name}-relay`);
    }
  }, [open, resource]);

  const close = () => {
    reset();
    onClose();
  };

  const loadRecommendations = async () => {
    if (!resource) return;
    setLoading(true);
    try {
      const response = await api.get<unknown, ApiEnvelope<RelayRecommendation>>(
        `/admin/socks5-resources/${resource.id}/relay-recommendations?limit=100&include_unavailable=true`,
      );
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setRecommendation(response.data);
      setSelectedNodeId(response.data.candidates.find((candidate) => candidate.recommended && candidate.eligible)?.relay_node_id);
      setStep(1);
    } catch (error) {
      message.error(error instanceof Error ? error.message : text('加载中转节点推荐失败', 'Failed to load Relay Node recommendations'));
    } finally {
      setLoading(false);
    }
  };

  const runPreview = async () => {
    if (!resource || !selectedNodeId || !ruleName.trim()) return;
    setLoading(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<SmartRelayPreview>>('/admin/smart-relay/preview', {
        resource_id: resource.id,
        relay_node_id: selectedNodeId,
        port_mode: portMode,
        manual_port: portMode === 'MANUAL' ? manualPort : null,
      });
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setPreview(response.data);
      setIdempotencyKey(crypto.randomUUID());
      setStep(3);
    } catch (error) {
      message.error(error instanceof Error ? error.message : text('创建预检失败', 'Create preview failed'));
    } finally {
      setLoading(false);
    }
  };

  const create = async () => {
    if (!resource || !selectedNodeId || !preview || !idempotencyKey) return;
    setLoading(true);
    try {
      const response = await api.post<unknown, ApiEnvelope<SmartRelayCreated>>('/admin/smart-relay', {
        resource_id: resource.id,
        relay_node_id: selectedNodeId,
        port_mode: portMode,
        manual_port: portMode === 'MANUAL' ? manualPort : null,
        rule_name: ruleName.trim(),
        idempotency_key: idempotencyKey,
        expected_resource_revision: preview.resource_revision,
        expected_health_generation: preview.health_generation,
        expected_health_checked_at: preview.health_checked_at,
      });
      if (response.code !== 0 || !response.data) throw new Error(response.message);
      setCreated(response.data);
      setStep(4);
      onCreated();
    } catch (error) {
      message.error(error instanceof Error ? error.message : text('创建中转失败，请重新预检', 'Relay creation failed; run preview again'));
    } finally {
      setLoading(false);
    }
  };

  const copy = async (value: string) => {
    const copied = await copyText(value);
    message[copied ? 'success' : 'error'](copied ? text('已复制', 'Copied') : text('复制失败', 'Copy failed'));
  };

  const footer = step === 4 ? [<Button key="close" type="primary" onClick={close}>{text('完成并清除密码', 'Finish and clear password')}</Button>] : [
    step > 0 ? <Button key="back" disabled={loading} onClick={() => { setPreview(null); setIdempotencyKey(''); setStep(step - 1); }}>{text('上一步', 'Back')}</Button> : null,
    step === 0 ? <Button key="recommend" type="primary" loading={loading} disabled={!resource?.enabled} onClick={() => void loadRecommendations()}>{text('分析中转节点', 'Analyze Relay Nodes')}</Button> : null,
    step === 1 ? <Button key="node" type="primary" disabled={!selected?.eligible} onClick={() => setStep(2)}>{text('选择此节点', 'Select this Node')}</Button> : null,
    step === 2 ? <Button key="preview" type="primary" loading={loading} disabled={!ruleName.trim() || (portMode === 'MANUAL' && !manualPort)} onClick={() => void runPreview()}>{text('生成预览', 'Generate Preview')}</Button> : null,
    step === 3 ? <Button key="create" type="primary" danger loading={loading} disabled={!preview?.eligible} onClick={() => void create()}>{text('确认并原子创建', 'Confirm Atomic Create')}</Button> : null,
  ];

  const createdUrl = created ? buildSocksUrl(created) : '';

  return (
    <Modal title={<Space><ThunderboltOutlined />{text('一键创建 SOCKS5 中转', 'Create SOCKS5 Relay')}</Space>} width={980} open={open} onCancel={close} footer={footer} destroyOnHidden maskClosable={false}>
      <Steps current={step} size="small" style={{ marginBottom: 24 }} items={[
        text('资源', 'Resource'), text('中转节点', 'Relay Node'), text('规则', 'Rule'), text('预览', 'Preview'), text('完成', 'Success'),
      ].map((title) => ({ title }))} />

      {step === 0 && resource ? (
        <Descriptions bordered size="small" column={2} items={[
          { key: 'resource', label: text('资源', 'Resource'), children: `${resource.name} (#${resource.id})` },
          { key: 'endpoint', label: text('上游地址', 'Upstream'), children: formatRelayEndpoint(resource.host, resource.port) },
          { key: 'exit', label: text('检测出口 IP', 'Detected Exit IP'), children: resource.detected_exit_ip || '-' },
          { key: 'country', label: text('检测出口国家', 'Detected Country'), children: resource.detected_country || resource.country_code || '-' },
          { key: 'health', label: text('健康状态', 'Health'), children: <Tag color={resource.status === 'ONLINE' ? 'green' : 'red'}>{resource.status}</Tag> },
          { key: 'checked', label: text('最近检测', 'Last Check'), children: resource.last_check_at || '-' },
        ]} />
      ) : null}

      {step === 1 ? (
        <div>
          {!selectedNodeId ? <Alert type="warning" showIcon message={text('没有符合硬性条件的中转节点', 'No Relay Node satisfies the hard requirements')} style={{ marginBottom: 12 }} /> : null}
          {(['recommended', 'available', 'crossCountry', 'unknown', 'unavailable'] as CandidateGroup[]).map((label) => {
            const candidates = groups.get(label) ?? [];
            if (!candidates.length) return null;
            const labels: Record<CandidateGroup, string> = {
              recommended: text('推荐节点', 'Recommended'), available: text('可用节点', 'Available'),
              crossCountry: text('跨国节点', 'Cross-country'), unknown: text('国家未知', 'Country unknown'),
              unavailable: text('不可用节点', 'Unavailable'),
            };
            return <div key={label}><Divider>{labels[label]} ({candidates.length})</Divider>{candidates.map((candidate) => (
              <CandidateCard key={candidate.relay_node_id} candidate={candidate} selected={candidate.relay_node_id === selectedNodeId} onSelect={() => setSelectedNodeId(candidate.relay_node_id)} chinese={chinese} />
            ))}</div>;
          })}
        </div>
      ) : null}

      {step === 2 ? (
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Descriptions bordered size="small" column={2} items={[
            { key: 'resource', label: text('资源', 'Resource'), children: resource?.name },
            { key: 'node', label: text('中转节点', 'Relay Node'), children: `${selected?.relay_node_name} · ${selected?.country_code || '-'}` },
          ]} />
          <div><Typography.Text strong>{text('规则名称', 'Rule Name')}</Typography.Text><Input maxLength={128} value={ruleName} onChange={(event) => setRuleName(event.target.value)} /></div>
          <div><Typography.Text strong>{text('监听端口', 'Listen Port')}</Typography.Text><br /><Segmented value={portMode} onChange={(value) => setPortMode(value as PortMode)} options={[
            { value: 'AUTO', label: text('自动分配', 'AUTO') }, { value: 'MANUAL', label: text('手动指定', 'MANUAL') },
          ]} /></div>
          {portMode === 'MANUAL' ? <InputNumber min={1} max={65535} value={manualPort} onChange={(value) => setManualPort(value)} style={{ width: '100%' }} placeholder={text('必须位于节点分组端口范围且未被占用', 'Must be within the Node group port range and unused')} /> : <Alert type="info" showIcon message={text('创建事务中选择第一个可用端口；预览不会锁定端口。', 'The first available port is selected during the create transaction; preview does not reserve a port.')} />}
          <Alert type="success" showIcon message={text('入口用户名和高强度密码将由服务端安全随机生成。', 'The Relay username and strong password are generated securely by the server.')} />
        </Space>
      ) : null}

      {step === 3 && preview ? (
        <>
          {!preview.eligible || preview.warnings.length ? <Alert type={preview.eligible ? 'warning' : 'error'} showIcon message={preview.eligible ? text('请确认以下警告', 'Review the warnings') : text('当前条件不再允许创建', 'Creation is no longer allowed')} description={preview.warnings.join(' · ') || undefined} style={{ marginBottom: 16 }} /> : null}
          <Descriptions bordered size="small" column={2} items={[
            { key: 'resource', label: text('资源', 'Resource'), children: recommendation?.resource_name },
            { key: 'exit', label: text('检测出口 IP', 'Detected Exit IP'), children: preview.candidate.detected_exit_ip || '-' },
            { key: 'detectedCountry', label: text('检测出口国家', 'Detected Country'), children: preview.candidate.detected_country || '-' },
            { key: 'node', label: text('中转节点', 'Relay Node'), children: `${preview.candidate.relay_node_name} (#${preview.candidate.relay_node_id})` },
            { key: 'nodeCountry', label: text('节点国家', 'Relay Country'), children: preview.candidate.country_code || '-' },
            { key: 'countryMatch', label: text('国家匹配', 'Country Match'), children: countryMatchDisplay(preview.candidate.country_match, chinese) },
            { key: 'health', label: text('健康状态', 'Health'), children: preview.candidate.health_status },
            { key: 'healthAge', label: text('健康数据时效', 'Health Age'), children: preview.candidate.health_age_seconds == null ? '-' : `${preview.candidate.health_age_seconds}s` },
            { key: 'latency', label: text('延迟', 'Latency'), children: preview.candidate.latency_ms == null ? '-' : `${preview.candidate.latency_ms} ms` },
            { key: 'load', label: text('节点负载', 'Node Load'), children: `CPU ${preview.candidate.node_cpu ?? '-'}% · RAM ${preview.candidate.node_memory ?? '-'}%` },
            { key: 'port', label: text('端口模式', 'Port Mode'), children: preview.port_mode === 'AUTO' ? text('自动（提交时分配）', 'AUTO (allocated at commit)') : text(`手动（${preview.manual_port}）`, `MANUAL (${preview.manual_port})`) },
            { key: 'selection', label: text('选择方式', 'Selection'), children: preview.candidate.recommended ? text('推荐', 'RECOMMENDED') : text('手动', 'MANUAL') },
            { key: 'reason', label: text('推荐理由', 'Recommendation Reason'), span: 2, children: preview.candidate.reasons.join(' · ') },
          ]} />
        </>
      ) : null}

      {step === 4 && created ? (
        <>
          <Alert type="success" showIcon icon={<CheckCircleOutlined />} message={text('中转规则已提交', 'Relay Rule submitted')} description={text(`部署状态：${created.deployment_status}。Panel 不会将数据库提交冒充为监听器已生效。`, `Deployment status: ${created.deployment_status}. A database commit is not presented as an ACTIVE listener.`)} style={{ marginBottom: 16 }} />
          <Alert type="warning" showIcon message={text('密码只显示这一次', 'Password is shown once')} description={text('离开此页面后无法重新读取；请立即复制并安全保存。', 'It cannot be read again after leaving this page. Copy and store it now.')} style={{ marginBottom: 16 }} />
          <Descriptions bordered column={1} size="small" items={[
            { key: 'host', label: 'Host', children: created.host },
            { key: 'port', label: 'Port', children: created.port },
            { key: 'username', label: text('用户名', 'Username'), children: created.relay_username },
            { key: 'password', label: text('密码', 'Password'), children: created.relay_password || text('已在先前请求中显示', 'Shown in the previous response') },
            { key: 'protocol', label: text('协议', 'Protocol'), children: created.protocol },
            { key: 'exit', label: text('预期出口', 'Expected Exit'), children: `${created.exit_ip} · ${created.exit_country || '-'}` },
            { key: 'mode', label: text('选择方式', 'Selection'), children: created.selection_mode },
            { key: 'url', label: 'SOCKS5 URL', children: createdUrl ? <Space><Typography.Text code copyable={false}>{createdUrl}</Typography.Text><Button icon={<CopyOutlined />} onClick={() => void copy(createdUrl)}>{text('复制', 'Copy')}</Button></Space> : text('密码已不再返回', 'Password is no longer returned') },
          ]} />
        </>
      ) : null}
    </Modal>
  );
}
