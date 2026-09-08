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

type Props = {
  open: boolean;
  resource: Socks5Resource | null;
  onClose: () => void;
  onCreated: () => void;
};

type PortMode = 'AUTO' | 'MANUAL';

const groupLabel = (candidate: RelayCandidate) => {
  if (!candidate.eligible) return 'Unavailable';
  if (candidate.recommended) return 'Recommended';
  if (candidate.country_match === 'MATCHED') return 'Available';
  return 'Cross-country';
};

function CandidateCard({ candidate, selected, onSelect }: {
  candidate: RelayCandidate;
  selected: boolean;
  onSelect: () => void;
}) {
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
            {candidate.recommended ? <Tag color="blue">Recommended</Tag> : null}
            <Tag color={candidate.eligible ? 'green' : 'red'}>{candidate.eligible ? 'Eligible' : 'Unavailable'}</Tag>
            <Tag color={candidate.country_match === 'MATCHED' ? 'cyan' : 'orange'}>{candidate.country_match}</Tag>
            <Tag>{candidate.health_status}</Tag>
          </Space>
          <div style={{ marginTop: 8 }}>
            <Space wrap size={[16, 4]}>
              <span>{candidate.country_code || '??'} · {candidate.region || '-'} · {candidate.city || '-'}</span>
              <span>{candidate.latency_ms == null ? 'Latency -' : `${candidate.latency_ms} ms`}</span>
              <span>{candidate.health_age_seconds == null ? 'Health age -' : `Health ${candidate.health_age_seconds}s ago`}</span>
              <span>Last Check {candidate.health_checked_at || '-'}</span>
              <span>Ports {candidate.port_available}/{candidate.port_total}</span>
              <span>Endpoint {candidate.endpoint_host || '-'}</span>
              <span>Score {candidate.score}</span>
            </Space>
          </div>
          <Progress percent={Math.min(100, load)} size="small" showInfo={false} status={load >= 95 ? 'exception' : 'normal'} />
          <Typography.Text type="secondary">{candidate.reasons.join(' · ') || 'No positive signals'}</Typography.Text>
          {candidate.warnings.length ? (
            <div style={{ marginTop: 4 }}><Typography.Text type="warning">{candidate.warnings.join(' · ')}</Typography.Text></div>
          ) : null}
        </Col>
      </Row>
    </Card>
  );
}

export default function SmartRelayWizard({ open, resource, onClose, onCreated }: Props) {
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
    const result = new Map<string, RelayCandidate[]>();
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
      message.error(error instanceof Error ? error.message : '加载 Relay Node 推荐失败');
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
      message.error(error instanceof Error ? error.message : '创建预检失败');
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
      message.error(error instanceof Error ? error.message : '创建中转失败，请重新预检');
    } finally {
      setLoading(false);
    }
  };

  const copy = async (value: string) => {
    const copied = await copyText(value);
    message[copied ? 'success' : 'error'](copied ? '已复制' : '复制失败');
  };

  const footer = step === 4 ? [<Button key="close" type="primary" onClick={close}>完成并清除密码</Button>] : [
    step > 0 ? <Button key="back" disabled={loading} onClick={() => { setPreview(null); setIdempotencyKey(''); setStep(step - 1); }}>上一步</Button> : null,
    step === 0 ? <Button key="recommend" type="primary" loading={loading} disabled={!resource?.enabled} onClick={() => void loadRecommendations()}>分析 Relay Nodes</Button> : null,
    step === 1 ? <Button key="node" type="primary" disabled={!selected?.eligible} onClick={() => setStep(2)}>选择此节点</Button> : null,
    step === 2 ? <Button key="preview" type="primary" loading={loading} disabled={!ruleName.trim() || (portMode === 'MANUAL' && !manualPort)} onClick={() => void runPreview()}>生成预览</Button> : null,
    step === 3 ? <Button key="create" type="primary" danger loading={loading} disabled={!preview?.eligible} onClick={() => void create()}>确认并原子创建</Button> : null,
  ];

  const createdUrl = created ? buildSocksUrl(created) : '';

  return (
    <Modal title={<Space><ThunderboltOutlined />一键创建 SOCKS5 中转</Space>} width={980} open={open} onCancel={close} footer={footer} destroyOnHidden maskClosable={false}>
      <Steps current={step} size="small" style={{ marginBottom: 24 }} items={['Resource', 'Relay Node', 'Rule', 'Preview', 'Success'].map((title) => ({ title }))} />

      {step === 0 && resource ? (
        <Descriptions bordered size="small" column={2} items={[
          { key: 'resource', label: 'Resource', children: `${resource.name} (#${resource.id})` },
          { key: 'endpoint', label: 'Upstream', children: formatRelayEndpoint(resource.host, resource.port) },
          { key: 'exit', label: 'Detected Exit IP', children: resource.detected_exit_ip || '-' },
          { key: 'country', label: 'Detected Country', children: resource.detected_country || resource.country_code || '-' },
          { key: 'health', label: 'Health', children: <Tag color={resource.status === 'ONLINE' ? 'green' : 'red'}>{resource.status}</Tag> },
          { key: 'checked', label: 'Last Check', children: resource.last_check_at || '-' },
        ]} />
      ) : null}

      {step === 1 ? (
        <div>
          {!selectedNodeId ? <Alert type="warning" showIcon message="没有符合硬性条件的 Relay Node" style={{ marginBottom: 12 }} /> : null}
          {['Recommended', 'Available', 'Cross-country', 'Unavailable'].map((label) => {
            const candidates = groups.get(label) ?? [];
            if (!candidates.length) return null;
            return <div key={label}><Divider>{label} ({candidates.length})</Divider>{candidates.map((candidate) => (
              <CandidateCard key={candidate.relay_node_id} candidate={candidate} selected={candidate.relay_node_id === selectedNodeId} onSelect={() => setSelectedNodeId(candidate.relay_node_id)} />
            ))}</div>;
          })}
        </div>
      ) : null}

      {step === 2 ? (
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <Descriptions bordered size="small" column={2} items={[
            { key: 'resource', label: 'Resource', children: resource?.name },
            { key: 'node', label: 'Relay Node', children: `${selected?.relay_node_name} · ${selected?.country_code || '-'}` },
          ]} />
          <div><Typography.Text strong>Rule Name</Typography.Text><Input maxLength={128} value={ruleName} onChange={(event) => setRuleName(event.target.value)} /></div>
          <div><Typography.Text strong>Listen Port</Typography.Text><br /><Segmented value={portMode} onChange={(value) => setPortMode(value as PortMode)} options={['AUTO', 'MANUAL']} /></div>
          {portMode === 'MANUAL' ? <InputNumber min={1} max={65535} value={manualPort} onChange={(value) => setManualPort(value)} style={{ width: '100%' }} placeholder="必须位于节点分组端口范围且未被占用" /> : <Alert type="info" showIcon message="创建事务中选择第一个可用端口；预览不会锁定端口。" />}
          <Alert type="success" showIcon message="Relay 用户名和高强度密码将由服务端 CSPRNG 自动生成。" />
        </Space>
      ) : null}

      {step === 3 && preview ? (
        <>
          {!preview.eligible || preview.warnings.length ? <Alert type={preview.eligible ? 'warning' : 'error'} showIcon message={preview.eligible ? '请确认以下警告' : '当前条件不再允许创建'} description={preview.warnings.join(' · ') || undefined} style={{ marginBottom: 16 }} /> : null}
          <Descriptions bordered size="small" column={2} items={[
            { key: 'resource', label: 'Resource', children: recommendation?.resource_name },
            { key: 'exit', label: 'Detected Exit IP', children: preview.candidate.detected_exit_ip || '-' },
            { key: 'detectedCountry', label: 'Detected Country', children: preview.candidate.detected_country || '-' },
            { key: 'node', label: 'Relay Node', children: `${preview.candidate.relay_node_name} (#${preview.candidate.relay_node_id})` },
            { key: 'nodeCountry', label: 'Relay Country', children: preview.candidate.country_code || '-' },
            { key: 'countryMatch', label: 'Country Match', children: preview.candidate.country_match },
            { key: 'health', label: 'Health', children: preview.candidate.health_status },
            { key: 'healthAge', label: 'Health Age', children: preview.candidate.health_age_seconds == null ? '-' : `${preview.candidate.health_age_seconds}s` },
            { key: 'latency', label: 'Latency', children: preview.candidate.latency_ms == null ? '-' : `${preview.candidate.latency_ms} ms` },
            { key: 'load', label: 'Node Load', children: `CPU ${preview.candidate.node_cpu ?? '-'}% · RAM ${preview.candidate.node_memory ?? '-'}%` },
            { key: 'port', label: 'Port Mode', children: preview.port_mode === 'AUTO' ? 'AUTO (allocated at commit)' : `MANUAL (${preview.manual_port})` },
            { key: 'selection', label: 'Selection', children: preview.candidate.recommended ? 'RECOMMENDED' : 'MANUAL' },
            { key: 'reason', label: 'Recommendation Reason', span: 2, children: preview.candidate.reasons.join(' · ') },
          ]} />
        </>
      ) : null}

      {step === 4 && created ? (
        <>
          <Alert type="success" showIcon icon={<CheckCircleOutlined />} message="Relay Rule 已提交" description={`Deployment status: ${created.deployment_status}. Panel 不会将数据库提交冒充为 Listener 已 ACTIVE。`} style={{ marginBottom: 16 }} />
          <Alert type="warning" showIcon message="密码只显示这一次" description="离开此页面后无法重新读取；请立即复制并安全保存。" style={{ marginBottom: 16 }} />
          <Descriptions bordered column={1} size="small" items={[
            { key: 'host', label: 'Host', children: created.host },
            { key: 'port', label: 'Port', children: created.port },
            { key: 'username', label: 'Username', children: created.relay_username },
            { key: 'password', label: 'Password', children: created.relay_password || '已在先前请求中显示' },
            { key: 'protocol', label: 'Protocol', children: created.protocol },
            { key: 'exit', label: 'Expected Exit', children: `${created.exit_ip} · ${created.exit_country || '-'}` },
            { key: 'mode', label: 'Selection', children: created.selection_mode },
            { key: 'url', label: 'SOCKS5 URL', children: createdUrl ? <Space><Typography.Text code copyable={false}>{createdUrl}</Typography.Text><Button icon={<CopyOutlined />} onClick={() => void copy(createdUrl)}>复制</Button></Space> : '密码已不再返回' },
          ]} />
        </>
      ) : null}
    </Modal>
  );
}
