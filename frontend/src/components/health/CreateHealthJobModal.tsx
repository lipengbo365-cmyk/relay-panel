import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert, Button, Card, Descriptions, Form, Input, InputNumber, Modal,
  Radio, Select, Space, Typography,
} from 'antd';
import {
  createHealthJob, dryRunHealthJob, listHealthResources, listRelayNodes,
  SafeHealthRequestError, toSafeHealthError,
  type CreateHealthJobRequest, type CreateHealthJobResponse,
  type HealthDryRunResponse, type HealthStatus, type SafeError,
} from '../../api/health';
import type { RelayNode, Socks5Resource } from '../../api/types';
import { buildHealthJobRequest, type HealthSelectorForm } from './healthSelectors';
import { useHealthLocale } from './healthLocale';

interface CreateHealthJobModalProps {
  open: boolean;
  onClose: () => void;
  onCreated: (result: CreateHealthJobResponse) => void;
}

const INITIAL_DRAFT: HealthSelectorForm = {
  resource_ids: [], resource_country_codes: '', resource_statuses: [], resource_tags: '',
  resource_enabled: 'true', resource_tag_match: 'ALL',
  node_ids: [], node_country_codes: '', node_tags: '',
  node_enabled: 'true', node_tag_match: 'ALL', max_items: 10_000,
};

const HEALTH_STATUSES: HealthStatus[] = [
  'ONLINE', 'OFFLINE', 'AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'DISABLED', 'UNKNOWN',
];

function requestSnapshot(request: CreateHealthJobRequest): string {
  return JSON.stringify(request);
}

interface VerifiedDryRun {
  request: CreateHealthJobRequest;
  snapshot: string;
  result: HealthDryRunResponse;
}

interface CreateIntent {
  snapshot: string;
  key: string;
  outcomeUnknown: boolean;
}

function SafeActionError({ error }: { error: SafeError }) {
  return <Alert type="error" showIcon title={error.code} description={error.message} />;
}

export function CreateHealthJobModal({ open, onClose, onCreated }: CreateHealthJobModalProps) {
  const { copy: c, healthStatus, matrix, tagMatch } = useHealthLocale();
  const [form] = Form.useForm<HealthSelectorForm>();
  const [draft, setDraft] = useState<HealthSelectorForm>(INITIAL_DRAFT);
  const [resources, setResources] = useState<Socks5Resource[]>([]);
  const [resourceTotal, setResourceTotal] = useState<number | null>(null);
  const [nodes, setNodes] = useState<RelayNode[]>([]);
  const [resourceSearch, setResourceSearch] = useState('');
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState<SafeError | null>(null);
  const [verified, setVerified] = useState<VerifiedDryRun | null>(null);
  const [dryRunLoading, setDryRunLoading] = useState(false);
  const [createLoading, setCreateLoading] = useState(false);
  const [actionError, setActionError] = useState<SafeError | null>(null);
  const [intent, setIntent] = useState<CreateIntent | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const createInFlight = useRef(false);

  const request = useMemo(() => buildHealthJobRequest(draft), [draft]);
  const snapshot = useMemo(() => requestSnapshot(request), [request]);
  const verifiedCurrent = verified?.snapshot === snapshot;
  const noResources = resourceTotal === 0;
  const noNodes = !catalogLoading && nodes.length === 0;
  const noSupportedNodes = nodes.length > 0 && nodes.every((node) => !node.supports_socks5_check);
  const canDryRun = !dryRunLoading && !createLoading && !noResources && !noNodes && !noSupportedNodes;
  const canCreate = Boolean(verifiedCurrent && verified?.result.within_limit
    && verified.result.item_count > 0 && !createLoading && !dryRunLoading);

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      setCatalogLoading(true);
      setCatalogError(null);
      void listHealthResources(
        { page: 1, page_size: 100, search: resourceSearch || undefined },
        controller.signal,
      ).then((page) => {
        setResources(page.items);
        setResourceTotal(page.total);
      }).catch((error) => {
        if (!controller.signal.aborted) setCatalogError(toSafeHealthError(error));
      }).finally(() => {
        if (!controller.signal.aborted) setCatalogLoading(false);
      });
    }, 200);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [open, resourceSearch]);

  useEffect(() => {
    if (!open) return;
    const controller = new AbortController();
    void listRelayNodes(controller.signal).then(setNodes).catch((error) => {
      if (!controller.signal.aborted) setCatalogError(toSafeHealthError(error));
    });
    return () => controller.abort();
  }, [open]);

  const invalidatePreview = (values: HealthSelectorForm) => {
    setDraft(values);
    setVerified(null);
    setIntent(null);
    setActionError(null);
    setConfirmOpen(false);
  };

  const handleDryRun = async () => {
    if (!canDryRun) return;
    const submitted = request;
    const submittedSnapshot = snapshot;
    setDryRunLoading(true);
    setActionError(null);
    setIntent(null);
    try {
      const result = await dryRunHealthJob(submitted);
      setVerified({ request: submitted, snapshot: submittedSnapshot, result });
    } catch (error) {
      setVerified(null);
      setActionError(error instanceof SafeHealthRequestError ? error.safe : toSafeHealthError(error));
    } finally {
      setDryRunLoading(false);
    }
  };

  const closeAndReset = () => {
    setDraft(INITIAL_DRAFT);
    form.resetFields();
    setVerified(null);
    setIntent(null);
    setActionError(null);
    setConfirmOpen(false);
    setResourceSearch('');
    onClose();
  };

  const handleCreate = async () => {
    if (!canCreate || !verified || verified.snapshot !== snapshot || createInFlight.current) return;
    createInFlight.current = true;
    const existing = intent?.snapshot === verified.snapshot ? intent : null;
    const nextIntent: CreateIntent = existing ?? {
      snapshot: verified.snapshot,
      key: crypto.randomUUID(),
      outcomeUnknown: false,
    };
    setIntent(nextIntent);
    setCreateLoading(true);
    setActionError(null);
    setConfirmOpen(false);
    try {
      const result = await createHealthJob(verified.request, nextIntent.key);
      setIntent(null);
      onCreated(result);
      closeAndReset();
    } catch (error) {
      const safeError = error instanceof SafeHealthRequestError ? error.safe : toSafeHealthError(error);
      const outcomeUnknown = error instanceof SafeHealthRequestError && error.outcomeUnknown;
      setActionError(safeError);
      if (outcomeUnknown) {
        setIntent({ ...nextIntent, outcomeUnknown: true });
      } else if (safeError.code === 'IDEMPOTENCY_KEY_REUSED' || safeError.code === 'INVALID_IDEMPOTENCY_KEY') {
        setIntent(null);
        setVerified(null);
      }
    } finally {
      createInFlight.current = false;
      setCreateLoading(false);
    }
  };

  const selectorSummary = verified ? [
    `${c.resourceIds}：${verified.request.resource_selector.ids?.length || c.allMatching}`,
    `${c.nodeIds}：${verified.request.node_selector.ids?.length || c.allMatching}`,
    `${c.resourceTags}：${tagMatch(verified.request.resource_selector.tag_match ?? 'ALL')}`,
    `${c.nodeTags}：${tagMatch(verified.request.node_selector.tag_match ?? 'ALL')}`,
  ].join(' · ') : '';

  return (
    <>
      <Modal
        title={c.createHealthJob}
        open={open}
        onCancel={closeAndReset}
        width="min(960px, 96vw)"
        destroyOnHidden
        footer={[
          <Button key="close" onClick={closeAndReset}>{c.close}</Button>,
          <Button key="dry" loading={dryRunLoading} disabled={!canDryRun} onClick={() => void handleDryRun()}>
            {c.previewChecks}
          </Button>,
          <Button key="create" type="primary" loading={createLoading} disabled={!canCreate} onClick={() => setConfirmOpen(true)}>
            {intent?.outcomeUnknown ? c.retrySameCreateRequest : c.createJob}
          </Button>,
        ]}
      >
        <Alert
          type="info" showIcon title={c.durableManualJob}
          description={c.durableManualJobDescription}
          style={{ marginBottom: 16 }}
        />
        {catalogError ? <div style={{ marginBottom: 16 }}><SafeActionError error={catalogError} /></div> : null}
        {noResources ? <Alert type="warning" showIcon title={c.noResourcesAvailable} style={{ marginBottom: 16 }} /> : null}
        {noNodes ? <Alert type="warning" showIcon title={c.noNodesAvailable} style={{ marginBottom: 16 }} /> : null}
        {noSupportedNodes ? <Alert type="warning" showIcon title={c.noSupportedNodes} style={{ marginBottom: 16 }} /> : null}
        {actionError ? <div style={{ marginBottom: 16 }}><SafeActionError error={actionError} /></div> : null}
        {intent?.outcomeUnknown ? (
          <Alert
            type="warning" showIcon title={c.createOutcomeUnknown}
            description={c.createOutcomeUnknownDescription}
            style={{ marginBottom: 16 }}
          />
        ) : null}

        <Form
          form={form} layout="vertical" initialValues={INITIAL_DRAFT}
          onValuesChange={(_changed, values: HealthSelectorForm) => invalidatePreview(values)}
        >
          <div className="rp-health-selector-grid">
            <Card title={c.resourceSelector} size="small">
              <Form.Item name="resource_ids" label={c.resourceIds}>
                <Select
                  mode="multiple" allowClear showSearch filterOption={false} loading={catalogLoading}
                  onSearch={setResourceSearch} placeholder={c.allMatchingResources}
                  options={resources.map((resource) => ({
                    value: resource.id,
                    label: `${resource.name} · ${resource.country_code || '—'} · ${healthStatus(resource.status as HealthStatus)}`,
                  }))}
                />
              </Form.Item>
              <Form.Item name="resource_country_codes" label={c.countryCodes}><Input placeholder="US, JP" /></Form.Item>
              <Form.Item name="resource_statuses" label={c.healthStatuses}>
                <Select mode="multiple" allowClear options={HEALTH_STATUSES.map((status) => ({ value: status, label: healthStatus(status) }))} />
              </Form.Item>
              <Form.Item name="resource_tags" label={c.tags}><Input placeholder={c.resourceTagsPlaceholder} /></Form.Item>
              <Space wrap>
                <Form.Item name="resource_enabled" label={c.enabled}>
                  <Select style={{ width: 130 }} options={[
                    { value: 'true', label: c.enabledValue }, { value: 'false', label: c.disabledValue }, { value: 'any', label: c.anyValue },
                  ]} />
                </Form.Item>
                <Form.Item name="resource_tag_match" label={c.tagMatch}><Radio.Group options={['ALL', 'ANY'].map((value) => ({ value, label: tagMatch(value) }))} optionType="button" /></Form.Item>
              </Space>
            </Card>

            <Card title={c.nodeSelector} size="small">
              <Form.Item name="node_ids" label={c.nodeIds}>
                <Select
                  mode="multiple" allowClear showSearch optionFilterProp="label" placeholder={c.allMatchingNodes}
                  options={nodes.map((node) => ({
                    value: node.id,
                    label: `${node.name} · ${node.country_code || '—'} · ${node.online ? c.online : c.offline} · ${node.supports_socks5_check ? c.checkSupported : c.noCheckSupport}`,
                  }))}
                />
              </Form.Item>
              <Form.Item name="node_country_codes" label={c.countryCodes}><Input placeholder="US, JP" /></Form.Item>
              <Form.Item name="node_tags" label={c.tags}><Input placeholder={c.nodeTagsPlaceholder} /></Form.Item>
              <Space wrap>
                <Form.Item name="node_enabled" label={c.enabled}>
                  <Select style={{ width: 130 }} options={[
                    { value: 'true', label: c.enabledValue }, { value: 'false', label: c.disabledValue }, { value: 'any', label: c.anyValue },
                  ]} />
                </Form.Item>
                <Form.Item name="node_tag_match" label={c.tagMatch}><Radio.Group options={['ALL', 'ANY'].map((value) => ({ value, label: tagMatch(value) }))} optionType="button" /></Form.Item>
              </Space>
              <Alert
                type="info" showIcon
                title={`${nodes.filter((node) => node.online).length}/${nodes.length} ${c.online} · ${nodes.filter((node) => node.supports_socks5_check).length}/${nodes.length} ${c.checkSupported}`}
                description={c.readinessDescription}
              />
            </Card>
          </div>
          <Form.Item name="max_items" label={c.maximumItems} style={{ marginTop: 16 }}>
            <InputNumber min={1} max={20_000} />
          </Form.Item>
        </Form>

        <Card title={c.dryRunSummary} size="small">
          {!verifiedCurrent || !verified ? (
            <Typography.Text type="secondary">{c.previewRequired}</Typography.Text>
          ) : (
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Descriptions
                size="small" bordered column={{ xs: 1, sm: 2, lg: 3 }}
                items={[
                  { key: 'resources', label: c.resources, children: verified.result.resource_count },
                  { key: 'nodes', label: c.nodes, children: verified.result.node_count },
                  { key: 'items', label: c.checks, children: verified.result.item_count },
                  { key: 'limit', label: c.effectiveLimit, children: verified.result.effective_limit },
                  { key: 'matrix', label: c.matrix, children: matrix(verified.result.matrix_mode) },
                  { key: 'within', label: c.withinLimit, children: verified.result.within_limit ? c.yes : c.no },
                ]}
              />
              <Typography.Text type="secondary">{selectorSummary}</Typography.Text>
              {!verified.result.within_limit ? (
                <Alert type="error" showIcon title="MATRIX_TOO_LARGE" description={`${verified.result.item_count} > ${verified.result.effective_limit}。${c.matrixTooLarge}`} />
              ) : null}
            </Space>
          )}
        </Card>
      </Modal>

      <Modal
        title={intent?.outcomeUnknown ? c.retryCreateConfirmTitle : c.createConfirmTitle}
        open={confirmOpen} onCancel={() => setConfirmOpen(false)} onOk={() => void handleCreate()}
        confirmLoading={createLoading} okText={intent?.outcomeUnknown ? c.retrySameRequest : c.createJob}
      >
        {verified ? (
          <Space orientation="vertical">
            <Typography.Text>{c.resources}：{verified.result.resource_count}</Typography.Text>
            <Typography.Text>{c.nodes}：{verified.result.node_count}</Typography.Text>
            <Typography.Text strong>{c.finalChecks}：{verified.result.item_count}</Typography.Text>
            <Typography.Text>{c.limit}：{verified.result.effective_limit}</Typography.Text>
            <Typography.Text>{c.matrix}：{matrix(verified.result.matrix_mode)}</Typography.Text>
            <Typography.Text type="secondary">{selectorSummary}</Typography.Text>
          </Space>
        ) : null}
      </Modal>
    </>
  );
}
