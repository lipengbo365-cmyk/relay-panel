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
    `${verified.request.resource_selector.ids?.length || 'all matching'} resource IDs`,
    `${verified.request.node_selector.ids?.length || 'all matching'} node IDs`,
    `resource tags ${verified.request.resource_selector.tag_match}`,
    `node tags ${verified.request.node_selector.tag_match}`,
  ].join(' · ') : '';

  return (
    <>
      <Modal
        title="Create Health Job"
        open={open}
        onCancel={closeAndReset}
        width="min(960px, 96vw)"
        destroyOnHidden
        footer={[
          <Button key="close" onClick={closeAndReset}>Close</Button>,
          <Button key="dry" loading={dryRunLoading} disabled={!canDryRun} onClick={() => void handleDryRun()}>
            Preview Checks
          </Button>,
          <Button key="create" type="primary" loading={createLoading} disabled={!canCreate} onClick={() => setConfirmOpen(true)}>
            {intent?.outcomeUnknown ? 'Retry Same Create Request' : 'Create Job'}
          </Button>,
        ]}
      >
        <Alert
          type="info" showIcon title="Durable manual health job"
          description="The backend Dry Run is authoritative. Detection combinations use Resource × Node (CARTESIAN) semantics."
          style={{ marginBottom: 16 }}
        />
        {catalogError ? <div style={{ marginBottom: 16 }}><SafeActionError error={catalogError} /></div> : null}
        {noResources ? <Alert type="warning" showIcon title="No SOCKS5 Resources are available." style={{ marginBottom: 16 }} /> : null}
        {noNodes ? <Alert type="warning" showIcon title="No Relay Nodes are available." style={{ marginBottom: 16 }} /> : null}
        {noSupportedNodes ? <Alert type="warning" showIcon title="No Relay Node currently advertises SOCKS5 health-check support." style={{ marginBottom: 16 }} /> : null}
        {actionError ? <div style={{ marginBottom: 16 }}><SafeActionError error={actionError} /></div> : null}
        {intent?.outcomeUnknown ? (
          <Alert
            type="warning" showIcon title="Create outcome unknown"
            description="Retry the same request to safely discover the original result. The request identity is reused in memory."
            style={{ marginBottom: 16 }}
          />
        ) : null}

        <Form
          form={form} layout="vertical" initialValues={INITIAL_DRAFT}
          onValuesChange={(_changed, values: HealthSelectorForm) => invalidatePreview(values)}
        >
          <div className="rp-health-selector-grid">
            <Card title="Resource Selector" size="small">
              <Form.Item name="resource_ids" label="Resource IDs">
                <Select
                  mode="multiple" allowClear showSearch filterOption={false} loading={catalogLoading}
                  onSearch={setResourceSearch} placeholder="All matching Resources"
                  options={resources.map((resource) => ({
                    value: resource.id,
                    label: `${resource.name} · ${resource.country_code || '—'} · ${resource.status}`,
                  }))}
                />
              </Form.Item>
              <Form.Item name="resource_country_codes" label="Country Codes"><Input placeholder="US, JP" /></Form.Item>
              <Form.Item name="resource_statuses" label="Health Statuses">
                <Select mode="multiple" allowClear options={HEALTH_STATUSES.map((status) => ({ value: status, label: status }))} />
              </Form.Item>
              <Form.Item name="resource_tags" label="Tags"><Input placeholder="residential, provider-a" /></Form.Item>
              <Space wrap>
                <Form.Item name="resource_enabled" label="Enabled">
                  <Select style={{ width: 130 }} options={[
                    { value: 'true', label: 'Enabled' }, { value: 'false', label: 'Disabled' }, { value: 'any', label: 'Any' },
                  ]} />
                </Form.Item>
                <Form.Item name="resource_tag_match" label="Tag Match"><Radio.Group options={['ALL', 'ANY']} optionType="button" /></Form.Item>
              </Space>
            </Card>

            <Card title="Node Selector" size="small">
              <Form.Item name="node_ids" label="Node IDs">
                <Select
                  mode="multiple" allowClear showSearch optionFilterProp="label" placeholder="All matching Nodes"
                  options={nodes.map((node) => ({
                    value: node.id,
                    label: `${node.name} · ${node.country_code || '—'} · ${node.online ? 'Online' : 'Offline'} · ${node.supports_socks5_check ? 'SOCKS5 check supported' : 'No check support'}`,
                  }))}
                />
              </Form.Item>
              <Form.Item name="node_country_codes" label="Country Codes"><Input placeholder="US, JP" /></Form.Item>
              <Form.Item name="node_tags" label="Tags"><Input placeholder="premium, west" /></Form.Item>
              <Space wrap>
                <Form.Item name="node_enabled" label="Enabled">
                  <Select style={{ width: 130 }} options={[
                    { value: 'true', label: 'Enabled' }, { value: 'false', label: 'Disabled' }, { value: 'any', label: 'Any' },
                  ]} />
                </Form.Item>
                <Form.Item name="node_tag_match" label="Tag Match"><Radio.Group options={['ALL', 'ANY']} optionType="button" /></Form.Item>
              </Space>
              <Alert
                type="info" showIcon
                title={`${nodes.filter((node) => node.online).length}/${nodes.length} online · ${nodes.filter((node) => node.supports_socks5_check).length}/${nodes.length} support SOCKS5 checks`}
                description="Readiness is displayed only; it does not silently change the Node selector."
              />
            </Card>
          </div>
          <Form.Item name="max_items" label="Maximum Items" style={{ marginTop: 16 }}>
            <InputNumber min={1} max={20_000} />
          </Form.Item>
        </Form>

        <Card title="Backend Dry Run Summary" size="small">
          {!verifiedCurrent || !verified ? (
            <Typography.Text type="secondary">Preview is required after every selector change.</Typography.Text>
          ) : (
            <Space orientation="vertical" style={{ width: '100%' }}>
              <Descriptions
                size="small" bordered column={{ xs: 1, sm: 2, lg: 3 }}
                items={[
                  { key: 'resources', label: 'Resources', children: verified.result.resource_count },
                  { key: 'nodes', label: 'Nodes', children: verified.result.node_count },
                  { key: 'items', label: 'Checks', children: verified.result.item_count },
                  { key: 'limit', label: 'Effective limit', children: verified.result.effective_limit },
                  { key: 'matrix', label: 'Matrix', children: verified.result.matrix_mode },
                  { key: 'within', label: 'Within limit', children: verified.result.within_limit ? 'Yes' : 'No' },
                ]}
              />
              <Typography.Text type="secondary">{selectorSummary}</Typography.Text>
              {!verified.result.within_limit ? (
                <Alert type="error" showIcon title="MATRIX_TOO_LARGE" description={`The ${verified.result.item_count} checks exceed the ${verified.result.effective_limit} item limit. Narrow the selectors.`} />
              ) : null}
            </Space>
          )}
        </Card>
      </Modal>

      <Modal
        title={intent?.outcomeUnknown ? 'Retry same create request?' : 'Create this health job?'}
        open={confirmOpen} onCancel={() => setConfirmOpen(false)} onOk={() => void handleCreate()}
        confirmLoading={createLoading} okText={intent?.outcomeUnknown ? 'Retry Same Request' : 'Create Job'}
      >
        {verified ? (
          <Space orientation="vertical">
            <Typography.Text>Resources: {verified.result.resource_count}</Typography.Text>
            <Typography.Text>Nodes: {verified.result.node_count}</Typography.Text>
            <Typography.Text strong>Final checks: {verified.result.item_count}</Typography.Text>
            <Typography.Text>Limit: {verified.result.effective_limit}</Typography.Text>
            <Typography.Text>Matrix: Resource × Node ({verified.result.matrix_mode})</Typography.Text>
            <Typography.Text type="secondary">{selectorSummary}</Typography.Text>
          </Space>
        ) : null}
      </Modal>
    </>
  );
}
