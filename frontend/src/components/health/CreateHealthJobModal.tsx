import { useMemo, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, Modal, Radio, Space, Switch, Typography } from 'antd';
import type { CreateHealthJobRequest, HealthDryRunResponse } from '../../api/health';

interface CreateHealthJobModalProps {
  open: boolean;
  onClose: () => void;
}

interface SelectorForm {
  resource_ids: string;
  resource_country_codes: string;
  resource_tags: string;
  node_ids: string;
  node_country_codes: string;
  node_tags: string;
  enabled_resources: boolean;
  enabled_nodes: boolean;
  tag_match: 'ANY' | 'ALL';
  max_items: number;
}

function ids(value: string): number[] {
  return value.split(',').map((part) => Number(part.trim())).filter((value) => Number.isInteger(value) && value > 0);
}

function strings(value: string): string[] {
  return value.split(',').map((part) => part.trim()).filter(Boolean);
}

export function CreateHealthJobModal({ open, onClose }: CreateHealthJobModalProps) {
  const [form] = Form.useForm<SelectorForm>();
  const [draft, setDraft] = useState<SelectorForm>({
    resource_ids: '', resource_country_codes: '', resource_tags: '',
    node_ids: '', node_country_codes: '', node_tags: '',
    enabled_resources: true, enabled_nodes: true, tag_match: 'ALL', max_items: 10_000,
  });
  const dryRun: HealthDryRunResponse | null = null;

  const request = useMemo<CreateHealthJobRequest>(() => ({
    resource_selector: {
      ids: ids(draft.resource_ids),
      enabled: draft.enabled_resources,
      country_codes: strings(draft.resource_country_codes),
      tags: strings(draft.resource_tags),
      tag_match: draft.tag_match,
    },
    node_selector: {
      ids: ids(draft.node_ids),
      enabled: draft.enabled_nodes,
      country_codes: strings(draft.node_country_codes),
      tags: strings(draft.node_tags),
      tag_match: draft.tag_match,
    },
    matrix_mode: 'CARTESIAN',
    max_items: draft.max_items,
  }), [draft]);

  return (
    <Modal
      title="Create Health Job"
      open={open}
      onCancel={onClose}
      width="min(900px, 96vw)"
      destroyOnHidden
      footer={[
        <Button key="close" onClick={onClose}>Close</Button>,
        <Button key="dry" disabled>Dry Run (F2)</Button>,
        <Button key="create" type="primary" disabled>Create Job (F3)</Button>,
      ]}
    >
      <Alert
        type="info"
        showIcon
        title="F1 contract-wired shell"
        description="This form builds the Stage 5.2 selector contract, but no request or dangerous action is sent in F1."
        style={{ marginBottom: 16 }}
      />
      <Form
        form={form}
        layout="vertical"
        initialValues={draft}
        onValuesChange={(_changed, values: SelectorForm) => setDraft(values)}
      >
        <Space align="start" wrap style={{ width: '100%' }}>
          <Card title="Resource Selector" style={{ flex: '1 1 360px' }}>
            <Form.Item name="resource_ids" label="Resource IDs"><Input placeholder="12, 18, 31" /></Form.Item>
            <Form.Item name="resource_country_codes" label="Country Codes"><Input placeholder="US, JP" /></Form.Item>
            <Form.Item name="resource_tags" label="Tags"><Input placeholder="residential, provider-a" /></Form.Item>
            <Form.Item name="enabled_resources" label="Enabled only" valuePropName="checked"><Switch /></Form.Item>
          </Card>
          <Card title="Node Selector" style={{ flex: '1 1 360px' }}>
            <Form.Item name="node_ids" label="Node IDs"><Input placeholder="2, 7" /></Form.Item>
            <Form.Item name="node_country_codes" label="Country Codes"><Input placeholder="US, JP" /></Form.Item>
            <Form.Item name="node_tags" label="Tags"><Input placeholder="premium, west" /></Form.Item>
            <Form.Item name="enabled_nodes" label="Enabled only" valuePropName="checked"><Switch /></Form.Item>
          </Card>
        </Space>
        <Space wrap>
          <Form.Item name="tag_match" label="Tag Match">
            <Radio.Group options={['ALL', 'ANY']} optionType="button" />
          </Form.Item>
          <Form.Item name="max_items" label="Maximum Items">
            <InputNumber min={1} max={20_000} />
          </Form.Item>
        </Space>
      </Form>

      <Card title="Dry Run Summary" size="small">
        {dryRun ? JSON.stringify(dryRun) : (
          <Typography.Text type="secondary">
            No Dry Run yet. The prepared request uses {request.matrix_mode} semantics and never contains credentials.
          </Typography.Text>
        )}
      </Card>
    </Modal>
  );
}
