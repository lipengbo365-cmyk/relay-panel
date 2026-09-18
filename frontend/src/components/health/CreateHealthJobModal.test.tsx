import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SafeHealthRequestError } from '../../api/health';
import { CreateHealthJobModal } from './CreateHealthJobModal';
import { buildHealthJobRequest, type HealthSelectorForm } from './healthSelectors';

const healthMocks = vi.hoisted(() => ({
  dryRunHealthJob: vi.fn(),
  createHealthJob: vi.fn(),
  listHealthResources: vi.fn(),
  listRelayNodes: vi.fn(),
}));

vi.mock('../../api/health', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../api/health')>(),
  ...healthMocks,
}));

const resource = {
  id: 11, name: 'US-SK5-001', host: 'masked.invalid', port: 1080,
  username_masked: 'u***', has_password: true, country: 'United States', country_code: 'US',
  region: '', city: '', isp: '', remark: '', tags: ['residential'], status: 'ONLINE' as const,
  enabled: true, detected_exit_ip: '203.0.113.10', detected_country: 'US', latency_ms: 80,
  consecutive_failures: 0, last_check_at: null, last_success_at: null, last_relay_node_id: 31,
  last_relay_node_name: 'US-LA-01', created_at: '', updated_at: '',
};

const node = {
  id: 31, device_group_id: 1, node_key: 'node-1', name: 'US-LA-01', country: 'United States',
  country_code: 'US', region: '', city: '', provider: '', public_ip: '192.0.2.10', advertise_host: '',
  bandwidth_mbps: 1000, remark: '', tags: ['west'], enabled: true, first_seen_at: '', last_seen_at: '',
  online: true, cpu: 10, ram: 20, connections: 1, node_version: '1.0.0', config_protocol_version: 6,
  socks5_check_queue: 0, supports_socks5_check: true,
};

const dryRun = {
  resource_count: 1,
  node_count: 1,
  item_count: 1,
  effective_limit: 10_000,
  within_limit: true,
  snapshot_estimated_at: 1_780_000_000_000,
  matrix_mode: 'CARTESIAN' as const,
};

const created = {
  job_id: '00000000-0000-4000-8000-000000000010',
  status: 'QUEUED' as const,
  total_items: 1,
  created_at: 1_780_000_000_000,
  replayed: false,
};

function renderModal(onCreated = vi.fn()) {
  render(<CreateHealthJobModal open onClose={() => {}} onCreated={onCreated} />);
  return { onCreated };
}

async function preview() {
  const button = screen.getByRole('button', { name: 'Preview Checks' });
  await waitFor(() => expect(button).toBeEnabled());
  await userEvent.click(button);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Create Job' })).toBeEnabled());
}

async function modalByTitle(title: string): Promise<HTMLElement> {
  const heading = await screen.findByText(title, { selector: '.ant-modal-title' });
  const dialog = heading.closest('[role="dialog"]');
  if (!(dialog instanceof HTMLElement)) throw new Error(`Dialog not found for ${title}`);
  return dialog;
}

async function confirmCreate(label = 'Create Job') {
  await userEvent.click(screen.getByRole('button', { name: label }));
  const dialog = await modalByTitle(label === 'Create Job' ? 'Create this health job?' : 'Retry same create request?');
  await userEvent.click(within(dialog).getByRole('button', { name: label === 'Create Job' ? 'Create Job' : 'Retry Same Request' }));
}

beforeEach(() => {
  healthMocks.dryRunHealthJob.mockReset().mockResolvedValue(dryRun);
  healthMocks.createHealthJob.mockReset().mockResolvedValue(created);
  healthMocks.listHealthResources.mockReset().mockResolvedValue({ items: [resource], total: 1, page: 1, page_size: 100 });
  healthMocks.listRelayNodes.mockReset().mockResolvedValue([node]);
  vi.spyOn(crypto, 'randomUUID').mockReturnValue('00000000-0000-4000-8000-000000000099');
});

describe('CreateHealthJobModal F3', () => {
  it('canonicalizes supported selectors with backend defaults', () => {
    const form: HealthSelectorForm = {
      resource_ids: [12, 11, 12], resource_country_codes: 'us, JP, us',
      resource_statuses: ['ONLINE', 'OFFLINE'], resource_tags: 'Residential, premium',
      resource_enabled: 'true', resource_tag_match: 'ANY', node_ids: [31],
      node_country_codes: 'us', node_tags: 'West, premium', node_enabled: 'any',
      node_tag_match: 'ALL', max_items: 500,
    };
    expect(buildHealthJobRequest(form)).toEqual({
      resource_selector: {
        ids: [11, 12], enabled: true, country_codes: ['JP', 'US'], statuses: ['OFFLINE', 'ONLINE'],
        tags: ['premium', 'residential'], tag_match: 'ANY',
      },
      node_selector: {
        ids: [31], enabled: null, country_codes: ['US'], tags: ['premium', 'west'], tag_match: 'ALL',
      },
      matrix_mode: 'CARTESIAN', max_items: 500,
    });
  });

  it('requires authoritative Dry Run and invalidates it after selector mutation', async () => {
    renderModal();
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
    await preview();
    expect(screen.getByText('Backend Dry Run Summary')).toBeInTheDocument();
    fireEvent.change(screen.getAllByPlaceholderText('US, JP')[0], { target: { value: 'JP' } });
    expect(screen.getByText('Preview is required after every selector change.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
  });

  it('blocks Create when backend says the matrix exceeds its limit', async () => {
    healthMocks.dryRunHealthJob.mockResolvedValueOnce({ ...dryRun, item_count: 20_001, effective_limit: 10_000, within_limit: false });
    renderModal();
    const button = screen.getByRole('button', { name: 'Preview Checks' });
    await waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);
    expect(await screen.findByText('MATRIX_TOO_LARGE')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
  });

  it('creates with one UUID and returns the backend Job', async () => {
    const onCreated = vi.fn();
    renderModal(onCreated);
    await preview();
    await confirmCreate();
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith(created));
    expect(healthMocks.createHealthJob).toHaveBeenCalledWith(
      expect.objectContaining({ matrix_mode: 'CARTESIAN' }),
      '00000000-0000-4000-8000-000000000099',
    );
  });

  it('treats replay as success and returns the original Job', async () => {
    const onCreated = vi.fn();
    healthMocks.createHealthJob.mockResolvedValueOnce({ ...created, replayed: true });
    renderModal(onCreated);
    await preview();
    await confirmCreate();
    await waitFor(() => expect(onCreated).toHaveBeenCalledWith({ ...created, replayed: true }));
  });

  it('reuses the same UUID after an unknown create outcome and never renders it', async () => {
    const onCreated = vi.fn();
    healthMocks.createHealthJob
      .mockRejectedValueOnce(new SafeHealthRequestError({ code: 'UNKNOWN_ERROR', message: 'Safe transport error.' }, true))
      .mockResolvedValueOnce({ ...created, replayed: true });
    renderModal(onCreated);
    await preview();
    await confirmCreate();
    expect(await screen.findByText('Create outcome unknown')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('00000000-0000-4000-8000-000000000099');
    await confirmCreate('Retry Same Create Request');
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(healthMocks.createHealthJob.mock.calls[0][1]).toBe(healthMocks.createHealthJob.mock.calls[1][1]);
  });

  it('does not silently mint a new key after idempotency conflict', async () => {
    healthMocks.createHealthJob.mockRejectedValueOnce(new SafeHealthRequestError({
      code: 'IDEMPOTENCY_KEY_REUSED', message: 'This request identity was already used for a different action.',
    }));
    renderModal();
    await preview();
    await confirmCreate();
    expect(await screen.findByText('IDEMPOTENCY_KEY_REUSED')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
    expect(healthMocks.createHealthJob).toHaveBeenCalledTimes(1);
  });

  it.each(['EMPTY_SELECTION', 'SELECTOR_REFERENCE_MISSING'] as const)('renders %s safely and keeps Create blocked', async (code) => {
    healthMocks.dryRunHealthJob.mockRejectedValueOnce(new SafeHealthRequestError({
      code,
      message: 'The selector could not be used.',
    }));
    renderModal();
    const button = screen.getByRole('button', { name: 'Preview Checks' });
    await waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);
    expect(await screen.findByText(code)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
  });

  it('mints a new UUID only after selector mutation and a new Dry Run', async () => {
    vi.mocked(crypto.randomUUID)
      .mockReset()
      .mockReturnValueOnce('00000000-0000-4000-8000-000000000091')
      .mockReturnValueOnce('00000000-0000-4000-8000-000000000092');
    healthMocks.createHealthJob
      .mockRejectedValueOnce(new SafeHealthRequestError({ code: 'UNKNOWN_ERROR', message: 'Safe transport error.' }, true))
      .mockResolvedValueOnce(created);
    renderModal();
    await preview();
    await confirmCreate();
    expect(await screen.findByText('Create outcome unknown')).toBeInTheDocument();

    fireEvent.change(screen.getAllByPlaceholderText('US, JP')[0], { target: { value: 'JP' } });
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
    await preview();
    await confirmCreate();

    await waitFor(() => expect(healthMocks.createHealthJob).toHaveBeenCalledTimes(2));
    expect(healthMocks.createHealthJob.mock.calls.map((call) => call[1])).toEqual([
      '00000000-0000-4000-8000-000000000091',
      '00000000-0000-4000-8000-000000000092',
    ]);
  });

  it('protects the active Create request from double submission', async () => {
    let resolveCreate: ((value: typeof created) => void) | undefined;
    healthMocks.createHealthJob.mockReturnValue(new Promise((resolve) => { resolveCreate = resolve; }));
    renderModal();
    await preview();
    await userEvent.click(screen.getByRole('button', { name: 'Create Job' }));
    const dialog = await modalByTitle('Create this health job?');
    const confirm = within(dialog).getByRole('button', { name: 'Create Job' });
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    expect(healthMocks.createHealthJob).toHaveBeenCalledTimes(1);
    resolveCreate?.(created);
    await waitFor(() => expect(healthMocks.createHealthJob).toHaveBeenCalledTimes(1));
  });
});
