import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { authFailedHealthItem, exactPairsRetryJob, retryWaitItem, runningJob, succeededJob } from '../test/healthFixtures';
import { SafeHealthRequestError } from '../api/health';
import HealthCenter from './HealthCenter';

const healthMocks = vi.hoisted(() => ({
  listHealthJobs: vi.fn(),
  getHealthJob: vi.fn(),
  listHealthJobItems: vi.fn(),
  listHealthResources: vi.fn(),
  listRelayNodes: vi.fn(),
  getResourceHealth: vi.fn(),
  getResourceHealthHistory: vi.fn(),
  dryRunHealthJob: vi.fn(),
  createHealthJob: vi.fn(),
  cancelHealthJob: vi.fn(),
  retryFailedHealthJob: vi.fn(),
}));

vi.mock('../api/health', async (importOriginal) => ({
  ...await importOriginal<typeof import('../api/health')>(),
  ...healthMocks,
}));

const resource = {
  id: 11, name: 'US-SK5-001', host: 'masked.invalid', port: 1080,
  username_masked: 'u***', has_password: true, country: 'United States', country_code: 'US',
  region: '', city: '', isp: '', remark: '', tags: [], status: 'ONLINE' as const, enabled: true,
  detected_exit_ip: '203.0.113.10', detected_country: 'US', latency_ms: 80,
  consecutive_failures: 0, last_check_at: '2026-09-18T00:00:00Z', last_success_at: '2026-09-18T00:00:00Z',
  last_relay_node_id: 31, last_relay_node_name: 'US-LA-01', created_at: '', updated_at: '',
};

const node = {
  id: 31, device_group_id: 1, node_key: 'node-1', name: 'US-LA-01', country: 'United States',
  country_code: 'US', region: '', city: '', provider: '', public_ip: '192.0.2.10', advertise_host: '',
  bandwidth_mbps: 1000, remark: '', tags: [], enabled: true, first_seen_at: '', last_seen_at: '', online: true,
  cpu: 10, ram: 20, connections: 1, node_version: '1.0.0', config_protocol_version: 6,
  socks5_check_queue: 0, supports_socks5_check: true,
};

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}

function renderPage(initial = '/health-center') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/health-center" element={<><HealthCenter /><LocationProbe /></>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function modalByTitle(title: string): Promise<HTMLElement> {
  const heading = await screen.findByText(title, { selector: '.ant-modal-title' });
  const dialog = heading.closest('[role="dialog"]');
  if (!(dialog instanceof HTMLElement)) throw new Error(`Dialog not found for ${title}`);
  return dialog;
}

beforeEach(() => {
  healthMocks.listHealthJobs.mockResolvedValue({ items: [runningJob], next_cursor: null });
  healthMocks.getHealthJob.mockResolvedValue(exactPairsRetryJob);
  healthMocks.listHealthJobItems.mockResolvedValue({ items: [], next_cursor: null });
  healthMocks.listHealthResources.mockImplementation(({ status }: { status?: string } = {}) => Promise.resolve({
    items: status ? [] : [resource], total: status === 'ONLINE' || !status ? 1 : 0, page: 1, page_size: 50,
  }));
  healthMocks.listRelayNodes.mockResolvedValue([node]);
  healthMocks.getResourceHealth.mockResolvedValue([]);
  healthMocks.getResourceHealthHistory.mockResolvedValue([]);
  healthMocks.dryRunHealthJob.mockResolvedValue({
    resource_count: 1, node_count: 1, item_count: 1, effective_limit: 10_000,
    within_limit: true, snapshot_estimated_at: 1_780_000_000_000, matrix_mode: 'CARTESIAN',
  });
  healthMocks.createHealthJob.mockResolvedValue({
    job_id: runningJob.id, status: 'QUEUED', total_items: 1, created_at: 1_780_000_000_000, replayed: false,
  });
  healthMocks.cancelHealthJob.mockResolvedValue(runningJob);
  healthMocks.retryFailedHealthJob.mockResolvedValue({
    job_id: exactPairsRetryJob.id, status: 'QUEUED', total_items: 1, created_at: 1_780_000_000_000, replayed: false,
  });
  vi.spyOn(crypto, 'randomUUID').mockReturnValue('00000000-0000-4000-8000-000000000088');
});

describe('HealthCenter F3', () => {
  it('renders real Overview and Node readiness data', async () => {
    renderPage();
    expect(await screen.findByText('US-LA-01')).toBeInTheDocument();
    expect(screen.getByText('SOCKS5 Resources')).toBeInTheDocument();
    expect(screen.getByText('Protocol')).toBeInTheDocument();
  });

  it('loads a copied Job URL and closes it without losing tab state', async () => {
    renderPage(`/health-center?tab=jobs&job=${exactPairsRetryJob.id}`);
    expect(await screen.findByText('Exact failed-pair snapshot')).toBeInTheDocument();
    expect(healthMocks.getHealthJob).toHaveBeenCalledWith(exactPairsRetryJob.id, expect.any(AbortSignal));
    await act(async () => { await userEvent.click(screen.getByLabelText('Close')); });
    expect(screen.getByTestId('location')).toHaveTextContent('tab=jobs');
    expect(screen.getByTestId('location')).not.toHaveTextContent('job=');
  });

  it('renders Jobs and requires Dry Run before Create', async () => {
    renderPage('/health-center?tab=jobs');
    expect(await screen.findByText(runningJob.id)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /healthCreateJob/ }));
    const previewButton = screen.getByRole('button', { name: 'Preview Checks' });
    await waitFor(() => expect(previewButton).toBeEnabled());
    expect(screen.getByRole('button', { name: 'Create Job' })).toBeDisabled();
    await waitFor(() => expect(healthMocks.listHealthJobs).toHaveBeenCalled());
  });

  it('submits Cancel, then renders the backend CANCEL_REQUESTED state', async () => {
    healthMocks.getHealthJob.mockResolvedValue(runningJob);
    const cancelRequested = {
      ...runningJob,
      status: 'CANCEL_REQUESTED' as const,
      cancel_requested: true,
    };
    healthMocks.cancelHealthJob.mockImplementation(async () => {
      healthMocks.getHealthJob.mockResolvedValue(cancelRequested);
      return cancelRequested;
    });
    renderPage(`/health-center?tab=jobs&job=${runningJob.id}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel Job' }));
    const dialog = await modalByTitle('Cancel this health Job?');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Request Cancellation' }));
    expect(await screen.findByText('Cancellation in progress')).toBeInTheDocument();
    expect(healthMocks.cancelHealthJob).toHaveBeenCalledWith(runningJob.id, expect.any(AbortSignal));
    expect(screen.getByText('CANCEL_REQUESTED')).toBeInTheDocument();
  });

  it('reuses one retry UUID after unknown outcome and opens the replayed child', async () => {
    healthMocks.retryFailedHealthJob
      .mockRejectedValueOnce(new SafeHealthRequestError({ code: 'UNKNOWN_ERROR', message: 'Safe transport error.' }, true))
      .mockResolvedValueOnce({
        job_id: '00000000-0000-4000-8000-000000000077',
        status: 'QUEUED', total_items: 1, created_at: 1_780_000_000_000, replayed: true,
      });
    renderPage(`/health-center?tab=jobs&job=${exactPairsRetryJob.id}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Retry Execution Failures' }));
    let dialog = await modalByTitle('Retry execution failures?');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Retry Execution Failures' }));
    expect(await screen.findByText('Retry outcome unknown')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry Same Request' }));
    dialog = await modalByTitle('Retry execution failures?');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Retry Same Request' }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent('job=00000000-0000-4000-8000-000000000077'));
    expect(healthMocks.retryFailedHealthJob.mock.calls[0][1]).toBe(healthMocks.retryFailedHealthJob.mock.calls[1][1]);
    expect(document.body.textContent).not.toContain('00000000-0000-4000-8000-000000000088');
  }, 60_000);

  it.each(['NO_FAILED_ITEMS', 'JOB_NOT_TERMINAL'] as const)('renders %s safely and refreshes authoritative detail', async (code) => {
    healthMocks.retryFailedHealthJob.mockRejectedValueOnce(new SafeHealthRequestError({
      code,
      message: 'The retry request is not currently valid.',
    }));
    renderPage(`/health-center?tab=jobs&job=${exactPairsRetryJob.id}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Retry Execution Failures' }));
    const dialog = await modalByTitle('Retry execution failures?');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Retry Execution Failures' }));
    expect(await screen.findByText(code)).toBeInTheDocument();
    await waitFor(() => expect(healthMocks.getHealthJob.mock.calls.length).toBeGreaterThan(1));
  });

  it('performs a final Item refresh after the Job first reaches a terminal state', async () => {
    const terminalJob = { ...succeededJob, id: runningJob.id };
    const terminalItem = {
      ...authFailedHealthItem,
      job_id: runningJob.id,
      health_status: 'ONLINE' as const,
    };
    healthMocks.getHealthJob
      .mockResolvedValueOnce(runningJob)
      .mockResolvedValue(terminalJob);
    healthMocks.listHealthJobItems
      .mockResolvedValueOnce({ items: [{ ...retryWaitItem, job_id: runningJob.id }], next_cursor: null })
      .mockResolvedValueOnce({ items: [{ ...retryWaitItem, job_id: runningJob.id }], next_cursor: null })
      .mockResolvedValue({ items: [terminalItem], next_cursor: null });

    renderPage(`/health-center?tab=jobs&job=${runningJob.id}`);
    expect((await screen.findAllByText('RETRY_WAIT')).length).toBeGreaterThan(1);
    await userEvent.click(screen.getByRole('button', { name: /refresh/ }));
    await waitFor(() => expect(healthMocks.getHealthJob.mock.calls.length).toBeGreaterThan(1));
    await waitFor(() => expect(healthMocks.listHealthJobItems.mock.calls.length).toBeGreaterThan(2));
    await waitFor(() => {
      const resourceCell = screen.getByText('US-SK5-001');
      const row = resourceCell.closest('tr');
      expect(row).not.toBeNull();
      expect(within(row as HTMLElement).getByText('ONLINE')).toBeInTheDocument();
    });
  });
});
