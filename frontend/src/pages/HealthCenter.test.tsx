import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { exactPairsRetryJob, runningJob } from '../test/healthFixtures';
import HealthCenter from './HealthCenter';

const healthMocks = vi.hoisted(() => ({
  listHealthJobs: vi.fn(),
  getHealthJob: vi.fn(),
  listHealthJobItems: vi.fn(),
  listHealthResources: vi.fn(),
  listRelayNodes: vi.fn(),
  getResourceHealth: vi.fn(),
  getResourceHealthHistory: vi.fn(),
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
});

describe('HealthCenter F2', () => {
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

  it('renders Jobs from GET data and keeps Create actions disabled', async () => {
    renderPage('/health-center?tab=jobs');
    expect(await screen.findByText(runningJob.id)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /healthCreateJob/ }));
    expect(screen.getByRole('button', { name: 'Dry Run (F2)' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Create Job (F3)' })).toBeDisabled();
    await waitFor(() => expect(healthMocks.listHealthJobs).toHaveBeenCalled());
  });
});
