import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ResourceHealthView } from './ResourceHealthView';

const mocks = vi.hoisted(() => ({
  listHealthResources: vi.fn(),
  getResourceHealth: vi.fn(),
  getResourceHealthHistory: vi.fn(),
}));
vi.mock('../../api/health', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../api/health')>(),
  ...mocks,
}));

const resource = {
  id: 11, name: 'Resource Eleven', host: 'invalid', port: 1080, username_masked: null, has_password: false,
  country: '', country_code: '', region: '', city: '', isp: '', remark: '', tags: [], status: 'ONLINE' as const,
  enabled: true, detected_exit_ip: '203.0.113.11', detected_country: 'US', latency_ms: 42,
  consecutive_failures: 0, last_check_at: '2026-09-18T00:00:00Z', last_success_at: null,
  last_relay_node_id: 99, last_relay_node_name: null, created_at: '', updated_at: '',
};

beforeEach(() => {
  mocks.listHealthResources.mockResolvedValue({ items: [resource], total: 1, page: 1, page_size: 50 });
  mocks.getResourceHealth.mockResolvedValue([]);
  mocks.getResourceHealthHistory.mockResolvedValue([]);
});

describe('ResourceHealthView', () => {
  it('loads current health and bounded history only after opening one Resource', async () => {
    render(<ResourceHealthView nodeNames={new Map()} />);
    expect(await screen.findByText('Resource Eleven')).toBeInTheDocument();
    expect(mocks.getResourceHealth).not.toHaveBeenCalled();
    expect(mocks.getResourceHealthHistory).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText('Resource Eleven'));
    await waitFor(() => expect(mocks.getResourceHealth).toHaveBeenCalledWith(11, expect.any(AbortSignal)));
    expect(mocks.getResourceHealthHistory).toHaveBeenCalledWith(11, 50, 0, expect.any(AbortSignal));
    expect(screen.getByText('Node #99')).toBeInTheDocument();
  });
});
