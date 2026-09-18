import { useMemo } from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { HealthJobStatus } from '../api/health';
import { runningJob, succeededJob } from '../test/healthFixtures';
import { useHealthJobDetail, useHealthJobPage } from './useHealthReadModel';

const mockList = vi.hoisted(() => vi.fn());
const mockGet = vi.hoisted(() => vi.fn());
vi.mock('../api/health', async (importOriginal) => ({
  ...await importOriginal<typeof import('../api/health')>(),
  listHealthJobs: mockList,
  getHealthJob: mockGet,
}));

function Probe({ status }: { status?: HealthJobStatus }) {
  const filters = useMemo(() => ({ status }), [status]);
  const result = useHealthJobPage(filters);
  return <output data-testid="jobs">{result.data.items.map((job) => job.status).join(',')}</output>;
}

function DetailProbe() {
  const result = useHealthJobDetail(runningJob.id);
  return <>
    <output data-testid="detail-status">{result.data?.status ?? 'loading'}</output>
    <button onClick={() => result.commitActionData({
      ...runningJob,
      status: 'CANCEL_REQUESTED',
      cancel_requested: true,
    })}>commit action</button>
  </>;
}

beforeEach(() => {
  vi.useRealTimers();
  mockList.mockReset();
  mockGet.mockReset();
  Object.defineProperty(document, 'hidden', { configurable: true, value: false });
});

describe('useHealthJobDetail action fencing', () => {
  it('does not let an older GET overwrite a newer POST action result', async () => {
    let resolveSlow: ((value: typeof runningJob) => void) | undefined;
    mockGet.mockReturnValue(new Promise((resolve) => { resolveSlow = resolve; }));
    render(<DetailProbe />);
    await act(async () => {
      screen.getByRole('button', { name: 'commit action' }).click();
    });
    expect(screen.getByTestId('detail-status')).toHaveTextContent('CANCEL_REQUESTED');
    await act(async () => { resolveSlow?.(runningJob); });
    await waitFor(() => expect(screen.getByTestId('detail-status')).toHaveTextContent('CANCEL_REQUESTED'));
  });
});

describe('useHealthJobPage', () => {
  it('uses 5s polling for active jobs and 15s after terminal state', async () => {
    vi.useFakeTimers();
    mockList.mockResolvedValueOnce({ items: [runningJob], next_cursor: null })
      .mockResolvedValue({ items: [succeededJob], next_cursor: null });
    render(<Probe />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByTestId('jobs')).toHaveTextContent('RUNNING');
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(screen.getByTestId('jobs')).toHaveTextContent('SUCCEEDED');
    const calls = mockList.mock.calls.length;
    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(mockList).toHaveBeenCalledTimes(calls);
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    expect(mockList.mock.calls.length).toBeGreaterThan(calls);
    vi.useRealTimers();
  });

  it('does not let a slow stale filter response overwrite the current filter', async () => {
    let resolveSlow: ((value: { items: Array<typeof runningJob>; next_cursor: null }) => void) | undefined;
    mockList.mockImplementation(({ status }: { status?: HealthJobStatus }) => {
      if (status === 'RUNNING') return new Promise((resolve) => { resolveSlow = resolve; });
      return Promise.resolve({ items: [succeededJob], next_cursor: null });
    });
    const view = render(<Probe status="RUNNING" />);
    view.rerender(<Probe status="SUCCEEDED" />);
    expect(await screen.findByText('SUCCEEDED')).toBeInTheDocument();
    await act(async () => { resolveSlow?.({ items: [runningJob], next_cursor: null }); });
    await waitFor(() => expect(screen.getByTestId('jobs')).toHaveTextContent('SUCCEEDED'));
  });
});
