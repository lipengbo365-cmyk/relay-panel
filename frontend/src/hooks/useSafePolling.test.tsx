import { useEffect } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { useSafePolling } from './useSafePolling';

function Probe({ run }: { run: (signal: AbortSignal) => Promise<void> }) {
  const { refresh, refreshing, consecutiveFailures } = useSafePolling({ intervalMs: 1_000, run });
  useEffect(() => { void refresh(); }, [refresh]);
  return <output data-testid="poll-state">{refreshing ? 'refreshing' : 'idle'}:{consecutiveFailures}</output>;
}

describe('useSafePolling', () => {
  it('prevents overlapping requests and records the last success', async () => {
    vi.useFakeTimers();
    let resolve: (() => void) | undefined;
    const run = vi.fn(() => new Promise<void>((done) => { resolve = done; }));
    render(<Probe run={run} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
    expect(run).toHaveBeenCalledTimes(1);
    await act(async () => { resolve?.(); await Promise.resolve(); });
    expect(screen.getByTestId('poll-state')).toHaveTextContent('idle:0');
    vi.useRealTimers();
  });

  it('pauses while hidden, refreshes on visibility, and backs off after failure', async () => {
    vi.useFakeTimers();
    const run = vi.fn().mockRejectedValueOnce(new Error('safe failure')).mockResolvedValue(undefined);
    Object.defineProperty(document, 'hidden', { configurable: true, value: false });
    render(<Probe run={run} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(screen.getByTestId('poll-state')).toHaveTextContent('idle:1');

    Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    await act(async () => { await vi.advanceTimersByTimeAsync(2_000); });
    expect(run).toHaveBeenCalledTimes(1);

    Object.defineProperty(document, 'hidden', { configurable: true, value: false });
    await act(async () => { document.dispatchEvent(new Event('visibilitychange')); await Promise.resolve(); });
    expect(run).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('poll-state')).toHaveTextContent('idle:0');
    vi.useRealTimers();
  });
});
