import { useCallback, useEffect, useRef, useState } from 'react';

export interface SafePollingOptions {
  enabled?: boolean;
  intervalMs: number;
  maxBackoffMs?: number;
  run: (signal: AbortSignal) => Promise<void>;
}
export interface SafePollingState {
  refreshing: boolean;
  consecutiveFailures: number;
  lastSuccessAt: number | null;
  refresh: () => Promise<void>;
}

export function useSafePolling({
  enabled = true,
  intervalMs,
  maxBackoffMs = 30_000,
  run,
}: SafePollingOptions): SafePollingState {
  const inFlight = useRef(false);
  const controller = useRef<AbortController | null>(null);
  const timer = useRef<number | null>(null);
  const runRef = useRef(run);
  const failuresRef = useRef(0);
  const [refreshing, setRefreshing] = useState(false);
  const [consecutiveFailures, setConsecutiveFailures] = useState(0);
  const [lastSuccessAt, setLastSuccessAt] = useState<number | null>(null);

  useEffect(() => { runRef.current = run; }, [run]);

  const refresh = useCallback(async () => {
    if (!enabled || document.hidden || inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);
    controller.current?.abort();
    const nextController = new AbortController();
    controller.current = nextController;
    try {
      await runRef.current(nextController.signal);
      if (!nextController.signal.aborted) {
        failuresRef.current = 0;
        setConsecutiveFailures(0);
        setLastSuccessAt(Date.now());
      }
    } catch {
      if (!nextController.signal.aborted) {
        failuresRef.current += 1;
        setConsecutiveFailures(failuresRef.current);
      }
    } finally {
      if (!nextController.signal.aborted) setRefreshing(false);
      inFlight.current = false;
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) return;
    let disposed = false;

    const schedule = () => {
      if (disposed) return;
      const multiplier = Math.max(1, 2 ** failuresRef.current);
      const delay = Math.min(intervalMs * multiplier, maxBackoffMs);
      timer.current = window.setTimeout(async () => {
        await refresh();
        schedule();
      }, delay);
    };
    const onVisibility = () => {
      if (!document.hidden) void refresh();
    };

    schedule();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      disposed = true;
      if (timer.current !== null) window.clearTimeout(timer.current);
      controller.current?.abort();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [enabled, intervalMs, maxBackoffMs, refresh]);

  return { refreshing, consecutiveFailures, lastSuccessAt, refresh };
}
