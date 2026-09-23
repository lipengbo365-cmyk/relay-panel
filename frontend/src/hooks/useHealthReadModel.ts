import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  getHealthJob,
  getResourceHealth,
  getResourceHealthHistory,
  isTerminalHealthJob,
  listHealthJobItems,
  listHealthJobs,
  listHealthResources,
  listRelayNodes,
  toSafeHealthError,
  type HealthJob,
  type HealthJobFilters,
  type HealthJobItem,
  type HealthJobItemListParams,
  type HealthStatus,
  type ResourceHealthHistoryRecord,
  type SafeError,
} from '../api/health';
import type { RelayNode, Socks5Health, Socks5Resource } from '../api/types';
import { useSafePolling } from './useSafePolling';

interface ReadState<T> {
  data: T;
  loading: boolean;
  error: SafeError | null;
}

function useLatestRequest<T>(initial: T) {
  const [state, setState] = useState<ReadState<T>>({ data: initial, loading: true, error: null });
  const generation = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const run = useCallback(async (reader: (signal: AbortSignal) => Promise<T>) => {
    const current = ++generation.current;
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setState((value) => ({ ...value, loading: true, error: null }));
    try {
      const data = await reader(next.signal);
      if (!next.signal.aborted && generation.current === current) {
        setState({ data, loading: false, error: null });
      }
      return data;
    } catch (error) {
      if (!next.signal.aborted && generation.current === current) {
        setState((value) => ({ ...value, loading: false, error: toSafeHealthError(error) }));
      }
      throw error;
    }
  }, []);

  const commit = useCallback((data: T) => {
    generation.current += 1;
    controller.current?.abort();
    controller.current = null;
    setState({ data, loading: false, error: null });
  }, []);

  const invalidate = useCallback(() => {
    generation.current += 1;
    controller.current?.abort();
    controller.current = null;
  }, []);

  useEffect(() => () => controller.current?.abort(), []);
  return { state, run, commit, invalidate };
}

export function useHealthJobPage(filters: HealthJobFilters, cursor?: string, refreshKey = 0, enabled = true) {
  const request = useLatestRequest<{ items: HealthJob[]; next_cursor: string | null }>({ items: [], next_cursor: null });
  const runRequest = request.run;
  const load = useCallback(
    (signal?: AbortSignal) => runRequest((ownSignal) => listHealthJobs(
      { ...filters, cursor, limit: 50 },
      signal ? AbortSignal.any([signal, ownSignal]) : ownSignal,
    )),
    [cursor, filters, runRequest],
  );
  const hasActive = request.state.data.items.some((job) => !isTerminalHealthJob(job.status));
  const polling = useSafePolling({
    enabled,
    intervalMs: hasActive ? 5_000 : 15_000,
    run: async (signal) => { await load(signal); },
  });

  useEffect(() => {
    if (enabled) void load().catch(() => undefined);
  }, [enabled, load, refreshKey]);
  return { ...request.state, ...polling, reload: load };
}

export function useHealthJobDetail(jobId: string | null, refreshKey = 0) {
  const request = useLatestRequest<HealthJob | null>(null);
  const runRequest = request.run;
  const load = useCallback(
    (signal?: AbortSignal) => jobId
      ? runRequest((ownSignal) => getHealthJob(
        jobId,
        signal ? AbortSignal.any([signal, ownSignal]) : ownSignal,
      ))
      : Promise.resolve(null),
    [jobId, runRequest],
  );
  const polling = useSafePolling({
    enabled: jobId !== null && request.state.data !== null && !isTerminalHealthJob(request.state.data.status),
    intervalMs: 2_000,
    run: async (signal) => { await load(signal); },
  });

  useEffect(() => {
    if (jobId) void load().catch(() => undefined);
  }, [jobId, load, refreshKey]);
  return {
    ...request.state,
    ...polling,
    reload: load,
    commitActionData: request.commit,
    invalidate: request.invalidate,
  };
}

export function useHealthJobItems(
  jobId: string | null,
  params: HealthJobItemListParams,
  refreshKey = 0,
) {
  const request = useLatestRequest<{ items: HealthJobItem[]; next_cursor: string | null }>({ items: [], next_cursor: null });
  const runRequest = request.run;
  const load = useCallback(
    () => jobId
      ? runRequest((signal) => listHealthJobItems(jobId, { ...params, limit: 100 }, signal))
      : Promise.resolve({ items: [], next_cursor: null }),
    [jobId, params, runRequest],
  );
  useEffect(() => {
    if (jobId) void load().catch(() => undefined);
  }, [jobId, load, refreshKey]);
  return { ...request.state, reload: load };
}

export function useHealthNameMaps(refreshKey = 0) {
  const [resources, setResources] = useState<ReadonlyMap<number, string>>(new Map());
  const [nodes, setNodes] = useState<ReadonlyMap<number, string>>(new Map());
  useEffect(() => {
    const controller = new AbortController();
    void Promise.allSettled([
      listHealthResources({ page: 1, page_size: 500 }, controller.signal).then((page) => {
        setResources(new Map(page.items.map((item) => [item.id, item.name])));
      }),
      listRelayNodes(controller.signal).then((items) => {
        setNodes(new Map(items.map((item) => [item.id, item.name])));
      }),
    ]);
    return () => controller.abort();
  }, [refreshKey]);
  return { resourceNames: resources, nodeNames: nodes };
}

interface OverviewData {
  resourceTotal?: number;
  healthTotals: Partial<Record<HealthStatus, number>>;
  nodes: RelayNode[];
  recentJobs: HealthJob[];
  resourceError: SafeError | null;
  nodeError: SafeError | null;
  jobsError: SafeError | null;
}

const SUMMARY_STATUSES: HealthStatus[] = [
  'ONLINE', 'OFFLINE', 'AUTH_FAILED', 'TIMEOUT', 'CONNECT_FAILED', 'DISABLED', 'UNKNOWN',
];

export function useHealthOverview(refreshKey = 0, enabled = true) {
  const initial: OverviewData = {
    healthTotals: {}, nodes: [], recentJobs: [], resourceError: null, nodeError: null, jobsError: null,
  };
  const lastOverview = useRef<OverviewData>(initial);
  const request = useLatestRequest<OverviewData>(initial);
  const runRequest = request.run;
  const load = useCallback(() => runRequest(async (signal) => {
    const [resourceResults, nodeResult, jobsResult] = await Promise.all([
      Promise.allSettled([
        listHealthResources({ page: 1, page_size: 1 }, signal),
        ...SUMMARY_STATUSES.map((status) => listHealthResources({ page: 1, page_size: 1, status }, signal)),
      ]),
      listRelayNodes(signal).then((value) => ({ value })).catch((error) => ({ error })),
      listHealthJobs({ limit: 5 }, signal).then((value) => ({ value })).catch((error) => ({ error })),
    ]);
    const healthTotals: Partial<Record<HealthStatus, number>> = { ...lastOverview.current.healthTotals };
    SUMMARY_STATUSES.forEach((status, index) => {
      const result = resourceResults[index + 1];
      if (result.status === 'fulfilled') healthTotals[status] = result.value.total;
    });
    const totalResult = resourceResults[0];
    const resourceFailure = resourceResults.find((result) => result.status === 'rejected');
    const next: OverviewData = {
      resourceTotal: totalResult.status === 'fulfilled'
        ? totalResult.value.total
        : lastOverview.current.resourceTotal,
      healthTotals,
      nodes: 'value' in nodeResult ? nodeResult.value : lastOverview.current.nodes,
      recentJobs: 'value' in jobsResult ? jobsResult.value.items : lastOverview.current.recentJobs,
      resourceError: resourceFailure?.status === 'rejected' ? toSafeHealthError(resourceFailure.reason) : null,
      nodeError: 'error' in nodeResult ? toSafeHealthError(nodeResult.error) : null,
      jobsError: 'error' in jobsResult ? toSafeHealthError(jobsResult.error) : null,
    };
    lastOverview.current = next;
    return next;
  }), [runRequest]);
  const polling = useSafePolling({ enabled, intervalMs: 10_000, run: async () => { await load(); } });
  useEffect(() => {
    if (enabled) void load().catch(() => undefined);
  }, [enabled, load, refreshKey]);
  return { ...request.state, ...polling, reload: load };
}

export function useResourcePage(page: number, search: string, status?: HealthStatus, refreshKey = 0) {
  const request = useLatestRequest<{ items: Socks5Resource[]; total: number; page: number; page_size: number }>({
    items: [], total: 0, page: 1, page_size: 50,
  });
  const runRequest = request.run;
  const load = useCallback(
    () => runRequest((signal) => listHealthResources({ page, page_size: 50, search, status }, signal)),
    [page, runRequest, search, status],
  );
  useEffect(() => { void load().catch(() => undefined); }, [load, refreshKey]);
  return { ...request.state, reload: load };
}

export function useResourceHealthDetail(resourceId: number | null, refreshKey = 0) {
  const health = useLatestRequest<Socks5Health[]>([]);
  const history = useLatestRequest<ResourceHealthHistoryRecord[]>([]);
  const runHealth = health.run;
  const runHistory = history.run;
  const load = useCallback(async () => {
    if (resourceId === null) return;
    await Promise.allSettled([
      runHealth((signal) => getResourceHealth(resourceId, signal)),
      runHistory((signal) => getResourceHealthHistory(resourceId, 50, 0, signal)),
    ]);
  }, [resourceId, runHealth, runHistory]);
  useEffect(() => { void load(); }, [load, refreshKey]);
  return { health: health.state, history: history.state, reload: load };
}

export function useNodeReadiness(nodes: RelayNode[]) {
  return useMemo(() => ({
    total: nodes.length,
    online: nodes.filter((node) => node.online).length,
    supported: nodes.filter((node) => node.supports_socks5_check).length,
  }), [nodes]);
}
