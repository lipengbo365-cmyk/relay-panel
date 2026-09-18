import { useEffect, useMemo, useRef, useState } from 'react';
import {
  cancelHealthJob,
  isTerminalHealthJob,
  retryFailedHealthJob,
  SafeHealthRequestError,
  toSafeHealthError,
  type HealthJobItemListParams,
  type HealthJobItemState,
  type SafeError,
} from '../../api/health';
import { useHealthJobDetail, useHealthJobItems } from '../../hooks/useHealthReadModel';
import { HealthJobDetailDrawer } from './HealthJobDetailDrawer';

interface Props {
  open: boolean;
  jobId: string | null;
  resourceNames: ReadonlyMap<number, string>;
  nodeNames: ReadonlyMap<number, string>;
  refreshKey: number;
  onClose: () => void;
  onOpenJob: (jobId: string) => void;
  onJobsChanged: () => void;
  onNotice: (message: string) => void;
}

interface RetryIntent {
  parentJobId: string;
  key: string;
  outcomeUnknown: boolean;
}

export function HealthJobDetailContainer({
  open,
  jobId,
  resourceNames,
  nodeNames,
  refreshKey,
  onClose,
  onOpenJob,
  onJobsChanged,
  onNotice,
}: Props) {
  const [state, setState] = useState<HealthJobItemState | undefined>();
  const [safeErrorCode, setSafeErrorCode] = useState('');
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [cancelLoading, setCancelLoading] = useState(false);
  const [retryLoading, setRetryLoading] = useState(false);
  const [cancelUnknown, setCancelUnknown] = useState(false);
  const [retryUnknown, setRetryUnknown] = useState(false);
  const [actionError, setActionError] = useState<SafeError | null>(null);
  const retryIntent = useRef<RetryIntent | null>(null);
  const cancelController = useRef<AbortController | null>(null);
  const retryController = useRef<AbortController | null>(null);
  const cancelInFlight = useRef(false);
  const retryInFlight = useRef(false);
  const terminalItemsRefreshedFor = useRef<string | null>(null);
  const cursor = cursorStack.at(-1);
  const params = useMemo<HealthJobItemListParams>(() => ({
    state,
    safe_error_code: safeErrorCode.trim() || undefined,
    cursor,
  }), [cursor, safeErrorCode, state]);
  const detail = useHealthJobDetail(open ? jobId : null, refreshKey);
  const items = useHealthJobItems(open ? jobId : null, params, refreshKey);

  useEffect(() => {
    cancelController.current?.abort();
    retryController.current?.abort();
    retryIntent.current = null;
    setCancelLoading(false);
    setRetryLoading(false);
    cancelInFlight.current = false;
    retryInFlight.current = false;
    terminalItemsRefreshedFor.current = null;
    setCancelUnknown(false);
    setRetryUnknown(false);
    setActionError(null);
    setCursorStack([]);
    setState(undefined);
    setSafeErrorCode('');
  }, [jobId]);

  useEffect(() => () => {
    cancelController.current?.abort();
    retryController.current?.abort();
  }, []);

  useEffect(() => {
    if (
      !jobId
      || detail.data?.id !== jobId
      || !isTerminalHealthJob(detail.data.status)
      || terminalItemsRefreshedFor.current === jobId
    ) return;
    terminalItemsRefreshedFor.current = jobId;
    void items.reload().catch(() => undefined);
  }, [detail.data, items, jobId]);

  const resetItems = (nextState?: HealthJobItemState, nextCode = safeErrorCode) => {
    setCursorStack([]);
    setState(nextState);
    setSafeErrorCode(nextCode);
  };

  const handleCancel = async () => {
    if (!jobId || cancelInFlight.current) return;
    cancelInFlight.current = true;
    cancelController.current?.abort();
    const controller = new AbortController();
    cancelController.current = controller;
    setCancelLoading(true);
    setCancelUnknown(false);
    setActionError(null);
    try {
      const updated = await cancelHealthJob(jobId, controller.signal);
      if (controller.signal.aborted) return;
      detail.commitActionData(updated);
      onJobsChanged();
      onNotice('Cancellation requested. Backend status remains authoritative.');
    } catch (error) {
      if (controller.signal.aborted) return;
      const safe = error instanceof SafeHealthRequestError ? error.safe : toSafeHealthError(error);
      setActionError(safe);
      setCancelUnknown(error instanceof SafeHealthRequestError && error.outcomeUnknown);
      if (!(error instanceof SafeHealthRequestError) || !error.outcomeUnknown) {
        detail.invalidate();
        void detail.reload().catch(() => undefined);
      }
    } finally {
      cancelInFlight.current = false;
      if (!controller.signal.aborted) setCancelLoading(false);
    }
  };

  const handleRetry = async () => {
    if (!jobId || retryInFlight.current) return;
    retryInFlight.current = true;
    const existing = retryIntent.current?.parentJobId === jobId ? retryIntent.current : null;
    const intent = existing ?? { parentJobId: jobId, key: crypto.randomUUID(), outcomeUnknown: false };
    retryIntent.current = intent;
    retryController.current?.abort();
    const controller = new AbortController();
    retryController.current = controller;
    setRetryLoading(true);
    setRetryUnknown(false);
    setActionError(null);
    try {
      const child = await retryFailedHealthJob(jobId, intent.key, controller.signal);
      if (controller.signal.aborted) return;
      retryIntent.current = null;
      setRetryUnknown(false);
      detail.invalidate();
      void detail.reload().catch(() => undefined);
      onJobsChanged();
      onNotice(child.replayed
        ? 'This retry request already exists; the original child Job was opened.'
        : 'Execution failures were queued in a new child Job.');
      onOpenJob(child.job_id);
    } catch (error) {
      if (controller.signal.aborted) return;
      const safe = error instanceof SafeHealthRequestError ? error.safe : toSafeHealthError(error);
      const outcomeUnknown = error instanceof SafeHealthRequestError && error.outcomeUnknown;
      setActionError(safe);
      retryIntent.current = { ...intent, outcomeUnknown };
      setRetryUnknown(outcomeUnknown);
      if (!outcomeUnknown && (safe.code === 'NO_FAILED_ITEMS' || safe.code === 'JOB_NOT_TERMINAL')) {
        detail.invalidate();
        void detail.reload().catch(() => undefined);
      }
    } finally {
      retryInFlight.current = false;
      if (!controller.signal.aborted) setRetryLoading(false);
    }
  };

  return <HealthJobDetailDrawer
    open={open}
    jobId={jobId}
    job={detail.data}
    items={items.data.items}
    loading={detail.loading}
    error={detail.error}
    itemsLoading={items.loading}
    itemsError={items.error}
    nextItemsCursor={items.data.next_cursor}
    canPreviousItems={cursorStack.length > 0}
    itemState={state}
    safeErrorCode={safeErrorCode}
    resourceNames={resourceNames}
    nodeNames={nodeNames}
    cancelLoading={cancelLoading}
    retryLoading={retryLoading}
    cancelOutcomeUnknown={cancelUnknown}
    retryOutcomeUnknown={retryUnknown}
    actionError={actionError}
    onCancelJob={() => void handleCancel()}
    onRetryFailed={() => void handleRetry()}
    onItemStateChange={(next) => resetItems(next)}
    onSafeErrorCodeChange={(next) => resetItems(state, next)}
    onNextItems={() => items.data.next_cursor && setCursorStack((current) => [...current, items.data.next_cursor!])}
    onPreviousItems={() => setCursorStack((current) => current.slice(0, -1))}
    onRetry={() => { void detail.reload(); void items.reload(); }}
    onClose={onClose}
  />;
}
