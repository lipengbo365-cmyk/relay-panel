import { useMemo, useState } from 'react';
import type { HealthJobItemListParams, HealthJobItemState } from '../../api/health';
import { useHealthJobDetail, useHealthJobItems } from '../../hooks/useHealthReadModel';
import { HealthJobDetailDrawer } from './HealthJobDetailDrawer';

interface Props {
  open: boolean;
  jobId: string | null;
  resourceNames: ReadonlyMap<number, string>;
  nodeNames: ReadonlyMap<number, string>;
  refreshKey: number;
  onClose: () => void;
}

export function HealthJobDetailContainer({ open, jobId, resourceNames, nodeNames, refreshKey, onClose }: Props) {
  const [state, setState] = useState<HealthJobItemState | undefined>();
  const [safeErrorCode, setSafeErrorCode] = useState('');
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const cursor = cursorStack.at(-1);
  const params = useMemo<HealthJobItemListParams>(() => ({
    state,
    safe_error_code: safeErrorCode.trim() || undefined,
    cursor,
  }), [cursor, safeErrorCode, state]);
  const detail = useHealthJobDetail(open ? jobId : null, refreshKey);
  const items = useHealthJobItems(open ? jobId : null, params, refreshKey);

  const resetItems = (nextState?: HealthJobItemState, nextCode = safeErrorCode) => {
    setCursorStack([]);
    setState(nextState);
    setSafeErrorCode(nextCode);
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
    onItemStateChange={(next) => resetItems(next)}
    onSafeErrorCodeChange={(next) => resetItems(state, next)}
    onNextItems={() => items.data.next_cursor && setCursorStack((current) => [...current, items.data.next_cursor!])}
    onPreviousItems={() => setCursorStack((current) => current.slice(0, -1))}
    onRetry={() => { void detail.reload(); void items.reload(); }}
    onClose={onClose}
  />;
}
