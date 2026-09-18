import api, { type ApiEnvelope } from './client';
import type {
  RelayNode,
  Socks5Health,
  Socks5ResourcePage,
} from './types';

export type HealthJobSource =
  | 'MANUAL'
  | 'SCHEDULED'
  | 'RETRY_FAILED'
  | 'POLICY_RUN_NOW';

export type HealthJobStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'CANCEL_REQUESTED'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'PARTIAL'
  | 'CANCELLED'
  | 'PARTIAL_CANCELLED';

export type HealthJobItemState =
  | 'QUEUED'
  | 'LEASED'
  | 'DISPATCHING'
  | 'IN_FLIGHT'
  | 'RETRY_WAIT'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED';

export type HealthStatus =
  | 'ONLINE'
  | 'OFFLINE'
  | 'AUTH_FAILED'
  | 'TIMEOUT'
  | 'CONNECT_FAILED'
  | 'DISABLED'
  | 'UNKNOWN';

export type HealthTagMatch = 'ANY' | 'ALL';
export type HealthMatrixMode = 'CARTESIAN';
export type HealthSnapshotSemantics = 'CARTESIAN' | 'EXACT_PAIRS';

export interface HealthResourceSelector {
  ids?: number[];
  enabled?: boolean | null;
  country_codes?: string[];
  statuses?: HealthStatus[];
  tags?: string[];
  tag_match?: HealthTagMatch;
}

export interface HealthNodeSelector {
  ids?: number[];
  enabled?: boolean | null;
  country_codes?: string[];
  tags?: string[];
  tag_match?: HealthTagMatch;
}

export interface HealthJobSelector {
  resource_selector: HealthResourceSelector;
  node_selector: HealthNodeSelector;
}

export interface HealthDryRunRequest extends HealthJobSelector {
  matrix_mode?: HealthMatrixMode;
  max_items?: number;
}

export interface HealthDryRunResponse {
  resource_count: number;
  node_count: number;
  item_count: number;
  effective_limit: number;
  within_limit: boolean;
  snapshot_estimated_at: number;
  matrix_mode: HealthMatrixMode;
}

export type CreateHealthJobRequest = HealthDryRunRequest;

export interface CreateHealthJobResponse {
  job_id: string;
  status: HealthJobStatus;
  total_items: number;
  created_at: number;
  replayed: boolean;
}

export type RetryFailedResponse = CreateHealthJobResponse;

export interface HealthJob {
  id: string;
  source: HealthJobSource;
  parent_job_id: string | null;
  status: HealthJobStatus;
  resource_selector: HealthResourceSelector;
  node_selector: HealthNodeSelector;
  snapshot_hash: string;
  matrix_mode: HealthMatrixMode;
  snapshot_semantics: HealthSnapshotSemantics;
  selectors_reconstruct_snapshot: boolean;
  retry_policy_version: string;
  cancel_requested: boolean;
  total_items: number;
  queued_count: number;
  running_count: number;
  succeeded_count: number;
  failed_count: number;
  cancelled_count: number;
  failure_code: string | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
}

export interface HealthJobItem {
  id: number;
  job_id: string;
  resource_id: number | null;
  relay_node_id: number | null;
  resource_id_snapshot: number;
  relay_node_id_snapshot: number;
  state: HealthJobItemState;
  attempt_count: number;
  retry_count: number;
  not_before: number;
  first_started_at: number | null;
  last_started_at: number | null;
  deadline_at: number | null;
  health_status: HealthStatus | null;
  safe_error_code: string | null;
  safe_error_message: string | null;
  completed_after_cancel: boolean;
  created_at: number;
  updated_at: number;
  finished_at: number | null;
}

export interface HealthCursorResponse<T> {
  items: T[];
  next_cursor: string | null;
}

export type HealthJobListResponse = HealthCursorResponse<HealthJob>;
export type HealthJobDetailResponse = HealthJob;
export type HealthJobItemsResponse = HealthCursorResponse<HealthJobItem>;

export type HealthSafeErrorCode =
  | 'EMPTY_SELECTION'
  | 'MATRIX_TOO_LARGE'
  | 'SELECTOR_REFERENCE_MISSING'
  | 'INVALID_IDEMPOTENCY_KEY'
  | 'IDEMPOTENCY_KEY_REUSED'
  | 'JOB_NOT_FOUND'
  | 'JOB_NOT_TERMINAL'
  | 'NO_FAILED_ITEMS'
  | 'DATABASE_ERROR'
  | 'INVALID_CURSOR'
  | 'INVALID_STATUS'
  | 'INVALID_SOURCE'
  | 'INVALID_ITEM_STATE'
  | 'INVALID_LIMIT'
  | 'SELECTOR_TOO_LARGE'
  | 'INVALID_SELECTOR_ID'
  | 'INVALID_SELECTOR_VALUE'
  | 'INVALID_RESOURCE_STATUS'
  | 'INVALID_MATRIX_MODE'
  | 'INVALID_MAX_ITEMS'
  | 'IDEMPOTENCY_LEDGER_ORPHANED'
  | 'UNKNOWN_ERROR';

export interface SafeError {
  code: HealthSafeErrorCode;
  message: string;
}

export interface HealthJobListParams {
  status?: HealthJobStatus;
  source?: HealthJobSource;
  cursor?: string;
  limit?: number;
}

export interface HealthJobFilters {
  status?: HealthJobStatus;
  source?: HealthJobSource;
}

export interface HealthJobItemListParams {
  state?: HealthJobItemState;
  safe_error_code?: string;
  cursor?: string;
  limit?: number;
}

export interface HealthResourceListParams {
  page?: number;
  page_size?: number;
  search?: string;
  status?: HealthStatus;
  country?: string;
  detected_country?: string;
  tag?: string;
  enabled?: boolean;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface ResourceHealthHistoryRecord {
  id: number;
  resource_id: number;
  relay_node_id: number;
  status: HealthStatus;
  tcp_latency_ms: number | null;
  handshake_latency_ms: number | null;
  connect_latency_ms: number | null;
  total_latency_ms: number | null;
  exit_ip: string | null;
  country: string | null;
  error_stage: string | null;
  error_code: string | null;
  safe_error_message: string | null;
  checked_at: string;
}

const SAFE_CODES = new Set<HealthSafeErrorCode>([
  'EMPTY_SELECTION',
  'MATRIX_TOO_LARGE',
  'SELECTOR_REFERENCE_MISSING',
  'INVALID_IDEMPOTENCY_KEY',
  'IDEMPOTENCY_KEY_REUSED',
  'JOB_NOT_FOUND',
  'JOB_NOT_TERMINAL',
  'NO_FAILED_ITEMS',
  'DATABASE_ERROR',
  'INVALID_CURSOR',
  'INVALID_STATUS',
  'INVALID_SOURCE',
  'INVALID_ITEM_STATE',
  'INVALID_LIMIT',
  'SELECTOR_TOO_LARGE',
  'INVALID_SELECTOR_ID',
  'INVALID_SELECTOR_VALUE',
  'INVALID_RESOURCE_STATUS',
  'INVALID_MATRIX_MODE',
  'INVALID_MAX_ITEMS',
  'IDEMPOTENCY_LEDGER_ORPHANED',
]);

const SAFE_MESSAGES: Record<HealthSafeErrorCode, string> = {
  EMPTY_SELECTION: 'The selection does not contain any executable pair.',
  MATRIX_TOO_LARGE: 'The selected Resource × Node matrix exceeds the allowed limit.',
  SELECTOR_REFERENCE_MISSING: 'A selected Resource or Node no longer exists.',
  INVALID_IDEMPOTENCY_KEY: 'The request identity is invalid. Start the action again.',
  IDEMPOTENCY_KEY_REUSED: 'This request identity was already used for a different action.',
  JOB_NOT_FOUND: 'The health job was not found.',
  JOB_NOT_TERMINAL: 'This action requires a terminal health job.',
  NO_FAILED_ITEMS: 'This job has no execution failures to retry.',
  DATABASE_ERROR: 'The health service could not read its stored state.',
  INVALID_CURSOR: 'The page cursor is invalid or expired. Return to the first page.',
  INVALID_STATUS: 'The selected job status is not supported.',
  INVALID_SOURCE: 'The selected job source is not supported.',
  INVALID_ITEM_STATE: 'The selected item state is not supported.',
  INVALID_LIMIT: 'The requested page size is not supported.',
  SELECTOR_TOO_LARGE: 'The selector contains too many values.',
  INVALID_SELECTOR_ID: 'A selector contains an invalid identifier.',
  INVALID_SELECTOR_VALUE: 'A selector contains an invalid value.',
  INVALID_RESOURCE_STATUS: 'The selected Resource health status is not supported.',
  INVALID_MATRIX_MODE: 'The selected matrix mode is not supported.',
  INVALID_MAX_ITEMS: 'The requested item limit is not supported.',
  IDEMPOTENCY_LEDGER_ORPHANED: 'The original request record is unavailable. Start a new intent.',
  UNKNOWN_ERROR: 'The health request failed safely. Try again.',
};

function objectValue(value: unknown, key: string): unknown {
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

export function toSafeHealthError(error: unknown): SafeError {
  const response = objectValue(error, 'response');
  const data = objectValue(response, 'data');
  const rawMessage = objectValue(data, 'message');
  const code = typeof rawMessage === 'string' && SAFE_CODES.has(rawMessage as HealthSafeErrorCode)
    ? rawMessage as HealthSafeErrorCode
    : 'UNKNOWN_ERROR';
  return { code, message: SAFE_MESSAGES[code] };
}

export class SafeHealthRequestError extends Error {
  readonly safe: SafeError;
  readonly outcomeUnknown: boolean;

  constructor(safe: SafeError, outcomeUnknown = false) {
    super(safe.message);
    this.name = 'SafeHealthRequestError';
    this.safe = safe;
    this.outcomeUnknown = outcomeUnknown;
  }
}

function isUnknownTransportOutcome(error: unknown): boolean {
  return objectValue(error, 'response') === undefined
    && objectValue(error, 'code') !== 'ERR_CANCELED';
}

async function healthRequest<T>(request: Promise<ApiEnvelope<T>>): Promise<T> {
  try {
    const response = await request;
    if (response.code !== 0 || response.data === null) {
      const raw = response.message;
      const code = SAFE_CODES.has(raw as HealthSafeErrorCode)
        ? raw as HealthSafeErrorCode
        : 'UNKNOWN_ERROR';
      throw new SafeHealthRequestError({ code, message: SAFE_MESSAGES[code] });
    }
    return response.data;
  } catch (error) {
    if (error instanceof SafeHealthRequestError) throw error;
    throw new SafeHealthRequestError(toSafeHealthError(error), isUnknownTransportOutcome(error));
  }
}

function queryString<T extends object>(values: T): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== '') query.set(key, String(value));
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : '';
}

export function dryRunHealthJob(request: HealthDryRunRequest, signal?: AbortSignal) {
  return healthRequest(api.post<unknown, ApiEnvelope<HealthDryRunResponse>>(
    '/admin/socks5-health/jobs/dry-run',
    request,
    { signal },
  ));
}

export function createHealthJob(
  request: CreateHealthJobRequest,
  idempotencyKey: string,
  signal?: AbortSignal,
) {
  return healthRequest(api.post<unknown, ApiEnvelope<CreateHealthJobResponse>>(
    '/admin/socks5-health/jobs',
    request,
    { headers: { 'Idempotency-Key': idempotencyKey }, signal },
  ));
}

export function listHealthJobs(params: HealthJobListParams = {}, signal?: AbortSignal) {
  const query = queryString(params);
  return healthRequest(api.get<unknown, ApiEnvelope<HealthJobListResponse>>(
    `/admin/socks5-health/jobs${query}`,
    { signal },
  ));
}

export function getHealthJob(jobId: string, signal?: AbortSignal) {
  return healthRequest(api.get<unknown, ApiEnvelope<HealthJobDetailResponse>>(
    `/admin/socks5-health/jobs/${encodeURIComponent(jobId)}`,
    { signal },
  ));
}

export function listHealthJobItems(
  jobId: string,
  params: HealthJobItemListParams = {},
  signal?: AbortSignal,
) {
  const query = queryString(params);
  return healthRequest(api.get<unknown, ApiEnvelope<HealthJobItemsResponse>>(
    `/admin/socks5-health/jobs/${encodeURIComponent(jobId)}/items${query}`,
    { signal },
  ));
}

export function cancelHealthJob(jobId: string, signal?: AbortSignal) {
  return healthRequest(api.post<unknown, ApiEnvelope<HealthJobDetailResponse>>(
    `/admin/socks5-health/jobs/${encodeURIComponent(jobId)}/cancel`,
    {},
    { signal },
  ));
}

export function retryFailedHealthJob(
  jobId: string,
  idempotencyKey: string,
  signal?: AbortSignal,
) {
  return healthRequest(api.post<unknown, ApiEnvelope<RetryFailedResponse>>(
    `/admin/socks5-health/jobs/${encodeURIComponent(jobId)}/retry-failed`,
    {},
    { headers: { 'Idempotency-Key': idempotencyKey }, signal },
  ));
}

export function getResourceHealth(resourceId: number, signal?: AbortSignal) {
  return healthRequest(api.get<unknown, ApiEnvelope<Socks5Health[]>>(
    `/admin/socks5-resources/${resourceId}/health`,
    { signal },
  ));
}

export function getResourceHealthHistory(
  resourceId: number,
  limit = 50,
  offset = 0,
  signal?: AbortSignal,
) {
  const query = queryString({ limit, offset });
  return healthRequest(api.get<unknown, ApiEnvelope<ResourceHealthHistoryRecord[]>>(
    `/admin/socks5-resources/${resourceId}/check-history${query}`,
    { signal },
  ));
}

export function listHealthResources(
  params: HealthResourceListParams = {},
  signal?: AbortSignal,
) {
  const query = queryString(params);
  return healthRequest(api.get<unknown, ApiEnvelope<Socks5ResourcePage>>(
    `/admin/socks5-resources/page${query}`,
    { signal },
  ));
}

export function listRelayNodes(signal?: AbortSignal) {
  return healthRequest(api.get<unknown, ApiEnvelope<RelayNode[]>>(
    '/admin/relay-nodes',
    { signal },
  ));
}

export const TERMINAL_HEALTH_JOB_STATUSES: ReadonlySet<HealthJobStatus> = new Set([
  'SUCCEEDED',
  'FAILED',
  'PARTIAL',
  'CANCELLED',
  'PARTIAL_CANCELLED',
]);

export function isTerminalHealthJob(status: HealthJobStatus): boolean {
  return TERMINAL_HEALTH_JOB_STATUSES.has(status);
}

export function healthJobProgress(job: Pick<HealthJob,
  | 'total_items'
  | 'succeeded_count'
  | 'failed_count'
  | 'cancelled_count'
>): number {
  if (job.total_items <= 0) return 0;
  const terminal = job.succeeded_count + job.failed_count + job.cancelled_count;
  return Math.min(100, Math.max(0, Math.round((terminal / job.total_items) * 100)));
}
