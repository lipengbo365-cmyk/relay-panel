import type { HealthJob, HealthJobItem } from '../api/health';

const baseJob: HealthJob = {
  id: '00000000-0000-4000-8000-000000000001',
  source: 'MANUAL',
  parent_job_id: null,
  status: 'QUEUED',
  resource_selector: { ids: [11], enabled: true, country_codes: [], statuses: [], tags: [], tag_match: 'ALL' },
  node_selector: { ids: [31], enabled: true, country_codes: [], tags: [], tag_match: 'ALL' },
  snapshot_hash: 'a'.repeat(64),
  matrix_mode: 'CARTESIAN',
  snapshot_semantics: 'CARTESIAN',
  selectors_reconstruct_snapshot: true,
  retry_policy_version: 'v1',
  cancel_requested: false,
  total_items: 4,
  queued_count: 4,
  running_count: 0,
  succeeded_count: 0,
  failed_count: 0,
  cancelled_count: 0,
  failure_code: null,
  created_at: 1_780_000_000_000,
  started_at: null,
  finished_at: null,
};

export const queuedJob: HealthJob = { ...baseJob };
export const runningJob: HealthJob = {
  ...baseJob,
  id: '00000000-0000-4000-8000-000000000002',
  status: 'RUNNING',
  queued_count: 1,
  running_count: 1,
  succeeded_count: 2,
  started_at: baseJob.created_at + 1_000,
};
export const succeededJob: HealthJob = {
  ...baseJob,
  id: '00000000-0000-4000-8000-000000000003',
  status: 'SUCCEEDED',
  queued_count: 0,
  succeeded_count: 4,
  started_at: baseJob.created_at + 1_000,
  finished_at: baseJob.created_at + 4_000,
};
export const partialJob: HealthJob = {
  ...succeededJob,
  id: '00000000-0000-4000-8000-000000000004',
  status: 'PARTIAL',
  succeeded_count: 3,
  failed_count: 1,
};
export const cancelledJob: HealthJob = {
  ...succeededJob,
  id: '00000000-0000-4000-8000-000000000005',
  status: 'CANCELLED',
  succeeded_count: 0,
  cancelled_count: 4,
  cancel_requested: true,
};
export const exactPairsRetryJob: HealthJob = {
  ...partialJob,
  id: '00000000-0000-4000-8000-000000000006',
  source: 'RETRY_FAILED',
  parent_job_id: partialJob.id,
  snapshot_semantics: 'EXACT_PAIRS',
  selectors_reconstruct_snapshot: false,
};

const baseItem: HealthJobItem = {
  id: 1,
  job_id: runningJob.id,
  resource_id: 11,
  relay_node_id: 31,
  resource_id_snapshot: 11,
  relay_node_id_snapshot: 31,
  state: 'RETRY_WAIT',
  attempt_count: 1,
  retry_count: 1,
  not_before: baseJob.created_at + 2_000,
  first_started_at: baseJob.created_at + 1_000,
  last_started_at: baseJob.created_at + 1_000,
  deadline_at: baseJob.created_at + 900_000,
  health_status: null,
  safe_error_code: 'UPSTREAM_UNAVAILABLE',
  safe_error_message: 'Upstream service unavailable',
  completed_after_cancel: false,
  created_at: baseJob.created_at,
  updated_at: baseJob.created_at + 2_000,
  finished_at: null,
};

export const retryWaitItem: HealthJobItem = { ...baseItem };
export const authFailedHealthItem: HealthJobItem = {
  ...baseItem,
  id: 2,
  state: 'SUCCEEDED',
  health_status: 'AUTH_FAILED',
  safe_error_code: null,
  safe_error_message: null,
  finished_at: baseJob.created_at + 3_000,
};
export const completedAfterCancelItem: HealthJobItem = {
  ...authFailedHealthItem,
  id: 3,
  health_status: 'ONLINE',
  completed_after_cancel: true,
};
export const deletedResourceItem: HealthJobItem = {
  ...authFailedHealthItem,
  id: 4,
  resource_id: null,
  relay_node_id: null,
  resource_id_snapshot: 987,
  relay_node_id_snapshot: 654,
};

export const healthJobFixtures = [
  queuedJob,
  runningJob,
  succeededJob,
  partialJob,
  cancelledJob,
  exactPairsRetryJob,
];
