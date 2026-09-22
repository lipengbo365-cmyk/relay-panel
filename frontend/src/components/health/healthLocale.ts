import type {
  HealthJobItemState,
  HealthJobSource,
  HealthJobStatus,
  HealthStatus,
} from '../../api/health';
import { useI18n } from '../../i18n/context';
import type { Lang } from '../../i18n/context';

const zhCN = {
  center: '健康检测', overview: '总览', jobs: '检测任务', resourceHealth: '资源健康',
  refresh: '刷新', lastRefresh: '最后刷新',
  healthJob: '健康检测任务', source: '来源', status: '状态', parentJob: '父任务',
  snapshotSemantics: '快照语义', matrixMode: '组合模式', retryPolicy: '重试策略',
  cancelRequested: '已请求取消', failureCode: '失败代码', snapshotHash: '快照哈希',
  created: '创建时间', started: '开始时间', finished: '完成时间', yes: '是', no: '否',
  progressCounters: '后端计数器进度', queued: '排队中', running: '运行中', succeeded: '成功',
  failed: '失败', cancelled: '已取消', selectors: '筛选条件',
  exactSnapshot: '精确失败组合快照', exactSnapshotMismatch: '协议不一致：精确组合不能从筛选条件重新推导。',
  exactSnapshotDescription: 'selectors_reconstruct_snapshot = false。界面不会自行推导“资源 × 节点”组合。',
  cancellationInProgress: '正在取消', cancellationInProgressDescription: '后端正在取消尚未开始的检查；已经执行中的检查仍可能完成并记录健康结果。',
  cancelOutcomeUnknown: '取消结果暂时未知', cancelOutcomeUnknownDescription: '请刷新，或使用相同请求再次取消；以后端状态为准。',
  retryOutcomeUnknown: '重试结果暂时未知', retryOutcomeUnknownDescription: '使用相同请求重试，可找回原子任务，不会重复创建。',
  exactResultUnavailable: '无法提供该任务当时的精确出口 IP 与延迟',
  exactResultUnavailableDescription: '任务项分别展示执行状态和健康结果；当前资源健康状态不会冒充历史任务结果。',
  retryCancelRequest: '重试取消请求', cancellationRequested: '已请求取消', cancelJob: '取消任务',
  cancelTooltip: '请求取消；执行中的检查仍可能完成。', cancelUnavailableTooltip: '仅非终态任务可以取消。',
  retrySameRequest: '重试同一请求', retryExecutionFailures: '重试执行失败项',
  retryTooltip: '只重试执行失败项，不会重新检测所有不健康代理。',
  jobItems: '任务明细', itemStateFilter: '任务项状态筛选', allStates: '全部状态',
  safeErrorFilter: '安全错误代码筛选', safeErrorCode: '安全错误代码', item: '明细',
  resource: '资源', relayNode: '中转节点', executionState: '执行状态', healthResult: '健康结果',
  attempts: '尝试次数', retries: '重试次数', safeError: '安全错误', afterCancel: '取消后完成',
  completedAfterCancel: '在请求取消后完成', previousItems: '上一页明细', nextItems: '下一页明细',
  noJobItems: '没有任务明细', cancelConfirmTitle: '确定取消这个健康检测任务？',
  requestCancellation: '请求取消', cancelConfirmDescription: '取消会停止尚未开始或仍可取消的检查。已经执行中的检查可能完成并正常记录健康结果。',
  retryConfirmTitle: '确定重试执行失败项？', retryConfirmDescription: '只重试执行状态为“失败”的任务项。离线、认证失败、连接失败等健康结果不会自动重新检测。',
  dataMayBeStale: '数据可能不是最新', dataMayBeStaleDescription: '最近一次刷新失败，当前仍显示上次成功获取的数据。',
  jobStatusFilter: '任务状态筛选', jobSourceFilter: '任务来源筛选', filterStatus: '状态', filterSource: '来源',
  cursorHint: '翻页游标由后端管理，修改筛选条件后会自动重置。', jobId: '任务 ID',
  progress: '进度', actions: '操作', detail: '详情', previous: '上一页', next: '下一页',
  createHealthJob: '新建健康检测任务', close: '关闭', previewChecks: '预览检测', createJob: '创建任务',
  retrySameCreateRequest: '重试同一创建请求', durableManualJob: '持久化手动健康检测任务',
  durableManualJobDescription: '后端预检结果为最终依据，检测组合采用“资源 × 节点”的笛卡尔积语义。',
  noResourcesAvailable: '没有可用的 SOCKS5 资源。', noNodesAvailable: '没有可用的中转节点。',
  noSupportedNodes: '当前没有中转节点声明支持 SOCKS5 健康检测。', createOutcomeUnknown: '创建结果暂时未知',
  createOutcomeUnknownDescription: '使用相同请求重试即可安全找回原结果；请求标识会在当前页面中保持不变。',
  resourceSelector: '资源筛选', resourceIds: '资源 ID', allMatchingResources: '全部符合条件的资源',
  countryCodes: '国家代码', healthStatuses: '健康状态', tags: '标签', enabled: '启用状态',
  enabledValue: '已启用', disabledValue: '已禁用', anyValue: '不限', tagMatch: '标签匹配',
  nodeSelector: '节点筛选', nodeIds: '节点 ID', allMatchingNodes: '全部符合条件的节点',
  online: '在线', offline: '离线', checkSupported: '支持 SOCKS5 检测', noCheckSupport: '不支持检测',
  nodeReadinessSummary: '在线 · 支持 SOCKS5 检测', readinessDescription: '就绪状态仅用于显示，不会暗中修改节点筛选条件。',
  maximumItems: '最大任务项数量', dryRunSummary: '后端预检摘要', previewRequired: '每次修改筛选条件后都必须重新预览。',
  resources: '资源数', nodes: '节点数', checks: '检测项', effectiveLimit: '有效上限', matrix: '组合方式',
  withinLimit: '未超出上限', matrixTooLarge: '检测项数量超过上限，请缩小筛选范围。',
  createConfirmTitle: '确定创建这个健康检测任务？', retryCreateConfirmTitle: '确定重试同一创建请求？',
  finalChecks: '最终检测项', limit: '上限', allMatching: '全部符合条件', resourceTags: '资源标签', nodeTags: '节点标签',
  socks5Resources: 'SOCKS5 资源', relayNodesOnline: '在线中转节点', nodeReadiness: '节点就绪状态',
  supportsSocks5Check: '支持 SOCKS5 检测', readinessSignals: '在线状态与协议能力是两个独立的后端信号，浏览器不会自行推断节点是否可用。',
  node: '节点', protocol: '协议版本', queue: '检测队列', recentJobs: '最近检测任务', job: '任务',
  aggregateUnavailable: '暂不提供过期与覆盖率统计', aggregateUnavailableDescription: '后端尚未提供权威的聚合接口，本页面不会根据浏览器时间自行估算。',
  searchResource: '搜索资源', resourceHealthStatus: '资源健康状态', currentProjectionHint: '当前健康状态来自分页资源投影。',
  currentHealth: '当前健康状态', latestNode: '最近检测节点', exitIp: '出口 IP', country: '国家/地区',
  latency: '延迟', failureStreak: '连续失败次数', lastChecked: '最近检测时间', truthScope: '数据范围', current: '当前值',
  resourcePageSummary: '个资源 · 第', pageSuffix: '页', currentHealthTitle: '当前健康状态',
  currentHealthDescription: '这里显示该资源当前的权威健康状态，不会替代历史任务中的检测结果。',
  tcp: 'TCP', handshake: 'SOCKS5 握手', connect: '连接目标', total: '总耗时', checkedAt: '检测时间',
  listProjection: '列表投影状态', projectionCheckedAt: '投影检测时间', checkHistory: '检测历史 · 最近 50 条',
  health: '健康状态', totalLatency: '总延迟', error: '错误', healthLoadFailed: '健康数据加载失败', retrySafely: '安全重试',
  noHealthJobs: '暂无健康检测任务', noHealthJobsDetail: '点击“新建检测任务”开始第一次检测。',
  noFilteredJobs: '没有符合筛选条件的任务', noFilteredJobsDetail: '清除筛选条件或返回第一页。',
  noItems: '没有任务明细', noItemsDetail: '当前筛选条件下没有任务项。',
  noResources: '没有 SOCKS5 资源', noResourcesDetail: '请先添加资源，再创建健康检测任务。',
  noNodes: '没有中转节点', noNodesDetail: '健康检测任务至少需要一个已启用的中转节点。',
  noFailedItems: '没有执行失败项', noFailedItemsDetail: '重试仅适用于执行状态为“失败”的任务项。',
  noHistory: '暂无健康检测历史', noHistoryDetail: '该资源尚未产生健康检测历史。',
  createReplayNotice: '该请求已存在，已打开原健康检测任务。', createSuccessNotice: '健康检测任务已创建。',
  cancelNotice: '已请求取消；最终状态以后端为准。', retryReplayNotice: '该重试请求已存在，已打开原子任务。',
  retrySuccessNotice: '执行失败项已加入新的子任务。',
} as const;

const enUS: { [K in keyof typeof zhCN]: string } = {
  center: 'Health Center', overview: 'Overview', jobs: 'Jobs', resourceHealth: 'Resource Health', refresh: 'Refresh', lastRefresh: 'Last refresh',
  healthJob: 'Health Job', source: 'Source', status: 'Status', parentJob: 'Parent Job', snapshotSemantics: 'Snapshot Semantics', matrixMode: 'Matrix Mode', retryPolicy: 'Retry Policy', cancelRequested: 'Cancel Requested', failureCode: 'Failure Code', snapshotHash: 'Snapshot Hash', created: 'Created', started: 'Started', finished: 'Finished', yes: 'Yes', no: 'No',
  progressCounters: 'Progress from backend counters', queued: 'Queued', running: 'Running', succeeded: 'Succeeded', failed: 'Failed', cancelled: 'Cancelled', selectors: 'Selectors', exactSnapshot: 'Exact failed-pair snapshot', exactSnapshotMismatch: 'Contract mismatch: EXACT_PAIRS must not be reconstructed from selectors.', exactSnapshotDescription: 'selectors_reconstruct_snapshot = false. The UI will not infer a Resource × Node Cartesian matrix.', cancellationInProgress: 'Cancellation in progress', cancellationInProgressDescription: 'The backend is cancelling work that has not started. In-flight checks may still complete and record a health result.', cancelOutcomeUnknown: 'Cancel outcome unknown', cancelOutcomeUnknownDescription: 'Refresh or retry the same cancellation request; backend state remains authoritative.', retryOutcomeUnknown: 'Retry outcome unknown', retryOutcomeUnknownDescription: 'Retry the same request to discover the original child Job without creating a duplicate.', exactResultUnavailable: 'Exact per-Job exit IP and latency are unavailable', exactResultUnavailableDescription: 'Items show execution state and health result separately. Current Resource health is never substituted for this historical Job result.', retryCancelRequest: 'Retry Cancel Request', cancellationRequested: 'Cancellation Requested', cancelJob: 'Cancel Job', cancelTooltip: 'Request cancellation; in-flight checks may still finish.', cancelUnavailableTooltip: 'Available only while a Job is non-terminal.', retrySameRequest: 'Retry Same Request', retryExecutionFailures: 'Retry Execution Failures', retryTooltip: 'Retries execution failures only; it does not recheck every unhealthy proxy.', jobItems: 'Job Items', itemStateFilter: 'Item state filter', allStates: 'All states', safeErrorFilter: 'Safe error code filter', safeErrorCode: 'Safe error code', item: 'Item', resource: 'Resource', relayNode: 'Relay Node', executionState: 'Execution State', healthResult: 'Health Result', attempts: 'Attempts', retries: 'Retries', safeError: 'Safe Error', afterCancel: 'After Cancel', completedAfterCancel: 'Completed after cancel', previousItems: 'Previous items', nextItems: 'Next items', noJobItems: 'No job items', cancelConfirmTitle: 'Cancel this health Job?', requestCancellation: 'Request Cancellation', cancelConfirmDescription: 'Cancellation stops checks that have not started or can still be cancelled. Checks already in flight may finish and legally record health results.', retryConfirmTitle: 'Retry execution failures?', retryConfirmDescription: 'Only orchestration Items in the FAILED execution state are retried. Health results such as OFFLINE, AUTH_FAILED, or CONNECT_FAILED are not automatically rechecked.',
  dataMayBeStale: 'Data may be stale', dataMayBeStaleDescription: 'The latest refresh failed. Last successful data remains visible.', jobStatusFilter: 'Job status filter', jobSourceFilter: 'Job source filter', filterStatus: 'Status', filterSource: 'Source', cursorHint: 'Cursors are opaque and reset when filters change.', jobId: 'Job ID', progress: 'Progress', actions: 'Actions', detail: 'Detail', previous: 'Previous', next: 'Next',
  createHealthJob: 'Create Health Job', close: 'Close', previewChecks: 'Preview Checks', createJob: 'Create Job', retrySameCreateRequest: 'Retry Same Create Request', durableManualJob: 'Durable manual health job', durableManualJobDescription: 'The backend Dry Run is authoritative. Detection combinations use Resource × Node (CARTESIAN) semantics.', noResourcesAvailable: 'No SOCKS5 Resources are available.', noNodesAvailable: 'No Relay Nodes are available.', noSupportedNodes: 'No Relay Node currently advertises SOCKS5 health-check support.', createOutcomeUnknown: 'Create outcome unknown', createOutcomeUnknownDescription: 'Retry the same request to safely discover the original result. The request identity is reused in memory.', resourceSelector: 'Resource Selector', resourceIds: 'Resource IDs', allMatchingResources: 'All matching Resources', countryCodes: 'Country Codes', healthStatuses: 'Health Statuses', tags: 'Tags', enabled: 'Enabled', enabledValue: 'Enabled', disabledValue: 'Disabled', anyValue: 'Any', tagMatch: 'Tag Match', nodeSelector: 'Node Selector', nodeIds: 'Node IDs', allMatchingNodes: 'All matching Nodes', online: 'Online', offline: 'Offline', checkSupported: 'SOCKS5 check supported', noCheckSupport: 'No check support', nodeReadinessSummary: 'online · support SOCKS5 checks', readinessDescription: 'Readiness is displayed only; it does not silently change the Node selector.', maximumItems: 'Maximum Items', dryRunSummary: 'Backend Dry Run Summary', previewRequired: 'Preview is required after every selector change.', resources: 'Resources', nodes: 'Nodes', checks: 'Checks', effectiveLimit: 'Effective limit', matrix: 'Matrix', withinLimit: 'Within limit', matrixTooLarge: 'The checks exceed the item limit. Narrow the selectors.', createConfirmTitle: 'Create this health job?', retryCreateConfirmTitle: 'Retry same create request?', finalChecks: 'Final checks', limit: 'Limit', allMatching: 'all matching', resourceTags: 'resource tags', nodeTags: 'node tags',
  socks5Resources: 'SOCKS5 Resources', relayNodesOnline: 'Relay Nodes Online', nodeReadiness: 'Node Readiness', supportsSocks5Check: 'Supports SOCKS5 Check', readinessSignals: 'Online and protocol capability are separate backend signals. Eligibility is not inferred in the browser.', node: 'Node', protocol: 'Protocol', queue: 'Queue', recentJobs: 'Recent Jobs', job: 'Job', aggregateUnavailable: 'Stale and coverage metrics are not available', aggregateUnavailableDescription: 'The backend does not expose an authoritative aggregate contract yet. This page does not estimate them from browser timestamps.',
  searchResource: 'Search Resource', resourceHealthStatus: 'Resource health status', currentProjectionHint: 'Current Health uses the paged Resource projection.', currentHealth: 'Current Health', latestNode: 'Latest Node', exitIp: 'Exit IP', country: 'Country', latency: 'Latency', failureStreak: 'Failure Streak', lastChecked: 'Last Checked', truthScope: 'Truth Scope', current: 'CURRENT', resourcePageSummary: 'Resources · page', pageSuffix: '', currentHealthTitle: 'Current Health', currentHealthDescription: 'Current Health Truth for this Resource. These values are not substituted into historical Job Items.', tcp: 'TCP', handshake: 'Handshake', connect: 'Connect', total: 'Total', checkedAt: 'Checked At', listProjection: 'List Projection', projectionCheckedAt: 'Projection Checked At', checkHistory: 'Check History · latest 50', health: 'Health', totalLatency: 'Total Latency', error: 'Error', healthLoadFailed: 'Health data could not be loaded', retrySafely: 'Retry safely', noHealthJobs: 'No health jobs', noHealthJobsDetail: 'Create a health job to begin.', noFilteredJobs: 'No jobs match these filters', noFilteredJobsDetail: 'Clear a filter or return to the first page.', noItems: 'No job items', noItemsDetail: 'This job has no items matching the current filter.', noResources: 'No SOCKS5 resources', noResourcesDetail: 'Add resources before creating a health job.', noNodes: 'No Relay Nodes', noNodesDetail: 'A health job requires at least one enabled Relay Node.', noFailedItems: 'No execution failures', noFailedItemsDetail: 'Retry applies only to items whose execution state is FAILED.', noHistory: 'No health history', noHistoryDetail: 'This resource has not produced health history yet.', createReplayNotice: 'This request already exists; the original health Job was opened.', createSuccessNotice: 'Health Job created.', cancelNotice: 'Cancellation requested. Backend status remains authoritative.', retryReplayNotice: 'This retry request already exists; the original child Job was opened.', retrySuccessNotice: 'Execution failures were queued in a new child Job.',
};

export const getHealthCopy = (lang: Lang) => lang === 'zh-CN' ? zhCN : enUS;

const jobStatusZh: Record<HealthJobStatus, string> = {
  QUEUED: '排队中', RUNNING: '运行中', CANCEL_REQUESTED: '正在取消', SUCCEEDED: '成功',
  FAILED: '失败', PARTIAL: '部分完成', CANCELLED: '已取消', PARTIAL_CANCELLED: '部分取消',
};
const itemStateZh: Record<HealthJobItemState, string> = {
  QUEUED: '排队中', LEASED: '已领取', DISPATCHING: '正在下发', IN_FLIGHT: '检测中',
  RETRY_WAIT: '等待重试', SUCCEEDED: '成功', FAILED: '失败', CANCELLED: '已取消',
};
const healthStatusZh: Record<HealthStatus, string> = {
  ONLINE: '在线', OFFLINE: '离线', AUTH_FAILED: '认证失败', TIMEOUT: '超时',
  CONNECT_FAILED: '连接失败', DISABLED: '已禁用', UNKNOWN: '未知',
};
const sourceZh: Record<HealthJobSource, string> = {
  MANUAL: '手动创建', SCHEDULED: '计划任务', RETRY_FAILED: '重试失败项', POLICY_RUN_NOW: '策略立即执行',
};

export function useHealthLocale() {
  const { lang, t } = useI18n();
  const chinese = lang === 'zh-CN' && t('healthCenter') !== 'healthCenter';
  return {
    chinese,
    copy: getHealthCopy(chinese ? 'zh-CN' : 'en-US'),
    jobStatus: (value: HealthJobStatus) => chinese ? jobStatusZh[value] : value,
    itemState: (value: HealthJobItemState) => chinese ? itemStateZh[value] : value,
    healthStatus: (value: HealthStatus) => chinese ? healthStatusZh[value] : value,
    source: (value: HealthJobSource) => chinese ? sourceZh[value] : value,
    tagMatch: (value: string) => chinese ? (value === 'ALL' ? '全部匹配' : '任一匹配') : value,
    matrix: (value: string) => chinese && value === 'CARTESIAN' ? '资源 × 节点（笛卡尔积）' : value,
    semantics: (value: string) => chinese
      ? (value === 'EXACT_PAIRS' ? '精确资源节点组合' : '资源 × 节点（笛卡尔积）')
      : value,
  };
}
