import { useMemo, useState } from 'react';
import { Alert, Tabs } from 'antd';
import { useSearchParams } from 'react-router-dom';
import { HealthCenterHeader } from '../components/health/HealthCenterHeader';
import { HealthOverview } from '../components/health/HealthOverview';
import { HealthJobList } from '../components/health/HealthJobList';
import { ResourceHealthView } from '../components/health/ResourceHealthView';
import { HealthJobDetailContainer } from '../components/health/HealthJobDetailContainer';
import { CreateHealthJobModal } from '../components/health/CreateHealthJobModal';
import { useI18n } from '../i18n/context';
import type { HealthJobFilters } from '../api/health';
import {
  useHealthJobPage,
  useHealthNameMaps,
  useHealthOverview,
  useNodeReadiness,
} from '../hooks/useHealthReadModel';

type HealthTab = 'overview' | 'jobs' | 'resources';

function tabFromQuery(value: string | null): HealthTab {
  return value === 'jobs' || value === 'resources' ? value : 'overview';
}

export default function HealthCenter() {
  const { t } = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();
  const [createOpen, setCreateOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [jobFilters, setJobFilters] = useState<HealthJobFilters>({});
  const [jobCursor, setJobCursor] = useState<string | undefined>();
  const [actionNotice, setActionNotice] = useState<string | null>(null);
  const activeTab = tabFromQuery(searchParams.get('tab'));
  const jobId = searchParams.get('job');
  const stableFilters = useMemo(() => jobFilters, [jobFilters]);
  const overview = useHealthOverview(refreshKey, activeTab === 'overview');
  const jobs = useHealthJobPage(stableFilters, jobCursor, refreshKey, activeTab === 'jobs');
  const names = useHealthNameMaps(refreshKey);
  const readiness = useNodeReadiness(overview.data.nodes);
  const lastRefreshAt = Math.max(overview.lastSuccessAt ?? 0, jobs.lastSuccessAt ?? 0) || null;

  const updateParams = (change: (next: URLSearchParams) => void, replace = false) => {
    const next = new URLSearchParams(searchParams);
    change(next);
    setSearchParams(next, { replace });
  };

  const openJob = (id: string) => {
    updateParams((next) => {
      next.set('tab', 'jobs');
      next.set('job', id);
    });
  };

  const closeJob = () => {
    updateParams((next) => next.delete('job'));
  };

  const tabItems = [
    {
      key: 'overview',
      label: t('healthOverview'),
      children: <HealthOverview
        loading={overview.loading && overview.data.resourceTotal === undefined}
        resourceTotal={overview.data.resourceTotal}
        healthTotals={overview.data.healthTotals}
        nodeOnline={readiness.online}
        nodeTotal={readiness.total}
        supportedNodes={readiness.supported}
        nodes={overview.data.nodes}
        recentJobs={overview.data.recentJobs}
        resourceError={overview.data.resourceError}
        nodeError={overview.data.nodeError}
        jobsError={overview.data.jobsError}
        stale={overview.consecutiveFailures > 0}
        onRetry={() => void overview.reload()}
        onOpenJob={openJob}
      />,
    },
    {
      key: 'jobs',
      label: t('healthJobs'),
      children: <HealthJobList
        jobs={jobs.data.items}
        loading={jobs.loading}
        error={jobs.error}
        stale={jobs.consecutiveFailures > 0}
        nextCursor={jobs.data.next_cursor}
        onOpenJob={openJob}
        onFiltersChange={setJobFilters}
        onCursorChange={setJobCursor}
        onCursorReset={() => setJobCursor(undefined)}
        onRetry={() => void jobs.reload()}
      />,
    },
    {
      key: 'resources',
      label: t('healthResourceHealth'),
      children: <ResourceHealthView refreshKey={refreshKey} nodeNames={names.nodeNames} />,
    },
  ];

  return (
    <div data-testid="health-center-page">
      {actionNotice ? (
        <Alert
          type="success"
          showIcon
          closable
          title={actionNotice}
          onClose={() => setActionNotice(null)}
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <HealthCenterHeader
        title={t('healthCenter')}
        createLabel={t('healthCreateJob')}
        refreshLabel={t('refresh')}
        lastRefreshLabel={t('healthLastRefresh')}
        lastRefreshAt={lastRefreshAt}
        onCreate={() => setCreateOpen(true)}
        refreshing={overview.refreshing || jobs.refreshing}
        onRefresh={() => setRefreshKey((value) => value + 1)}
      />

      <Tabs
        activeKey={activeTab}
        items={tabItems}
        onChange={(key) => updateParams((next) => {
          next.set('tab', key);
          next.delete('job');
        }, true)}
      />

      <HealthJobDetailContainer
        open={jobId !== null}
        jobId={jobId}
        resourceNames={names.resourceNames}
        nodeNames={names.nodeNames}
        refreshKey={refreshKey}
        onClose={closeJob}
        onOpenJob={openJob}
        onJobsChanged={() => setRefreshKey((value) => value + 1)}
        onNotice={setActionNotice}
      />

      <CreateHealthJobModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(result) => {
          setCreateOpen(false);
          setActionNotice(result.replayed
            ? 'This request already exists; the original health Job was opened.'
            : 'Health Job created.');
          setRefreshKey((value) => value + 1);
          openJob(result.job_id);
        }}
      />
    </div>
  );
}
