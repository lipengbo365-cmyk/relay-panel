import { useState } from 'react';
import { Tabs } from 'antd';
import { useSearchParams } from 'react-router-dom';
import { HealthCenterHeader } from '../components/health/HealthCenterHeader';
import { HealthOverview } from '../components/health/HealthOverview';
import { HealthJobList } from '../components/health/HealthJobList';
import { ResourceHealthView } from '../components/health/ResourceHealthView';
import { HealthJobDetailDrawer } from '../components/health/HealthJobDetailDrawer';
import { CreateHealthJobModal } from '../components/health/CreateHealthJobModal';
import { useI18n } from '../i18n/context';

type HealthTab = 'overview' | 'jobs' | 'resources';

function tabFromQuery(value: string | null): HealthTab {
  return value === 'jobs' || value === 'resources' ? value : 'overview';
}

export default function HealthCenter() {
  const { t } = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();
  const [createOpen, setCreateOpen] = useState(false);
  const [lastRefreshAt, setLastRefreshAt] = useState<number | null>(null);
  const activeTab = tabFromQuery(searchParams.get('tab'));
  const jobId = searchParams.get('job');

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
    updateParams((next) => next.delete('job'), true);
  };

  const tabItems = [
    {
      key: 'overview',
      label: t('healthOverview'),
      children: <HealthOverview onOpenJob={openJob} />,
    },
    {
      key: 'jobs',
      label: t('healthJobs'),
      children: <HealthJobList jobs={[]} onOpenJob={openJob} />,
    },
    {
      key: 'resources',
      label: t('healthResourceHealth'),
      children: <ResourceHealthView resources={[]} />,
    },
  ];

  return (
    <div data-testid="health-center-page">
      <HealthCenterHeader
        title={t('healthCenter')}
        createLabel={t('healthCreateJob')}
        refreshLabel={t('refresh')}
        lastRefreshLabel={t('healthLastRefresh')}
        lastRefreshAt={lastRefreshAt}
        onCreate={() => setCreateOpen(true)}
        onRefresh={() => setLastRefreshAt(Date.now())}
      />

      <Tabs
        activeKey={activeTab}
        items={tabItems}
        onChange={(key) => updateParams((next) => {
          next.set('tab', key);
          next.delete('job');
        }, true)}
      />

      <HealthJobDetailDrawer
        open={jobId !== null}
        jobId={jobId}
        onClose={closeJob}
      />

      <CreateHealthJobModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  );
}
