import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { runningJob } from '../../test/healthFixtures';
import { HealthOverview } from './HealthOverview';

describe('HealthOverview', () => {
  it('keeps successful sections visible during a partial API failure', () => {
    render(<HealthOverview
      resourceTotal={10}
      healthTotals={{ ONLINE: 7, UNKNOWN: 3 }}
      nodeTotal={2}
      nodeOnline={1}
      supportedNodes={1}
      recentJobs={[runningJob]}
      nodeError={{ code: 'DATABASE_ERROR', message: 'The health service could not read its stored state.' }}
    />);
    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText(runningJob.id)).toBeInTheDocument();
    expect(screen.getByText('DATABASE_ERROR')).toBeInTheDocument();
  });
});
