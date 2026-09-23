import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  HealthJobProgress,
  HealthStatusTag,
  ItemStateTag,
  JobStatusTag,
} from './HealthStatus';
import { nodeDisplayName, resourceDisplayName } from './healthDisplay';
import { healthJobProgress, isTerminalHealthJob } from '../../api/health';
import { partialJob, runningJob } from '../../test/healthFixtures';

describe('health status primitives', () => {
  it('renders every distinct status family without collapsing PARTIAL into FAILED', () => {
    render(<>
      <JobStatusTag status="PARTIAL" />
      <ItemStateTag state="RETRY_WAIT" />
      <HealthStatusTag status="AUTH_FAILED" />
    </>);
    expect(screen.getByText('PARTIAL')).toBeInTheDocument();
    expect(screen.getByText('RETRY_WAIT')).toBeInTheDocument();
    expect(screen.getByText('AUTH_FAILED')).toBeInTheDocument();
    expect(screen.queryByText(/^FAILED$/)).not.toBeInTheDocument();
  });

  it('computes progress exclusively from backend counters', () => {
    expect(healthJobProgress(runningJob)).toBe(50);
    expect(healthJobProgress({ ...runningJob, total_items: 0 })).toBe(0);
    render(<HealthJobProgress job={partialJob} />);
    expect(screen.getByText('4/4')).toBeInTheDocument();
  });

  it('detects only backend terminal job states', () => {
    expect(isTerminalHealthJob('PARTIAL')).toBe(true);
    expect(isTerminalHealthJob('PARTIAL_CANCELLED')).toBe(true);
    expect(isTerminalHealthJob('CANCEL_REQUESTED')).toBe(false);
    expect(isTerminalHealthJob('RUNNING')).toBe(false);
  });

  it('keeps deleted object IDs visible as stable fallbacks', () => {
    expect(resourceDisplayName(987, new Map())).toBe('Resource #987');
    expect(nodeDisplayName(654, new Map())).toBe('Node #654');
  });
});
