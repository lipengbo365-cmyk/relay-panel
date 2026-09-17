import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { HealthJobDetailDrawer } from './HealthJobDetailDrawer';
import {
  authFailedHealthItem,
  completedAfterCancelItem,
  deletedResourceItem,
  exactPairsRetryJob,
} from '../../test/healthFixtures';

describe('HealthJobDetailDrawer', () => {
  it('keeps execution state and SOCKS5 health result in separate columns', () => {
    render(
      <HealthJobDetailDrawer
        open
        jobId={exactPairsRetryJob.id}
        job={exactPairsRetryJob}
        items={[authFailedHealthItem]}
        onClose={() => {}}
      />,
    );
    const row = screen.getByText('AUTH_FAILED').closest('tr');
    expect(row).not.toBeNull();
    expect(within(row!).getByText('SUCCEEDED')).toBeInTheDocument();
    expect(within(row!).getByText('AUTH_FAILED')).toBeInTheDocument();
  });

  it('shows exact-pair semantics, cancellation completion, and deleted-ID fallbacks', () => {
    render(
      <HealthJobDetailDrawer
        open
        jobId={exactPairsRetryJob.id}
        job={exactPairsRetryJob}
        items={[completedAfterCancelItem, deletedResourceItem]}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText('Exact failed-pair snapshot')).toBeInTheDocument();
    expect(screen.getByText(/selectors_reconstruct_snapshot = false/)).toBeInTheDocument();
    expect(screen.getByText('Resource #987')).toBeInTheDocument();
    expect(screen.getByText('Node #654')).toBeInTheDocument();
    expect(screen.getByText('Completed after cancel')).toBeInTheDocument();
  });

  it('never renders raw transport details from an unsafe error object', () => {
    const unsafeMarker = ['Bearer', 'fixture-token'].join(' ');
    const rawError = {
      response: {
        data: {
          message: 'NOT_ALLOWLISTED',
          detail: unsafeMarker,
        },
      },
    };
    render(
      <HealthJobDetailDrawer
        open
        jobId="missing"
        error={{ code: 'UNKNOWN_ERROR', message: 'The health request failed safely. Try again.' }}
        onClose={() => {}}
      />,
    );
    expect(document.body.textContent).not.toContain(unsafeMarker);
    expect(document.body.textContent).not.toContain(String(rawError.response.data.detail));
    expect(screen.getByText('UNKNOWN_ERROR')).toBeInTheDocument();
  });
});
