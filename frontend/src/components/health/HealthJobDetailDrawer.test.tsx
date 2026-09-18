import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { HealthJobDetailDrawer } from './HealthJobDetailDrawer';
import {
  authFailedHealthItem,
  completedAfterCancelItem,
  deletedResourceItem,
  exactPairsRetryJob,
  runningJob,
  succeededJob,
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

  it('enables Cancel only for non-terminal Jobs and confirms in-flight semantics', async () => {
    const onCancelJob = vi.fn();
    render(
      <HealthJobDetailDrawer
        open
        jobId={runningJob.id}
        job={runningJob}
        onCancelJob={onCancelJob}
        onClose={() => {}}
      />,
    );
    expect(screen.getByRole('button', { name: 'Cancel Job' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Retry Execution Failures' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Cancel Job' }));
    const title = await screen.findByText('Cancel this health Job?', { selector: '.ant-modal-title' });
    const dialog = title.closest('[role="dialog"]') as HTMLElement;
    expect(within(dialog).getByText(/already in flight may finish/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Request Cancellation' }));
    expect(onCancelJob).toHaveBeenCalledOnce();
  });

  it('enables Retry only for terminal execution failures and explains health failures', async () => {
    const onRetryFailed = vi.fn();
    render(
      <HealthJobDetailDrawer
        open
        jobId={exactPairsRetryJob.id}
        job={exactPairsRetryJob}
        onRetryFailed={onRetryFailed}
        onClose={() => {}}
      />,
    );
    expect(screen.getByRole('button', { name: 'Cancel Job' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Retry Execution Failures' })).toBeEnabled();
    await userEvent.click(screen.getByRole('button', { name: 'Retry Execution Failures' }));
    const title = await screen.findByText('Retry execution failures?', { selector: '.ant-modal-title' });
    const dialog = title.closest('[role="dialog"]') as HTMLElement;
    expect(within(dialog).getByText(/AUTH_FAILED/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Retry Execution Failures' }));
    expect(onRetryFailed).toHaveBeenCalledOnce();
  });

  it('does not enable execution Retry for a terminal health failure with failed_count zero', () => {
    render(
      <HealthJobDetailDrawer
        open
        jobId={succeededJob.id}
        job={succeededJob}
        items={[authFailedHealthItem]}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText('AUTH_FAILED')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Retry Execution Failures' })).toBeDisabled();
  });

  it('shows backend cancellation state without fabricating CANCELLED', () => {
    render(
      <HealthJobDetailDrawer
        open
        jobId={runningJob.id}
        job={{ ...runningJob, status: 'CANCEL_REQUESTED', cancel_requested: true }}
        onClose={() => {}}
      />,
    );
    expect(screen.getByText('Cancellation in progress')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancellation Requested' })).toBeDisabled();
    expect(screen.getByText('CANCEL_REQUESTED')).toBeInTheDocument();
  });
});
