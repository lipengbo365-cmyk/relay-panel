import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { HealthJobList } from './HealthJobList';
import { runningJob } from '../../test/healthFixtures';

describe('HealthJobList', () => {
  it('renders backend counters and opens a selected job', () => {
    const open = vi.fn();
    render(<HealthJobList jobs={[runningJob]} onOpenJob={open} />);
    expect(screen.getByText(runningJob.id)).toBeInTheDocument();
    expect(screen.getByText('2/4')).toBeInTheDocument();
    fireEvent.click(screen.getByText(runningJob.id));
    expect(open).toHaveBeenCalledWith(runningJob.id);
  });

  it('resets opaque cursor history when a filter changes', async () => {
    const cursor = vi.fn();
    const reset = vi.fn();
    render(
      <HealthJobList
        jobs={[runningJob]}
        nextCursor="opaque.next.cursor"
        onOpenJob={vi.fn()}
        onCursorChange={cursor}
        onCursorReset={reset}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /next/i }));
    expect(cursor).toHaveBeenLastCalledWith('opaque.next.cursor');

    await act(async () => {
      fireEvent.mouseDown(screen.getByLabelText('Job status filter'));
    });
    fireEvent.click(await screen.findByTitle('RUNNING'));
    expect(reset).toHaveBeenCalled();
    expect(cursor).toHaveBeenLastCalledWith(undefined);
  });
});
