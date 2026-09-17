import { describe, expect, it } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import HealthCenter from './HealthCenter';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}{location.search}</output>;
}

function renderPage(initial = '/health-center') {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <Routes>
        <Route path="/health-center" element={<><HealthCenter /><LocationProbe /></>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('HealthCenter', () => {
  it('renders the three F1 tabs and distinct empty states', () => {
    renderPage();
    expect(screen.getByTestId('health-center-page')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'healthOverview' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'healthJobs' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'healthResourceHealth' })).toBeInTheDocument();
    expect(screen.getByText('No health jobs')).toBeInTheDocument();
  });

  it('opens a copied Job URL and closes the drawer by updating the URL', async () => {
    renderPage('/health-center?tab=jobs&job=00000000-0000-4000-8000-000000000099');
    expect(screen.getByText('Job data wiring is reserved for F2 Read-only Data Views.')).toBeInTheDocument();
    expect(screen.getByTestId('location')).toHaveTextContent('job=00000000-0000-4000-8000-000000000099');
    await act(async () => {
      await userEvent.click(screen.getByLabelText('Close'));
    });
    expect(screen.getByTestId('location')).not.toHaveTextContent('job=');
  });

  it('changes tabs through URL state and opens the contract-only Create shell', async () => {
    renderPage();
    fireEvent.click(screen.getByRole('tab', { name: 'healthJobs' }));
    expect(screen.getByTestId('location')).toHaveTextContent('tab=jobs');
    fireEvent.click(screen.getByRole('button', { name: /healthCreateJob/ }));
    expect(screen.getByText('F1 contract-wired shell')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create Job (F3)' })).toBeDisabled();
  });
});
