import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AuthContext } from '../auth/AuthContext';
import { RequireAdmin } from '../RequireAdmin';
import HealthCenter from './HealthCenter';
import type { UserSelf } from '../api/types';

const adminUser: UserSelf = {
  id: 1,
  username: 'fixture-admin',
  admin: true,
  balance: '0',
  plan_id: null,
  plan_name: null,
  max_rules: 0,
  current_rules: 0,
  traffic_used: 0,
  traffic_limit: 0,
  registered_at: '2026-01-01 00:00:00',
  must_change_password: false,
};

function renderRoute(isAdmin: boolean) {
  return render(
    <AuthContext.Provider value={{
      token: ['fixture', 'session'].join('-'),
      isAdmin,
      user: { ...adminUser, admin: isAdmin },
      authReady: true,
      mustChangePassword: false,
      login: async () => {},
      logout: () => {},
      refreshCurrentUser: async () => {},
    }}>
      <MemoryRouter initialEntries={['/health-center']}>
        <Routes>
          <Route path="/health-center" element={<RequireAdmin><HealthCenter /></RequireAdmin>} />
          <Route path="/403" element={<div>FORBIDDEN</div>} />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

describe('Health Center authorization', () => {
  it('allows an authenticated admin', () => {
    renderRoute(true);
    expect(screen.getByTestId('health-center-page')).toBeInTheDocument();
  });

  it('redirects a non-admin to the forbidden route', () => {
    renderRoute(false);
    expect(screen.getByText('FORBIDDEN')).toBeInTheDocument();
    expect(screen.queryByTestId('health-center-page')).not.toBeInTheDocument();
  });
});
