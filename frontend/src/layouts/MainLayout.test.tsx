import { render } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

vi.mock('react-router-dom', () => ({
  Outlet: () => <div>outlet</div>,
  useNavigate: () => vi.fn(),
  useLocation: () => ({ pathname: '/rules' }),
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isAdmin: true,
    user: { id: 1 },
    logout: vi.fn(),
  }),
}));

vi.mock('../hooks/useSite', () => ({
  useSite: () => ({ site_name: 'RealityPanel' }),
}));

vi.mock('../hooks/useAnnouncementBadge', () => ({
  useAnnouncementBadge: () => ({ unread: false }),
}));

import MainLayout from './MainLayout';

describe('MainLayout desktop scroll wiring', () => {
  it('attaches scoped classes to every desktop layout boundary', () => {
    const { container } = render(<MainLayout />);

    expect(container.querySelector('.rp-app-layout')).not.toBeNull();
    expect(container.querySelector('.rp-app-sider')).not.toBeNull();
    expect(container.querySelector('.rp-app-main')).not.toBeNull();
    expect(container.querySelector('.rp-app-content')).not.toBeNull();
  });
});
