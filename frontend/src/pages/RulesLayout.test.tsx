import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

const { mockGet, refreshCurrentUser } = vi.hoisted(() => ({
  mockGet: vi.fn().mockResolvedValue({ code: 0, message: 'ok', data: [] }),
  refreshCurrentUser: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: {
    get: mockGet,
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    isAdmin: true,
    user: { id: 1 },
    refreshCurrentUser,
  }),
}));

vi.mock('react-router-dom', () => ({
  useSearchParams: () => [new URLSearchParams(), vi.fn()],
}));

import Rules from './Rules';

describe('Rules table practical layout', () => {
  it('keeps the action column present and fixed to the right', async () => {
    render(<Rules />);

    const actionHeader = await screen.findByRole('columnheader', { name: 'action' });
    expect(actionHeader).toHaveClass('ant-table-cell-fix-end');
  });
});
