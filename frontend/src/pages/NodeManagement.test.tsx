import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const { mockGet, mockAuth } = vi.hoisted(() => ({ mockGet: vi.fn(), mockAuth: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get: mockGet, post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() } }));
vi.mock('../auth/useAuth', () => ({ useAuth: mockAuth }));
import NodeManagement from './NodeManagement';
const ok = (data: unknown) => ({ code: 0, message: 'ok', data });
const flush = () => act(async () => { await vi.advanceTimersByTimeAsync(0); });
const mount = (view: string) => render(<MemoryRouter initialEntries={[`/node-management?view=${view}`]}><Routes>
  <Route path="/node-management" element={<NodeManagement />} />
  <Route path="/node-bootstrap" element={<div>Existing Bootstrap flow</div>} />
</Routes></MemoryRouter>);
beforeEach(() => { vi.useFakeTimers(); mockGet.mockReset(); mockAuth.mockReset(); mockGet.mockResolvedValue(ok([])); });
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });
describe('Node Management entry and permission boundaries', () => {
  it('retains the existing admin installer from the empty by-group view', async () => {
    mockAuth.mockReturnValue({ isAdmin: true }); mount('groups'); await flush();
    fireEvent.click(screen.getByRole('button', { name: /nodeBootstrapTitle/ }));
    expect(screen.getByText('Existing Bootstrap flow')).toBeInTheDocument();
  });
  it('retains the installer from the all-node view when Pool loading fails', async () => {
    mockAuth.mockReturnValue({ isAdmin: true });
    mockGet.mockImplementation((url: string) => Promise.resolve(url === '/admin/node-pool/nodes' ? { code: 500, message: 'unavailable', data: null } : ok([])));
    mount('all'); await flush();
    expect(screen.getByText('poolLoadFailed')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /nodeBootstrapTitle/ }));
    expect(screen.getByText('Existing Bootstrap flow')).toBeInTheDocument();
  });
  it('ordinary users observe authorized summaries and keep owned-group CRUD without admin fetches', async () => {
    mockAuth.mockReturnValue({ isAdmin: false }); mount('groups'); await flush();
    expect(screen.queryByRole('button', { name: /nodeBootstrapTitle/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'deviceGroups' })); await flush();
    expect(screen.getByRole('button', { name: /addGroup/ })).toBeInTheDocument();
    expect(mockGet.mock.calls.map(call => call[0]).every(url => !url.startsWith('/admin/'))).toBe(true);
    expect(mockGet).toHaveBeenCalledWith('/nodes/shared');
    expect(mockGet).toHaveBeenCalledWith('/groups');
  });
});
