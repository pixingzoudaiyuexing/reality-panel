import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../api/client', () => ({ default: { get, post, put: vi.fn(), delete: vi.fn() } }));
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ isAdmin: true }) }));
vi.mock('../components/nodes/RelayPreferencePanel', () => ({
  RelayPreferencePanel: ({ onDiagnoseNode }: { onDiagnoseNode?: (node: { node_id: string; public_ipv4: string }) => void }) =>
    <button disabled={!onDiagnoseNode} onClick={() => onDiagnoseNode?.({ node_id: 'same-node', public_ipv4: '203.0.113.10' })}>route-diagnose</button>,
}));
import Groups from './Groups';
const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const group = { id: 7, name: 'business-seven', group_type: 'in', uid: 1, connect_host: '', port_range: '10000-65535', rate: 1, config: '{}' };
const pool = (home: number, member: number) => ({ identity_group_id: home, node_id: 'same-node', display_name: `home-${home}`, online: true, source_kind: 'pool_native', memberships: [{ group_id: member }], public_ipv4: '203.0.113.10' });
function setup(nodes: ReturnType<typeof pool>[], fail = false) {
  get.mockImplementation((url: string) => {
    if (url === '/groups') return Promise.resolve(ok([group]));
    if (url === '/admin/node-pool/nodes') return fail ? Promise.reject(new Error('unavailable')) : Promise.resolve(ok(nodes));
    return Promise.resolve(ok([]));
  });
}
beforeEach(() => { get.mockReset(); post.mockReset(); post.mockResolvedValue(ok({ checks: [], healthy: true })); });
describe('business-group routing diagnosis identity', () => {
  it('resolves the unique member home, even when another home has the same node ID', async () => {
    setup([pool(8, 9), pool(901, 7)]);
    render(<Groups cards />);
    fireEvent.click(await screen.findByRole('button', { name: /business-seven/ }));
    fireEvent.click(screen.getByRole('button', { name: 'route-diagnose' }));
    await waitFor(() => expect(post).toHaveBeenCalledWith('/admin/nodes/901/same-node/diagnose', {}));
    expect(post).not.toHaveBeenCalledWith('/admin/nodes/7/same-node/diagnose', {});
  });
  it.each(['ambiguous', 'unavailable', 'not-a-member'])('does not diagnose when physical identity is %s', async (mode) => {
    setup(mode === 'ambiguous' ? [pool(901, 7), pool(902, 7)] : [pool(8, 9)], mode === 'unavailable');
    render(<Groups cards />);
    fireEvent.click(await screen.findByRole('button', { name: /business-seven/ }));
    fireEvent.click(screen.getByRole('button', { name: 'route-diagnose' }));
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(post).not.toHaveBeenCalled();
  });
});
