import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DomainPreflight } from './DomainPreflight';

const { post } = vi.hoisted(() => ({ post: vi.fn() }));
vi.mock('../../api/client', () => ({ default: { post } }));
const t = (key: string) => key;
beforeEach(() => { post.mockReset(); });
describe('read-only domain preflight', () => {
  it.each([
    ['ABSENT', 'domainCheckAbsent'], ['PANEL_COMPATIBLE_A', 'domainCheckOwned'],
    ['EXTERNAL_A', 'domainCheckExternal'], ['CNAME', 'domainCheckCname'],
    ['UNMANAGED_ZONE', 'domainCheckUnmanaged'], ['UNCONFIGURED', 'domainCheckUnconfigured'],
    ['PROVIDER_READ_FAILURE', 'domainCheckFailed'],
  ])('shows %s without any DNS mutation', async (category, message) => {
    post.mockResolvedValue({ code: 0, data: { fqdn: 'test.example.com', category, records: [] } });
    render(<DomainPreflight fqdn="test.example.com" t={t} />);
    fireEvent.click(screen.getByRole('button', { name: 'domainCheck' }));
    expect(await screen.findByText(message)).toBeInTheDocument();
    expect(post).toHaveBeenCalledExactlyOnceWith('/admin/rules/domain-preflight', { fqdn: 'test.example.com' });
  });
  it('does not disguise read rejection as absence', async () => {
    post.mockRejectedValue(new Error('read failure'));
    render(<DomainPreflight fqdn="test.example.com" t={t} />);
    fireEvent.click(screen.getByRole('button', { name: 'domainCheck' }));
    expect(await screen.findByText('domainCheckFailed')).toBeInTheDocument();
    expect(screen.queryByText('domainCheckAbsent')).not.toBeInTheDocument();
  });
  it('changing SNI clears the old result and isolates an in-flight response', async () => {
    let resolve!: (value: unknown) => void;
    post.mockImplementation(() => new Promise(r => { resolve = r; }));
    const { rerender } = render(<DomainPreflight key="a.example.com" fqdn="a.example.com" t={t} />);
    fireEvent.click(screen.getByRole('button', { name: 'domainCheck' }));
    rerender(<DomainPreflight key="b.example.com" fqdn="b.example.com" t={t} />);
    resolve({ code: 0, data: { fqdn: 'a.example.com', category: 'CNAME', records: [] } });
    await waitFor(() => expect(screen.getByRole('button', { name: 'domainCheck' })).toBeEnabled());
    expect(screen.queryByText('domainCheckCname')).not.toBeInTheDocument();
  });
});
