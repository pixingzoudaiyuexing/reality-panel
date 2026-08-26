import { describe, expect, it, beforeEach, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';

const { mockGet, mockPut, mockPost } = vi.hoisted(() => ({
  mockGet: vi.fn(),
  mockPut: vi.fn(),
  mockPost: vi.fn(),
}));

vi.mock('../api/client', () => ({
  default: { get: mockGet, put: mockPut, post: mockPost },
}));

import SystemSettings from './SystemSettings';

const ok = <T,>(data: T) => ({ code: 0, message: 'ok', data });
const dnsSettings = {
  enabled: true,
  base_url: 'http://dns.example.test',
  uid: 7,
  configured: true,
  has_api_key: true,
};

describe('SystemSettings DNSMgr integration', () => {
  beforeEach(() => {
    mockGet.mockReset();
    mockPut.mockReset();
    mockPost.mockReset();
    mockGet.mockImplementation((url: string) => {
      if (url === '/admin/settings/registration') {
        return Promise.resolve(ok({
          registration_enabled: false,
          default_registration_plan_id: 1,
          allowed_plan_ids: [1],
        }));
      }
      if (url === '/admin/plans') {
        return Promise.resolve(ok([{ id: 1, name: 'default', max_rules: 10 }]));
      }
      if (url === '/admin/settings/dnsmgr') return Promise.resolve(ok(dnsSettings));
      return Promise.reject(new Error(`unexpected GET ${url}`));
    });
  });

  it('never receives or prefills the API key and blank replacement preserves it', async () => {
    mockPut.mockResolvedValue(ok(dnsSettings));
    await act(async () => { render(<SystemSettings />); });

    await waitFor(() => expect(screen.getByText('dnsMgrSettings')).toBeInTheDocument());
    const keyInput = screen.getByLabelText('apiKeyReplacement');
    expect(keyInput).toHaveValue('');
    expect(document.body.textContent).not.toContain('stored-secret');

    const saveButtons = screen.getAllByRole('button', { name: 'save' });
    fireEvent.click(saveButtons[1]);
    await waitFor(() => expect(mockPut).toHaveBeenCalled());
    expect(mockPut).toHaveBeenCalledWith('/admin/settings/dnsmgr', {
      enabled: true,
      base_url: 'http://dns.example.test',
      uid: 7,
    });
    expect(keyInput).toHaveValue('');
  });

  it('renders the typed safe connection-test result', async () => {
    mockPost.mockResolvedValue(ok({
      category: 'OK',
      domain_count: 3,
      empty_domain_list: false,
      zone_ownership_verified: false,
    }));
    await act(async () => { render(<SystemSettings />); });

    await waitFor(() => expect(screen.getByText('dnsMgrSettings')).toBeInTheDocument());
    fireEvent.click(screen.getByRole('button', { name: 'testConnection' }));
    await waitFor(() => expect(mockPost).toHaveBeenCalled());
    expect(mockPost).toHaveBeenCalledWith('/admin/settings/dnsmgr/test', {
      base_url: 'http://dns.example.test',
      uid: 7,
    });
    expect(await screen.findByText('connectionTestResult: OK')).toBeInTheDocument();
    expect(screen.getByText('domainCount: 3')).toBeInTheDocument();
  });
});
