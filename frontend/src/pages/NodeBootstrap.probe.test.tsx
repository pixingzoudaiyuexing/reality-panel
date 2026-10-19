/// <reference types="node" />
import { afterEach, describe, expect, it } from 'vitest';
import { createServer, type Server } from 'node:http';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import api from '../api/client';
import NodeBootstrap from './NodeBootstrap';

let server: Server | undefined;
const originalBase = api.defaults.baseURL;
afterEach(async () => {
  api.defaults.baseURL = originalBase;
  if (server) {
    server.closeAllConnections();
    await new Promise<void>(resolve => server!.close(() => resolve()));
    server = undefined;
  }
});

describe('SSH probe through the real Axios client and HTTP transport', () => {
  it.each([200, 409])('keeps the safe backend message through HTTP %s and the envelope interceptor', async status => {
    server = createServer((request, response) => {
      response.setHeader('Access-Control-Allow-Origin', '*');
      response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return; }
      request.resume();
      request.on('end', () => {
        response.writeHead(status, { 'Content-Type': 'application/json' });
        response.end(JSON.stringify({ code: 409, message: 'EXISTING_STATE_COMMAND_FAILED: safe backend diagnostic', data: null }));
      });
    });
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('local test listener missing');
    api.defaults.baseURL = `http://127.0.0.1:${address.port}/api/v1`;
    const user = userEvent.setup();
    render(<MemoryRouter><NodeBootstrap /></MemoryRouter>);
    await user.type(screen.getByLabelText('nodeBootstrapHost 1'), 'local-fixture');
    await user.type(screen.getByLabelText('nodeBootstrapPassword 1'), 'fixture-only');
    await user.click(screen.getByRole('button', { name: /nodeBootstrapTestConnection/ }));
    await screen.findByText('EXISTING_STATE_COMMAND_FAILED: safe backend diagnostic');
    expect(screen.getByText('nodeBootstrapDeploy').closest('button')).toBeDisabled();
  });

  it('accepts a successful probe taking longer than the former ten second timeout', async () => {
    server = createServer((request, response) => {
      response.setHeader('Access-Control-Allow-Origin', '*');
      response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return; }
      request.resume();
      request.on('end', () => {
        setTimeout(() => {
          response.setHeader('Content-Type', 'application/json');
          response.end(JSON.stringify({ code: 0, message: 'ok', data: { fingerprint: 'SHA256:local-test', os: 'Debian', architecture: 'amd64', existing: { classification: 'CLEAN_HOST' } } }));
        }, 11_000);
      });
    });
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('local test listener missing');
    api.defaults.baseURL = `http://127.0.0.1:${address.port}/api/v1`;
    const user = userEvent.setup();
    render(<MemoryRouter><NodeBootstrap /></MemoryRouter>);
    await user.type(screen.getByLabelText('nodeBootstrapHost 1'), 'local-fixture');
    await user.type(screen.getByLabelText('nodeBootstrapPassword 1'), 'fixture-only');
    await user.click(screen.getByRole('button', { name: /nodeBootstrapTestConnection/ }));
    await screen.findByText('nodeBootstrapRowPASSED', {}, { timeout: 15_000 });
    expect(screen.getByText('nodeBootstrapDeploy').closest('button')).toBeEnabled();
    expect(api.defaults.timeout).toBe(10_000);
  }, 20_000);
});
