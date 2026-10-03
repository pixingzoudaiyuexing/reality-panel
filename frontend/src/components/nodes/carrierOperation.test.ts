import { describe, expect, it } from 'vitest';
import { carrierOperation } from './carrierOperation';
import type { CarrierAffinityView, CarrierPolicy } from '../../api/types';
const desired: CarrierPolicy = { default_node_id: 'a', bindings: [{ line_id: 'Liantong', mode: 'node', node_id: 'a' }, { line_id: 'Liantong', mode: 'node', node_id: 'b' }] };
const base: CarrierAffinityView = { group_id: 1, default_node_id: 'a', active_policy: desired, pending_policy: null, transaction: { state: 'idle', kind: null, started_at: null, last_error: null, rollback_error: null }, bindings: [], catalog_stale: false,
  dns_records: [{ rule_id: 1, fqdn: 'test.example', line_id: 'Liantong', provider: 'huawei', state: 'PROPAGATED', last_error: null }] };
describe('authoritative Carrier operation', () => {
  it('requires final policy, idle transaction and verified DNS for success', () => {
    expect(carrierOperation(base, desired, false, true)).toBe('ready');
    expect(carrierOperation({ ...base, pending_policy: desired }, desired, false, false)).toBe('syncing');
    expect(carrierOperation({ ...base, dns_records: [{ ...base.dns_records![0], state: 'MUTATION_VERIFIED' }] }, desired, false, false)).toBe('pending');
  });
  it('does not infer failure or success from lost response', () => {
    expect(carrierOperation({ ...base, active_policy: { default_node_id: 'a', bindings: [] } }, desired, false, true)).toBe('unknown');
    expect(carrierOperation({ ...base, pending_policy: desired, transaction: { ...base.transaction, state: 'switching' } }, desired, false, true)).toBe('syncing');
  });
  it('reports provider error, rollback success and rollback failure separately', () => {
    expect(carrierOperation({ ...base, transaction: { ...base.transaction, state: 'failed', last_error: 'DNSMGR_TEMPORARY' } }, desired, false, false)).toBe('failed');
    expect(carrierOperation({ ...base, transaction: { ...base.transaction, state: 'failed_rolled_back' } }, desired, false, false)).toBe('rolled_back');
    expect(carrierOperation({ ...base, transaction: { ...base.transaction, state: 'failed_manual_intervention', rollback_error: 'POST_WRITE_NOT_VERIFIED' } }, desired, false, false)).toBe('rollback_failed');
  });
  it('detects DNS failure even with HTTP-success and an idle policy', () => {
    expect(carrierOperation({ ...base, dns_records: [{ ...base.dns_records![0], state: 'FAILED', last_error: 'DNSMGR_TIMEOUT' }] }, desired, false, false)).toBe('failed');
  });
  it('canonicalizes Multi-A membership independent of binding order', () => {
    expect(carrierOperation(base, { ...desired, bindings: [...desired.bindings].reverse() }, false, true)).toBe('ready');
  });
});
