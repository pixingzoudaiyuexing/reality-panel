import type { CarrierAffinityView, CarrierPolicy } from '../../api/types';

export function carrierPolicyKey(policy: CarrierPolicy): string {
  return JSON.stringify({ default_node_id: policy.default_node_id ?? null,
    bindings: policy.bindings.filter((b) => b.line_id !== 'default').map((b) => ({ line_id: b.line_id, mode: b.mode, node_id: b.node_id ?? null }))
      .sort((a, b) => `${a.line_id}:${a.mode}:${a.node_id}`.localeCompare(`${b.line_id}:${b.mode}:${b.node_id}`)) });
}

export function carrierOperation(view: CarrierAffinityView | null, desired: CarrierPolicy | null, submitting: boolean, unknown: boolean) {
  if (submitting && view?.transaction.state !== 'switching' && view?.transaction.state !== 'rolling_back') return 'submitting';
  if (view?.transaction.rollback_error || view?.transaction.state === 'failed_manual_intervention') return 'rollback_failed';
  if (view?.transaction.state === 'rolling_back') return 'rolling_back';
  if (view?.transaction.state === 'failed_rolled_back') return 'rolled_back';
  if (view?.transaction.state === 'failed' || view?.transaction.last_error) return 'failed';
  if (view?.transaction.state === 'switching' || view?.pending_policy) return 'syncing';
  if (submitting) return 'submitting';
  const matches = !!view && !!desired && carrierPolicyKey(view.active_policy) === carrierPolicyKey(desired);
  const records = view?.dns_records ?? [];
  const dnsFailed = records.some((r) => r.last_error || ['FAILED', 'CONFLICT', 'MUTATION_OUTCOME_UNKNOWN'].includes(r.state)) || view?.bindings.some((b) => b.dns_state === 'failed');
  if (dnsFailed) return 'failed';
  const dnsReady = records.length ? records.every((r) => r.state === 'PROPAGATED' || r.state === 'NOT_ELIGIBLE') : !!view && view.bindings.every((b) => b.dns_state === 'effective');
  if (matches && dnsReady) return 'ready';
  if (matches || (!desired && view?.bindings.some((b) => b.dns_state !== 'effective'))) return 'pending';
  if (unknown || desired) return 'unknown';
  return 'idle';
}


/** A current authoritative snapshot, not a comparison with historical intent. */
export function carrierBackendTerminal(view: CarrierAffinityView | null): boolean {
  return !!view && view.transaction.state === 'idle' && !view.pending_policy
    && !view.transaction.last_error && !view.transaction.rollback_error
    && carrierOperation(view, view.active_policy, false, false) === 'ready';
}
