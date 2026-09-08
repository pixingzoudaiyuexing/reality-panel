import type { Tfn } from './types';

export function carrierApplyErrorMessage(error: unknown, t: Tfn): string {
  const responseMessage = (error as { response?: { data?: { message?: string } } })
    ?.response?.data?.message;
  const backendMessage = responseMessage ?? (error instanceof Error ? error.message : '');
  const labels: Record<string, Parameters<Tfn>[0]> = {
    DEFAULT_LINE_OWNED_BY_RELAY_PREFERENCE: 'carrierErrorDefaultAuthority',
    FAILOVER_ENABLED: 'carrierErrorFailoverEnabled',
    CATALOG_STALE: 'carrierErrorCatalogStale',
    CATALOG_UNAVAILABLE: 'carrierCatalogUnavailable',
    DNSMGR_UNAVAILABLE: 'carrierErrorDnsMgrUnavailable',
    TRANSACTION_IN_PROGRESS: 'carrierErrorTransactionInProgress',
    OWNERSHIP_UNVERIFIED: 'carrierErrorOwnershipUnverified',
  };
  if (labels[backendMessage]) return t(labels[backendMessage]);
  const providerPrefix = 'PROVIDER_PREFLIGHT: ';
  if (backendMessage.startsWith(providerPrefix)) {
    const detail = backendMessage.slice(providerPrefix.length, providerPrefix.length + 200).trim();
    return detail ? `${t('carrierErrorProviderPreflight')}: ${detail}` : t('carrierErrorProviderPreflight');
  }
  return t('carrierSaveFailed');
}
