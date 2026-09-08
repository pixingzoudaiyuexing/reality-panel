import type { NodeOperation } from '../../api/types';

export function operationStatusLabel(operation: NodeOperation, t: (key: string) => string): string {
  if (operation.status !== 'VERIFYING') return t(`nodeOperationStatus_${operation.status}`);
  if (operation.action === 'restart') return t('nodeOperationVerifyingRestart');
  if (operation.action === 'upgrade') return t('nodeOperationVerifyingUpgrade');
  if (operation.action === 'uninstall') return t('nodeOperationVerifyingUninstall');
  return t('nodeOperationStatus_VERIFYING');
}
