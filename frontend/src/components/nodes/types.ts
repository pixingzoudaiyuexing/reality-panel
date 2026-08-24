import type { useI18n } from '../../i18n/context';
import type { NodeDisplayRow, NodeLifecycleAction } from '../../api/types';

/** The i18n t() function type, shared across node components. */
export type Tfn = ReturnType<typeof useI18n>['t'];

export type NodeLifecycleHandler = (row: NodeDisplayRow, action: NodeLifecycleAction) => void;
