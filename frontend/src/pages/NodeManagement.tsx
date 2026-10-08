import { Button, Drawer, Segmented } from 'antd';
import { CloudServerOutlined } from '@ant-design/icons';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../auth/useAuth';
import { useI18n } from '../i18n/context';
import Groups from './Groups';
import NodePool from './NodePool';
import NodeStatus from './NodeStatus';

/** A single entry point; data authorization remains in the existing APIs. */
export default function NodeManagement() {
  const { t } = useI18n();
  const [ownedGroupsOpen, setOwnedGroupsOpen] = useState(false);
  const { isAdmin } = useAuth();
  const [params, setParams] = useSearchParams();
  const view = params.get('view') === 'all' ? 'all' : 'groups';
  return <>
    <div className="rp-page-header"><h2 className="rp-page-title"><CloudServerOutlined /> {t('nodeManagement')}</h2></div>
    <Segmented aria-label={t('nodeManagement')} value={view} options={[
      { label: t('nodeViewGroups'), value: 'groups' }, { label: t('nodeViewAll'), value: 'all' },
    ]} onChange={value => setParams({ view: String(value) })} />
    <div className="rp-node-management-body">
      {view === 'groups' ? (isAdmin ? <Groups cards /> : <>
        <Button style={{ marginBottom: 12 }} onClick={() => setOwnedGroupsOpen(true)}>{t('deviceGroups')}</Button>
        <NodeStatus embedded />
      </>) : isAdmin
        ? <NodePool renderNodes={(nodes, actions, reload, metadataAvailable) => <NodeStatus flat poolNodes={nodes} poolActions={actions} onPoolChanged={reload} poolMetadataAvailable={metadataAvailable} />} />
        : <NodeStatus flat />}
    </div>
    <Drawer title={t('deviceGroups')} open={ownedGroupsOpen} onClose={() => setOwnedGroupsOpen(false)} size="90%" destroyOnHidden>
      {ownedGroupsOpen && <Groups cards />}
    </Drawer>
  </>;
}
