from pathlib import Path
import os,subprocess,json,time,hashlib,shutil,tarfile,gzip,re
root=Path.cwd();e=root/'publication-evidence';e.mkdir();assets=root/'release-dist';head=os.environ['FROZEN_SOURCE'];results=[]
os.environ.update(CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CI='true',TZ='UTC',PYTHONDONTWRITEBYTECODE='1',RP_REQUIRE_SSH_INSPECTION_TESTS='1')
assert not any(k.startswith('CARGO_PROFILE_RELEASE') for k in os.environ)
def inventory(folder):return {str(p.relative_to(folder)):hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.rglob('*') if p.is_file()}
def integrity():
 assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==head
 status=subprocess.check_output(['git','status','--porcelain'],text=True)
 if status:(e/'source-status-failure.json').write_text(json.dumps({'head':head,'status':status},indent=2))
 assert not status,status
 assert all(hashlib.sha256(Path(n).read_bytes()).hexdigest()==v for n,v in frozen.items())
def gate(name,args,cwd=root):
 print('START',name,flush=True);start=time.monotonic()
 with (e/(name+'.log')).open('w') as log:p=subprocess.run(args,cwd=cwd,env=os.environ,stdout=log,stderr=subprocess.STDOUT)
 results.append({'gate':name,'rc':p.returncode,'seconds':round(time.monotonic()-start,3),'command':args});(e/'gates-progress.json').write_text(json.dumps(results,indent=2));print('END',name,p.returncode,flush=True)
 if p.returncode:raise RuntimeError('RELEASE GATE FAILED: '+name)
 integrity()
frozen={n:hashlib.sha256(Path(n).read_bytes()).hexdigest() for n in subprocess.check_output(['git','ls-files'],text=True).splitlines()};tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],text=True).strip();(e/'frozen-source.json').write_text(json.dumps({'head':head,'tree':tree,'hashes':frozen},indent=2));integrity()
try:
 gate('shell-syntax',['python3','-c',"import subprocess; p=subprocess.check_output(['git','ls-files','*.sh'],text=True).splitlines();[subprocess.run(['bash','-n',x],check=True) for x in p];print('PASS',len(p))"])
 for name,args in [('failed-retry-filesystem',['python3','scripts/relay-node-failed-install-cleanup.test.py']),('existing-install-inspection',['python3','scripts/relay-node-existing-install.test.py']),('bootstrap-transactions',['bash','scripts/relay-node-bootstrap.test.sh']),('bootstrap-cleanup',['python3','scripts/relay-node-bootstrap-cleanup.test.py']),('legacy-upgrader-v130',['python3','scripts/test_legacy_node_upgrade.py']),('legacy-upgrader-v143',['python3','scripts/test_legacy_node_upgrade_v143.py']),('legacy-upgrader-v144',['python3','scripts/test_legacy_node_upgrade_v144.py']),('legacy-profile-contracts',['python3','scripts/test_legacy_node_upgrade_profiles.py']),('release-version',['bash','scripts/release-version-contract.sh','v1.4.13']),('release-version-tests',['bash','scripts/release-version-contract.test.sh','v1.4.13']),('release-check',['bash','scripts/release-check.sh','1.4.13']),('fmt',['cargo','fmt','--all','--','--check']),('check',['cargo','check','--workspace','--locked']),('rust-tests',['cargo','test','--workspace','--locked','--','--test-threads=1','--nocapture']),('clippy',['cargo','clippy','--workspace','--all-targets','--locked','--','-D','warnings']),('repo-test-parity',['bash','scripts/check-repo-test-parity.sh']),('artifact-permissions',['bash','scripts/node-artifact-permissions.test.sh'])]:gate(name,args)
 raw=(e/'rust-tests.log').read_text();assert 'S3 REAL POSTGRES RUNTIME AUTH CONTRACT: EXECUTED' in raw
 assert 'REAL SSH INSPECTION API: EXECUTED' in raw and 'REAL SSH INSPECTION FAILURES: EXECUTED' in raw
 nums=[list(map(int,m)) for m in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out',raw)];summary={'passed':sum(n[0] for n in nums),'failed':sum(n[1] for n in nums),'ignored':sum(n[2] for n in nums),'filtered':sum(n[4] for n in nums),'real_pg_executed':True};assert summary['failed']==summary['ignored']==summary['filtered']==0;(e/'rust-summary.json').write_text(json.dumps(summary,indent=2))
 for name,args in [('npm-ci',['npm','ci','--no-audit','--no-fund']),('typecheck',['npm','run','typecheck']),('frontend-lint',['npm','run','lint']),('frontend-tests',['npm','test','--','--maxWorkers=1','--reporter=json','--outputFile='+str(e/'frontend-results.json')]),('frontend-build',['npm','run','build'])]:gate(name,args,root/'frontend')
 gate('debug-build',['cargo','build','--workspace','--locked']);sandbox=e/'loopback-sandbox';sandbox.mkdir();archive=subprocess.check_output(['git','archive','HEAD']);subprocess.run(['tar','-xf','-','-C',str(sandbox)],input=archive,check=True);(sandbox/'target/debug').mkdir(parents=True)
 for binary in ['relay-panel','relay-node']:shutil.copyfile(root/'target/debug'/binary,sandbox/'target/debug'/binary);(sandbox/'target/debug'/binary).chmod(0o755)
 gate('loopback-e2e',['python3','tests/e2e_test.py'],sandbox);integrity()
 gate('optimized-build',['cargo','build','--release','--locked','-p','relay-panel','-p','relay-node']);integrity();assets.mkdir()
 for src,dst in [('target/release/relay-panel','reality-panel-linux-amd64'),('target/release/relay-node','reality-node-linux-amd64'),('install.sh','install.sh'),('deploy.sh','deploy.sh'),('update.sh','update.sh'),('scripts/relay-node-install.sh','relay-node-install.sh')]:shutil.copyfile(root/src,assets/dst);(assets/dst).chmod(0o755)
 (assets/'VERSION').write_text('1.4.13\n');(assets/'SOURCE_COMMIT').write_text(head+'\n')
 subprocess.run(['tar','--format=gnu','-czf',str(assets/'reality-panel-web.tar.gz'),'-C',str(root/'frontend/dist'),'.'],check=True);unpack=e/'web-unpacked';unpack.mkdir()
 gate('gnu-tar-list',['tar','-tzf',str(assets/'reality-panel-web.tar.gz')]);gate('gnu-tar-extract',['tar','-xzf',str(assets/'reality-panel-web.tar.gz'),'-C',str(unpack)])
 with tarfile.open(assets/'reality-panel-web.tar.gz') as t:
  assert not t.pax_headers;assert all(not m.pax_headers and '__MACOSX' not in m.name and not any(x.startswith('._') for x in Path(m.name).parts) for m in t.getmembers())
 raw=gzip.decompress((assets/'reality-panel-web.tar.gz').read_bytes());assert all(x not in raw for x in [b'LIBARCHIVE.xattr',b'SCHILY.xattr',b'com.apple.provenance'])
 dist=inventory(root/'frontend/dist');assert dist==inventory(unpack);(e/'web-validation.json').write_text(json.dumps({'verdict':'PASS','head':head,'gnu_format':True,'pax_metadata':False,'apple_metadata':False,'inventory':dist,'file_count':len(dist)},indent=2))
 for name,want in [('reality-panel-linux-amd64','relay-panel 1.4.13'),('reality-node-linux-amd64','relay-node 1.4.13')]:
  version=subprocess.check_output([str(assets/name),'--version'],text=True).strip();assert version==want;arch=subprocess.check_output(['file',str(assets/name)],text=True);assert 'ELF 64-bit' in arch and 'x86-64' in arch
 (assets/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(assets.iterdir())));gate('sha256-assets',['sha256sum','-c','SHA256SUMS'],assets)
 items=[{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(assets.iterdir())];assert len(items)==10;(e/'assets-manifest.json').write_text(json.dumps(items,indent=2));integrity();(e/'validation-completed.json').write_text(json.dumps({'verdict':'PASS','head':head,'tree':tree,'linux_amd64':True,'runner':'GitHub Actions rust1.96-bookworm','real_postgres':True,'release_profile_override':False,'source_clean':True,'tests_skip_used':False,'production_touched':False,'test_deployment':'NOT PERFORMED (Owner waiver)','gates':results},indent=2));print('ALL RELEASE GATES AND TEN ASSETS PASS',flush=True)
except Exception as ex:
 (e/'validation-failure.json').write_text(json.dumps({'head':head,'verdict':'FAIL','reason':str(ex),'gates':results},indent=2));raise
