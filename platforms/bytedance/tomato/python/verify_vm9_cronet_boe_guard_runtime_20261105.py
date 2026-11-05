from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path

NAME = 'vm9_cronet_boe_guard_runtime_20261105'
APK = Path(r'C:\AI\6\fq_7xz.apk')
BRIDGE = Path(r'C:\AI\6\frida-java-bridge_plain_runtime_compat.js')
PROBE = Path(r'C:\AI\6\probe_boe_runtime.py')
HEX256 = re.compile(r'^[0-9a-f]{64}$')

def req(c,m):
    if not c: raise ValueError(m)

def h(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def verify(path):
    r=json.loads(path.read_text(encoding='utf-8'))
    req(r['schema']=='vm9-cronet-boe-guard-runtime-20261105-v1','schema')
    req(r['evidence_date']=='2026-11-05','date')
    scope=r['source_scope']
    req(scope['package_name']=='com.dragon.read' and scope['version_name']=='7.2.5.32' and scope['device_serial']=='emulator-5554' and scope['frida_version']=='17.24.3' and scope['frida_server_privilege']=='root','scope')
    a=r['source_artifacts']
    for k in ('apk_sha256','bridge_sha256','probe_script_sha256'): req(isinstance(a[k],str) and HEX256.fullmatch(a[k]),k)
    req(h(APK)==a['apk_sha256'],'APK hash'); req(h(BRIDGE)==a['bridge_sha256'],'bridge hash'); req(h(PROBE)==a['probe_script_sha256'],'probe hash')
    req(a['apk_sha256']=='95889d1a1ad0b11ed2451eedf0389516e1382640182026e82eb515e04fbc04fd','APK identity')
    req(a['bridge_sha256']=='749e107feb32c21227fa79a5feda5c4a13bf4d797d51d8c94156d8d4b3e97eb2','bridge identity')
    p=r['probe']; req(p=={'method':'com.dragon.read.util.DebugManager.isBOEMode()','return_type':'boolean','observed_return':False,'event_count':1},'probe')
    c=r['claims']; req(c['boe_mode_runtime_observed'] is True and c['boe_adapter_registration_guard_condition_false'] is True,'boe claim')
    for k in ('cronet_entry_runtime_observed_in_this_probe','runtime_adapter_identity_resolved','r4_callback_cronet_identity_joined','ordinary_cronet_six_head_chain_verified','callback_url_or_map_object_identity_joined','provider_method_or_field_identity_joined','android_captured_jni_buffer_consumption_byte_joined','complete_standalone_signer_verified','whole_request_native_python_differential_verified','online_header_acceptance_verified'):
        req(c[k] is False,k)
    s=json.dumps(r,ensure_ascii=False)
    for x in ('http://','https://','Bearer ','ibssh_','frp-hat'): req(x.lower() not in s.lower(),'forbidden raw value')
    return {'schema':r['schema'],'boe_mode_runtime_observed':c['boe_mode_runtime_observed'],'observed_return':p['observed_return'],'boe_adapter_registration_guard_condition_false':c['boe_adapter_registration_guard_condition_false']}

def main():
    ap=argparse.ArgumentParser(); root=Path(__file__).resolve().parents[1]; ap.add_argument('--evidence',type=Path,default=root/'evidence'/f'{NAME}.json'); args=ap.parse_args(); print(json.dumps(verify(args.evidence),sort_keys=True))
if __name__=='__main__': main()
