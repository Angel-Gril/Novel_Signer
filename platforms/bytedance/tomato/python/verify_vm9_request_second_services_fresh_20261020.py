"""Public second-VM service contract rejects malformed providers before effects.

Real constructed request acceptance is recorded separately; this verifier
checks early rejection and unchanged pages without running a guest provider.
"""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_request_prefix_fresh_20261007 as owner
from vm9_allocator import RefillUnsupported


def guards():
    files={'fopen':lambda *a:None,'fread':lambda *a:None,'fclose':lambda *a:None}
    bindings={'pthread_mutex_lock':0x51010000,'pthread_mutex_unlock':0x51010004}
    cases=[]
    for value in (True,[],(),1):cases.append(('file_type_'+type(value).__name__,dict(identifier_file_services=value),'identifier'))
    for key in files:
        bad=dict(files);bad.pop(key);cases.append(('file_missing_'+key,dict(identifier_file_services=bad),'identifier'))
        bad=dict(files);bad[key]=None;cases.append(('file_noncallable_'+key,dict(identifier_file_services=bad),'identifier'))
    bad=dict(files,unexpected=lambda *a:None);cases.append(('file_unknown_service',dict(identifier_file_services=bad),'identifier'))
    for value in (True,[],(),1):cases.append(('mutex_type_'+type(value).__name__,dict(mutex_import_bindings=value),'mutex'))
    for key in bindings:
        bad=dict(bindings);bad.pop(key);cases.append(('mutex_missing_'+key,dict(mutex_import_bindings=bad),'mutex'))
        for label,value in (('NULL',0),('boolean',True),('negative',-4),('wrap',1<<64),('unaligned',0x51010001),('string','binding')):
            bad=dict(bindings);bad[key]=value;cases.append((key+'_'+label,dict(mutex_import_bindings=bad),'mutex'))
    bad=dict(bindings,unexpected=0x51010008);cases.append(('mutex_unknown_import',dict(mutex_import_bindings=bad),'mutex'))
    rows=[]
    for label,kw,kind in cases:
        p={0x70000:bytearray(b'\x6b'*4096)};before={k:bytes(v) for k,v in p.items()};effects=[]
        def forbidden(*a):effects.append('called');raise AssertionError('provider ran before validation')
        try:owner.execute_prefix(p,{},None,0,0,allocate=forbidden,free=forbidden,**kw)
        except RefillUnsupported as exc:assert str(exc).startswith('request '+kind)
        else:raise AssertionError(label+' accepted')
        assert not effects and before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,no_guest_or_provider_effect=True))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    rows=guards();result=dict(component='Public request second VM service contract',rollback_guards=len(rows),
        native_Python_controls=0,negative_cases=rows,no_native_groups_replayed=True,
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        owner_sha256=hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest(),
        whole_request_native_differential_verified=False,complete_signer_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS public second services',len(rows),'early rejection checks',flush=True)


if __name__=='__main__':main()
