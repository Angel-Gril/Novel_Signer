"""Fresh native differences for +0x2698f0 before its VM body.

No private strings, state outputs, device data or JVM are used as model input.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import vm9_objects as model
from vm9_allocator import _read_span, _write_span, RefillUnsupported
from verify_vm9_signer_objects import GUEST, LIBRARY_SHA256, fresh_pages, image_pages, native
from verify_vm9_strings import Effects, fields

OWNER,SOURCE,DATA=GUEST+0x1000,GUEST+0x1800,GUEST+0x2000


def fixture(library,base,length):
    pages=fresh_pages();pages.update(image_pages(library,base))
    _write_span(pages,SOURCE,(base+0x34F5F8).to_bytes(8,'little'))
    fields(pages,SOURCE+8,length+1,length,DATA)
    _write_span(pages,DATA,bytes(i%251+1 for i in range(length))+b'\0')
    return pages


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==LIBRARY_SHA256
    cases=[];negatives=[]
    for base in (0x122C0000,0x775C205000):
        samples=[(length,flag,None) for length in (0,1,7,32,165) for flag in (0,1,255,256,0xFFFFFFFF)]
        samples.append((7,1,1))  # Payload malloc NULL is a recoverable empty clone.
        for length,flag,failure in samples:
                failures=() if failure is None else (failure,)
                pages=fixture(a.library,base,length);actual=Effects(blocks={},failures=failures);expected=Effects(blocks={},failures=failures)
                observed={(p<<12,4096):None for p in pages if not GUEST<=p<<12<GUEST+0x10000}
                returned,memory,_,_=native(a.library,base,0x2698F0,[OWNER,SOURCE,flag],pages,
                    stop_offset=0x269988,observed_memory=observed,
                    malloc_handler=lambda c,n:expected.native(c,'malloc',n))
                result=model.construct_mutex_backed_string_owner_prefix(pages,object_address=OWNER,
                    source_object_address=SOURCE,flag=flag,image_base=base,allocate=actual.malloc)
                assert result.object_address==returned,'tail caller object argument'
                current=_read_span(pages,GUEST,0xA000)
                if current!=memory:
                    first=next(i for i,(x,y) in enumerate(zip(current,memory)) if x!=y)
                    raise AssertionError(f'length{length}/flag{flag} guest+{first:#x}')
                assert actual.calls==expected.calls and actual.blocks==expected.blocks,'allocator state/order'
                assert all(_read_span(pages,x,n)==data for (x,n),data in observed.items()),'image'
                assert _read_span(pages,OWNER+0x29,7)==b'\xa5'*7,'owner padding'
                assert _read_span(pages,result.mutex_address+0x95,3)==bytes(3),'mutex memset padding'
                cases.append({'image_base':hex(base),'synthetic_string_length':length,'synthetic_flag':flag,
                    'guest_and_all_image_bytes_match':True,'allocator_state_and_order_match':True,
                    'caller_object_argument_match':True,'owner_padding_preserved':True,'mutex_padding_zero':True,
                    'allocations':len(actual.blocks),'allocation_failure_index':failure})
    base=0x122C0000
    for label in ('unmapped_owner','unmapped_source','length_bound','allocation_0','allocation_2','allocation_3'):
        pages=fixture(a.library,base,7);before={k:bytes(v) for k,v in pages.items()}
        failures=(int(label[-1]),) if label.startswith('allocation_') else ()
        effects=Effects(blocks={},failures=failures)
        try:
            model.construct_mutex_backed_string_owner_prefix(pages,
                object_address=GUEST+0x100000 if label=='unmapped_owner' else OWNER,
                source_object_address=GUEST+0x100000 if label=='unmapped_source' else SOURCE,
                flag=1,image_base=base,allocate=effects.malloc,
                max_payload_bytes=1 if label=='length_bound' else 0x100000)
        except (RefillUnsupported,ValueError):
            assert {k:bytes(v) for k,v in pages.items()}==before,label+' rollback'
            negatives.append({'case':label,'rejected':True,'page_rollback':True})
        else:raise AssertionError(label+' accepted')
    report={'library_sha256':LIBRARY_SHA256,'entry_offset':'0x2698f0','boundary_offset':'0x269988',
        'native_differences':len(cases),'negative_count':len(negatives),'cases':cases,'negative_cases':negatives,
        'fresh_synthetic_inputs':True,'native_outputs_used_as_model_input':False,'jvm_used':False,
        'vm_0xa46a0_body_implemented':False,'complete_python_medusa':False,
        'rollback_scope':'guest_pages_only; allocator ledger is an external effect'}
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'native_differences':len(cases),'negative_count':len(negatives)}))


if __name__=='__main__':main()
