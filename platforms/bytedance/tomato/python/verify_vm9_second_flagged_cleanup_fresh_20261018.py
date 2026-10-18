"""Exact second VM flag-controlled string destruction, with fresh guest pages."""
from pathlib import Path
import argparse,hashlib,inspect,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services
from verify_vm9_configuration_init import string_object
from vm9_allocator import _read_span,_write_span,RefillUnsupported
import vm9_request_287474_vm as second

G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)
PROFILES=('inactive','inactive_unmapped_payload','inactive_flag_only','inactive_no_free',
    'active_NULL','active_empty','active_short','active_binary','active_long','active_FF',
    'late_descriptor','provider_changes_flag','cross_packed','cross_receiver','cross_flag','cross_payload')
GUARDS=('wrong_target','packed_wrap','packed_unmapped','receiver_NULL','receiver_wrap','receiver_unmapped',
    'packed_receiver_alias','unaligned_stack','wrapped_stack','packed_spill','receiver_spill',
    'payload_spill','payload_packed_alias','payload_receiver_alias','unmapped_payload',
    'missing_free','late_descriptor_unmapped','provider_failure','provider_changes_packed')


def w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))


def fixture(library,image,label):
    p=oracle.fresh_pages();p.update(oracle.image_pages(library,image))
    block=G+(0x1FF8 if label=='cross_packed' else 0x1000)
    out=G+(0x2FF0 if label=='cross_receiver' else 0x2FE8 if label=='cross_flag' else 0x1800)
    payload=G+(0x3FFE if label=='cross_payload' else 0x2400)
    data={'active_empty':b'','active_binary':bytes(range(256)),'active_long':b'x'*129}.get(label,b'owned')
    string_object(p,image,out,data,payload=payload);w(p,out+24,0 if label.startswith('inactive') else 0xFF if label=='active_FF' else 1,1)
    if label=='active_NULL':w(p,out+16,0)
    if label=='inactive_unmapped_payload':w(p,out+16,0x66000000)
    if label=='inactive_flag_only':
        out=0x66000FE8;p[0x66001]=bytearray(4096)
    _write_span(p,block,b''.join(v.to_bytes(8,'little') for v in (image+0x1B55F8,out))+b'\x5A'*24)
    blocks={} if label.startswith('inactive') or label=='active_NULL' else {payload:len(data)+1}
    return p,block,out,blocks


def services(label,image,out,blocks):
    s=Services(blocks=blocks)
    if label in ('late_descriptor','provider_changes_flag'):
        def mutate(kind,index,read,write):
            if kind=='free':
                if label=='late_descriptor':write(image+0x6E208,b'\x17\x28\x39\x4A\x5B\x6C\x7D\x8E')
                else:write(out+24,b'\x7F')
        s.effects.mutate=mutate
    return s


def invoke(p,s,image,block,changes=None):
    kw=dict(argument_block_address=block,entry_stack_address=SP,image_base=image,free=s.free)
    kw.update(changes or {})
    return second.apply_request_287474_flagged_cleanup_callback(p,**kw)


def compare(library,image,label):
    p,block,out,blocks=fixture(library,image,label);packed=_read_span(p,block,40)
    expected=services(label,image,out,blocks);actual=services(label,image,out,blocks)
    watch={(page<<12,4096):None for page in p if not G<=page<<12<G+0x10000}
    watch.update({(G,SP-G-0x1000):None,(SP,G+0x10000-SP):None})
    steps=[0];minimum=[SP];seen=set()
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP));seen.add(a-image)
    raw=inspect.getsource(oracle.native);marker='    cpu.mem_write(GUEST, flatten(pages))'
    assert raw.count(marker)==1
    raw=raw.replace(marker,marker+'''
    mapped={page for start,end,prot in cpu.mem_regions() for page in range(start>>12,(end>>12)+1)}
    for page in pages:
        if page not in mapped:cpu.mem_map(page<<12,4096);mapped.add(page)''')
    ns=dict(vars(oracle));exec(compile(raw,'flag-only-native-mapping','exec'),ns)
    _,_,allocations,_=ns['native'](library,image,0x288AC8,[block],p,
        extra_registers={arm.UC_ARM64_REG_SP:SP},host_imports={0x347FA0:expected.native_free},
        observed_memory=watch,instruction_observer=observe,instruction_limit=10000)
    result=invoke(p,actual,image,block,{'free':None} if label=='inactive_no_free' else None)
    for (a,n),data in watch.items():assert _read_span(p,a,n)==data,(label,hex(a))
    assert actual.events==expected.events and actual.freed==expected.freed and actual.effects.blocks==expected.effects.blocks,label
    assert result==out and _read_span(p,block,40)==packed and not allocations
    assert {0x288AC8,0x1B55F8}<=seen and ((0x2484B8 in seen)==(not label.startswith('inactive')))
    assert SP-0x1000<=minimum[0]<=SP
    print('PASS flagged cleanup',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,steps=steps[0],native_stack_bytes=SP-minimum[0],
        original_wrapper_and_flagged_cleanup_returned=True,declared_nonstack_memory_equal=True,
        ordered_free_and_prefree_bytes_equal=True,packed_bytes_unchanged=True,native_snapshot_input=False,
        native_physical_X0_compared=False,complete_physical_ABI_verified=False)


def guards(library):
    rows=[];image=BASES[0]
    for label in GUARDS:
        p,block,out,blocks=fixture(library,image,'active_short');s=services('active_short',image,out,blocks);changes={}
        if label=='wrong_target':w(p,block,image+1)
        elif label=='packed_wrap':block=(1<<64)-8
        elif label=='packed_unmapped':block=0x66000000
        elif label in ('receiver_NULL','receiver_wrap','receiver_unmapped'):
            w(p,block+8,{'receiver_NULL':0,'receiver_wrap':(1<<64)-8,'receiver_unmapped':0x66000000}[label])
        elif label=='packed_receiver_alias':w(p,block+8,block)
        elif label=='unaligned_stack':changes['entry_stack_address']=SP-1
        elif label=='wrapped_stack':changes['entry_stack_address']=1<<64
        elif label=='packed_spill':_write_span(p,SP-16,_read_span(p,block,16));block=SP-16
        elif label=='receiver_spill':w(p,block+8,SP-32)
        elif label=='payload_spill':w(p,out+16,SP-0x1000)
        elif label=='payload_packed_alias':w(p,out+16,block)
        elif label=='payload_receiver_alias':w(p,out+16,out)
        elif label=='unmapped_payload':w(p,out+16,0x66000000)
        elif label=='missing_free':changes['free']=None
        elif label=='late_descriptor_unmapped':
            def mutate(kind,index,read,write):write(block,b'\x42')
            del p[(image+0x6E208)>>12]
        elif label=='provider_failure':
            def fail(tx,a):s.free(tx,a);raise RefillUnsupported('free failed after effect')
            changes['free']=fail
        elif label=='provider_changes_packed':
            def mutate(kind,index,read,write):write(block,bytes(8))
            s.effects.mutate=mutate
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,s,image,block,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[compare(args.library,image,label) for image in BASES for label in PROFILES];negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Second flag-controlled string cleanup',native_Python_controls=len(rows),
        rollback_guards=len(negative),cases=rows,negative_cases=negative,library_sha256=oracle.LIBRARY_SHA256,
        native_snapshot_input=False,synthetic_free_services=True,complete_signer_verified=False,
        physical_ABI_verified=False,external_effect_rollback_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS flagged cleanup',len(rows),'controls',len(negative),'guards',flush=True)


if __name__=='__main__':main()
