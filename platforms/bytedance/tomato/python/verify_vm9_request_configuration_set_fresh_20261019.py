"""Fresh original +285EF0/+2568C8 wrapper and scoped configuration writes.

Independent synthetic inputs; matching libc mutexes execute. TLS resolution
and allocation are explicit component services. No native snapshot input.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import vm9_objects as objects
import vm9_registry as registry
import verify_vm9_signer_objects as oracle
import verify_vm9_request_prefix_fresh_20261007 as owner
from vm9_allocator import _read_span, _write_span, RefillUnsupported
from verify_vm9_registry import fixture, BASES
from verify_vm9_registry_initialization import warm_tls, FLAG, TREE, ENTRY_SP
from verify_vm9_root_configuration import TLS
from verify_vm9_request_counter_fresh_20261012 import Services, w
from verify_vm9_strings import Effects, fields
from verify_vm9_jni_environment_fresh_20261007 import LIBC_SHA256

G=oracle.GUEST; OBJECT=G+0x1000; QUERY=G+0x1800; DATA=G+0x1C00; BLOCK=G+0x1900


def fresh(library, image, profile):
    p,blocks,addresses=fixture(library,image,profile.get('keys',[]));warm_tls(p)
    setup=Effects(blocks=blocks)
    objects.construct_registry_layout320(p,object_address=OBJECT,image_base=image,allocate=setup.malloc)
    for (obj,_,value),old in zip(addresses,profile.get('values',[])):
        w(p,value,old,4)
        registry.insert_configuration_pair(p,container_address=OBJECT+8,key_address=obj,
            value_address=value,image_base=image,allocate=setup.malloc,free=setup.free)
    key=profile.get('key',b'fresh-key');query=profile.get('query',QUERY)
    data=profile.get('data',DATA);block=profile.get('block',BLOCK)
    w(p,query,image+0x34F5F8);fields(p,query+8,len(key)+1,len(key),data)
    _write_span(p,data,key+b'\0')
    _write_span(p,block,b'\xa5'*48)
    for offset,value in ((0,image+0x2568C8),(8,OBJECT),(16,query)):
        w(p,block+offset,value)
    w(p,block+24,profile.get('value',42),4)
    if 'padding' in profile:_write_span(p,ENTRY_SP-0x1000,bytes([profile['padding']])*0x1000)
    return p,setup.blocks,setup.next,block,query,data


def service(image, blocks, next_address, profile, query, data):
    s=Services(image,blocks,next_address,profile)
    def mutate(kind,index,read,write):
        if kind!='malloc':return
        if profile.get('live_key') and index==2:write(data,b'zresh-key\0')
        if profile.get('live_padding') and index==0:write(ENTRY_SP-0xB8+9,b'padding')
    s.effects.mutate=mutate
    return s


def invoke(p,s,image,block,changes=None):
    kw=dict(argument_block_address=block,entry_stack_address=ENTRY_SP,image_base=image,
        thread_pointer=TLS,allocate=s.malloc,free=s.free,get_tls=s.tls,
        initialize_registry=s.initialize,broadcast=s.broadcast)
    kw.update(changes or {})
    return owner.apply_request_configuration_set_callback(p,**kw)


def compare(library,libc,image,label,profile):
    p,blocks,next_address,block,query,data=fresh(library,image,profile)
    expected=service(image,blocks,next_address,profile,query,data)
    actual=service(image,blocks,next_address,profile,query,data)
    watch={(page<<12,4096):None for page in p if not G<=page<<12<G+0x10000}
    watch.update({(TLS,0xB00):None,(ENTRY_SP-0x70,20):None,(ENTRY_SP-0x58,8):None,
        (ENTRY_SP-0xB0,8):None})
    writes=[];steps=[0];minimum=[ENTRY_SP];seen=set()
    def observe(cpu,a):
        steps[0]+=1;minimum[0]=min(minimum[0],cpu.reg_read(arm.UC_ARM64_REG_SP))
        if a-image in (0x285EF0,0x2568C8):seen.add(a-image)
    def write(cpu,a,n):
        if not ENTRY_SP-0x1000<=a<ENTRY_SP:watch[a,n]=None;writes.append((a,n))
    packed=_read_span(p,block,48)
    _,memory,_,_=oracle.native(library,image,0x285EF0,[block],p,libc=libc,
        real_mutexes=True,real_singletons=True,thread_id=137,instruction_limit=300000,
        host_imports=expected.imports(libc),syscall_handler=expected.syscall,
        malloc_handler=expected.native_malloc,observed_memory=watch,instruction_observer=observe,
        memory_write_observer=write,extra_registers={arm.UC_ARM64_REG_SP:ENTRY_SP,
            arm.UC_ARM64_REG_TPIDR_EL0:TLS})
    result=invoke(p,actual,image,block)
    got=_read_span(p,G,0xA000)
    assert got==memory,(label,'guest',next((hex(i) for i,(x,y) in enumerate(zip(got,memory)) if x!=y),None))
    for (a,n),b in watch.items():assert _read_span(p,a,n)==b,(label,hex(a),n)
    assert result==int.from_bytes(_read_span(p,block+28,4),'little')
    assert _read_span(p,block,28)==packed[:28] and _read_span(p,block+32,16)==packed[32:]
    assert actual.events==expected.events,(label,'ordered effects')
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed,(label,'pre-free bytes')
    assert seen=={0x285EF0,0x2568C8} and writes
    print('PASS configuration wrapper',hex(image),label,flush=True)
    return dict(case=label,image_base=hex(image),steps=steps[0],native_stack_bytes=ENTRY_SP-minimum[0],
        declared_range_count=len(watch),original_wrapper_and_setter_returned=True,
        guest_image_TLS_and_native_nonstack_write_bytes_equal=True,defined_guard_and_canary_equal=True,
        ordered_allocator_TLS_wake_and_prefree_bytes_equal=True,packed_inputs_and_padding_preserved=True,
        packed_u32_result_equal=True,allocation_count=actual.effects.allocation_index,
        free_count=len(actual.freed),native_snapshot_input=False,physical_X0_compared=False)


def guards(library):
    labels=['packed_NULL','packed_wrap','packed_unmapped','packed_result_unmapped','wrong_target',
        'registry_NULL','registry_wrap','registry_unmapped','key_NULL','key_wrap','key_unmapped',
        'payload_NULL','payload_wrap','payload_unmapped','negative_length','key_bound','tree_bound',
        'invalid_byte_bound','invalid_node_bound','stack_unaligned','stack_wrap','stack_unmapped',
        'thread_wrap','thread_unmapped','packed_spill','registry_spill','key_spill','payload_spill',
        'registry_packed_alias','key_registry_alias','key_packed_alias','payload_packed_alias',
        'payload_key_alias','payload_registry_alias','payload_TLS_alias','registry_TLS_alias',
        'missing_allocate','missing_free','missing_get_tls','missing_initialize_registry','missing_broadcast',
        'allocation_NULL_scope','allocation_NULL_key','allocation_NULL_value',
        'allocation_NULL_pair','allocation_NULL_node','allocation_invalid','allocation_wrap',
        'allocation_unmapped','allocation_packed_alias','allocation_registry_alias','allocation_key_alias',
        'allocation_payload_alias','allocation_TLS_alias','allocation_spill','allocation_live_alias',
        'provider_changes_packed','provider_failure','canary_change','TLS_exception','active_readers',
        'multiple_TLS_keys','contended_mutex','wake_error']
    rows=[];image=BASES[0]
    template,blocks,next_address,default_block,query,data=fresh(library,image,{})
    for label in labels:
        p={k:bytearray(v) for k,v in template.items()};block=default_block
        s=service(image,blocks,next_address,{},query,data);changes={}
        if label.startswith('packed_') and label in ('packed_NULL','packed_wrap','packed_unmapped'):
            block={'packed_NULL':0,'packed_wrap':(1<<64)-8,'packed_unmapped':0x66000000}[label]
        elif label=='packed_result_unmapped':
            new=G+0xFFE4;_write_span(p,new,_read_span(p,block,28));block=new
        elif label=='wrong_target':w(p,block,0)
        elif label.startswith(('registry_','key_')) and label.split('_')[-1] in ('NULL','wrap','unmapped'):
            w(p,block+(8 if label.startswith('registry') else 16),
                {'NULL':0,'wrap':(1<<64)-8,'unmapped':0x66000000}[label.split('_')[-1]])
        elif label.startswith('payload_') and label.split('_')[-1] in ('NULL','wrap','unmapped'):
            w(p,query+16,{'NULL':0,'wrap':(1<<64)-1,'unmapped':0x66000000}[label.split('_')[-1]])
        elif label=='negative_length':w(p,query+12,0xFFFFFFFF,4)
        elif label=='key_bound':changes['max_bytes']=1
        elif label=='tree_bound':changes['max_nodes']=0
        elif label=='invalid_byte_bound':changes['max_bytes']=True
        elif label=='invalid_node_bound':changes['max_nodes']=True
        elif label=='stack_unaligned':changes['entry_stack_address']=ENTRY_SP-1
        elif label=='stack_wrap':changes['entry_stack_address']=1<<64
        elif label=='stack_unmapped':changes['entry_stack_address']=0x68001000
        elif label=='thread_wrap':changes['thread_pointer']=(1<<64)-8
        elif label=='thread_unmapped':changes['thread_pointer']=0x66000000
        elif label=='packed_spill':_write_span(p,ENTRY_SP-48,_read_span(p,block,32));block=ENTRY_SP-48
        elif label in ('registry_spill','key_spill'):w(p,block+(8 if label.startswith('registry') else 16),ENTRY_SP-32)
        elif label=='payload_spill':w(p,query+16,ENTRY_SP-32)
        elif label=='registry_packed_alias':w(p,block+8,block)
        elif label=='key_registry_alias':w(p,block+16,OBJECT)
        elif label=='key_packed_alias':w(p,block+16,block)
        elif label.startswith('payload_') and label.endswith('_alias'):
            w(p,query+16,{'payload_packed_alias':block,'payload_key_alias':query,
                'payload_registry_alias':OBJECT,'payload_TLS_alias':TLS+0x28}[label])
        elif label=='registry_TLS_alias':w(p,block+8,TLS)
        elif label.startswith('missing_'):changes[label[len('missing_'):]]=None
        elif label.startswith('allocation_NULL_'):
            s.effects.failures.add({'scope':0,'key':1,'payload':2,'value':3,'pair':4,'node':5}[label[len('allocation_NULL_'):]])
        elif label.startswith('allocation_') and label!='allocation_live_alias':
            address={'allocation_invalid':True,'allocation_wrap':(1<<64)-1,'allocation_unmapped':0x66000000,
                'allocation_packed_alias':block,'allocation_registry_alias':OBJECT,'allocation_key_alias':query,
                'allocation_payload_alias':data,'allocation_TLS_alias':TLS+0x28,'allocation_spill':ENTRY_SP-32}[label]
            changes['allocate']=lambda tx,n,a=address:a
        elif label=='allocation_live_alias':
            held=[]
            def repeat(tx,n):
                if held:return held[0]
                result=s.malloc(tx,n);held.append(result);return result
            changes['allocate']=repeat
        elif label in ('provider_changes_packed','provider_failure','canary_change'):
            def change(tx,n,case=label):
                result=s.malloc(tx,n)
                if case=='provider_changes_packed':w(tx,block,0)
                elif case=='canary_change':w(tx,TLS+0x28,7)
                else:raise RefillUnsupported('allocator failed after effect')
                return result
            changes['allocate']=change
        elif label=='TLS_exception':
            def fail(*a):raise RefillUnsupported('TLS failed')
            changes['get_tls']=fail
        elif label=='active_readers':w(p,OBJECT+0x110,1,4)
        elif label=='multiple_TLS_keys':w(p,TREE+16,2)
        elif label=='contended_mutex':w(p,OBJECT+0x88,2,2)
        elif label=='wake_error':
            changes['broadcast']=lambda tx,a:objects.broadcast_condition_no_waiters(tx,condition_address=a,wake=lambda *a:-1)
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,s,image,block,changes)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='all');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    profiles=[('insert',{}),('insert_left',dict(keys=[b'm'],values=[1],key=b'a')),
        ('insert_right',dict(keys=[b'a'],values=[2],key=b'z')),
        ('balanced_insert',dict(keys=[b'm',b'f',b't',b'b',b'h',b'p',b'x'],values=[3]*7,key=b'j')),
        ('empty',dict(key=b'')),('binary',dict(key=b'\xff\x80')),
        ('embedded_NUL',dict(key=b'a\0tail')),
        ('NUL_equivalent',dict(keys=[b'a\0old'],values=[7],key=b'a\0new')),
        ('replace_zero',dict(keys=[b'fresh-key'],values=[0],value=0xFFFFFFFF)),
        ('replace_high',dict(keys=[b'fresh-key'],values=[0x80000000],value=0)),
        ('replace_uint32',dict(keys=[b'fresh-key'],values=[0xFFFFFFFF],value=0x80000000)),
        ('cross_key',dict(query=G+0x1FF4)),('cross_payload',dict(data=G+0x2FFD)),
        ('cross_packed',dict(block=G+0x9FE4)),('zero_stack_padding',dict(padding=0)),
        ('different_stack_padding',dict(padding=0x6B)),('live_padding',dict(live_padding=True)),
        ('live_key_after_allocate',dict(live_key=True)),('NULL_clone_payload',dict(failures=(2,)))]
    if args.group=='guards':
        result=json.loads(args.output.read_text())
        assert result['verifier_sha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        rows=result['cases']
    else:
        rows=[compare(args.library,args.libc,image,label,p) for image in BASES for label,p in profiles]
    negative=[]
    result=dict(component='Outer configuration setter wrapper',native_Python_controls=len(rows),
        rollback_guards=len(negative),cases=rows,negative_cases=negative,
        library_sha256=oracle.LIBRARY_SHA256,libc_sha256=LIBC_SHA256,native_snapshot_input=False,
        verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        synthetic_allocation_services=True,warm_TLS_component_boundary=True,
        complete_signer_verified=False,physical_ABI_verified=False,external_effect_rollback_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    if args.group in ('guards','all'):
        negative=guards(args.library);result.update(rollback_guards=len(negative),negative_cases=negative)
        args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS outer configuration setter',len(rows),'controls',len(negative),'guards',flush=True)


if __name__=='__main__':main()
