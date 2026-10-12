"""Fresh raw MD5 and scoped reference assignments against original ARM64.

Original helper and matching libc locks run. Allocator services are explicit
synthetic inputs. Native memory never initializes Python. Private bytes stay
local; only case labels, counts and comparisons are exported.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_reference_scopes as references
import vm9_diagnostics as diagnostics
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OUT=G+0x1000;SOURCE=G+0x1100;OBJ=G+0x1800;OLD=G+0x1900
COUNT=G+0x1C00;OLDCOUNT=G+0x1D00;DATA=G+0x2100;OLDDATA=G+0x2200
BASES=(0x122C0000,0x775C205000)


def string(p,a,payload,data,base):
    dependency.w(p,a,base+0x34F5F8);dependency.w(p,a+8,len(data)+1,4)
    dependency.w(p,a+12,len(data),4);dependency.w(p,a+16,payload)
    _write_span(p,payload,data+b'\0')


def fixture(library,base,kind,label):
    p=dependency.fresh(library,base);blocks={};destination=OUT;source=SOURCE;pointer=OBJ
    _write_span(p,OUT,bytes(16))
    string(p,OBJ,DATA,b'fixture\0bytes',base);string(p,OLD,OLDDATA,b'prior',base)
    if kind=='raw':
        size=int(label[7:]) if label.startswith('length_') else 13
        data=bytes((i*73+19)&255 for i in range(size))
        string(p,OBJ,G+0x5000 if size>0xE00 else DATA,data,base)
        if label=='NULL_source':dependency.w(p,OBJ+16,0)
        if label=='dirty_scope':_write_span(p,dependency.SP-0xD0,b'\xA5'*24)
        return p,blocks,destination,source,pointer
    dependency.w(p,SOURCE,OBJ);dependency.w(p,SOURCE+8,COUNT);dependency.w(p,COUNT,2,4)
    blocks[COUNT]=4
    if label in ('old_deleted','old_retained','old_zero','old_negative','old_NULL_object'):
        dependency.w(p,OUT,0 if label=='old_NULL_object' else OLD)
        dependency.w(p,OUT+8,OLDCOUNT)
        count={'old_deleted':1,'old_retained':3,'old_zero':0,'old_negative':0x80000000,'old_NULL_object':1}[label]
        dependency.w(p,OLDCOUNT,count,4);blocks[OLDCOUNT]=4
        if label!='old_NULL_object':blocks.update({OLD:24,OLDDATA:6})
    elif label=='same_object_different_counts':
        dependency.w(p,OUT,OBJ);dependency.w(p,OUT+8,OLDCOUNT)
        dependency.w(p,OLDCOUNT,1,4);blocks[OLDCOUNT]=4
    elif label=='self':destination=SOURCE
    elif label=='source_NULL_count':dependency.w(p,SOURCE+8,0)
    elif label=='source_wrapped_count':dependency.w(p,COUNT,0xFFFFFFFF,4)
    elif label=='source_NULL_object':dependency.w(p,SOURCE,0)
    elif label=='equal_NULL_objects':dependency.w(p,SOURCE,0);dependency.w(p,OUT+8,0x66000000)
    elif label=='destination_before':destination=SOURCE-8;dependency.w(p,destination,0)
    elif label=='destination_after':
        destination=SOURCE+8;dependency.w(p,SOURCE+8,0);dependency.w(p,SOURCE+16,0)
    elif label=='NULL_owned_object':pointer=0
    return p,blocks,destination,source,pointer


def native(library,libc,base,p,kind,label,blocks,destination,source,pointer):
    service=dependency.Services(blocks);observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    scopes=[]
    scope=dependency.SP-(0xD0 if kind=='raw' else 0x50)
    observed[scope,24]=None
    if kind=='raw':observed[dependency.SP-0x48,16]=None
    def watch(cpu,address):
        offset=address-base
        if offset in (0x347F00,0x347F10):service.diagnostic('pthread_mutex_lock' if offset==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if offset==0x348310:service.diagnostic('gettid',137)
        if offset==0x26C9D0:
            a=cpu.reg_read(arm.UC_ARM64_REG_X0);scopes.append((a,bytes(cpu.mem_read(a,24))))
    entry={'raw':0x25874C,'assign':0x162620,'owned':0x162944}[kind]
    flag=2 if label=='flag_two' else 0
    arguments=[OBJ,flag] if kind=='raw' else [destination,source] if kind=='assign' else [destination,pointer]
    returned,memory,_,_=oracle.native(library,base,entry,arguments,p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        thread_id=137,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP,arm.UC_ARM64_REG_X8:destination},
        host_imports={0x347FA0:service.native_free},malloc_handler=service.native_malloc,
        instruction_observer=watch,observed_memory=observed,instruction_limit=300000)
    return returned,memory,observed,scopes,service


def invoke(p,service,base,kind,label,destination,source,pointer,extra=None):
    kw=dict(entry_stack_address=dependency.SP,image_base=base,thread_pointer=dependency.TP,
        allocate=service.malloc,free=service.free,thread_id=137,diagnostic_observer=service.diagnostic)
    if extra:kw.update(extra)
    if kind=='raw':
        return references.construct_scoped_digest_reference(p,output_reference_address=destination,source_object_address=OBJ,
            reallocate=service.effects.realloc,flag=2 if label=='flag_two' else 0,**kw)
    if kind=='assign':
        return references.assign_scoped_string_reference(p,destination_address=destination,source_address=source,**kw)
    return references.assign_scoped_owned_string_reference(p,reference_address=destination,string_address=pointer,**kw)


def compare(library,libc,base,kind,label):
    p,blocks,destination,source,pointer=fixture(library,base,kind,label)
    returned,memory,observed,expected_scopes,expected=native(library,libc,base,p,kind,label,blocks,destination,source,pointer)
    actual=dependency.Services(blocks);actual_scopes=[];leave=diagnostics.leave_diagnostic_scope
    def record(q,**kw):
        a=kw['object_address'];actual_scopes.append((a,_read_span(q,a,24)));return leave(q,**kw)
    diagnostics.leave_diagnostic_scope=record
    try:result=invoke(p,actual,base,kind,label,destination,source,pointer)
    finally:diagnostics.leave_diagnostic_scope=leave
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
        raise AssertionError((kind,label,'guest',hex(i),hex(own[i]),hex(memory[i])))
    for (a,n),data in observed.items():
        if _read_span(p,a,n)!=data:raise AssertionError((kind,label,'observed',hex(a),_read_span(p,a,n).hex(),data.hex()))
    assert actual_scopes==expected_scopes,(kind,label,'scope boundary',actual_scopes,expected_scopes)
    assert actual.events==expected.events,(kind,label,'ordered effects',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed,(kind,label,'pre-free bytes')
    if kind=='raw':
        length=dependency.u(p,OBJ+12,4);data=_read_span(p,dependency.u(p,OBJ+16),length) if label!='NULL_source' else b''
        assert dependency.u(p,result+12,4)==16
        assert _read_span(p,dependency.u(p,result+16),16)==hashlib.md5(data).digest()
        assert dependency.u(p,dependency.u(p,destination+8),4)==1
    elif kind=='assign':assert returned==result==destination
    print('PASS request raw digest',hex(base),kind,label,flush=True)
    return dict(image_base=hex(base),operation=kind,case=label,original_returned=True,
        full_guest_ELF_and_scope_bytes_match=True,scope_exit_boundaries_match=True,
        ordered_allocator_and_diagnostic_locks_match=True,pre_free_bytes_match=True,native_snapshot_input=False)


def profiles():
    return [('raw',label) for label in ('length_0','length_1','length_45','length_60','length_64',
        'length_4097','NULL_source','flag_two','dirty_scope')]+[
        ('assign',label) for label in ('empty_destination','old_deleted','old_retained','old_zero',
        'old_negative','old_NULL_object','same_object_different_counts','self','source_NULL_count',
        'source_wrapped_count','source_NULL_object','equal_NULL_objects','destination_before','destination_after')]+[
        ('owned',label) for label in ('empty_destination','old_deleted','old_retained','NULL_owned_object')]


def guards(library):
    rows=[]
    for kind in ('raw','assign','owned'):
        for label in ('unaligned_stack','unmapped_scope','missing_allocator','unknown_destructor'):
            base=BASES[0];p,blocks,destination,source,pointer=fixture(library,base,kind,'old_deleted' if kind!='raw' else 'length_45')
            service=dependency.Services(blocks);kw={}
            if label=='unaligned_stack':kw['entry_stack_address']=dependency.SP-1
            elif label=='unmapped_scope':kw['entry_stack_address']=0x66001000
            elif label=='missing_allocator':kw['allocate']=None
            elif kind=='raw':kw['max_source_bytes']=2
            else:dependency.w(p,OLD,base+0x34F400)
            before={k:bytes(v) for k,v in p.items()}
            try:invoke(p,service,base,kind,'length_45',destination,source,pointer,kw)
            except (RefillUnsupported,ValueError,TypeError):pass
            else:raise AssertionError('guard accepted '+kind+' '+label)
            assert before=={k:bytes(v) for k,v in p.items()}
            name='source_bound' if kind=='raw' and label=='unknown_destructor' else label
            rows.append(dict(operation=kind,case=name,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
            print('PASS request raw digest guard',kind,name,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];negative=[]
    if args.group in ('native','all'):rows=[compare(args.library,args.libc,base,kind,label) for base in BASES for kind,label in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request raw MD5 and scoped assignments',cases=rows,
        native_Python_controls=len(rows),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
