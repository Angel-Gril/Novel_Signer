"""Fresh actual allocator/GC/root against native function-return controls."""
from __future__ import annotations
from pathlib import Path
import argparse,collections,hashlib,json,os
from elftools.elf.elffile import ELFFile
import vm9_allocator as a,vm9_root_allocator as model
import verify_vm9_worker_allocator as h,verify_vm9_libc_stdio as io
import verify_vm9_root_configuration as fixture,verify_vm9_signer_objects as oracle
from vm9_libc_boot import _u,_w
from unicorn.arm64_const import UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X8,UC_ARM64_REG_X30,UC_ARM64_REG_SP,UC_ARM64_REG_PC,UC_ARM64_REG_TPIDR_EL0


def fresh(library,libc,image,property_value):
    p=h.fresh(library,libc,image)
    inputs,strings,sdk_name=fixture.fresh_inputs(library,base=image,property_value=property_value)
    for key,value in inputs.items():
        if io.GUEST<=key<<12<io.GUEST+0xC000:p[key]=bytearray(value)
    return p,strings,sdk_name


def case(library,libc,image,property_value,vm_module,*,stack_address=h.TOP,mapping_address=None,canary=None):
    p,strings,sdk_name=fresh(library,libc,image,property_value)
    if canary is not None:_w(p,fixture.TLS+0x28,canary)
    seed={k:bytearray(v) for k,v in p.items()};me=h.Environment(p,2);ne=h.Environment(seed,2)
    if mapping_address is not None:me.os.next_address=ne.os.next_address=mapping_address
    exports={}
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={symbol.name:io.LIBC+symbol['st_value'] for section in elf.iter_sections() if section['sh_type']=='SHT_DYNSYM'
            for symbol in section.iter_symbols() if symbol['st_shndx']!='SHN_UNDEF'}
    observed=io.observed_spans();observed[fixture.TLS,0xB00]=None
    observed.update({(key<<12,4096):None for key in p if image<=key<<12<image+0x400000})
    observed.update({(io.LIBC+0xD8DC8,8):None,(io.LIBC+0xDE888,8):None,(io.LIBC+0xDB380,0x48):None,
        (io.LIBC+0xE01C0,16):None,(io.LIBC+0xDE930,16):None})
    native_effects=[];model_effects=[];pending=[];expected={};mapped=[False];booted=[False];counts=collections.Counter()
    backing=stack_address-0xA0-0x80-0x5A0+0x458
    def observe(cpu,pc):
        if pc==image+0x257578 and not mapped[0]:
            mapped[0]=True;cpu.mem_map(h.STACK,h.STACK_BYTES)
            for address in range(h.STACK,h.STACK+h.STACK_BYTES,4096):cpu.mem_write(address,bytes(seed[address>>12]))
        if pc==io.LIBC+0x8E250 and not booted[0]:
            booted[0]=True;cpu.mem_write(io.TABLE,a._read_span(seed,io.TABLE,141*16))
        if pending and pc==pending[-1][0]:
            _,kind,value=pending.pop()
            if kind=='malloc':native_effects.append(['allocate',value,cpu.reg_read(UC_ARM64_REG_X0)])
            else:native_effects.append(['free',value])
        if pc-image in (0x347FD0,0x347FA0):
            kind='malloc' if pc-image==0x347FD0 else 'free'
            counts[kind]+=1;pending.append((cpu.reg_read(UC_ARM64_REG_X30),kind,cpu.reg_read(UC_ARM64_REG_X0)))
        if pc==io.LIBC+0x9833C:counts['gc']+=1
        if pc==io.LIBC+0x97F40:counts['flush']+=1
        if pc==image+0x257368:
            expected['registers']=[int.from_bytes(cpu.mem_read(backing+i*8,8),'little') for i in range(32)]
    def redirect(name):
        def effect(cpu):cpu.reg_write(UC_ARM64_REG_PC,exports[name])
        return effect
    def register(cpu):
        fields=[cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
        native_effects.append(['register',*fields]);return 0
    def clock(cpu):
        clock_id=cpu.reg_read(UC_ARM64_REG_X0);assert clock_id in (0,1)
        native_effects.append(['clock',clock_id]);cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X1),
            (1791023800).to_bytes(8,'little')+(500000000).to_bytes(8,'little'));return 0
    def mkdir(cpu):_w_bytes=(17).to_bytes(4,'little');cpu.mem_write(fixture.TLS+0x100,_w_bytes);return 0xFFFFFFFF
    def property_find(cpu):
        assert bytes(cpu.mem_read(cpu.reg_read(UC_ARM64_REG_X0),len(sdk_name)+1))==sdk_name+b'\0'
        return fixture.PROPERTY if property_value is not None else 0
    def property_read(cpu):
        assert cpu.reg_read(UC_ARM64_REG_X0)==fixture.PROPERTY and not cpu.reg_read(UC_ARM64_REG_X1)
        cpu.mem_write(cpu.reg_read(UC_ARM64_REG_X2),property_value+b'\0');return len(property_value)
    def syscall(cpu,number):
        if number==98:
            fields=[cpu.reg_read(reg) for reg in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]
            assert fields[1]&0x7F==1;native_effects.append(['wake',*fields]);return 0
        if number==56 and io.cstring(cpu,cpu.reg_read(UC_ARM64_REG_X1))!=b'/proc/stat':return -2
        if number in (57,63) and cpu.reg_read(UC_ARM64_REG_X0)!=53:return -9
        if number in (48,79):return -2
        if number==198:return -97
        if number==233:
            fields=[cpu.reg_read(UC_ARM64_REG_X0+i) for i in range(3)]
            assert fields[0]%4096==0 and fields[1]>0 and fields[1]%4096==0 and fields[2]==4
            assert any(r.base<=fields[0] and fields[0]+fields[1]<=r.end for r in ne.os.mappings)
            ne.calls.append(['madvise',*fields]);return 0
        return ne.syscall(cpu,number,observed)
    def returned(cpu):
        assert not pending
        expected['final']={span:bytes(cpu.mem_read(*span)) for span in observed}
        expected['guest']=bytes(cpu.mem_read(io.GUEST,0xA000));expected['returned']=True
        cpu.reg_write(UC_ARM64_REG_PC,io.STOP)
    imports={0x347FA0:redirect('free'),0x347EA0:register,0x348450:clock,0x3484A0:mkdir,
        0x3481A0:lambda cpu:fixture.TLS+0x100,0x348250:property_find,0x348260:property_read,io.CONTINUE-image:returned}
    for offset,name in ((0x3484B0,'strtol'),(0x3486B0,'pthread_once'),(0x348620,'pthread_key_create'),
        (0x3485D0,'pthread_getspecific'),(0x348580,'pthread_setspecific'),(0x3485A0,'pthread_cond_broadcast'),
        (0x347FE0,'memcmp'),(0x347F70,'vsnprintf')):imports[offset]=redirect(name)
    initial={k:v for k,v in io.inputs(seed).items()
        if not h.STACK<=k<<12<h.STACK+h.STACK_BYTES and not h.WORKERS[0]<=k<<12<h.WORKERS[-1]+0x2000}
    _,memory,substitutions,_=oracle.native(library,image,0x257578,
        [io.GUEST+0x1000,io.GUEST+0x1010,io.GUEST+0x1020,5],initial,libc=libc,real_malloc=True,
        real_mutexes=True,real_singletons=True,thread_id=137,host_imports=imports,syscall_handler=syscall,
        instruction_observer=observe,observed_memory=observed,
        extra_registers={UC_ARM64_REG_SP:stack_address,UC_ARM64_REG_TPIDR_EL0:fixture.TLS,
            UC_ARM64_REG_X8:io.GUEST+0x1800,UC_ARM64_REG_X30:io.CONTINUE},instruction_limit=10000000)
    assert not substitutions and expected.get('returned') and 'registers' in expected
    print('NATIVE_ACTUAL_ROOT_RETURN',hex(image),dict(counts),flush=True)
    def service(tx,operation,*fields):
        if operation=='madvise':
            assert fields[0]%4096==0 and fields[1]>0 and fields[1]%4096==0 and fields[2]==4
            # The service may receive nested page staging; the root bridge owns
            # the live transaction. Region containment is checked by production metadata.
            me.calls.append(['madvise',*fields]);return 0
        return me.service(tx,operation,*fields)
    def allocate_effect(p,size,pointer):model_effects.append(['allocate',size,pointer])
    def free_effect(p,pointer):model_effects.append(['free',pointer])
    def atexit(p,destructor,obj,dso):model_effects.append(['register',destructor,obj,dso]);return 0
    def wake(p,pointer,operation,count):model_effects.append(['wake',pointer,operation,count]);return 0
    def read_clock(p,clock_id):model_effects.append(['clock',clock_id]);return 0,1791023800,500000000
    def root_syscall(p,number,args):
        if number in (48,56,79):return -2
        if number in (57,63):return -9
        if number==198:return -97
        raise a.RefillUnsupported('unknown root virtual syscall')
    def root_mkdir(p,path,mode):_w(p,fixture.TLS+0x100,17,4);return 0xFFFFFFFF
    previous=vm_module.B
    result=model.construct_root_reference(me.os,vm_module=vm_module,image_base=image,libc_base=io.LIBC,
        output_reference_address=io.GUEST+0x1800,first_reference_address=io.GUEST+0x1000,
        second_reference_address=io.GUEST+0x1010,initializer_reference_address=io.GUEST+0x1020,flag=5,
        entry_stack_address=stack_address,thread_pointer=fixture.TLS,scratch_address=h.SCRATCH,errno_address=fixture.TLS+0x100,
        brk=me.brk,os_call=service,read_property=lambda p,name:property_value,syscall=root_syscall,mkdir=root_mkdir,
        read_clock=read_clock,once_wake=wake,register_destructor=atexit,thread_id=137,
        allocation_effect=allocate_effect,free_effect=free_effect)
    assert vm_module.B==previous
    register_diffs=[(i,hex(x),hex(y)) for i,(x,y) in enumerate(zip(result.vm_result.registers,expected['registers'])) if x!=y]
    differences=[]
    for (address,width),data in expected['final'].items():
        actual=a._read_span(p,address,width)
        if actual!=data:differences.append((hex(address),[(i,x,y) for i,(x,y) in enumerate(zip(actual,data)) if x!=y][:8]))
    print('ROOT_COMPARE','registers',register_diffs,'span differences',differences[:12],
        'effects',native_effects==model_effects,'OS',me.calls==ne.calls,flush=True)
    assert not register_diffs and not differences
    assert expected['guest']==memory==a._read_span(p,io.GUEST,0xA000)
    assert native_effects==model_effects and me.calls==ne.calls
    assert me.os.mappings==ne.os.mappings and me.os.next_address==ne.os.next_address
    assert counts['malloc']==206 and counts['free']==93 and counts['gc']==1
    assert result.vm_result.steps==716 and result.vm_result.stop_offset==0x99F04
    assert _u(p,io.GUEST+0x1800)==result.object_address and _u(p,result.reference_count_address,4)==1
    return dict(image_base=hex(image),root_vm_steps=716,root_vm_stop_offset='0x99f04',
        actual_native_malloc_plt_calls=206,actual_native_free_plt_calls=93,actual_gc_calls=counts['gc'],
        actual_small_flush_calls=counts['flush'],all_32_vm_slots_match=True,
        final_guest_all_image_tls_libc_globals_and_retained_mapping_bytes_match=True,
        allocation_free_registration_clock_wake_order_match=True,os_order_mapping_records_protection_and_cursor_match=True,
        root_reference_count_is_one=True,native_root_factory_returned=True,python_root_factory_returned=True,
        native_input_snapshot_used=False,substituted_allocations=0,explicit_virtual_os=True,
        observable_allocator_stack_spills_match=True,
        diagnostic_scope_excluded=True,physical_stack_compared=False,
        main_startup_worker_composed_before_root=False)



def rejection_cases(library,libc,vm_module):
    rows=[];image=0x122C0000
    labels=('unaligned_stack','missing_tls','mapping_provider_failure',
        'first_allocation_observer_failure','after_gc_allocation_observer_failure',
        'final_free_observer_failure','final_allocation_observer_failure','oversized_property')
    for label in labels:
        p,_,_=fresh(library,libc,image,None);env=h.Environment(p,2)
        if label=='missing_tls':p.pop(fixture.TLS>>12)
        before={k:bytes(v) for k,v in p.items()};records=env.os.mappings[:];cursor=env.os.next_address
        previous=vm_module.B;counts=collections.Counter();progress={'gc':False}
        def injected():raise a.RefillUnsupported('injected actual root provider failure')
        def mark_gc(p):
            key=_u(p,_u(p,io.LIBC+0xD8F98),4)
            wrapper=a.pthread_getspecific(p,key=key,thread_pointer=fixture.TLS,generation_table=io.LIBC+0xE0200)
            cache=_u(p,wrapper+0x10) if wrapper else 0
            if cache and _u(p,cache+0x1C,4)==1:progress['gc']=True
        def allocate_effect(p,size,pointer):
            counts['allocate']+=1;mark_gc(p)
            if label=='first_allocation_observer_failure' or (
                    label=='after_gc_allocation_observer_failure' and progress['gc']) or (
                    label=='final_allocation_observer_failure' and counts['allocate']==206):injected()
        def free_effect(p,pointer):
            counts['free']+=1;mark_gc(p)
            if label=='final_free_observer_failure' and counts['free']==93:injected()
        def service(tx,operation,*fields):
            if label=='mapping_provider_failure' and operation=='mmap':injected()
            if operation=='madvise':env.calls.append(['madvise',*fields]);return 0
            return env.service(tx,operation,*fields)
        def register(p,*fields):counts['register']+=1;return 0
        def wake(p,*fields):counts['wake']+=1;return 0
        def clock(p,clock_id):counts['clock']+=1;return 0,1791023800,500000000
        def syscall(p,number,args):
            if number in (48,56,79):return -2
            if number in (57,63):return -9
            if number==198:return -97
            raise a.RefillUnsupported('unknown root virtual syscall')
        def mkdir(p,path,mode):_w(p,fixture.TLS+0x100,17,4);return 0xFFFFFFFF
        try:
            model.construct_root_reference(env.os,vm_module=vm_module,image_base=image,libc_base=io.LIBC,
                output_reference_address=io.GUEST+0x1800,first_reference_address=io.GUEST+0x1000,
                second_reference_address=io.GUEST+0x1010,initializer_reference_address=io.GUEST+0x1020,flag=5,
                entry_stack_address=h.TOP+1 if label=='unaligned_stack' else h.TOP,thread_pointer=fixture.TLS,
                scratch_address=h.SCRATCH,errno_address=fixture.TLS+0x100,brk=env.brk,os_call=service,
                read_property=lambda p,name:b'3'*92 if label=='oversized_property' else None,
                syscall=syscall,mkdir=mkdir,read_clock=clock,once_wake=wake,register_destructor=register,
                thread_id=137,allocation_effect=allocate_effect,free_effect=free_effect)
        except (a.RefillUnsupported,ValueError) as exc:
            if label.endswith('provider_failure') or label.endswith('observer_failure'):
                assert str(exc)=='injected actual root provider failure'
            elif label=='oversized_property':assert '92-byte buffer' in str(exc)
            elif label=='missing_tls':assert 'missing checkpoint page' in str(exc)
            else:assert 'stack must be aligned' in str(exc)
        else:raise AssertionError(label+' actual root accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        assert env.os.mappings==records and env.os.next_address==cursor and vm_module.B==previous
        if label=='after_gc_allocation_observer_failure':assert progress['gc'] and counts['allocate']>170
        if label=='final_free_observer_failure':assert progress['gc'] and counts['allocate']==205 and counts['free']==93
        if label=='final_allocation_observer_failure':assert progress['gc'] and counts['allocate']==206 and counts['free']==93
        rows.append(dict(case=label,rejected=True,guest_pages_owned_mappings_and_cursor_unchanged=True,
            vm_base_restored=True,completed_effects=dict(counts),gc_cursor_advanced_before_rejection=progress['gc'],
            external_provider_effects_rolled_back=False))
        print('actual root rollback',label,'PASS',flush=True)
    return rows

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--profile',action='append',choices=('absent','sdk_30','sdk_negative','sdk_signed_suffix'))
    ap.add_argument('--base',action='append',type=lambda value:int(value,0));args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==h.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve());import vm_full
    values={'absent':None,'sdk_30':b'30','sdk_negative':b'-1','sdk_signed_suffix':b'  +31suffix'};rows=[]
    for image in args.base or (0x122C0000,0x775C205000):
        for label in args.profile or values:
            row=case(args.library,args.libc,image,values[label],vm_full);row['property_profile']=label;rows.append(row)
            print('fresh actual root',hex(image),label,'PASS',flush=True)
    if not args.base and not args.profile:
        for image in (0x122C0000,0x775C205000):
            row=case(args.library,args.libc,image,None,vm_full,stack_address=h.TOP-0x1000,
                mapping_address=0x13A00000,canary=0x3F71A29C5DE408B6)
            row.update(property_profile='absent',input_profile='relocated_stack_mapping_changed_canary');rows.append(row)
            print('fresh actual root',hex(image),'relocated inputs PASS',flush=True)
    rejected=rejection_cases(args.library,args.libc,vm_full)
    args.output.write_text(json.dumps(dict(schema='vm9-root-actual-allocator-v1' ,sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=h.LIBC_SHA256,cases=rows,rejection_cases=rejected,bounded_root_factory_actual_allocator_verified=True,native_input_snapshot_used=False,
        complete_python_medusa=False,fresh_input_signer_output_verified=False,current_online_header_matrix_verified=False),indent=2)+'\n',encoding='utf-8')
    print('actual root',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
