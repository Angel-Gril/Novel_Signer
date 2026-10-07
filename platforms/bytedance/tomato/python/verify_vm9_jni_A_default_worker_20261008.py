"""Original A JNI return and same-run default worker/import observations.

Explicit ctor/JNI and virtual-worker continuations; controlled allocator,
JavaVM/JNI/clock/exit/OS services and warm reference/TLS states remain inputs.
Thread creation publishes deferred handles only. No Android loader or actual
OS threads are claimed, and no complete Python bootstrap is compared.
"""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_jni_cold_once_fresh_20261008 as cold
import verify_vm9_jni_initialization_fresh_20261007 as initialization
from verify_vm9_root_configuration import LIBC_BASE
from vm9_allocator import _read_span, _write_span

GUEST=cold.GUEST
TABLE=GUEST+0x6000
MAIN_THREAD=GUEST+0x3000
WORKER_THREAD=GUEST+0x7000
SCHEDULE=GUEST+0xF900
ARENAS=GUEST+0x10000
ARENA_BYTES=6*0x4000


def bindings(library):
    slots={name:[] for name in ('memcpy','memset')}
    with library.open('rb') as stream:
        elf=ELFFile(stream);plt=elf.get_section_by_name('.plt')
        rels=elf.get_section_by_name('.rela.plt');symbols=elf.get_section(rels['sh_link'])
        exports={symbols.get_symbol(rel['r_info_sym']).name:plt['sh_addr']+32+i*16
            for i,rel in enumerate(rels.iter_relocations())}
        assert exports['memcpy']==0x347F60 and exports['memset']==0x347F20
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                symbol=symbols.get_symbol(rel['r_info_sym'])
                if symbol.name in slots and rel['r_info_type']==257:
                    assert symbol['st_shndx']=='SHN_UNDEF' and rel['r_addend']==0
                    slots[symbol.name].append(rel['r_offset'])
    assert len(slots['memcpy'])==16 and slots['memset']
    return slots,exports


def case(args,base,mode,*,bind_memset=False,isolated_arena=True):
    assert mode in ('return','worker_entry','memset_packet','task_return','arena_collision','worker_wait')
    slots,plt=bindings(args.library)
    with args.libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports={s.name:LIBC_BASE+s['st_value'] for section in elf.iter_sections()
            if section['sh_type']=='SHT_DYNSYM' for s in section.iter_symbols()
            if s['st_shndx']!='SHN_UNDEF'}
    original_fixture,original_native=cold.fixture,cold.native
    threads=[];signals=[];entries=[];jni_returns=[];switches=[];packets=[];terminal={}
    arenas=[];default_wakes=[];callers=[];nested_returns=[];canary_pairs=[]
    task_return_points=[];task_cleanup_points=[]

    def fixture(library,image,profile,**options):
        pages,blocks=original_fixture(library,image,profile,**options)
        _write_span(pages,TABLE,_read_span(pages,cold.TABLE,4096))
        cold.w(pages,cold.ENV,TABLE);cold.w(pages,cold.INNER_ENV,TABLE)
        _write_span(pages,MAIN_THREAD,_read_span(pages,GUEST+0xD000,0x50))
        for name in ('memcpy','memset'):
            for offset in slots[name]:
                assert cold.u(pages,image+offset)==0
                if name=='memcpy' or bind_memset:cold.w(pages,image+offset,image+plt[name])
        return pages,blocks

    def execute(library,image,function,arguments,pages,**options):
        previous=options['instruction_observer'];original_syscall=options['syscall_handler']
        options['stop_offset']={'return':None,'worker_entry':0x280554,'memset_packet':0x281620,'task_return':0x326620,'arena_collision':0x280A70,'worker_wait':0x3485B0}[mode]
        options['instruction_limit']=900000000 if mode in ('task_return','arena_collision','worker_wait') else 1000000
        options['code_hook_ranges']=tuple((image+a,image+b) for a,b in
            ((0x165388,0x1684F0),(0x26C858,0x271940),(0x27B41C,0x281800),
             (0x326000,0x326B00),(0x347E00,0x348800)))+((GUEST+0xF000,GUEST+0xFF00),)
        previous_malloc=options['malloc_handler']
        def allocate(cpu,size):
            if size!=0x4000 or not isolated_arena:return previous_malloc(cpu,size)
            assert len(arenas)<6
            pointer=ARENAS+len(arenas)*0x4000;arenas.append(pointer);return pointer
        options['malloc_handler']=allocate
        options['extra_registers']={arm.UC_ARM64_REG_TPIDR_EL0:MAIN_THREAD}
        imports=options['host_imports']
        def create(cpu):
            values=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(4)]
            assert values[1]==0 and values[2]-image in (0x326A2C,0x3260A4)
            assert len(threads)<3
            handle=GUEST+0xC800+len(threads)*0x100
            cpu.mem_write(values[0],handle.to_bytes(8,'little'));threads.append([handle,*values]);return 0
        def actual(cpu,name):
            cpu.reg_write(arm.UC_ARM64_REG_PC,exports[name]);return None
        def signal(cpu):return actual(cpu,'pthread_cond_signal')
        def syscall(cpu,number):
            if cpu.reg_read(arm.UC_ARM64_REG_X0)==image+0x3E2EE0:
                if not switches:return original_syscall(cpu,number)
                values=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
                assert number==98 and values[1:]==[129,0x7FFFFFFF]
                default_wakes.append([number,*values,0]);return 0
            values=[cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]
            assert number==98 and values[1]==129 and values[2]==1
            signals.append([number,*values,0]);return 0
        imports.update({0x348000:create,0x348590:signal});options['syscall_handler']=syscall
        prior_exit=imports[0x347EA0]
        def exiting(cpu):
            result=prior_exit(cpu)
            if mode!='return' and cpu.reg_read(arm.UC_ARM64_REG_PC)==image+0x27B41C:
                cpu.reg_write(arm.UC_ARM64_REG_X30,SCHEDULE)
            return result
        def schedule(cpu):
            assert cpu.reg_read(arm.UC_ARM64_REG_X0)==0x10006
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==cold.SP
            assert [row[3]-image for row in threads]==[0x326A2C,0x3260A4,0x3260A4]
            jni_returns.append(0x10006)
            if isolated_arena:
                cpu.mem_map(ARENAS,ARENA_BYTES);cpu.mem_write(ARENAS,bytes([0x3C])*ARENA_BYTES)
            cpu.mem_write(WORKER_THREAD,bytes(0xB00))
            cpu.mem_write(WORKER_THREAD+8,(WORKER_THREAD+0x200).to_bytes(8,'little'))
            cpu.mem_write(WORKER_THREAD+0x210,(149).to_bytes(4,'little'))
            cpu.mem_write(WORKER_THREAD+0x10,(37).to_bytes(4,'little'))
            cpu.mem_write(GUEST+0x1300,bytes(8))
            cpu.reg_write(arm.UC_ARM64_REG_TPIDR_EL0,WORKER_THREAD)
            cpu.reg_write(arm.UC_ARM64_REG_SP,cold.SP)
            cpu.reg_write(arm.UC_ARM64_REG_X0,threads[1][4])
            cpu.reg_write(arm.UC_ARM64_REG_X30,cold.STOP)
            cpu.reg_write(arm.UC_ARM64_REG_PC,image+0x3260A4)
            switches.append('JNI_return_to_same_run_queue_worker');return None
        prior_get=imports[0x3485D0];prior_set=imports[0x348580]
        prior_key=imports[0x348620];prior_once=imports[0x3486B0]
        def get_specific(cpu):
            return prior_get(cpu) if cpu.reg_read(arm.UC_ARM64_REG_X0)==0x80000021 else actual(cpu,'pthread_getspecific')
        def set_specific(cpu):
            return prior_set(cpu) if cpu.reg_read(arm.UC_ARM64_REG_X0) in (0x80000021,0x80000022) else actual(cpu,'pthread_setspecific')
        def key_create(cpu):
            return prior_key(cpu) if cpu.reg_read(arm.UC_ARM64_REG_X0)==image+0x3E2FB0 else actual(cpu,'pthread_key_create')
        def once(cpu):
            return prior_once(cpu) if cpu.reg_read(arm.UC_ARM64_REG_X0)==image+0x3E31F8 else actual(cpu,'pthread_once')
        imports.update({0x347EA0:exiting,SCHEDULE-image:schedule,0x3485D0:get_specific,
            0x348580:set_specific,0x348620:key_create,0x3486B0:once})
        def observe(cpu,address):
            previous(cpu,address);off=address-image
            if off in (0x28040C,0x280468,0x280484,0x3260A4,0x326578,0x280554,0x280590):entries.append(hex(off))
            if off in tuple(0x280590+i*0x80 for i in range(6)):callers.append(off)
            if off in tuple(0x2809D4+i*0x1E4 for i in range(6))+tuple(0x280A50+i*0x1E4 for i in range(6)):
                nested_returns.append(off)
                tp=cpu.reg_read(arm.UC_ARM64_REG_X19);fp=cpu.reg_read(arm.UC_ARM64_REG_X29)
                canary_pairs.append([int.from_bytes(cpu.mem_read(tp+0x28,8),'little'),
                    int.from_bytes(cpu.mem_read(fp-8,8),'little')])
            if off==0x326620:task_return_points.append(off)
            if off==0x167310 and task_return_points:task_cleanup_points.append(off)
            if off==0x168324:
                entries.append(dict(vm_bytecode_offset_hex=hex(cpu.reg_read(arm.UC_ARM64_REG_X0)-image)))
            if off==0x281610:
                pointer=cpu.reg_read(arm.UC_ARM64_REG_X0)
                packets.append([int.from_bytes(cpu.mem_read(pointer+i*8,8),'little') for i in range(4)])
        options['instruction_observer']=observe
        result=original_native(library,image,function,arguments,pages,**options)
        terminal['x0']=result[0]
        return result
    cold.fixture=fixture;cold.native=execute
    try:out=cold.run_native(args,base,{'long_word':0},bootstrap=True)
    finally:cold.fixture=original_fixture;cold.native=original_native
    assert [row[3]-base for row in threads]==[0x326A2C,0x3260A4,0x3260A4]
    assert len(signals)==2 and len(out[6])==1
    assert '0x280468' in entries and '0x280484' in entries
    if mode=='return':
        assert terminal['x0']==0x10006 and not switches and not jni_returns
    else:
        assert jni_returns==[0x10006] and len(switches)==1 and '0x3260a4' in entries
    if mode in ('task_return','worker_wait'):
        assert callers==[0x280590+i*0x80 for i in range(6)]
        assert len(nested_returns)==48 and len(default_wakes)==6 and len(arenas)==6
        assert all(a==b for a,b in canary_pairs)
        assert all(int.from_bytes(out[9][base+0x3E09E8+i*0x48 & ~4095,4096][(base+0x3E09E8+i*0x48)&4095:((base+0x3E09E8+i*0x48)&4095)+8],'little')==(1<<64)-1 for i in range(6))
    if mode=='worker_wait':
        assert len(task_return_points)==1 and len(task_cleanup_points)==1
    if mode=='arena_collision':
        assert len(canary_pairs)==6 and canary_pairs[-1][0]!=canary_pairs[-1][1]
        assert not arenas and not default_wakes
    if mode=='memset_packet':
        assert len(packets)==1
        expected=base+plt['memset'] if bind_memset else 0
        assert packets[0][0]==expected and packets[0][2]&255==0, (packets, expected)
        assert dict(vm_bytecode_offset_hex='0xedcf0') in entries
        assert dict(vm_bytecode_offset_hex='0xee3b0') in entries
    return dict(image_base_hex=hex(base),mode=mode,memset_ABS64_bound=bind_memset,
        native_terminal_reached=True,full_original_JNI_OnLoad_return_verified=True,
        original_JNI_return_hex='0x10006',same_native_execution=True,
        explicit_driver_continuations=out[6]+switches,thread_create_requests=len(threads),
        thread_start_offsets_hex=[hex(row[3]-base) for row in threads],
        queue_signal_no_waiter_events=signals,original_cold_once_broadcast_events=out[4].wake_events,
        startup_entries=entries,same_run_worker_argument_used=mode!='return',
        deferred_guest_handles_only=True,real_OS_threads_created=False,
        worker_uses_explicit_TLS=mode!='return',worker_reuses_main_physical_stack=mode!='return',
        default_task_entry_reached=mode!='return',default_task_body_entered=mode not in ('return','worker_entry'),
        default_task_body_return_verified=mode in ('task_return','worker_wait'),
        task_cleanup_after_return_observed=bool(task_cleanup_points),
        worker_condition_wait_boundary_reached=mode=='worker_wait',
        worker_condition_wait_executed=False,worker_exit_verified=False,
        default_caller_entries_hex=[hex(v) for v in callers],nested_VM_returns=len(nested_returns),
        all_observed_canaries_match=all(a==b for a,b in canary_pairs),
        isolated_arena_service_used=isolated_arena and mode!='return',
        isolated_arena_allocations=len(arenas),default_task_no_waiter_broadcasts=len(default_wakes),
        allocator_overlap_reproduced=mode=='arena_collision',memset_packet_words_hex=[[hex(v) for v in row] for row in packets],
        memset_callback_executed=mode in ('task_return','arena_collision','worker_wait'),Python_full_bootstrap_compared=False,
        native_input_snapshot_used=False,complete_python_medusa=False)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==cold.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==initialization.LIBC_SHA256
    cases=[];controls=[];tasks=[];waits=[]
    for base in (0x122C0000,0x775C205000):
        for mode in ('return','worker_entry'):
            cases.append(case(args,base,mode));print('A JNI/worker:',hex(base),mode,'passed',flush=True)
        for bound in (False,True):
            controls.append(case(args,base,'memset_packet',bind_memset=bound))
            print('A worker memset:',hex(base),bound,'passed',flush=True)
    for base in (0x122C0000,0x775C205000):
        tasks.append(case(args,base,'task_return',bind_memset=True))
        print('A full same-run task:',hex(base),'passed',flush=True)
    for base in (0x122C0000,0x775C205000):
        waits.append(case(args,base,'worker_wait',bind_memset=True))
        print('A task cleanup/worker wait:',hex(base),'passed',flush=True)
    collision=case(args,0x122C0000,'arena_collision',bind_memset=True,isolated_arena=False)
    print('A overlapping allocator control passed',flush=True)
    slots,plt=bindings(args.library)
    evidence=dict(schema='vm9-jni-A-default-worker-v1',evidence_date='2026-10-07',
        evidence_timezone='UTC',host_trial_label='20261008',sample_sha256=cold.LIBRARY_SHA256,
        matching_libc_sha256=initialization.LIBC_SHA256,original_JNI_return_observations=2,
        same_run_worker_entry_observations=2,memset_import_binding_observations=4,
        cases=cases,binding_controls=controls,same_run_default_task_observations=len(tasks),
        same_run_default_task_cases=tasks,worker_wait_boundary_observations=len(waits),worker_wait_boundary_cases=waits,allocator_collision_controls=[collision],ELF_ABS64_slots={k:[hex(v) for v in values] for k,values in slots.items()},
        PLT_offsets_hex={k:hex(plt[k]) for k in slots},
        main_thread_storage_offset_hex=hex(MAIN_THREAD-GUEST),worker_thread_storage_offset_hex=hex(WORKER_THREAD-GUEST),
        JNI_table_offset_hex=hex(TABLE-GUEST),main_and_worker_SP_hex=hex(cold.SP),
        explicit_allocator_JVM_JNI_clock_exit_OS_services_used=True,
        warm_reference_and_TLS_global_OS_key_inputs_used=True,
        all_ELF_constructors_recovered=False,real_OS_threads_created=False,
        default_initialization_task_return_in_same_run_verified=True,
        complete_python_medusa=False,fresh_request_signature_verified=False,online_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('A startup: 2 JNI returns; 2 worker entries; 4 memset controls; 2 full tasks; 2 cleanup/wait observations; 1 allocator control passed',flush=True)


if __name__=='__main__':main()
