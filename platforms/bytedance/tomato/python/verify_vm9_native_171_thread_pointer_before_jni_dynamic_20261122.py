"""Verify native TP cache publication and stop before the next JNI VM call."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_getppid_import_return_dynamic_20261122 as previous

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_thread_pointer_before_jni_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-thread-pointer-before-jni-dynamic-20261122-v1'
VM_CALL, VM_RESUME = previous.VM_CALL, previous.VM_RESUME
WRAPPER, TARGET, CACHE, HELPER = 0x28876C, 0x204F58, 0x3DA090, 0x20513C
JNI_WRAPPER, JNI_TARGET = 0x288788, 0x26EDC4
MAX_OBSERVATIONS = 10000
TP_DESCRIPTOR_SHA256 = '41ae8b297e253f0df3c8e029b67f474c718bc87701023992bdfdcbcd86d2fd74'
JNI_DESCRIPTOR_SHA256 = '286a8fcd9299c0336124321932b4b8990bb4b122d4a7e3d72ea0bc7a7353edda'
CODE_RANGES = ((TARGET,0xEC),(HELPER,16),(WRAPPER,28),(JNI_WRAPPER,12))
CODE_SHA256 = {'0x204f58': 'ec61a98d7a5e4bd00ad583b18d33fcefa831dcf770f5524838150aa9e84ead37', '0x20513c': '8f9211680abacded2c23d35e71c0acf96501c3ba8acebdff61d983eb7ed7f024', '0x28876c': 'c2b99ea12b543d654d627a76b57c9a462fa743b9fc326046cf3ca66e030c8e3b', '0x288788': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565'}
CODE_HEX_JNI_WRAPPER = '012040a9e00308aa20001fd6'
sha256, raw_hash, digest = previous.sha256, previous.raw_hash, previous.digest


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints():
    return dict(thread_pointer_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent):
    return dict(inherited_getppid_evidence_sha256=sha256(previous.EVIDENCE),
        Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
        Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


def static_code(path):
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        rows={hex(pc):dict(size=size,hex=previous.previous.file_read(elf,pc,size).hex())
              for pc,size in CODE_RANGES}
    for pc,row in rows.items():
        assert raw_hash(bytes.fromhex(row['hex']))==CODE_SHA256[pc]
    return rows


def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        thread_pointer='inherited synthetic TPIDR_EL0 register; original MRS/cache/store instructions execute',
        final_boundary='stop before VM BLR to JNI environment acquisition; no new JNI service entry',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',getppid_prefix_fields_and_ledgers_verified=True,
        original_thread_pointer_callback_returned=True,cold_cache_TPIDR_EL0_read_verified=True,
        original_eight_byte_cache_publication_verified=True,cache_neighbor_bytes_preserved=True,
        two_original_helper_LR_adjustments_verified=True,skipped_bogus_stack_instructions_not_executed=True,
        full_X64_descriptor_result_and_padding_verified=True,SP_and_X19_X29_restored=True,
        no_new_allocator_service_JNI_or_SVC_events=True,next_JNI_VM_call_executed=False,
        JNI_wrapper_executed=False,JNI_environment_acquisition_executed=False,
        native_memory_used_as_python_model_input=False,current_native_suffix_return_verified=False,
        complete_standalone_signer_verified=False,ordinary_Cronet_six_headers_verified=False,
        Android_execution=False,online_acceptance_verified=False,physical_PAC_authentication_verified=False)


class ThreadPointerScenario(previous.GetppidScenario):
    def __init__(self,control):
        super().__init__(control)
        self._thread_active=False;self._thread_done=False;self._thread_returned=False
        self._thread_count=0;self._thread_trace=hashlib.sha256();self._thread_code={}
        self._thread_first=[];self._thread_tail=[];self._thread_state=None
        self._thread_call=None;self._thread_helpers=[];self._thread_stores=[]
        self._thread_mrs=False;self._thread_old=prior_evidence()['case_result']

    def _track_thread(self,cpu,pc):
        assert self.image<=pc<self.image+0x400000
        self._thread_count+=1;assert self._thread_count<MAX_OBSERVATIONS
        off=pc-self.image;raw=bytes(cpu.mem_read(pc,4))
        self._thread_trace.update(off.to_bytes(8,'little')+raw);self._thread_code[hex(off)]=raw.hex()
        if len(self._thread_first)<16:self._thread_first.append(hex(off))
        self._thread_tail=(self._thread_tail+[hex(off)])[-16:]

    def _return_pp_call(self,cpu):
        super()._return_pp_call(cpu)
        if not self._pp_done:return
        old=self._thread_old
        fields=((self._pp_count,'instruction_observations'),(self._pp_trace.hexdigest(),'instruction_trace_sha256'),
            (digest(self._pp_code),'observed_code_sha256'),(self._pp_first,'first_pc_offsets'),
            (self._pp_tail,'tail_pc_offsets'),(self._pp_calls,'callbacks'),(self._pp_parent,'retained_getpid'),
            (self._pp_binding,'binding'),(self._pp_reads,'import_reads'),(self._pp_writes,'descriptor_stores'),
            (self._pid_syscalls,'inherited_syscall_172'),(self._pp_syscalls,'syscall_173'))
        for value,key in fields:assert value==old[key],key
        events=self._thread_state['allocator_events_ref']
        assert events[len(self._pp_events_before):]==old['new_allocator_events']
        self._thread_events_before=deepcopy(events)
        self._thread_parent=dict(getppid_case_sha256=digest(old),verified_fields=[key for _,key in fields],
            instruction_observations=self._pp_count,instruction_trace_sha256=self._pp_trace.hexdigest(),
            observed_code_sha256=digest(self._pp_code),getppid_callback_return_verified=True)
        self._pp_done=False;self._pp_active=False;self._thread_active=True
        self._track_thread(cpu,self.image+VM_RESUME)

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._thread_active and address==self.image+CACHE:
                assert self._thread_call is not None and not self._thread_returned
                assert cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x205020
                assert self._thread_count==628 and size==8
                assert self._u(cpu,address)==0 and self._reg(cpu,8)==self._thread_tp
                self._thread_stores.append(dict(pc_offset='0x205020',index=self._thread_count,
                    cache_offset=hex(CACHE),size=size,before='0x0',value=hex(self._reg(cpu,8)),source_register='x8'))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def _start_thread_call(self,cpu,pc):
        assert self._thread_count==574 and self._thread_call is None
        assert bytes(cpu.mem_read(pc,4)).hex()=='00013fd6' and self._reg(cpu,8)==self.image+WRAPPER
        self._thread_descriptor=self._reg(cpu,0);raw=bytes(cpu.mem_read(self._thread_descriptor,32))
        assert raw_hash(raw)==TP_DESCRIPTOR_SHA256 and int.from_bytes(raw[:8],'little')==self.image+TARGET
        assert self._u(cpu,self._reg(cpu,19))==self.image+0x109B60
        self._thread_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._thread_saved=[self._reg(cpu,n) for n in range(19,30)]
        self._thread_call=dict(callsite_offset=hex(VM_CALL),call_instruction_bytes='00013fd6',call_index=574,
            wrapper_offset=hex(WRAPPER),target_offset=hex(TARGET),VM_cursor_offset='0x109b60',
            descriptor_address=hex(self._thread_descriptor),descriptor_before_hex=raw.hex(),
            descriptor_before_sha256=raw_hash(raw),wrapper_path=[],wrapper_code_verified=False,
            target_entered=False,returned_x0=None)

    def _observe_thread_target(self,cpu,pc):
        off=pc-self.image
        if off==TARGET:
            assert self._reg(cpu,0)==self._reg(cpu,19)==self._thread_descriptor
            assert self._reg(cpu,30)==self.image+0x28877C
            self._thread_tp=cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)
            assert self._thread_tp==0x7000A000
            self._thread_cache_before=bytes(cpu.mem_read(self.image+CACHE,16))
            assert self._thread_cache_before[:8]==bytes(8)
            self._thread_call.update(target_entered=True,target_arguments={'x0':hex(self._thread_descriptor)},
                target_return_offset='0x28877c',thread_pointer=hex(self._thread_tp),
                cache_before_hex=self._thread_cache_before.hex())
        if off==HELPER:
            spec=((12,0x204F7C,0x204F88),(20,0x205008,0x20501C))[len(self._thread_helpers)]
            amount,before,after=spec
            assert self._reg(cpu,0)==amount and self._reg(cpu,30)==self.image+before
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._thread_sp-0x30
            self._thread_helpers.append(dict(helper_offset=hex(HELPER),argument=amount,
                LR_before_offset=hex(before),LR_after_offset=hex(after),stack_offset=-48,returned=False))
        if off in (0x204F88,0x20501C):
            helper=self._thread_helpers[-1]
            assert helper['LR_after_offset']==hex(off) and self._reg(cpu,30)==pc
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._thread_sp-0x30
            helper['returned']=True
        if off==0x204FD8:
            assert cpu.reg_read(arm.UC_ARM64_REG_TPIDR_EL0)==self._thread_tp
        if off==0x204FDC:
            assert self._reg(cpu,8)==self._thread_tp
            self._thread_mrs=True

    def _return_thread_call(self,cpu):
        call=self._thread_call
        assert self._thread_count==640 and call['target_entered'] and self._thread_mrs
        assert self._reg(cpu,0)==self._thread_tp
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._thread_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._thread_saved
        assert call['wrapper_path']==[hex(a) for a in range(WRAPPER,WRAPPER+28,4)]
        before=bytes.fromhex(call['descriptor_before_hex']);after=bytes(cpu.mem_read(self._thread_descriptor,32))
        expected=bytearray(before);expected[8:16]=self._thread_tp.to_bytes(8,'little');assert after==expected
        cache=bytes(cpu.mem_read(self.image+CACHE,16))
        assert cache==self._thread_tp.to_bytes(8,'little')+self._thread_cache_before[8:]
        assert len(self._thread_stores)==1 and len(self._thread_helpers)==2
        assert all(h['returned'] for h in self._thread_helpers)
        assert not any(hex(a) in self._thread_code for a in (0x204F7C,0x204F80,0x204F84,
            0x205008,0x20500C,0x205010,0x205014,0x205018))
        assert self._u(cpu,self._receiver+0x88,4)==0
        call.update(return_index=640,returned_x0=hex(self._thread_tp),return_offset=hex(VM_RESUME),
            descriptor_after_hex=after.hex(),descriptor_after_sha256=raw_hash(after),
            output_width=8,descriptor_output_and_padding_verified=True,cache_after_hex=cache.hex(),
            cache_neighbor_bytes_preserved=True,stack_pointer_restored=True,
            callee_saved_registers_restored=True,reader_count=0,callback_returned=True)
        self._thread_returned=True

    def _next_JNI_call(self,cpu,pc,state):
        assert self._thread_returned and self._thread_count==2269
        assert self._reg(cpu,8)==self.image+JNI_WRAPPER and bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        descriptor=self._reg(cpu,0);raw=bytes(cpu.mem_read(descriptor,32))
        assert raw_hash(raw)==JNI_DESCRIPTOR_SHA256
        words=[int.from_bytes(raw[i:i+8],'little') for i in range(0,32,8)]
        assert words[0]==self.image+JNI_TARGET and self._u(cpu,self._reg(cpu,19))==self.image+0x109BBC
        assert any(a<=words[1] and words[1]+16<=b for a,b,_ in cpu.mem_regions())
        assert bytes(cpu.mem_read(self.image+JNI_WRAPPER,12)).hex()==CODE_HEX_JNI_WRAPPER
        self._thread_next=dict(callsite_offset=hex(VM_CALL),call_instruction_bytes='00013fd6',index=2269,
            wrapper_offset=hex(JNI_WRAPPER),wrapper_code_hex=CODE_HEX_JNI_WRAPPER,target_offset=hex(JNI_TARGET),
            VM_cursor_offset='0x109bbc',descriptor_address=hex(descriptor),descriptor_hex=raw.hex(),
            descriptor_sha256=raw_hash(raw),output_pair_address=hex(words[1]),output_pair_mapped=True,
            output_pair_before_hex=bytes(cpu.mem_read(words[1],16)).hex(),
            static_expected_target_arguments={'x0':hex(words[1])},
            VM_call_executed=False,wrapper_executed=False,target_executed=False,JNI_provider_entered=False)
        self._thread_done=True

    def observe(self,cpu,pc,state):
        self._thread_state=state
        if not self._thread_active:return super().observe(cpu,pc,state)
        self._track_thread(cpu,pc);off=pc-self.image
        if off==VM_CALL:
            if self._thread_returned:self._next_JNI_call(cpu,pc,state)
            else:self._start_thread_call(cpu,pc)
        call=self._thread_call
        if call is not None and not self._thread_returned:
            if off==WRAPPER:
                assert raw_hash(bytes(cpu.mem_read(pc,28)))==CODE_SHA256[hex(WRAPPER)]
                call['wrapper_code_verified']=True
            if WRAPPER<=off<WRAPPER+28:call['wrapper_path'].append(hex(off))
            self._observe_thread_target(cpu,pc)
            if off==VM_RESUME:self._return_thread_call(cpu)
        self._base_observe(cpu,pc,state)
        if self._thread_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.bootstrap.module_prefix().digest.context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self._thread_done and self._thread_returned
        old=self._thread_old
        assert result['allocator_events']==self._thread_events_before
        assert result['actual_allocator_counts']==old['allocator_counts_after']
        assert result['explicit_service_counts']==old['inherited_service_counts']
        assert proof['JNI_calls']==old['inherited_JNI_calls'] and proof['libc_SVC_boundaries']==old['inherited_libc_SVC']
        assert proof['main_image_SVC_boundaries']==old['inherited_main_SVC']
        assert self._pid_syscalls==old['inherited_syscall_172'] and self._pp_syscalls==old['syscall_173']
        assert self.late_jni_calls==old['late_jni'] and self.java_dispatch_calls==old['java_dispatch']
        return dict(control=old['control'],retained_getppid=self._thread_parent,
            instruction_observations=self._thread_count,instruction_trace_sha256=self._thread_trace.hexdigest(),
            observed_code_sha256=digest(self._thread_code),first_pc_offsets=self._thread_first,tail_pc_offsets=self._thread_tail,
            thread_callback=self._thread_call,cache_stores=self._thread_stores,helper_returns=self._thread_helpers,
            MRS_TPIDR_EL0_executed=self._thread_mrs,next_JNI_call=self._thread_next,
            allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],
            inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,
            inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls,
            new_allocator_events=[],stop_boundary=dict(stop_before=hex(VM_CALL),kind='before_JNI_acquisition_VM_call',
                VM_call_executed=False,JNI_environment_acquisition_executed=False))


def run(path,libc):
    parent=prior_evidence();p=previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=static_code(path)
    def create(control):
        s=ThreadPointerScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_code=code,case_result=rows[0],case_result_sha256=digest(rows[0]))


def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert set(data['static_code'])==set(CODE_SHA256)
    for pc,size in CODE_RANGES:
        row=data['static_code'][hex(pc)];raw=bytes.fromhex(row['hex'])
        assert len(raw)==row['size']==size and raw_hash(raw)==CODE_SHA256[hex(pc)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row)
    assert row['control']==old['control']
    assert row['retained_getppid']==dict(getppid_case_sha256=digest(old),verified_fields=[
        'instruction_observations','instruction_trace_sha256','observed_code_sha256','first_pc_offsets',
        'tail_pc_offsets','callbacks','retained_getpid','binding','import_reads','descriptor_stores',
        'inherited_syscall_172','syscall_173'],instruction_observations=old['instruction_observations'],
        instruction_trace_sha256=old['instruction_trace_sha256'],observed_code_sha256=old['observed_code_sha256'],
        getppid_callback_return_verified=True)
    assert row['instruction_observations']==2269<MAX_OBSERVATIONS
    assert row['first_pc_offsets'][0]==hex(VM_RESUME) and row['tail_pc_offsets'][-1]==hex(VM_CALL)
    for key in ('instruction_trace_sha256','observed_code_sha256'):
        assert len(row[key])==64 and len(bytes.fromhex(row[key]))==32
    call=row['thread_callback']
    assert call['callsite_offset']==hex(VM_CALL) and call['call_instruction_bytes']=='00013fd6'
    assert call['call_index']==574 and call['return_index']==640 and call['VM_cursor_offset']=='0x109b60'
    assert call['wrapper_offset']==hex(WRAPPER) and call['target_offset']==hex(TARGET)
    assert call['descriptor_address']=='0x7004cb20'
    before=bytes.fromhex(call['descriptor_before_hex']);after=bytes.fromhex(call['descriptor_after_hex'])
    assert len(before)==len(after)==32 and raw_hash(before)==call['descriptor_before_sha256']==TP_DESCRIPTOR_SHA256
    assert int.from_bytes(before[:8],'little')==row['control']['base']+TARGET
    expected=bytearray(before);expected[8:16]=(0x7000A000).to_bytes(8,'little')
    assert after==expected and raw_hash(after)==call['descriptor_after_sha256']
    assert call['wrapper_path']==[hex(a) for a in range(WRAPPER,WRAPPER+28,4)]
    assert call['target_arguments']=={'x0':call['descriptor_address']} and call['target_return_offset']=='0x28877c'
    assert call['thread_pointer']==call['returned_x0']=='0x7000a000' and call['return_offset']==hex(VM_RESUME)
    assert call['reader_count']==0 and call['output_width']==8
    cache_before=bytes.fromhex(call['cache_before_hex']);cache_after=bytes.fromhex(call['cache_after_hex'])
    assert len(cache_before)==len(cache_after)==16 and cache_before[:8]==bytes(8)
    assert cache_after==(0x7000A000).to_bytes(8,'little')+cache_before[8:]
    for key in ('wrapper_code_verified','target_entered','descriptor_output_and_padding_verified',
        'cache_neighbor_bytes_preserved','stack_pointer_restored','callee_saved_registers_restored','callback_returned'):
        assert call[key] is True
    assert row['MRS_TPIDR_EL0_executed'] is True
    assert row['cache_stores']==[dict(pc_offset='0x205020',index=628,cache_offset=hex(CACHE),
        size=8,before='0x0',value='0x7000a000',source_register='x8')]
    assert row['helper_returns']==[dict(helper_offset=hex(HELPER),argument=amount,
        LR_before_offset=hex(before),LR_after_offset=hex(after),stack_offset=-48,returned=True)
        for amount,before,after in ((12,0x204F7C,0x204F88),(20,0x205008,0x20501C))]
    next_call=row['next_JNI_call'];raw=bytes.fromhex(next_call['descriptor_hex'])
    assert len(raw)==32 and raw_hash(raw)==next_call['descriptor_sha256']==JNI_DESCRIPTOR_SHA256
    words=[int.from_bytes(raw[i:i+8],'little') for i in range(0,32,8)]
    assert words[0]==row['control']['base']+JNI_TARGET
    assert next_call['callsite_offset']==hex(VM_CALL) and next_call['call_instruction_bytes']=='00013fd6'
    assert next_call['index']==2269 and next_call['wrapper_offset']==hex(JNI_WRAPPER)
    assert next_call['wrapper_code_hex']==CODE_HEX_JNI_WRAPPER and next_call['target_offset']==hex(JNI_TARGET)
    assert next_call['VM_cursor_offset']=='0x109bbc' and next_call['descriptor_address']=='0x7004cb10'
    assert next_call['output_pair_address']==hex(words[1]) and next_call['output_pair_mapped'] is True
    assert len(bytes.fromhex(next_call['output_pair_before_hex']))==16
    assert next_call['static_expected_target_arguments']=={'x0':hex(words[1])}
    for key in ('VM_call_executed','wrapper_executed','target_executed','JNI_provider_entered'):
        assert next_call[key] is False
    for key,old_key in (('allocator_counts','allocator_counts_after'),('inherited_service_counts','inherited_service_counts'),
        ('inherited_JNI_calls','inherited_JNI_calls'),('inherited_libc_SVC','inherited_libc_SVC'),
        ('inherited_main_SVC','inherited_main_SVC'),('inherited_syscall_172','inherited_syscall_172'),
        ('inherited_syscall_173','syscall_173'),('late_jni','late_jni'),('java_dispatch','java_dispatch')):
        assert row[key]==old[old_key]
    assert row['new_allocator_events']==[]
    assert row['stop_boundary']==dict(stop_before=hex(VM_CALL),kind='before_JNI_acquisition_VM_call',
        VM_call_executed=False,JNI_environment_acquisition_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),
        (('claims','next_JNI_VM_call_executed'),True),(('claims','JNI_wrapper_executed'),True),
        (('claims','Android_execution'),True),
        (('case_result','instruction_observations'),0),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','retained_getppid','getppid_case_sha256'),'0'*64),
        (('case_result','thread_callback','target_offset'),'0x0'),
        (('case_result','thread_callback','wrapper_path'),[]),
        (('case_result','thread_callback','returned_x0'),'0x0'),
        (('case_result','thread_callback','descriptor_after_hex'),'00'*32),
        (('case_result','thread_callback','output_width'),4),
        (('case_result','thread_callback','stack_pointer_restored'),False),
        (('case_result','thread_callback','callee_saved_registers_restored'),False),
        (('case_result','thread_callback','cache_after_hex'),'00'*16),
        (('case_result','thread_callback','cache_neighbor_bytes_preserved'),False),
        (('case_result','cache_stores',0,'value'),'0x0'),(('case_result','cache_stores',0,'size'),4),
        (('case_result','cache_stores',0,'index'),0),
        (('case_result','helper_returns',0,'argument'),16),
        (('case_result','helper_returns',0,'LR_after_offset'),'0x204f7c'),
        (('case_result','helper_returns',0,'returned'),False),
        (('case_result','helper_returns',1,'LR_before_offset'),'0x0'),
        (('case_result','MRS_TPIDR_EL0_executed'),False),
        (('case_result','next_JNI_call','target_offset'),'0x0'),
        (('case_result','next_JNI_call','descriptor_sha256'),'0'*64),
        (('case_result','next_JNI_call','static_expected_target_arguments'),{}),
        (('case_result','next_JNI_call','output_pair_mapped'),False),
        (('case_result','new_allocator_events'),[['alloc',8,1,'0x0']]),
        (('case_result','stop_boundary','JNI_environment_acquisition_executed'),True)]
    for pc,_ in CODE_RANGES:changes.append((('static_code',hex(pc),'hex'),'00'))
    for key in ('VM_call_executed','wrapper_executed','target_executed','JNI_provider_entered'):
        changes.append((('case_result','next_JNI_call',key),True))
    for key in ('inherited_JNI_calls','inherited_libc_SVC','inherited_main_SVC','inherited_syscall_172',
                'inherited_syscall_173','late_jni','java_dispatch'):
        changes.append((('case_result',key),[]))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result' and path[1] not in ('instruction_trace_sha256','observed_code_sha256'):
            bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged thread-pointer evidence accepted: {path}')
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as output:output.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh thread-pointer replay differs'
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],native_thread_callback_returned=True,
        next_JNI_VM_call_executed=False,stop_before=hex(VM_CALL),complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
