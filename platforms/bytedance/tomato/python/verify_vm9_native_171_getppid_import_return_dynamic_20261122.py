"""Continue the returned getpid control through the evidenced getppid import."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm

import verify_vm9_native_171_getpid_import_return_dynamic_20261122 as previous
import verify_vm9_native_171_post_configuration_callback_boundary_dynamic_20261122 as callbacks
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap

EVIDENCE = previous.EVIDENCE.with_name('vm9_native_171_getppid_import_return_dynamic_20261122.json')
SCHEMA = 'vm9-native-171-getppid-import-return-dynamic-20261122-v1'
LIBC_BASE, IMPORT_SLOT, GETPPID, PPID_SVC = 0x51000000, 0x3833B8, 0x6A36C, 0x6A370
PPID_RESULT, MAX_OBSERVATIONS = 17, 200000
VM_CALL, VM_RESUME = previous.VM_CALL, previous.VM_RESUME
PPID_CODE = 'a81580d2010000d41f0440b1009480daa8e1dc54c0035fd6'
SPECS = (
    (0x2885e0, 0x32a444, '56837487c9ed72817afb08119f29b73261c9185963c59b9737f78077d99035c5', 857, 952, 0x10966c, 0x0, 1),
    (0x288530, 0x26c858, '9582fcd28b81130baea4b1bd1d22cc0c60f6020b835d0eef8835ec0d8a975425', 1814, 2204, 0x109698, 0x0, 1),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 3168, 3222, 0x1096cc, 0x0, 1),
    (0x2885e0, 0x32a4fc, '606cf77bdd214ccf1d732327b901ee4de07d837e7f1b8833893694f71b823311', 4039, 4123, 0x1096f8, 0x0, 0),
    (0x2885e0, 0x32a444, '56837487c9ed72817afb08119f29b73261c9185963c59b9737f78077d99035c5', 5079, 5174, 0x10972c, 0x0, 1),
    (0x288530, 0x26c858, '9582fcd28b81130baea4b1bd1d22cc0c60f6020b835d0eef8835ec0d8a975425', 6111, 6222, 0x10975c, 0x0, 1),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 7240, 7294, 0x109794, 0x0, 1),
    (0x2885e0, 0x32a4fc, '606cf77bdd214ccf1d732327b901ee4de07d837e7f1b8833893694f71b823311', 8111, 8195, 0x1097c0, 0x0, 0),
    (0x288530, 0x26c858, '9582fcd28b81130baea4b1bd1d22cc0c60f6020b835d0eef8835ec0d8a975425', 9456, 9567, 0x109864, 0x0, 0),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 10584, 10638, 0x1098e0, 0x0, 0),
    (0x288530, 0x26c858, '9582fcd28b81130baea4b1bd1d22cc0c60f6020b835d0eef8835ec0d8a975425', 11318, 11429, 0x109904, 0x0, 0),
    (0x288540, 0x26c9d0, 'e782c5c31933262cebdc5795c8d33713ffe81a8b83a2a14dec75dae2128b77bc', 12500, 12554, 0x109984, 0x0, 0),
    (0x28863c, GETPPID, 'be22cb527fac9a714fb2b02c41e25e346dcedff4325821054f769dcd2b545973', 13277, 13291, 0x109b40, PPID_RESULT, 0),
)
ORIGIN = {'load_cursor': 1088300, 'descriptor_cursor': 1088308, 'descriptor_bytecode': 1088304, 'read_index': 12934, 'vreg_write_index': 12936, 'vreg_read_index': 13019, 'descriptor_write_index': 13029, 'virtual_register': 1, 'virtual_register_address': 1879364464, 'descriptor_address': 1879362640}
sha256, digest, raw_hash = previous.sha256, previous.digest, previous.raw_hash
WRAPPERS = dict(callbacks.WRAPPERS)
WRAPPERS[previous.WRAPPER] = callbacks.NULL_CODE


def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
    previous.validate(data)
    return data


def source_fingerprints():
    return dict(getppid_import_verifier_sha256=sha256(Path(__file__)),
                inherited_source_fingerprints=previous.source_fingerprints())


def provenance(parent):
    return dict(inherited_getpid_evidence_sha256=sha256(previous.EVIDENCE),
                Metasec_sha256=parent['input_provenance']['Metasec_sha256'],
                Bionic_sha256=parent['input_provenance']['Bionic_sha256'])


def static_binding(path,libc):
    with path.open('rb') as stream:
        elf=ELFFile(stream);rows=[]
        for section in elf.iter_sections():
            if section['sh_type']!='SHT_RELA':continue
            symbols=elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                if rel['r_offset']!=IMPORT_SLOT:continue
                symbol=symbols.get_symbol(rel['r_info_sym'])
                assert symbol.name=='getppid' and symbol['st_shndx']=='SHN_UNDEF'
                assert rel['r_info_type']==257 and rel['r_addend']==0 and rel['r_info_sym']==59
                rows.append(dict(section=section.name,symbol='getppid',symbol_index=59,type=257,
                    addend=0,import_slot_offset=hex(IMPORT_SLOT),undefined=True))
        assert len(rows)==1 and previous.file_read(elf,IMPORT_SLOT,8)==bytes(8)
        for pc,code in previous.ORIGIN_CODE.items():
            assert previous.file_read(elf,pc,4).hex()==code
    with libc.open('rb') as stream:
        elf=ELFFile(stream)
        exports=[s for s in elf.get_section_by_name('.dynsym').iter_symbols()
                 if s.name=='getppid' and s['st_shndx']!='SHN_UNDEF']
        assert len(exports)==1 and exports[0]['st_value']==GETPPID
        assert previous.file_read(elf,GETPPID,24).hex()==PPID_CODE
    return dict(relocation=rows[0],unresolved_file_word='0x0',libc_export_offset=hex(GETPPID),
        resolved_target=hex(LIBC_BASE+GETPPID),libc_getppid_code_hex=PPID_CODE,
        origin_instruction_bytes={hex(pc):code for pc,code in previous.ORIGIN_CODE.items()})


def providers():
    return dict(inherited=previous.providers(),new_import='getppid ABS64 slot only, after the verified getpid return',
        syscall_173=dict(result=PPID_RESULT,kind='explicit synthetic parent PID; no host process lookup'),
        added_SVC_ledger='one syscall 173, separate from inherited syscall 172 and inherited SVC lists',
        maximum_instruction_observations=MAX_OBSERVATIONS)


def claims_for():
    return dict(evidence_label='Sample verified',returned_callbacks=len(SPECS),
        getpid_prefix_fields_and_instruction_receipt_verified=True,
        getppid_ELF_import_and_actual_VM_descriptor_provenance_verified=True,
        original_VM_builds_descriptor=True,wrapper_arguments_outputs_and_padding_verified=True,
        returned_callback_SP_and_X19_X29_restored=True,native_getppid_syscall_173_executed=True,
        explicit_syscall_173_result=PPID_RESULT,host_process_lookup=False,public_ELF_loader_changed=False,
        native_memory_used_as_python_model_input=False,next_VM_instruction_executed=False,
        current_native_suffix_return_verified=False,complete_standalone_signer_verified=False,
        ordinary_Cronet_six_headers_verified=False,Android_execution=False,
        online_acceptance_verified=False,physical_PAC_authentication_verified=False)


def arguments_for(wrapper,words,descriptor):
    if wrapper==previous.WRAPPER:return {'x0':hex(descriptor)}
    return callbacks.arguments_for(wrapper,words,descriptor)


def output_for(wrapper,raw,returned):
    if wrapper==previous.WRAPPER:
        out=bytearray(raw);out[8:12]=returned.to_bytes(4,'little');return bytes(out)
    return callbacks.output_for(wrapper,raw,returned)


def target_return(wrapper):
    if wrapper==previous.WRAPPER:return 0x28864C
    return callbacks.target_return(wrapper)


class GetppidScenario(previous.GetpidScenario):
    def __init__(self,control):
        super().__init__(control)
        self._pp_active=False;self._pp_done=False;self._pp_svc_seen=False
        self._pp_count=0;self._pp_trace=hashlib.sha256();self._pp_code={}
        self._pp_first=[];self._pp_tail=[];self._pp_calls=[];self._pp_call=None
        self._pp_reads=[];self._pp_writes=[];self._pp_syscalls=[]
        self._pp_old=prior_evidence()['case_result']

    def _track_pp(self,cpu,pc):
        self._pp_count+=1;assert self._pp_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x100000 else ('main',pc-self.image)
        raw=bytes(cpu.mem_read(pc,4));site=[domain,hex(off)]
        self._pp_trace.update(domain.encode()+off.to_bytes(8,'little')+raw)
        self._pp_code[domain+':'+hex(off)]=raw.hex()
        if len(self._pp_first)<16:self._pp_first.append(site)
        self._pp_tail=(self._pp_tail+[site])[-16:]

    def _checkpoint_getpid(self,cpu,state):
        old=self._pp_old
        fields=((self._pid_count,'instruction_observations'),(self._pid_pcs,'pc_path'),
            (self._pid_trace.hexdigest(),'instruction_trace_sha256'),(digest(self._pid_code),'observed_code_sha256'),
            (self._pid_prefix,'retained_prefix'),(self._pid_binding,'binding'),(self._pid_reads,'import_reads'),
            (self._pid_writes,'descriptor_stores'),(self._pid_syscalls,'syscall_172'),(self._pid_return,'callback_return'))
        for value,key in fields:assert value==old[key],key
        assert self.late_jni_calls==old['late_jni'] and self.java_dispatch_calls==old['java_dispatch']
        self._pp_parent=dict(getpid_case_sha256=digest(old),verified_getpid_fields=[key for _,key in fields],
            instruction_observations=self._pid_count,instruction_trace_sha256=self._pid_trace.hexdigest(),
            observed_code_sha256=digest(self._pid_code),getpid_callback_return_verified=True)
        self._pp_events_before=deepcopy(state['allocator_events_ref'])
        assert self._u(cpu,self.image+IMPORT_SLOT)==0
        assert self._u(cpu,self.image+previous.IMPORT_SLOT)==LIBC_BASE+previous.GETPID
        cpu.mem_write(self.image+IMPORT_SLOT,(LIBC_BASE+GETPPID).to_bytes(8,'little'))
        assert self._u(cpu,self.image+previous.IMPORT_SLOT)==LIBC_BASE+previous.GETPID
        self._pp_binding=dict(symbol='getppid',slot_offset=hex(IMPORT_SLOT),before='0x0',
            after=hex(LIBC_BASE+GETPPID),relocation_type=257,addend=0,
            original_getpid_binding_preserved=True,descriptor_not_written_by_binding=True)
        self._pid_done=False;self._pid_active=False;self._pid_bound=False
        self._pp_active=True;self._track_pp(cpu,self.image+VM_RESUME)

    def _base_observe(self,cpu,pc,state):
        if self._pid_done and pc==self.image+VM_RESUME and not self._pp_active:
            self._checkpoint_getpid(cpu,state)
        if self._pp_active and pc==self.image+previous.INDIRECT:
            assert self._pp_call is not None and self._pp_call['target_space']=='libc'
            assert self._reg(cpu,8)==LIBC_BASE+GETPPID
            assert self._reg(cpu,0)==self._reg(cpu,19)==self._pp_descriptor
            bootstrap.module_prefix().digest.Scenario.observe(self,cpu,pc,state)
            return
        return super()._base_observe(cpu,pc,state)

    def native_runner(self,*args,**kwargs):
        old_read,old_write,old_syscall=kwargs['memory_read_observer'],kwargs['memory_write_observer'],kwargs['syscall_handler']
        def read(cpu,address,size):
            if self._pp_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if address==self.image+IMPORT_SLOT:
                    assert pc==0x16F96C and size==8
                    assert self._reg(cpu,12)+self._reg(cpu,13)==address
                    self._pp_vreg=self._reg(cpu,28)+self._reg(cpu,14)*8
                    assert self._u(cpu,address)==LIBC_BASE+GETPPID
                    self._pp_reads.append(dict(kind='ABS64_import_read',native_pc=hex(pc),
                        index=self._pp_count,cursor=hex(self._u(cpu,self._reg(cpu,19))-self.image),
                        address=hex(address),size=size,value=hex(self._u(cpu,address)),
                        virtual_register=self._reg(cpu,14)))
                elif self._pp_reads and pc==0x171240 and self._u(cpu,self._reg(cpu,19))-self.image==ORIGIN['descriptor_cursor']:
                    assert address==self._pp_vreg and size==8 and self._u(cpu,address)==LIBC_BASE+GETPPID
                    self._pp_reads.append(dict(kind='virtual_register_read',native_pc=hex(pc),
                        index=self._pp_count,cursor=hex(self._u(cpu,self._reg(cpu,19))-self.image),
                        address=hex(address),size=size,value=hex(self._u(cpu,address)),
                        virtual_register=self._reg(cpu,14)))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._pp_active and self._pp_reads:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                cursor=self._u(cpu,self._reg(cpu,19))-self.image
                if (pc,cursor) in ((0x16F974,ORIGIN['load_cursor']),(0x171268,ORIGIN['descriptor_cursor'])):
                    reg=9 if pc==0x16F974 else 15
                    assert size==8 and self._reg(cpu,reg)==LIBC_BASE+GETPPID
                    if pc==0x16F974:assert address==self._pp_vreg
                    self._pp_writes.append(dict(native_pc=hex(pc),index=self._pp_count,cursor=hex(cursor),
                        address=hex(address),size=size,value=hex(self._reg(cpu,reg)),source_register='x'+str(reg)))
            if old_write:old_write(cpu,address,size)
        def syscall(cpu,number):
            if number!=173:return old_syscall(cpu,number)
            assert self._pp_active and self._pp_svc_seen and not self._pp_syscalls
            assert self._pp_call is not None and self._pp_call['target_space']=='libc'
            assert cpu.reg_read(arm.UC_ARM64_REG_PC)==LIBC_BASE+PPID_SVC+4
            self._pp_syscalls.append(dict(libc_svc_offset=hex(PPID_SVC),number=173,
                provider='explicit synthetic parent PID',result=PPID_RESULT))
            return PPID_RESULT
        kwargs.update(memory_read_observer=read,memory_write_observer=write,syscall_handler=syscall)
        return super().native_runner(*args,**kwargs)

    def pre_observe(self,cpu,pc,state):
        if self._pp_active and pc==LIBC_BASE+PPID_SVC:
            assert not self._pp_svc_seen and self._reg(cpu,8)==173
            assert bytes(cpu.mem_read(pc,4)).hex()=='010000d4'
            self._pp_svc_seen=True;self._track_pp(cpu,pc);return True
        return super().pre_observe(cpu,pc,state)

    def _start_pp_call(self,cpu,pc):
        assert self._pp_call is None and len(self._pp_calls)<len(SPECS)
        wrapper,target,expected_hash,start,_,cursor,_,_=SPECS[len(self._pp_calls)]
        libc=target==GETPPID;target_address=(LIBC_BASE if libc else self.image)+target
        assert self._pp_count==start and self._reg(cpu,8)==self.image+wrapper
        assert bytes(cpu.mem_read(pc,4)).hex()=='00013fd6'
        self._pp_descriptor=self._reg(cpu,0);raw=bytes(cpu.mem_read(self._pp_descriptor,32))
        self._pp_words=[int.from_bytes(raw[i:i+8],'little') for i in range(0,32,8)]
        assert self._pp_words[0]==target_address
        canonical=bytes(8)+raw[8:] if libc else raw
        assert raw_hash(canonical)==expected_hash
        assert self._u(cpu,self._reg(cpu,19))==self.image+cursor
        self._pp_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._pp_regs=[self._reg(cpu,n) for n in range(19,30)]
        self._pp_call=dict(ordinal=len(self._pp_calls),wrapper_offset=hex(wrapper),target_offset=hex(target),
            target_space='libc' if libc else 'main',call_index=start,VM_cursor_offset=hex(cursor),
            descriptor_address=hex(self._pp_descriptor),descriptor_before_hex=raw.hex(),
            descriptor_before_sha256=raw_hash(raw),canonical_unbound_descriptor_sha256=raw_hash(canonical),
            descriptor_words=[hex(w) for w in self._pp_words],wrapper_path=[],wrapper_code_verified=False,
            target_entered=False,target_observations=0)
        if target in (0x32A444,0x32A4FC):
            assert self._pp_words[1]==self._receiver
            self._pp_reader_before=bytes(cpu.mem_read(self._receiver,0x90))
            self._pp_call['reader_before_hex']=self._pp_reader_before.hex()
        if libc:
            assert len(self._pp_reads)==len(self._pp_writes)==2
            assert self._pp_writes[-1]['address']==hex(self._pp_descriptor)

    def _return_pp_call(self,cpu):
        call=self._pp_call
        wrapper,target,_,_,end,_,returned,readers=SPECS[len(self._pp_calls)]
        assert call['target_entered'] and self._pp_count==end and self._reg(cpu,0)==returned
        assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._pp_sp
        assert [self._reg(cpu,n) for n in range(19,30)]==self._pp_regs
        assert call['wrapper_path']==[hex(a) for a in range(wrapper,wrapper+len(bytes.fromhex(WRAPPERS[wrapper])),4)]
        after=bytes(cpu.mem_read(self._pp_descriptor,32))
        assert after==output_for(wrapper,bytes.fromhex(call['descriptor_before_hex']),returned)
        assert self._u(cpu,self._receiver+0x88,4)==readers
        if target in (0x32A444,0x32A4FC):
            expected=bytearray(self._pp_reader_before)
            assert int.from_bytes(expected[0x88:0x8C],'little')==1-readers
            expected[0x88:0x8C]=readers.to_bytes(4,'little')
            actual=bytes(cpu.mem_read(self._receiver,0x90));assert actual==expected
            call.update(reader_after_hex=actual.hex(),reader_other_bytes_preserved=True)
        call.update(return_index=end,returned_x0=hex(returned),reader_count=readers,
            descriptor_after_hex=after.hex(),descriptor_after_sha256=raw_hash(after),
            descriptor_output_and_padding_verified=True,stack_pointer_restored=True,
            callee_saved_registers_restored=True,callback_returned=True)
        self._pp_calls.append(call);self._pp_call=None
        self._pp_done=len(self._pp_calls)==len(SPECS)

    def observe(self,cpu,pc,state):
        if not self._pp_active:return super().observe(cpu,pc,state)
        self._track_pp(cpu,pc);off=pc-self.image
        if off==VM_CALL:self._start_pp_call(cpu,pc)
        call=self._pp_call
        if call is not None:
            wrapper=int(call['wrapper_offset'],16)
            if off==wrapper:
                assert bytes(cpu.mem_read(pc,len(bytes.fromhex(WRAPPERS[wrapper])))).hex()==WRAPPERS[wrapper]
                call['wrapper_code_verified']=True
            if wrapper<=off<wrapper+len(bytes.fromhex(WRAPPERS[wrapper])):call['wrapper_path'].append(hex(off))
            target=(LIBC_BASE if call['target_space']=='libc' else self.image)+int(call['target_offset'],16)
            if pc==target and not call['target_entered']:
                args=arguments_for(wrapper,self._pp_words,self._pp_descriptor)
                assert all(self._reg(cpu,int(reg[1:]))==int(value,16) for reg,value in args.items())
                assert self._reg(cpu,30)==self.image+target_return(wrapper)
                call.update(target_entered=True,target_arguments=args,target_return_offset=hex(target_return(wrapper)))
                if call['target_space']=='libc':assert bytes(cpu.mem_read(pc,24)).hex()==PPID_CODE
            if call['target_entered']:
                call['target_observations']+=1
                if off==VM_RESUME:self._return_pp_call(cpu)
        self._base_observe(cpu,pc,state)
        if self._pp_done:
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap.module_prefix().digest.context.outer.oracle.STOP)

    def finish(self,result,state,proof):
        assert self._pp_done and self._pp_call is None
        old=self._pp_old
        assert result['allocator_events'][:len(self._pp_events_before)]==self._pp_events_before
        added=result['allocator_events'][len(self._pp_events_before):]
        assert result['explicit_service_counts']==old['service_counts']
        assert proof['JNI_calls']==old['inherited_JNI_calls']
        assert proof['libc_SVC_boundaries']==old['inherited_libc_SVC']
        assert proof['main_image_SVC_boundaries']==old['inherited_main_SVC']
        assert self._pid_syscalls==old['syscall_172']
        assert self.late_jni_calls==old['late_jni'] and self.java_dispatch_calls==old['java_dispatch']
        return dict(control=old['control'],retained_getpid=self._pp_parent,binding=self._pp_binding,
            instruction_observations=self._pp_count,instruction_trace_sha256=self._pp_trace.hexdigest(),
            observed_code_sha256=digest(self._pp_code),first_pc_offsets=self._pp_first,tail_pc_offsets=self._pp_tail,
            callbacks=self._pp_calls,import_reads=self._pp_reads,descriptor_stores=self._pp_writes,
            inherited_syscall_172=self._pid_syscalls,syscall_173=self._pp_syscalls,
            allocator_counts_before=old['allocator_counts'],allocator_counts_after=result['actual_allocator_counts'],
            new_allocator_events=added,new_allocator_events_sha256=digest(added),
            inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],
            inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls,
            stop_boundary=dict(stop_before=hex(VM_RESUME),getppid_callback_returned=True,next_VM_instruction_executed=False))


def run(path,libc):
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    static=static_binding(path,libc)
    def create(control):
        scenario=GetppidScenario(control);scenario.path=path;scenario.continue_to_svc=True;return scenario
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],
        _handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),
        input_provenance=provenance(parent),static_binding=static,case_result=rows[0],case_result_sha256=digest(rows[0]))


def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    static=data['static_binding']
    assert static['relocation']==dict(section='.rela.dyn',symbol='getppid',symbol_index=59,type=257,
        addend=0,import_slot_offset=hex(IMPORT_SLOT),undefined=True)
    assert static['unresolved_file_word']=='0x0' and static['libc_export_offset']==hex(GETPPID)
    assert static['resolved_target']==hex(LIBC_BASE+GETPPID) and static['libc_getppid_code_hex']==PPID_CODE
    assert static['origin_instruction_bytes']=={hex(pc):code for pc,code in previous.ORIGIN_CODE.items()}
    row=data['case_result'];assert data['case_result_sha256']==digest(row)
    assert row['control']==old['control']
    assert row['retained_getpid']==dict(getpid_case_sha256=digest(old),verified_getpid_fields=[
        'instruction_observations','pc_path','instruction_trace_sha256','observed_code_sha256','retained_prefix',
        'binding','import_reads','descriptor_stores','syscall_172','callback_return'],
        instruction_observations=old['instruction_observations'],instruction_trace_sha256=old['instruction_trace_sha256'],
        observed_code_sha256=old['observed_code_sha256'],getpid_callback_return_verified=True)
    assert row['binding']==dict(symbol='getppid',slot_offset=hex(IMPORT_SLOT),before='0x0',
        after=hex(LIBC_BASE+GETPPID),relocation_type=257,addend=0,
        original_getpid_binding_preserved=True,descriptor_not_written_by_binding=True)
    assert row['instruction_observations']==13291<MAX_OBSERVATIONS
    assert row['first_pc_offsets'][0]==row['tail_pc_offsets'][-1]==['main',hex(VM_RESUME)]
    for key in ('instruction_trace_sha256','observed_code_sha256'):
        assert len(row[key])==64 and len(bytes.fromhex(row[key]))==32
    assert len(row['callbacks'])==len(SPECS)==13
    for i,(call,spec) in enumerate(zip(row['callbacks'],SPECS)):
        wrapper,target,expected_hash,start,end,cursor,returned,readers=spec
        libc=target==GETPPID;target_base=LIBC_BASE if libc else row['control']['base']
        assert call['ordinal']==i and call['wrapper_offset']==hex(wrapper) and call['target_offset']==hex(target)
        assert call['target_space']==('libc' if libc else 'main')
        assert call['call_index']==start and call['return_index']==end and call['VM_cursor_offset']==hex(cursor)
        assert call['returned_x0']==hex(returned) and call['reader_count']==readers
        raw=bytes.fromhex(call['descriptor_before_hex']);after=bytes.fromhex(call['descriptor_after_hex'])
        assert len(raw)==len(after)==32 and raw_hash(raw)==call['descriptor_before_sha256']
        canonical=bytes(8)+raw[8:] if libc else raw
        assert raw_hash(canonical)==call['canonical_unbound_descriptor_sha256']==expected_hash
        words=[int.from_bytes(raw[j:j+8],'little') for j in range(0,32,8)]
        assert words[0]==target_base+target and call['descriptor_words']==[hex(w) for w in words]
        assert after==output_for(wrapper,raw,returned) and raw_hash(after)==call['descriptor_after_sha256']
        assert call['target_arguments']==arguments_for(wrapper,words,int(call['descriptor_address'],16))
        assert call['target_return_offset']==hex(target_return(wrapper))
        assert call['wrapper_path']==[hex(a) for a in range(wrapper,wrapper+len(bytes.fromhex(WRAPPERS[wrapper])),4)]
        assert type(call['target_observations']) is int and call['target_observations']>0
        for key in ('wrapper_code_verified','target_entered','descriptor_output_and_padding_verified',
                    'stack_pointer_restored','callee_saved_registers_restored','callback_returned'):
            assert call[key] is True
        if target in (0x32A444,0x32A4FC):
            before=bytearray.fromhex(call['reader_before_hex'])
            assert len(before)==0x90 and int.from_bytes(before[0x88:0x8C],'little')==1-readers
            before[0x88:0x8C]=readers.to_bytes(4,'little')
            assert before.hex()==call['reader_after_hex'] and call['reader_other_bytes_preserved'] is True
    value=hex(LIBC_BASE+GETPPID);vreg=hex(ORIGIN['virtual_register_address']);desc=hex(ORIGIN['descriptor_address'])
    assert row['callbacks'][-1]['descriptor_address']==desc
    assert row['import_reads']==[
        dict(kind='ABS64_import_read',native_pc='0x16f96c',index=12934,cursor='0x109b2c',
             address=hex(row['control']['base']+IMPORT_SLOT),size=8,value=value,virtual_register=1),
        dict(kind='virtual_register_read',native_pc='0x171240',index=13019,cursor='0x109b34',
             address=vreg,size=8,value=value,virtual_register=1)]
    assert row['descriptor_stores']==[
        dict(native_pc='0x16f974',index=12936,cursor='0x109b2c',address=vreg,size=8,value=value,source_register='x9'),
        dict(native_pc='0x171268',index=13029,cursor='0x109b34',address=desc,size=8,value=value,source_register='x15')]
    assert row['syscall_173']==[dict(libc_svc_offset=hex(PPID_SVC),number=173,
        provider='explicit synthetic parent PID',result=PPID_RESULT)]
    assert row['inherited_syscall_172']==old['syscall_172']
    for key,old_key in (('inherited_service_counts','service_counts'),('inherited_JNI_calls','inherited_JNI_calls'),
        ('inherited_libc_SVC','inherited_libc_SVC'),('inherited_main_SVC','inherited_main_SVC'),
        ('late_jni','late_jni'),('java_dispatch','java_dispatch')):
        assert row[key]==old[old_key]
    assert row['allocator_counts_before']==old['allocator_counts']
    expected=dict(old['allocator_counts']);expected['malloc']+=1
    assert row['allocator_counts_after']==expected
    assert row['new_allocator_events']==[['alloc',48,325926896,'0x32a210']]
    assert row['new_allocator_events_sha256']==digest(row['new_allocator_events'])
    assert row['stop_boundary']==dict(stop_before=hex(VM_RESUME),getppid_callback_returned=True,next_VM_instruction_executed=False)


def damaged_evidence_rejected(data):
    changes=[(('claims','complete_standalone_signer_verified'),True),
        (('claims','host_process_lookup'),True),(('claims','original_VM_builds_descriptor'),False),
        (('static_binding','relocation','symbol'),'getpid'),(('static_binding','relocation','symbol_index'),20),
        (('static_binding','relocation','addend'),8),(('static_binding','resolved_target'),'0x0'),
        (('case_result','binding','after'),'0x0'),(('case_result','binding','descriptor_not_written_by_binding'),False),
        (('case_result','syscall_173',0,'result'),0),(('case_result','new_allocator_events'),[]),
        (('case_result','stop_boundary','next_VM_instruction_executed'),True),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64)]
    for group in ('import_reads','descriptor_stores'):
        for i in range(2):
            for key,value in (('native_pc','0x0'),('index',0),('cursor','0x0'),('address','0x0'),('value','0x0')):
                changes.append((('case_result',group,i,key),value))
    for i in range(len(SPECS)):
        for key,value in (('target_offset','0x0'),('target_arguments',{}),('wrapper_path',[]),
            ('return_index',0),('descriptor_output_and_padding_verified',False),
            ('stack_pointer_restored',False),('callee_saved_registers_restored',False),('callback_returned',False)):
            changes.append((('case_result','callbacks',i,key),value))
    for key in ('inherited_JNI_calls','inherited_libc_SVC','inherited_main_SVC','late_jni','java_dispatch'):
        changes.append((('case_result',key),[]))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result' and path[1] not in ('instruction_trace_sha256','observed_code_sha256'):
            bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged getppid evidence accepted: {path}')
    return len(changes)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):
        parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as output:output.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh getppid replay differs'
    row=data['case_result']
    print(json.dumps(dict(schema=SCHEMA,damaged_evidence_rejected=rejected,returned_callbacks=len(row['callbacks']),
        instruction_observations=row['instruction_observations'],syscall_173_result=PPID_RESULT,
        stop_before=hex(VM_RESUME),complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
