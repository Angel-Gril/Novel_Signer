"""Original five-word string formatter with TLS-to-packed argument provenance."""
from __future__ import annotations
from copy import deepcopy
import argparse,hashlib,json
from pathlib import Path
import verify_vm9_native_171_post_crc_tls_dynamic_20261124 as previous
import verify_vm9_second_format5_fresh_20261016 as format_fixture
from unicorn import arm64_const as arm
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM,CS_OP_REG
VM_CALL,VM_RESUME,LIBC_BASE=previous.VM_CALL,previous.VM_RESUME,previous.LIBC_BASE
bootstrap,digest,sha256=previous.bootstrap,previous.digest,previous.sha256
MAX_NEW_INSTRUCTIONS=300000
ALLOWED_PLT=previous.ALLOWED_PLT|{0x347F70,0x348320}
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_crc_format5_dynamic_20261125.json')
SCHEMA='vm9-native-171-post-crc-format5-dynamic-20261125-v1'


class WordFlow:
    """Track scalar copies and explicit unshifted X-register XOR from TLS result bytes."""
    def __init__(self,image,descriptor,value):
        self.image=image;self.value=value;self.registers={};self.register_values={};self.last_load={}
        self.memory={descriptor+16+i:() for i in range(4)}
        self.word_starts={descriptor+16+i:descriptor+16 for i in range(4)}
        self.memory_values={descriptor+16+i:value for i in range(4)}
        self.decoder=Cs(CS_ARCH_ARM64,CS_MODE_ARM);self.decoder.detail=True
        self.cache={};self.invalidations=[];self.steps=0

    def reg(self,r):
        name=self.instruction.reg_name(r)
        if name in ('fp','lr'):return 29 if name=='fp' else 30
        return int(name[1:]) if len(name)>1 and name[0] in 'xw' and name[1:].isdigit() else None

    def before(self,cpu,pc):
        if pc not in self.cache:self.cache[pc]=next(self.decoder.disasm(bytes(cpu.mem_read(pc,4)),pc))
        self.instruction=self.cache[pc];self.pc=pc;self.read_index=self.write_index=0
        ins=self.instruction;operands=ins.operands;copied=None;dest=None;expected=None
        if ins.mnemonic=='mov' and len(operands)==2 and all(o.type==CS_OP_REG for o in operands):
            dest=self.reg(operands[0].reg);src=self.reg(operands[1].reg);copied=self.registers.get(src)
            if copied is not None:expected=self.register_values[src]
        if ins.mnemonic=='eor' and len(operands)==3 and all(o.type==CS_OP_REG for o in operands):
            ids=[self.reg(o.reg) for o in operands]
            if all(i is not None for i in ids) and all(ins.reg_name(o.reg).startswith('x') for o in operands) and not operands[2].shift.value:
                destination,left,right=ids;tagged=[i for i in (left,right) if i in self.registers]
                if len(tagged)==1:
                    source=tagged[0];other=right if source==left else left
                    actual=lambda i:cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i)))
                    assert actual(source)==self.register_values[source]
                    expected=actual(left)^actual(right);dest=destination
                    copied=self.registers[source]+(dict(operation='xor64',PC=hex(pc-self.image),
                        TLS_operand='left' if source==left else 'right',counterpart_load=self.last_load.get(other)),)
        _,written=ins.regs_access()
        for r in written:
            index=self.reg(r)
            if index in self.registers:
                if ins.mnemonic not in ('mov','ldr','ldur','ldar','ldp') and not (ins.mnemonic=='eor' and copied is not None):
                    self.invalidations.append(dict(PC=hex(pc-self.image),operation=ins.mnemonic,register=index))
                self.registers.pop(index)
                self.register_values.pop(index,None)
            self.last_load.pop(index,None)
        if copied is not None and dest is not None:
            self.registers[dest]=copied+(dict(operation='register_copy',PC=hex(pc-self.image)),) if ins.mnemonic=='mov' else copied
            self.register_values[dest]=expected

    def path(self,address,width):
        if any(self.word_starts.get(address+i)!=address for i in range(width)):return None
        values=[self.memory.get(address+i) for i in range(width)]
        return values[0] if values and values[0] is not None and all(v==values[0] for v in values) else None

    def expected(self,address,width):return self.memory_values[address]&((1<<(width*8))-1)

    def read(self,cpu,address,width):
        ins=self.instruction
        if ins.mnemonic not in ('ldr','ldur','ldar','ldp') or width not in (4,8):return
        index=self.read_index if ins.mnemonic=='ldp' else 0;self.read_index+=1
        if index>=len(ins.operands) or ins.operands[index].type!=CS_OP_REG:return
        register=self.reg(ins.operands[index].reg)
        if register is None:return
        self.last_load[register]=dict(PC=hex(self.pc-self.image),address=hex(address),width=width)
        path=self.path(address,width)
        if path is not None:
            value=self.expected(address,width)
            assert int.from_bytes(cpu.mem_read(address,width),'little')==value
            row=dict(operation='load',PC=hex(self.pc-self.image),address=hex(address),width=width)
            self.registers[register]=path+(row,);self.steps+=1
            self.register_values[register]=value

    def write(self,cpu,address,width):
        ins=self.instruction;path=None
        if ins.mnemonic in ('str','stur','stlr','stp') and width in (4,8):
            index=self.write_index if ins.mnemonic=='stp' else 0;self.write_index+=1
            if index<len(ins.operands) and ins.operands[index].type==CS_OP_REG:
                register=self.reg(ins.operands[index].reg);path=self.registers.get(register)
                if path is not None:
                    value=self.register_values[register]&((1<<(width*8))-1)
                    assert cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(register)))&((1<<(width*8))-1)==value
                    path=path+(dict(operation='store',PC=hex(self.pc-self.image),address=hex(address),width=width),)
        for i in range(width):
            if path is None:
                self.memory.pop(address+i,None);self.memory_values.pop(address+i,None);self.word_starts.pop(address+i,None)
            else:
                self.memory[address+i]=path;self.memory_values[address+i]=value;self.word_starts[address+i]=address
        if path is not None:self.steps+=1


def render(fmt,words,read_string):
    """Independent bounded printf input calculation; no VM model or native output input."""
    out=bytearray();k=0;i=0
    while i<len(fmt):
        if fmt[i]!=37:out.append(fmt[i]);i+=1;continue
        if fmt[i:i+2]==b'%%':out.append(37);i+=2;continue
        tag=next((t for t in (b'%llu',b'%lu',b'%d',b'%u',b'%s') if fmt[i:i+len(t)]==t),None)
        assert tag is not None and k<len(words),'uncovered format or extra ambient argument'
        value=words[k];k+=1;i+=len(tag)
        if tag==b'%s':out.extend(read_string(value))
        else:
            if tag in (b'%d',b'%u'):value&=0xFFFFFFFF
            if tag==b'%d' and value&0x80000000:value-=1<<32
            out.extend(str(value).encode('ascii'))
        assert len(out)<=65536
    return bytes(out),k


class PostCrcFormat5(previous.PostCrcTls):
    def __init__(self,control):
        super().__init__(control)
        self._f5_active=self._f5_done=False;self._f5_sites=[];self._f5_code={};self._f5_writes=[]
        self._f5_calls=[];self._f5_passes=[];self._f5_seen=set();self._f5_aux=[]
        self._f5_copies=None
        self._f5_parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'))
        self._f5_expected_descriptor=int(self._f5_parent['case_result']['callbacks'][-1]['descriptor_address'],16)

    def _f5_track(self,cpu,pc):
        site=self._fmt_site(pc);self._f5_sites.append(site);self._f5_code[site]=bytes(cpu.mem_read(pc,4)).hex()

    def _f5_call(self,cpu):
        d=self._reg(cpu,0)
        return dict(index=len(self._f5_sites),descriptor_address=hex(d),descriptor_prefix_width=64,
            wrapper_offset=hex(self._reg(cpu,8)-self.image),target_offset=hex(self._u(cpu,d)-self.image),
            VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_call_executed=False,wrapper_entered=False,target_entered=False,returned=False)

    def _tu_stop(self,cpu,reason):
        if reason!='next_VM_callback_before_execution':return super()._tu_stop(cpu,reason)
        assert not self._f5_active and len(self._tu_sites)==2081
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._tu_protected)
        self._tu_done=True;self._tu_reason=reason;self._tu_active=False
        self._f5_state=self._tu_state;self._f5_events=deepcopy(self._f5_state['allocator_events_ref'])
        self._f5_active=True;self._f5_track(cpu,self.image+VM_CALL)
        call=self._f5_call(cpu);self._f5_calls.append(call)
        assert (call['wrapper_offset'],call['target_offset'],call['VM_cursor_offset'])==('0x2888b4','0x248908','0x10aa68')
        self._f5_descriptor=int(call['descriptor_address'],16);assert self._f5_descriptor==self._f5_expected_descriptor
        self._f5_packed=bytes(cpu.mem_read(self._f5_descriptor,64))
        self._f5_output=self._u(cpu,self._f5_descriptor+8);self._f5_format=self._u(cpu,self._f5_descriptor+16)
        self._f5_words=[self._u(cpu,self._f5_descriptor+24,4)]+[self._u(cpu,self._f5_descriptor+i) for i in range(32,64,8)]
        assert self._f5_output==int(self._sw_objects[-1]['object_address'],16)
        self._f5_before=bytes(cpu.mem_read(self._f5_output,32));self._f5_old_payload=self._u(cpu,self._f5_output+16)
        assert self._u(cpu,self._f5_output+8,4)==8 and self._u(cpu,self._f5_output+12,4)==0
        assert self._f5_old_payload==int(self._sw_objects[-1]['payload_address'],16)
        self._f5_protected=[(l,a,b) for l,a,b in self._tu_protected
            if not (l=='constructed_string' and a==self._f5_output or l=='constructed_payload' and a==self._f5_old_payload)]
        assert len(self._f5_protected)==len(self._tu_protected)-2
        self._f5_tls_arguments=[]
        for n,off in enumerate((24,32,40,48,56)):
            width=4 if n==0 else 8;path=self._f5_copies.path(self._f5_descriptor+off,width)
            if path is not None:
                assert self._f5_words[n]==self._f5_copies.expected(self._f5_descriptor+off,width)
                assert path[0]['PC']=='0x16f8a0' and path[0]['width']==4
                assert path[1]['PC']=='0x16f8a4' and path[1]['width']==8
                xors=[r for r in path if r['operation']=='xor64']
                assert len(xors)==1 and xors[0]['PC']=='0x16a7fc' and xors[0]['counterpart_load']['width']==8
                self._f5_tls_arguments.append(dict(argument_index=n,packed_offset=off,wrapper_width=width,copy_steps=list(path),
                    original_TLS_result_zero_extended_into_VM_register=True,TLS_xor_result_to_packed_chain_verified=True))
        assert self._f5_tls_arguments,'TLS-to-formatter provenance not established'
        fmt=self._bounded_cstring(cpu,self._f5_format,4096);self._f5_inputs=[('format',self._f5_format,fmt+b'\0')]
        def string(a):
            b=self._bounded_cstring(cpu,a,65536);self._f5_inputs.append(('string_argument',a,b+b'\0'));return b
        self._f5_expected,self._f5_consumed=render(fmt,self._f5_words,string)
        assert self._f5_consumed==5
        assert all(r['argument_index']<self._f5_consumed for r in self._f5_tls_arguments)
        self._f5_protected.extend(self._f5_inputs)
        self._base_observe(cpu,self.image+VM_CALL,self._f5_state)
        print('Retained complete TLS checkpoint; five-word formatter and TLS XOR argument provenance admitted',flush=True)

    def native_runner(self,*args,**kwargs):
        old_write,old_read=kwargs['memory_write_observer'],kwargs['memory_read_observer']
        def read(cpu,a,n):
            if self._tu_active and not self._f5_active and self._f5_copies is not None:self._f5_copies.read(cpu,a,n)
            if old_read:old_read(cpu,a,n)
        def write(cpu,a,n):
            pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
            if self._tu_active and not self._f5_active and self._f5_copies is not None:self._f5_copies.write(cpu,a,n)
            if self._f5_active:
                assert not any(a<b+len(raw) and b<a+n for _,b,raw in self._f5_protected),'formatter wrote retained input or state'
                assert not (a<self._f5_output+8 and self._f5_output<a+n),'formatter wrote vtable'
                assert not (a<self._f5_output+32 and self._f5_output+24<a+n),'formatter wrote object neighbor'
                if not self._f5_calls[0]['returned']:
                    assert not (a<self._f5_descriptor+64 and self._f5_descriptor<a+n),'formatter wrote packed input'
                self._f5_writes.append((len(self._f5_sites),self._fmt_site(pc),a,n))
            if old_write:old_write(cpu,a,n)
        kwargs['memory_write_observer'],kwargs['memory_read_observer']=write,read
        return super().native_runner(*args,**kwargs)

    def _f5_stop(self,cpu,reason):
        assert all(bytes(cpu.mem_read(a,len(b)))==b for _,a,b in self._f5_protected)
        self._f5_done=True;self._f5_reason=reason
        cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,bootstrap().digest.context.outer.oracle.STOP)

    def _jst_stop(self,cpu,reason):
        if self._f5_active:return self._f5_stop(cpu,reason)
        return super()._jst_stop(cpu,reason)

    def _f5_guard(self,cpu,pc):
        word=int.from_bytes(cpu.mem_read(pc,4),'little')
        if word==0xD4000001:self._f5_stop(cpu,'new_SVC_before_execution');return True
        target=None
        if word&0x7C000000==0x14000000:
            n=word&0x3FFFFFF
            if n&(1<<25):n-=1<<26
            target=pc+(n<<2)
        elif word&0xFFFFFC1F in (0xD61F0000,0xD63F0000,0xD65F0000):
            r=(word>>5)&31;target=0 if r==31 else self._reg(cpu,r)
        for a in (pc,target):
            if a is None:continue
            if a==self.image+0x26E70C:self._f5_stop(cpu,'JNI_dispatch_before_execution');return True
            if a==target and not self._jwx_executable(a):self._f5_stop(cpu,'external_branch_before_execution');return True
            if self.image+self._jwx_plt[0]<=a<self.image+self._jwx_plt[1] and a-self.image not in ALLOWED_PLT:
                self._f5_stop(cpu,'uncovered_PLT_before_execution');return True
        return False

    def observe(self,cpu,pc,state):
        if not self._f5_active:
            if self._tu_active and self._tu_calls[0]['returned']:
                if self._f5_copies is None:self._f5_copies=WordFlow(self.image,self._tu_descriptor,self._tu_value)
                self._f5_copies.before(cpu,pc)
            return super().observe(cpu,pc,state)
        self._f5_track(cpu,pc);off=pc-self.image;call=self._f5_calls[0]
        if len(self._f5_sites)>=MAX_NEW_INSTRUCTIONS:self._f5_stop(cpu,'instruction_budget');return
        if off==VM_CALL:
            assert call['returned'];self._f5_calls.append(self._f5_call(cpu));self._f5_stop(cpu,'next_VM_callback_before_execution');return
        if self._f5_guard(cpu,pc):return
        if off==0x2888B4:
            assert self._reg(cpu,0)==self._f5_descriptor;call.update(VM_call_executed=True,wrapper_entered=True)
        if off==0x248908:
            assert [self._reg(cpu,i) for i in range(7)]==[self._f5_output,self._f5_format,*self._f5_words]
            assert self._reg(cpu,30)==self.image+VM_RESUME;call['target_entered']=True
        if off in (0x347FD0,0x348320,0x347FA0):self._f5_seen.add(('PLT',off))
        if pc in (LIBC_BASE+0x1BB08,LIBC_BASE+0x1BB88,LIBC_BASE+0x1BAC0):self._f5_seen.add(('libc',pc-LIBC_BASE))
        if pc in (LIBC_BASE+0x9833C,LIBC_BASE+0x97F40):self._f5_aux.append(dict(index=len(self._f5_sites),kind='gc' if pc==LIBC_BASE+0x9833C else 'flush'))
        if off==0x347F70:
            buffer,size,fmt,va=[self._reg(cpu,i) for i in range(4)]
            assert fmt==self._f5_format and 0<size<=65537
            top=self._u(cpu,va+8);gr=self._u(cpu,va+24,4);gr=gr-(1<<32) if gr&(1<<31) else gr
            assert gr==-48 and [self._u(cpu,top+gr+i*8) for i in range(5)]==self._f5_words
            self._f5_pending_pass=(buffer,size)
            self._f5_passes.append(dict(index=len(self._f5_sites),buffer_size=size,GP_words_verified=5,
                initial_GP_offset=gr,matching_libc_body_entered=False,returned=False))
        if pc==LIBC_BASE+0x647EC:
            assert self._f5_passes and not self._f5_passes[-1]['matching_libc_body_entered']
            self._f5_passes[-1]['matching_libc_body_entered']=True
        if off==0x248A28:
            b,n=self._f5_pending_pass;assert self._reg(cpu,0)==len(self._f5_expected)
            expected=self._f5_expected[:n-1]+b'\0';assert bytes(cpu.mem_read(b,len(expected)))==expected
            self._f5_passes[-1].update(returned=True,returned_length_equals_independent_input_render=True,
                bounded_buffer_and_NUL_equal=True,return_index=len(self._f5_sites))
        if off==VM_RESUME:
            assert all(p['returned'] and p['matching_libc_body_entered'] for p in self._f5_passes) and self._f5_passes
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==int(call['SP'],16) and self._idctor_saved_hash(cpu)==call['callee_saved_sha256']
            assert bytes(cpu.mem_read(self._f5_descriptor,64))==self._f5_packed
            assert bytes(cpu.mem_read(self._f5_output,8))==self._f5_before[:8] and bytes(cpu.mem_read(self._f5_output+24,8))==self._f5_before[24:]
            cap,length,pointer=self._u(cpu,self._f5_output+8,4),self._u(cpu,self._f5_output+12,4),self._u(cpu,self._f5_output+16)
            assert length==len(self._f5_expected) and length<cap<=1048576
            assert bytes(cpu.mem_read(pointer,length+1))==self._f5_expected+b'\0'
            self._f5_string=dict(object_address=hex(self._f5_output),payload_address=hex(pointer),capacity=cap,length=length,
                equals_independent_input_render=True,NUL_terminated=True,vtable_and_neighbor_preserved=True,packed_all_64_bytes_preserved=True)
            self._f5_protected.extend([('formatted_object',self._f5_output,bytes(cpu.mem_read(self._f5_output,24))),
                ('formatted_payload',pointer,bytes(cpu.mem_read(pointer,cap)))])
            call.update(returned=True,return_index=len(self._f5_sites),caller_SP_and_callee_saved_restored=True)
            print('Original five-word formatter returned; input-render, varargs and live output verified',flush=True)
        self._base_observe(cpu,pc,state)
        assert self.late_jni_calls==self._jev_initial_late and self.java_dispatch_calls==self._jev_initial_java

    def finish(self,result,state,proof):
        assert self._f5_done and self._f5_reason=='next_VM_callback_before_execution' and self._f5_calls[0]['returned']
        assert {('PLT',0x347FD0),('PLT',0x347FA0),('libc',0x1BB08),('libc',0x1BAC0)}<=self._f5_seen
        events=result['allocator_events'][len(self._f5_events):];counts=deepcopy(result['actual_allocator_counts'])
        for e in events:counts['malloc' if e[0]=='alloc' else 'free']-=1
        for e in self._f5_aux:counts[e['kind']]-=1
        old=super().finish(dict(result,allocator_events=self._f5_events,actual_allocator_counts=counts),state,proof)
        assert old==self._f5_parent['case_result'],'complete warm TLS checkpoint differs'
        live={}
        for e in result['allocator_events']:
            if e[0]=='alloc':live[e[2]]=e[1]
            elif e[0]=='free':live.pop(e[1],None)
        assert live[int(self._f5_string['payload_address'],16)]>=self._f5_string['capacity']
        trace=hashlib.sha256()
        for site in self._f5_sites:trace.update(site.encode()+bytes.fromhex(self._f5_code[site]))
        return dict(complete_TLS_parent_case_equal=True,parent_case_sha256=digest(old),instruction_observations=len(self._f5_sites),
            instruction_trace_sha256=trace.hexdigest(),observed_code_sha256=digest(self._f5_code),callbacks=self._f5_calls,
            TLS_argument_provenance=self._f5_tls_arguments,format_argument_count=self._f5_consumed,vsnprintf_passes=self._f5_passes,
            formatted_string=self._f5_string,original_allocator_entry_sites=[dict(domain=d,offset=hex(o)) for d,o in sorted(self._f5_seen)],
            new_allocator_events=events,allocator_aux_events=self._f5_aux,native_write_observations=len(self._f5_writes),
            actual_allocator_counts=result['actual_allocator_counts'],explicit_service_counts=result['explicit_service_counts'],
            retained_JSON_CRC_TLS_and_inputs_preserved=True,new_providers=[],new_SVCs=[],new_JNI_effects=[],stop_reason=self._f5_reason,
            source_values_or_hashes_exported=False,allocation_contents_exported=False,format_bytes_or_hash_exported=False,
            native_snapshot_used_as_VM_model_input=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def run(library,libc):
    previous.validate(json.loads(previous.EVIDENCE.read_text(encoding='utf-8')))
    original=previous.PostCrcTls;previous.PostCrcTls=PostCrcFormat5
    try:return previous.run(library,libc)
    finally:previous.PostCrcTls=original

EXPECTED_CASE_SHA256='01d779289a89b57962950eb52f29281ab5b0e39ee6244af9f99a9c9682078a97'
EXPECTED_COMPONENTS_SHA256='67dab42f1dae585017557ca649134210d1e66fc42b36d2b549e2ce99e625d339'
EXPECTED_CASE_KEYS=['TLS_argument_provenance', 'actual_allocator_counts', 'allocation_contents_exported', 'allocator_aux_events', 'callbacks', 'complete_TLS_parent_case_equal', 'complete_standalone_signer_verified', 'explicit_service_counts', 'format_argument_count', 'format_bytes_or_hash_exported', 'formatted_string', 'instruction_observations', 'instruction_trace_sha256', 'native_snapshot_used_as_VM_model_input', 'native_write_observations', 'new_JNI_effects', 'new_SVCs', 'new_allocator_events', 'new_providers', 'observed_code_sha256', 'online_acceptance_verified', 'original_allocator_entry_sites', 'parent_case_sha256', 'retained_JSON_CRC_TLS_and_inputs_preserved', 'source_values_or_hashes_exported', 'stop_reason', 'vsnprintf_passes']

def sources():
    return dict(verifier_sha256=sha256(Path(__file__)),parent_verifier_sha256=sha256(Path(previous.__file__)),
        parent_chain_sha256=digest(previous.sources()),format_fixture_sha256=sha256(Path(format_fixture.__file__)),
        formatter_model_sha256=sha256(Path(format_fixture.configuration.__file__)),
        callback_model_sha256=sha256(Path(format_fixture.model.__file__)),
        object_model_sha256=sha256(Path(__file__).with_name('vm9_objects.py')),
        native_oracle_sha256=sha256(Path(format_fixture.oracle.__file__)))


def claims():
    return dict(evidence_label='Sample verified',complete_TLS_parent_case_equal=True,
        original_five_word_wrapper_and_formatter_executed=True,matching_libc_vsnprintf_malloc_and_free_executed=True,
        TLS_xor_result_chain_to_consumed_packed_argument_verified=True,first_W2_and_four_full_X_words_verified=True,
        original_vsnprintf_va_lists_returns_and_bounded_buffers_verified=True,
        live_formatted_output_equals_independent_input_render=True,packed64_vtable_and_neighbor_preserved=True,
        retained_JSON_CRC_TLS_and_inputs_preserved=True,source_values_or_hashes_exported=False,
        format_bytes_or_hash_exported=False,allocation_contents_exported=False,native_snapshot_used_as_VM_model_input=False,
        original_JNI_acquisition_body_executed=False,real_ART_JVM_execution=False,Android_execution=False,
        complete_physical_ABI_verified=False,concurrency_verified=False,complete_standalone_signer_verified=False,online_acceptance_verified=False)


def providers():
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),admitted_callback=['0x2888b4','0x248908'],
        maximum_new_observations=MAX_NEW_INSTRUCTIONS,additionally_admitted_existing_PLT=['0x347f70','0x348320'],
        new_import_bindings=[],new_providers=[],formatting='original formatter and matching libc vsnprintf',
        allocation='inherited original matching Bionic allocator routing',
        expected_output='independent bounded printf calculation from observed input words; no VM model invocation',
        unknown_callback_policy='stop before VM call',new_SVC_and_JNI_policy='stop before execution',
        inherited_JNI_provider='controlled eight-byte env write; original body bypassed',
        relevant_existing_format5_native_controls_rerun=16,relevant_existing_format_guards_rerun=16,
        other_inherited_component_controls_rerun=False,component_allocators='declared synthetic services; original matching libc printf executes')


def capture(library,libc):
    case=run(library,libc);parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));table=format_fixture.exports(libc)
    controls=dict(format5=[format_fixture.compare(library,libc,b,l,table) for b in format_fixture.BASES for l in format_fixture.PROFILES],
        format_guards=format_fixture.guards(library,libc))
    return dict(schema=SCHEMA,claims=claims(),providers=providers(),source_fingerprints=sources(),
        parent_evidence_sha256=sha256(previous.EVIDENCE),case_result=case,case_result_sha256=digest(case),
        component_controls=controls,inherited_controls_sha256=digest(parent['component_controls']))


def _validate(data,parent):
    assert set(data)=={'schema','claims','providers','source_fingerprints','parent_evidence_sha256','case_result',
        'case_result_sha256','component_controls','inherited_controls_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims() and data['providers']==providers()
    assert data['source_fingerprints']==sources() and data['parent_evidence_sha256']==sha256(previous.EVIDENCE)
    assert data['inherited_controls_sha256']==digest(parent['component_controls'])
    r=data['case_result'];assert data['case_result_sha256']==digest(r)==EXPECTED_CASE_SHA256 and set(r)==set(EXPECTED_CASE_KEYS)
    assert r['complete_TLS_parent_case_equal'] is True and r['parent_case_sha256']==digest(parent['case_result'])
    assert 0<r['instruction_observations']<MAX_NEW_INSTRUCTIONS and r['stop_reason']=='next_VM_callback_before_execution'
    assert r['new_providers']==r['new_SVCs']==r['new_JNI_effects']==[]
    assert r['retained_JSON_CRC_TLS_and_inputs_preserved'] is True
    assert all(r[k] is False for k in ('source_values_or_hashes_exported','allocation_contents_exported',
        'format_bytes_or_hash_exported','native_snapshot_used_as_VM_model_input','complete_standalone_signer_verified','online_acceptance_verified'))
    assert r['explicit_service_counts']==parent['case_result']['explicit_service_counts']
    calls=r['callbacks'];assert len(calls)==2 and calls[0]['index']==1 and calls[-1]['index']==r['instruction_observations']
    assert (calls[0]['wrapper_offset'],calls[0]['target_offset'])==('0x2888b4','0x248908') and calls[0]['descriptor_prefix_width']==64
    assert all(calls[0][k] is True for k in ('VM_call_executed','wrapper_entered','target_entered','returned','caller_SP_and_callee_saved_restored'))
    assert all(calls[-1][k] is False for k in ('VM_call_executed','wrapper_entered','target_entered','returned'))
    for k in ('descriptor_address','VM_cursor_offset','SP','callee_saved_sha256','wrapper_offset','target_offset'):
        assert calls[0][k]==parent['case_result']['callbacks'][-1][k]
    assert r['format_argument_count']==5 and r['TLS_argument_provenance']
    for p in r['TLS_argument_provenance']:
        assert 0<=p['argument_index']<5 and p['packed_offset']==(24,32,40,48,56)[p['argument_index']]
        assert p['wrapper_width']==(4 if p['argument_index']==0 else 8)
        assert p['original_TLS_result_zero_extended_into_VM_register'] is p['TLS_xor_result_to_packed_chain_verified'] is True
        assert p['copy_steps'][0]['PC']=='0x16f8a0' and p['copy_steps'][0]['width']==4
        assert p['copy_steps'][1]['PC']=='0x16f8a4' and p['copy_steps'][1]['width']==8
        assert p['copy_steps'][0]['address']==hex(int(parent['case_result']['callbacks'][0]['descriptor_address'],16)+16)
        assert p['copy_steps'][-1]['operation']=='store' and p['copy_steps'][-1]['address']==hex(int(calls[0]['descriptor_address'],16)+p['packed_offset'])
        xors=[step for step in p['copy_steps'] if step['operation']=='xor64']
        assert len(xors)==1 and xors[0]['PC']=='0x16a7fc' and xors[0]['counterpart_load']['width']==8
    assert r['vsnprintf_passes']
    for p in r['vsnprintf_passes']:
        assert p['GP_words_verified']==5 and p['initial_GP_offset']==-48
        assert all(p[k] is True for k in ('matching_libc_body_entered','returned','returned_length_equals_independent_input_render','bounded_buffer_and_NUL_equal'))
    output=r['formatted_string'];assert 0<=output['length']<output['capacity']<=1048576
    assert all(output[k] is True for k in ('equals_independent_input_render','NUL_terminated','vtable_and_neighbor_preserved','packed_all_64_bytes_preserved'))
    assert {('PLT','0x347fd0'),('PLT','0x347fa0'),('libc','0x1bb08'),('libc','0x1bac0')}<={(v['domain'],v['offset']) for v in r['original_allocator_entry_sites']}
    c=data['component_controls'];assert set(c)=={'format5','format_guards'} and digest(c)==EXPECTED_COMPONENTS_SHA256
    assert [(v['image_base'],v['case']) for v in c['format5']]==[(hex(b),l) for b in format_fixture.BASES for l in format_fixture.PROFILES]
    for v in c['format5']:
        assert all(v[k] is True for k in ('original_wrapper_formatter_and_matching_libc_printf_returned',
            'declared_guest_image_TLS_and_locale_bytes_equal','packed_bytes_and_following_padding_equal',
            'ordered_allocation_reallocation_free_locale_effects_equal','first_W2_and_four_X_arguments_supplied'))
        assert v['CPU_X0_return_compared'] is v['native_snapshot_input'] is v['physical_spills_and_PAC_compared'] is False
    assert len(c['format_guards'])==16
    assert all(v['rejected'] is v['all_pages_unchanged'] is True and v['external_provider_effects_rolled_back'] is False for v in c['format_guards'])


def validate(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent);_validate(data,parent)


def damaged_evidence_rejected(data):
    parent=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(parent)
    changes=[(('claims','real_ART_JVM_execution'),True),(('claims','original_JNI_acquisition_body_executed'),True),
        (('providers','new_providers'),['guessed_printf']),(('source_fingerprints','formatter_model_sha256'),'0'*64),
        (('inherited_controls_sha256',),'0'*64),(('case_result','complete_TLS_parent_case_equal'),False),
        (('case_result','TLS_argument_provenance'),[]),(('case_result','TLS_argument_provenance',0,'TLS_xor_result_to_packed_chain_verified'),False),
        (('case_result','TLS_argument_provenance',0,'packed_offset'),0),(('case_result','format_argument_count'),6),
        (('case_result','vsnprintf_passes',0,'GP_words_verified'),4),(('case_result','vsnprintf_passes',0,'matching_libc_body_entered'),False),
        (('case_result','vsnprintf_passes',0,'bounded_buffer_and_NUL_equal'),False),(('case_result','formatted_string','equals_independent_input_render'),False),
        (('case_result','formatted_string','packed_all_64_bytes_preserved'),False),(('case_result','formatted_string','NUL_terminated'),False),
        (('case_result','original_allocator_entry_sites'),[]),(('case_result','retained_JSON_CRC_TLS_and_inputs_preserved'),False),
        (('case_result','callbacks',-1,'target_entered'),True),(('case_result','allocation_contents_exported'),True),
        (('case_result','format_bytes_or_hash_exported'),True),(('case_result','registers'),[]),
        (('component_controls','format5',0,'native_snapshot_input'),True),(('component_controls','format_guards',0,'rejected'),False)]
    for path,value in changes:
        bad=deepcopy(data);target=bad
        for key in path[:-1]:target=target[key]
        target[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError,IndexError):continue
        raise AssertionError('damaged formatter evidence accepted: '+repr(path))
    return len(changes)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--elf',type=Path);p.add_argument('--libc',type=Path);p.add_argument('--compare-case',type=Path)
    m=p.add_mutually_exclusive_group();m.add_argument('--capture',action='store_true');m.add_argument('--replay',action='store_true');args=p.parse_args()
    if (args.capture or args.replay) and (args.elf is None or args.libc is None):p.error('--capture and --replay require --elf and --libc')
    if args.compare_case is not None and not args.capture:p.error('--compare-case requires --capture')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence exists; refusing overwrite')
        data=capture(args.elf,args.libc)
        if args.compare_case is not None:assert data['case_result']==json.loads(args.compare_case.read_text(encoding='utf-8'))
        validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as stream:stream.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert capture(args.elf,args.libc)==data
    print(json.dumps(dict(schema=SCHEMA,formatted_strings=1,damaged_evidence_rejected=rejected,complete_standalone_signer_verified=False)))


if __name__=='__main__':main()
