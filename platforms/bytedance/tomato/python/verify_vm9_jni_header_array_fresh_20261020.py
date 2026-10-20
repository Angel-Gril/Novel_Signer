"""Fresh original +271384 header array controls with explicit synthetic JNI.

Each side starts from independently declared tree/string inputs. Original ELF
execution supplies comparison results only; JNI handles and effects are explicit
component inputs. No request snapshot or private header contents are exported.
"""
from pathlib import Path
import argparse, hashlib, json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_registry import fixture, BASES
from verify_vm9_strings import Effects, fields
from verify_vm9_root_configuration import TLS
from vm9_allocator import _read_span, _write_span, RefillUnsupported
import vm9_registry as registry
import vm9_jni_header_array as model

G=oracle.GUEST; ENV=G+0x1000; TABLE=G+0x800; REF=G+0x1500
CLASS=G+0x2200; ARRAY=G+0x9800; SP=G+0xEF00
ALT=G+0x2A00; ALT_DATA=G+0x3A00
SLOTS={0x538:2,0x560:4,0x570:4,0x740:2,0xB8:2,0xB0:2,
       0x718:2,0x720:1,0x88:1,0x78:1}


def w(p,a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
def u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


def fresh(lib,base,label):
    keys=[b'fixture-header']
    if label=='empty':keys=[]
    if label=='multiple':keys=[b'c-key',b'a-key',b'b-key']
    if label in ('size22','size23','long','malloc_live_source'):keys=[b'k'*{'size22':22,'size23':23}.get(label,60)]
    p,blocks,addresses=fixture(lib,base,keys);setup=Effects(blocks=blocks)
    container=registry.construct_configuration_tree_reference(p,output_reference_address=REF,
        image_base=base,allocate=setup.malloc)
    values=[]
    for i,(key,_,_) in enumerate(addresses):
        value=G+0x2500+i*0x40;data=G+0x3400+i*0x100
        raw=b'value-'+bytes([65+i])
        if label in ('size22','size23','long'):raw=b'v'*{'size22':22,'size23':23}.get(label,127)
        if label=='embedded_NUL':raw=b'v\0ignored'
        w(p,value,base+0x34F5F8);fields(p,value+8,len(raw)+1,len(raw),data)
        _write_span(p,data,raw+b'\0');values.append(value)
        registry.insert_configuration_pair(p,container_address=container,key_address=key,
            value_address=value,image_base=base,allocate=setup.malloc,free=setup.free)
    w(p,ALT,base+0x34F5F8);fields(p,ALT+8,16,9,ALT_DATA);_write_span(p,ALT_DATA,b'live-swap\0')
    if label=='NULL_source':w(p,addresses[0][0]+16,0);w(p,values[0]+16,0)
    if label=='NULL_container':w(p,REF,0)
    w(p,base+0x3DF094,0 if label=='lazy_class_name' else 1,4)
    w(p,base+0x3DF110,CLASS);w(p,ENV,TABLE)
    w(p,TLS+0x28,0xAB567823C091D200)
    for i,slot in enumerate(SLOTS):w(p,TABLE+slot,G+0xF400+i*16)
    tree=registry._ConfigurationTree(p,container,base,4096,0x100000)
    node=u(p,tree.sentinel+0x10);pair=u(p,node+0x20) if keys else 0
    return p,setup,dict(pair=pair,key=addresses[0][0] if keys else 0,container=container,
        source=addresses[0][1] if keys else 0)


class Services:
    def __init__(self,base,setup,label,metadata):
        self.base,self.label,self.metadata=base,label,metadata
        self.effects=Effects(blocks=setup.blocks,mutate=self.mutate);self.effects.next=setup.next
        self.events=[];self.freed=[];self.strings={};self.elements={};self.nutf=0
        self.pending=label=='pre_exception';self.fn={G+0xF400+i*16:s for i,s in enumerate(SLOTS)}
    def mutate(self,kind,index,read,write):
        if self.label=='malloc_live_source' and kind=='malloc' and index==0:
            write(self.metadata['source'],b'Q')
    def malloc(self,p,n):return self.effects.malloc(p,n)
    def free_effect(self,a,read):
        self.freed.append([a,read(a,self.effects.blocks[a]).hex()])
    def free(self,p,a):
        self.free_effect(a,lambda a,n:_read_span(p,a,n));return self.effects.free(p,a)
    def native_free(self,c):
        a=c.reg_read(arm.UC_ARM64_REG_X0);self.free_effect(a,lambda a,n:bytes(c.mem_read(a,n)))
        return self.effects.native(c,'free',pointer=a)
    def jni(self,fn,args,read,write):
        slot=self.fn[fn];assert len(args)==SLOTS[slot] and args[0]==ENV
        detail=None;result=0
        if slot==0x560:
            assert args[2:]==(CLASS,0)
            result=0 if self.label=='NULL_array' else ARRAY
            self.elements[result]=[None]*args[1]
        elif slot==0x538:
            raw=bytearray()
            while read(args[1]+len(raw),1)!=b'\0':
                raw.extend(read(args[1]+len(raw),1));assert len(raw)<0x1000
            self.nutf+=1;result=0 if self.label=='NULL_UTF' else G+0x9000+self.nutf*16
            self.strings[result]=bytes(raw);detail=hashlib.sha256(raw).hexdigest()
            if self.label=='live_value_pointer' and self.nutf==1:write(self.metadata['pair']+8,ALT.to_bytes(8,'little'))
            if self.label=='new_exception':self.pending=True
        elif slot==0x570:
            assert args[1] in self.elements
            self.elements[args[1]][args[2]]=self.strings.get(args[3])
        elif slot==0x740:result={'global':2,'weak':3,'unknown':9,'invalid':0}.get(self.label,1)
        elif slot==0x720:result=int(self.pending)
        elif slot==0x78:result=G+0x9F00
        elif slot==0x88:self.pending=False
        else:assert slot in (0xB8,0xB0,0x718)
        self.events.append([slot,list(args),result,detail]);return result
    def model_jni(self,p,fn,args):
        return self.jni(fn,args,lambda a,n:_read_span(p,a,n),lambda a,b:_write_span(p,a,b))
    def imports(self):
        result={0x347FA0:self.native_free}
        for fn,slot in self.fn.items():
            def call(c,fn=fn,slot=slot):
                args=tuple(c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(SLOTS[slot]))
                return self.jni(fn,args,lambda a,n:bytes(c.mem_read(a,n)),lambda a,b:c.mem_write(a,b))
            result[fn-self.base]=call
        return result


def call(p,base,label,s,**changes):
    kw=dict(image_base=base,entry_stack_address=SP,thread_pointer=TLS,
        environment_pointer=0 if label=='NULL_env' else ENV,input_reference_address=REF,
        allocate=s.malloc,free=s.free,invoke_jni=s.model_jni)
    kw.update(changes);return model.construct_java_header_array(p,**kw)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    labels=('empty','one','multiple','size22','size23','long','embedded_NUL',
        'NULL_source','NULL_env','NULL_container','NULL_array','NULL_UTF','global','weak',
        'unknown','invalid','lazy_class_name','live_value_pointer','malloc_live_source',
        'pre_exception','new_exception')
    cases=[];guards=[]
    for base in BASES:
        for label in labels:
            p,setup,meta=fresh(args.library,base,label);expected=Services(base,setup,label,meta);actual=Services(base,setup,label,meta)
            watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
            watch[G+0xA000,SP-0x1000-(G+0xA000)]=None
            watch[SP,0x10000-(SP-G)]=None;watch[SP-0x68,8]=None
            if label not in ('NULL_env','NULL_container'):
                for a,n in ((SP-0x90,16),(SP-0xA0,16)):watch[a,n]=None
                if label!='empty':
                    for a,n in ((SP-0xB0,16),(SP-0x78,16)):watch[a,n]=None
                    if label!='NULL_source':
                        for a,n in ((SP-0x100,24),(SP-0x148,9)):watch[a,n]=None
            steps=[0];minimum=[SP]
            def observe(c,a):steps[0]+=1;minimum[0]=min(minimum[0],c.reg_read(arm.UC_ARM64_REG_SP))
            returned,memory,_,_=oracle.native(args.library,base,0x271384,[0 if label=='NULL_env' else ENV,REF],p,
                extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TLS},
                host_imports=expected.imports(),observed_memory=watch,instruction_observer=observe,
                malloc_handler=lambda c,n:expected.effects.native(c,'malloc',n),instruction_limit=100000)
            got=call(p,base,label,actual)
            assert got==returned,(label,'returned reference',got,returned)
            own=_read_span(p,G,0xA000)
            if own!=memory:
                i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b)
                raise AssertionError((label,'guest',hex(i),own[i],memory[i]))
            for (a,n),raw in watch.items():assert _read_span(p,a,n)==raw,(label,'image/stack',hex(a),n,_read_span(p,a,n).hex()[:100],raw.hex()[:100])
            assert actual.events==expected.events,(label,'JNI order',actual.events,expected.events)
            assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks,(label,'allocation')
            assert actual.freed==expected.freed,(label,'pre-free bytes')
            assert actual.elements==expected.elements and actual.strings==expected.strings,(label,'array content')
            if label=='one':assert actual.elements[ARRAY]==[b'fixture-header',b'value-A']
            if label=='multiple':assert actual.elements[ARRAY]==[b'a-key',b'value-B',b'b-key',b'value-C',b'c-key',b'value-A']
            if label=='live_value_pointer':assert actual.elements[ARRAY][1]==b'live-swap'
            if label=='malloc_live_source':assert actual.elements[ARRAY][0]==b'Q'+b'k'*59
            cases.append(dict(case=label,image_base=hex(base),native_instructions=steps[0],
                native_stack_bytes=SP-minimum[0],returned_reference_match=True,ordered_array_contents_match=True,
                declared_nonstack_guest_and_image_match=True,logical_stack_fields_match=True,
                JNI_effect_order_match=True,allocator_and_prefree_bytes_match=True,
                heap_allocation_count=sum(e[0]=='malloc' for e in actual.effects.calls),
                native_snapshot_input=False,native_output_used_as_Python_input=False))
            print('PASS',hex(base),label,steps[0],flush=True)
    base=BASES[0]
    checks=[('unaligned_SP',dict(entry_stack_address=SP-1)),('typed_SP',dict(entry_stack_address=True)),
        ('SP_wrap',dict(entry_stack_address=1<<64)),('typed_image',dict(image_base=True)),
        ('image_wrap',dict(image_base=(1<<64)-16)),('typed_env',dict(environment_pointer=True)),
        ('negative_env',dict(environment_pointer=-1)),('unmapped_env',dict(environment_pointer=0x66000000)),
        ('unmapped_ref',dict(input_reference_address=0x66000000)),('ref_wrap',dict(input_reference_address=(1<<64)-8)),
        ('ref_spill',dict(input_reference_address=SP-0x100)),('TLS_spill',dict(thread_pointer=SP-0x20)),
        ('unmapped_TLS',dict(thread_pointer=0x66000000)),('missing_malloc',dict(allocate=None)),
        ('missing_free',dict(free=None)),('missing_JNI',dict(invoke_jni=None)),
        ('node_zero',dict(max_nodes=0)),('node_bool',dict(max_nodes=True)),('node_excess',dict(max_nodes=4097)),
        ('byte_zero',dict(max_bytes=0)),('byte_bool',dict(max_bytes=True)),('byte_excess',dict(max_bytes=0x100001)),
        ('short_bound',dict(max_bytes=2)),('provider_failure',dict(invoke_jni=lambda *a:(_ for _ in ()).throw(RuntimeError('fixture')))),
        ('provider_result',dict(invoke_jni=lambda *a:1<<64)),('malloc_NULL',dict(allocate=lambda *a:0)),
        ('malloc_bool',dict(allocate=lambda *a:True)),('malloc_wrap',dict(allocate=lambda *a:(1<<64)-8)),
        ('malloc_unmapped',dict(allocate=lambda *a:0x66000000)),('malloc_spill',dict(allocate=lambda *a:SP-0x200)),
        ('malloc_source_alias',{}),('cold_class',{}),('missing_slot',{}),('NULL_table',{}),
        ('source_unmapped',{}),('source_spill',{}),('iterator_cycle',{}),('canary_changed',{}),
        ('container_spill',{}),('pair_spill',{}),('key_spill',{}),('live_iterator_dispatch',{})]
    for label,changes in checks:
        p,setup,meta=fresh(args.library,base,'long');s=Services(base,setup,'long',meta)
        if label=='cold_class':w(p,base+0x3DF110,0)
        if label=='missing_slot':w(p,TABLE+0x560,0)
        if label=='NULL_table':w(p,ENV,0)
        if label=='source_unmapped':w(p,meta['key']+16,0x66000000)
        if label=='source_spill':w(p,meta['key']+16,SP-0x200)
        if label=='container_spill':w(p,REF,SP-0x200)
        if label=='pair_spill':w(p,u(p,meta['container']+32),SP-0x200)
        if label=='key_spill':w(p,meta['pair'],SP-0x200)
        if label=='malloc_source_alias':changes=dict(allocate=lambda *a:meta['source'])
        if label in ('iterator_cycle','canary_changed','live_iterator_dispatch'):
            original=s.model_jni
            def altered(tx,fn,words,label=label):
                result=original(tx,fn,words)
                if s.fn[fn]==0x570:
                    if label=='canary_changed':w(tx,SP-0x68,0)
                    if label=='iterator_cycle':w(tx,u(tx,SP-0x98)+0x18,u(tx,SP-0x98))
                    if label=='live_iterator_dispatch':w(tx,SP-0xA0,1)
                return result
            changes=dict(invoke_jni=altered)
        before={k:bytes(v) for k,v in p.items()}
        try:call(p,base,'long',s,**changes)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError((label,'accepted'))
        assert before=={k:bytes(v) for k,v in p.items()},(label,'page rollback')
        guards.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('GUARD',label,flush=True)
    result=dict(component='Cached-class original JNI header array +271384',
        native_Python_controls=len(cases),rollback_guards=len(guards),cases=cases,negative_cases=guards,
        explicit_cached_String_class_required=True,synthetic_JNI_provider=True,
        native_input_snapshot_used=False,private_names_or_payloads_published=False,
        actual_request_output_integration_verified=False,cold_class_resolution_verified=False,
        whole_request_native_differential_verified=False,live_Android_JVM_verified=False,
        complete_physical_ABI_verified=False,external_provider_effect_rollback_verified=False,
        complete_python_medusa=False,fresh_signer_output_verified=False)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS header array',len(cases),'native',len(guards),'guards',flush=True)


if __name__=='__main__':main()
