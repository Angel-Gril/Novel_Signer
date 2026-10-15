"""Fresh seed, xorshift, identifier formatting and +2886b0/+25bd8c cache."""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
from verify_vm9_reference_scopes_fresh_20261011 import Services as ReferenceServices
from verify_vm9_jni_byte_array_fresh_20261011 import fresh,u,w,TP,SP
from vm9_allocator import RefillUnsupported,_read_span,_write_span
G=oracle.GUEST;OUT=G+0x1000;BLOCK=G+0x1200;OBJECT=G+0x1800;COUNT=G+0x1C00;DATA=G+0x2000
BASES=(0x122C0000,0x775C205000)
PROFILES=('cold','open_NULL','short_read','close_failure','warm','warm_NULL','warm_NULL_count',
    'output_cache_alias','output_pair_alias','guard_even','guard_pending','seed_warm','zero_seed','high_seed',
    'cross_page_output','cross_page_packed')
FORMAT_PROFILES=('format_32_nibbles','format_literal','format_mixed','format_template_alias','format_alphabet_alias','format_seed_alias')
SEED=bytes(range(16));LIBC_SHA256='d2376df6d2ac3e0213f85e3614c4c7ad1d28c84c44926058d5c1b95c855563db'


class Services(ReferenceServices):
    def __init__(self,image,label,blocks=()):
        super().__init__(blocks);self.image=image;self.label=label
    def opened(self,path,mode,read):
        assert path==self.image+0x3DE450 and mode==self.image+0x3DE464
        assert read(path,1)!=b'\0' and read(mode,1)!=b'\0'
        result=0 if self.label=='open_NULL' else G+0x3F00
        self.events.append(['fopen',path,mode,result]);return result
    def read(self,dest,size,count,handle,write):
        assert (dest,size,count,handle)==(self.image+0x3DE470,1,16,G+0x3F00)
        payload=bytes(16) if self.label=='zero_seed' else b'\xff'*16 if self.label=='high_seed' else SEED
        n=7 if self.label=='short_read' else 16
        write(dest,payload[:n]);self.events.append(['fread',dest,size,count,handle,n]);return n
    def closed(self,handle):
        assert handle==G+0x3F00;status=-1 if self.label=='close_failure' else 0
        self.events.append(['fclose',handle,status]);return status
    def file_services(self):
        return dict(fopen=lambda p,a,b:self.opened(a,b,lambda a,n:_read_span(p,a,n)),
            fread=lambda p,d,s,n,h:self.read(d,s,n,h,lambda a,b:_write_span(p,a,b)),
            fclose=lambda p,h:self.closed(h))
    def imports(self):
        def args(c,n):return [c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(n)]
        return {0x348460:lambda c:self.opened(*args(c,2),lambda a,n:bytes(c.mem_read(a,n))),
            0x348470:lambda c:self.read(*args(c,4),c.mem_write),
            0x348480:lambda c:self.closed(*args(c,1))&0xFFFFFFFF,
            0x347FA0:self.native_free}


def fixture(library,image,label):
    p=fresh(library,image);output=G+0x2FF8 if label=='cross_page_output' else OUT
    block=G+0x6FF8 if label=='cross_page_packed' else BLOCK
    mutex=G+0x3800;pair=G+0x3900;blocks={}
    if label in ('warm','warm_NULL','warm_NULL_count','output_cache_alias','output_pair_alias','guard_even','guard_pending'):
        for off in (0x3DE728,0x3DE738):w(p,image+off,0x101)
        w(p,image+0x3DE720,mutex);w(p,mutex,image+0x34C738);_write_span(p,mutex+8,bytes(40))
        w(p,image+0x3DE730,pair);w(p,pair,OBJECT if label!='warm_NULL' else 0)
        w(p,pair+8,0 if label=='warm_NULL_count' else COUNT);w(p,COUNT,3,4)
        _write_span(p,OBJECT,(image+0x34F5F8).to_bytes(8,'little')+b'\x06\0\0\0\x05\0\0\0'+DATA.to_bytes(8,'little'))
        _write_span(p,DATA,b'cache\0');blocks.update({OBJECT:24,COUNT:4,DATA:6})
        if label=='output_cache_alias':output=pair
        if label=='output_pair_alias':output=pair+8
        if label=='guard_even':w(p,image+0x3DE728,2,1);w(p,image+0x3DE738,2,1)
        if label=='guard_pending':w(p,image+0x3DE728,0x100);w(p,image+0x3DE738,0x100)
    if label=='seed_warm':w(p,image+0x3DE718,0x101);_write_span(p,image+0x3DE470,SEED)
    _write_span(p,block,(image+0x25BD8C).to_bytes(8,'little')+output.to_bytes(8,'little')+b'\x5a'*16)
    return p,dict(argument_block_address=block,entry_stack_address=SP,image_base=image,thread_pointer=TP,thread_id=137),blocks


def original(library,libc,image,label,p,kw,blocks=(),native=oracle.native):
    services=Services(image,label,blocks);steps=[0];seen=set()
    expected={0x2886B0,0x25BD8C,0x255CB4,0x255D84,0x255EC0,0x25BCE4,0x15F580,0x162620,0x1633B0}
    def observe(cpu,address):
        steps[0]+=1;off=address-image
        if off in expected:seen.add(off)
        if off in (0x347F00,0x347F10):services.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        elif off==0x348310:services.diagnostic('gettid',137)
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,0xA000):None,(kw['entry_stack_address']-0x60,24):None})
    _,_,allocations,ledger=native(library,image,0x2886B0,[kw['argument_block_address']],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={arm.UC_ARM64_REG_SP:kw['entry_stack_address'],arm.UC_ARM64_REG_TPIDR_EL0:kw['thread_pointer']},
        thread_id=137,host_imports=services.imports(),malloc_handler=services.native_malloc,
        instruction_limit=200000,instruction_observer=observe,observed_memory=watch)
    assert {0x2886B0,0x25BD8C,0x15F580}<=seen
    return watch,services,steps[0],seen


def red(library,libc):
    assert importlib.util.find_spec('vm9_request_identifier') is None
    rows=[]
    for image in BASES:
        p,kw,blocks=fixture(library,image,'cold');watch,s,steps,seen=original(library,libc,image,'cold',p,kw,blocks)
        assert {0x255CB4,0x255D84,0x255EC0,0x25BCE4,0x162620,0x1633B0}<=seen
        assert [e[0] for e in s.events if e[0].startswith('f')]==['fopen','fread','fclose']
        rows.append(dict(image_base=hex(image),previous_identifier_owner_missing=True,
            original_cold_wrapper_factory_formatter_and_cache_returned=True,
            explicit_seed_file_provider_used=True,native_instructions=steps,native_snapshot_input=False))
    return rows


def compare(library,libc,image,label):
    import vm9_request_identifier as model
    p,kw,blocks=fixture(library,image,label);watch,expected,steps,seen=original(library,libc,image,label,p,kw,blocks)
    actual=Services(image,label,blocks)
    model.apply_request_identifier_callback(p,**kw,allocate=actual.malloc,free=actual.free,
        file_services=actual.file_services(),diagnostic_observer=actual.diagnostic)
    for (a,n),b in watch.items():
        own=_read_span(p,a,n)
        if own!=b:
            first=next(i for i,(x,y) in enumerate(zip(own,b)) if x!=y)
            raise AssertionError((label,hex(a+first),own[first:first+24].hex(),b[first:first+24].hex()))
    assert actual.events==expected.events,(label,'events',actual.events,expected.events)
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed
    print('PASS identifier',hex(image),label,steps,flush=True)
    return dict(image_base=hex(image),case=label,component='cache',native_instructions=steps,
        original_wrapper_factory_and_cache_returned=True,declared_guest_image_and_outer_scope_bytes_equal=True,
        ordered_file_allocation_free_and_lock_effects_equal=True,pre_free_bytes_equal=True,
        formatter_executed=0x255D84 in seen,native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def compare_format(library,libc,image,label):
    import vm9_request_identifier as model
    p=fresh(library,image);_write_span(p,image+0x3DE470,SEED)
    # Initialize from ELF bytes through the existing lazy-constant owner.
    from vm9_configuration_init import _lazy_constant
    _lazy_constant(p,image,0x3DE4A8,0x97ED0,0x3DE480,0x97F40)
    _lazy_constant(p,image,0x3DE4C4,0x97F00,0x3DE4B0,0x97F20)
    template={'format_32_nibbles':b'x'*32,'format_literal':b'fixed-literal','format_mixed':b'xy-x!y'}
    if label in template:_write_span(p,image+0x3DE480,template[label]+b'\0')
    output=image+{'format_template_alias':0x3DE480,'format_alphabet_alias':0x3DE4B0,'format_seed_alias':0x3DE470}[label] if label.endswith('_alias') else OUT
    watch={(page<<12,4096):None for page in p if image<=page<<12<image+0x400000}
    watch.update({(G,0xA000):None,(SP-0x50,16):None});steps=[0];advances=[0]
    def observe(cpu,address):steps[0]+=1;advances[0]+=address-image==0x255EC0
    oracle.native(library,image,0x255D84,[output],p,libc=libc,observed_memory=watch,
        instruction_observer=observe,instruction_limit=10000,
        extra_registers={arm.UC_ARM64_REG_SP:SP,arm.UC_ARM64_REG_TPIDR_EL0:TP})
    model.generate_identifier(p,output_address=output,entry_stack_address=SP,image_base=image)
    assert advances[0]==2 and all(_read_span(p,a,n)==b for (a,n),b in watch.items()),label
    print('PASS identifier formatter',hex(image),label,steps[0],flush=True)
    return dict(image_base=hex(image),case=label,component='formatter',native_instructions=steps[0],
        original_formatter_and_two_state_advances_returned=True,declared_guest_image_and_entropy_scratch_equal=True,
        explicit_template_alphabet_and_output_alias_order_equal=True,no_file_allocator_or_JNI_services=True,
        native_snapshot_input=False,physical_spills_and_PAC_compared=False)


def guards(library):
    import vm9_request_identifier as model
    rows=[]
    labels=('wrong_target','missing_packed','unaligned_stack','missing_output','output_spill_alias','packed_spill_alias',
        'first_guard_wait','second_guard_wait','missing_thread_id','missing_file_services','mutex_allocation_NULL',
        'cache_allocation_NULL','file_open_failure','file_read_failure','file_close_failure','invalid_read_count',
        'template_bound','entropy_bound','mutex_contention')
    for label in labels:
        p,kw,blocks=fixture(library,BASES[0],'warm' if label=='mutex_contention' else 'cold')
        actual=Services(BASES[0],'cold',blocks);services=actual.file_services();image=kw['image_base']
        if label=='wrong_target':w(p,BLOCK,image+1)
        elif label=='missing_packed':kw['argument_block_address']=G+0x10000
        elif label=='unaligned_stack':kw['entry_stack_address']+=1
        elif label=='missing_output':w(p,BLOCK+8,G+0x9000);del p[(G+0x9000)>>12]
        elif label=='output_spill_alias':w(p,BLOCK+8,SP-0x200)
        elif label=='packed_spill_alias':
            _write_span(p,SP-0x200,_read_span(p,BLOCK,16));kw['argument_block_address']=SP-0x200
        elif label=='first_guard_wait':w(p,image+0x3DE728,0x200)
        elif label=='second_guard_wait':w(p,image+0x3DE738,0x200)
        elif label=='missing_thread_id':kw['thread_id']=None
        elif label=='missing_file_services':services=None
        elif label in ('mutex_allocation_NULL','cache_allocation_NULL'):actual.effects.failures={0 if label=='mutex_allocation_NULL' else 1}
        elif label.startswith('file_'):
            key={'file_open_failure':'fopen','file_read_failure':'fread','file_close_failure':'fclose'}[label]
            original=services[key]
            def failed(*a,original=original):original(*a);raise RuntimeError('explicit file provider failure')
            services[key]=failed
        elif label=='invalid_read_count':services['fread']=lambda *a:None
        elif label=='template_bound':kw['max_template_bytes']=0
        elif label=='entropy_bound':
            w(p,image+0x3DE4A8,1,4);_write_span(p,image+0x3DE480,b'x'*33+b'\0')
        elif label=='mutex_contention':w(p,G+0x3808,1,2)
        before={k:bytes(v) for k,v in p.items()}
        try:model.apply_request_identifier_callback(p,**kw,allocate=actual.malloc,free=actual.free,
            file_services=services,diagnostic_observer=actual.diagnostic)
        except (RefillUnsupported,ValueError,TypeError,RuntimeError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('red','native','guards'),default='native')
    parser.add_argument('--case',action='append',choices=PROFILES+FORMAT_PROFILES);a=parser.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(a.libc.read_bytes()).hexdigest()==LIBC_SHA256
    e=dict(cases=[],negative_cases=[],red_cases=[],complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False,complete_second_vm_verified=False,complete_physical_ABI_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,allocator_provider_mapping_rollback_verified=False)
    if a.mode=='red':e['red_cases']=red(a.library,a.libc)
    elif a.mode=='native':
        for b in BASES:
            for n in (a.case or PROFILES+FORMAT_PROFILES):
                e['cases'].append((compare_format if n in FORMAT_PROFILES else compare)(a.library,a.libc,b,n))
                a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
    else:e['negative_cases']=guards(a.library)
    e.update(native_Python_controls=len(e['cases']),rollback_guards=len(e['negative_cases']))
    a.output.write_text(json.dumps(e,indent=2)+'\n',encoding='utf-8',newline='\n')
if __name__=='__main__':main()
