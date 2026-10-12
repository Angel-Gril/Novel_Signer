"""Original lazy state service versus an independent Python composition.

The fresh caller supplies an initialized singleton136 reference, matching
the outer-request prerequisite. Allocation/free, absent property, unavailable
file/socket and no-waiter futex results are explicit virtual services.
"""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,os
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_root_configuration as root
import verify_vm9_signer_objects as oracle
import vm9_state as state
import vm9_objects as objects
import vm9_configuration_init as configuration
import vm9_allocator as allocator
from verify_vm9_libc_mapping import LIBC_SHA256
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;SP=G+0xEF00;BASES=(0x122C0000,0x775C205000)


class Services:
    def __init__(self,base):
        self.base=base;self.allocator=oracle.Allocator();self.frees=[];self.registrations=[];self.wakes=[]
    def allocate(self,p,n):return self.allocator.model(p,n)
    def free(self,p,a):self.frees.append(a)
    def reallocate(self,*args):raise RefillUnsupported('state service has no observed realloc')
    def get_specific(self,p,key):return allocator.pthread_getspecific(p,key=key,thread_pointer=root.TLS,generation_table=root.LIBC_BASE+root.LIBC_PTHREAD_GENERATION_OFFSET)
    def set_specific(self,p,key,pointer):return allocator.pthread_setspecific(p,key=key,value=pointer,thread_pointer=root.TLS,generation_table=root.LIBC_BASE+root.LIBC_PTHREAD_GENERATION_OFFSET)
    def create_key(self,p,address,destructor):return allocator.pthread_key_create(p,key_address=address,destructor=destructor,generation_table=root.LIBC_BASE+root.LIBC_PTHREAD_GENERATION_OFFSET)
    def wake(self,p,*args):self.wakes.append(list(args));return 0
    def register(self,p,*args):self.registrations.append(list(args));return 0
    def get_tls(self,p,control):return objects.get_emulated_tls_address(p,control_address=control,image_base=self.base,
        allocate=self.allocate,reallocate=self.reallocate,get_specific=self.get_specific,set_specific=self.set_specific,
        create_key=self.create_key,once_wake=self.wake)
    def destructor(self,p,d,o,s):return objects.register_emulated_thread_destructor(p,destructor_address=d,object_address=o,
        image_base=self.base,allocate=self.allocate,get_tls=self.get_tls,create_key=self.create_key,set_specific=self.set_specific,
        register_atexit=self.register,thread_id=137)
    def init_registry(self,p):return objects.initialize_scoped_tls_registry(p,image_base=self.base,get_tls=self.get_tls,register_destructor=self.destructor)
    def broadcast(self,p,a):return objects.broadcast_condition_no_waiters(p,condition_address=a,wake=self.wake)
    def syscall(self,p,n,args):
        if n in (48,56,79):return -2
        if n in (57,63):return -9
        if n==198:return -97
        raise RefillUnsupported('unknown virtual state service syscall')
    def mkdir(self,p,a,b):_write_span(p,root.TLS+0x100,(17).to_bytes(4,'little'));return 0xFFFFFFFF
    def prepare(self,p):return configuration.prepare_bionic_format_locale(p,once_address=root.LIBC_BASE+0xDE938,
        key_address=root.LIBC_BASE+0xDE930,generation_table=root.LIBC_BASE+root.LIBC_PTHREAD_GENERATION_OFFSET,
        thread_pointer=root.TLS,wake=self.wake)
    def execute(self,p,**options):
        import vm_full
        kw=dict(entry_stack_address=SP,thread_pointer=root.TLS,image_base=self.base,vm_module=vm_full,
            allocate=self.allocate,reallocate=self.reallocate,free=self.free,get_tls=self.get_tls,
            initialize_registry=self.init_registry,broadcast=self.broadcast,read_property=lambda p,n:None,
            syscall=self.syscall,errno_address=root.TLS+0x100,mkdir=self.mkdir,register_destructor=self.register,
            thread_id=137,prepare_format=self.prepare)
        kw.update(options);return state.get_state_service_reference(p,**kw)


def fresh(library,libc,base,label):
    p,_,sdk=root.fresh_inputs(library,base=base,property_value=None)
    p.update(oracle.image_pages(libc,root.LIBC_BASE))
    def w(a,v):_write_span(p,a,v.to_bytes(8,'little'))
    wrapper,payload,counter=G+0x3000,G+0x3100,G+0x3200
    _write_span(p,payload,bytes(136));w(payload,base+0x34C7B8)
    w(wrapper,payload);w(wrapper+8,counter);_write_span(p,counter,(1).to_bytes(4,'little'))
    w(base+0x3D1678,wrapper);_write_span(p,base+0x3D1680,b'\x01\x01')
    if label=='decoded_key':
        objects.decode_masked_bytes(p,source_address=base+0xA4674,destination_address=base+0x3DED4C,mask_address=base+0xA4688)
        _write_span(p,base+0x3DED50,(1).to_bytes(4,'little'))
    if label=='warm':Services(base).execute(p)
    if label=='warm_NULL_slot':_write_span(p,base+0x3DED68,b'\x01\x01')
    return p,sdk


def native(library,libc,base,p,sdk):
    with libc.open('rb') as stream:
        elf=ELFFile(stream);exports={s.name:root.LIBC_BASE+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    frees=[];registrations=[];wakes=[];clocks=[];observed={};cpus=[]
    def redirect(name):
        def call(c):c.reg_write(arm.UC_ARM64_REG_PC,exports[name])
        return call
    def free(c):frees.append(c.reg_read(arm.UC_ARM64_REG_X0));return 0
    def register(c):registrations.append([c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]);return 0
    def clock(c):
        clock_id=c.reg_read(arm.UC_ARM64_REG_X0);assert clock_id in (0,1);clocks.append(clock_id)
        c.mem_write(c.reg_read(arm.UC_ARM64_REG_X1),(1791023800).to_bytes(8,'little')+(500000000).to_bytes(8,'little'));return 0
    def mkdir(c):c.mem_write(root.TLS+0x100,(17).to_bytes(4,'little'));return 0xFFFFFFFF
    def find(c):assert bytes(c.mem_read(c.reg_read(arm.UC_ARM64_REG_X0),len(sdk)+1))==sdk+b'\0';return 0
    def syscall(c,n):
        if n in (48,56,79):return -2
        if n in (57,63):return -9
        if n==198:return -97
        if n==98 and c.reg_read(arm.UC_ARM64_REG_X1)&0x7F==1:
            wakes.append([c.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(3)]);return 0
        raise RefillUnsupported('unknown virtual native state syscall')
    imports={0x347FA0:free,0x347EA0:register,0x348450:clock,0x3484A0:mkdir,
        0x3481A0:lambda c:root.TLS+0x100,0x348250:find}
    for offset,name in ((0x3484B0,'strtol'),(0x3486B0,'pthread_once'),(0x348620,'pthread_key_create'),
        (0x3485D0,'pthread_getspecific'),(0x348580,'pthread_setspecific'),(0x3485A0,'pthread_cond_broadcast'),
        (0x347FE0,'memcmp'),(0x347F70,'vsnprintf')):imports[offset]=redirect(name)
    for page in p:
        if base<=page<<12<base+0x400000:observed[page<<12,4096]=None
    observed[root.TLS,0xB00]=None
    def see(c,a):
        if not cpus:cpus.append(c)
        assert c.reg_read(arm.UC_ARM64_REG_SP)>root.TLS+0xB00
    # Let the oracle load and resolve libc's own imports. The Python-only ELF
    # data pages must not overwrite those native loader relocations.
    native_pages={page:data for page,data in p.items() if not root.LIBC_BASE<=page<<12<root.LIBC_BASE+0x200000}
    result,memory,allocations,ledger=oracle.native(library,base,0x26A3AC,[],native_pages,libc=libc,real_singletons=True,
        real_mutexes=True,thread_id=137,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:root.TLS},
        host_imports=imports,syscall_handler=syscall,instruction_observer=see,observed_memory=observed,instruction_limit=500000)
    return result,memory,allocations,frees,registrations,wakes,clocks,observed


def compare(library,libc,base,label):
    p,sdk=fresh(library,libc,base,label);initial={k:bytearray(v) for k,v in p.items()}
    returned,memory,allocations,frees,regs,wakes,clocks,observed=native(library,libc,base,initial,sdk)
    model=Services(base);result=model.execute(p)
    assert result.wrapper_address==returned
    assert model.allocator.calls==allocations and model.frees==frees
    assert model.registrations==regs and model.wakes==wakes
    assert _read_span(p,G,0xA000)==memory
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    print('PASS state service',hex(base),label,len(allocations),'allocations',flush=True)
    return dict(image_base=hex(base),case=label,original_service_returned=True,
        warm_singleton136_is_explicit_input=True,cold_state_service=label in ('cold','decoded_key'),
        return_guest_data_ELF_and_TLS_pages_match=True,allocation_free_registration_wake_order_match=True,
        allocations=len(allocations),frees=len(frees),registrations=len(regs),wakes=len(wakes),
        native_clock_calls=len(clocks),native_snapshot_input=False)


def guards(library,libc):
    rows=[]
    for label in ('cold_sdk','guard_wait','unaligned_stack','missing_tid','wrapper_NULL','payload_NULL','invalid_stack'):
        base=BASES[0];p,_=fresh(library,libc,base,'cold');model=Services(base);kw={}
        if label=='cold_sdk':_write_span(p,base+0x3D1680,bytes(8))
        elif label=='guard_wait':_write_span(p,base+0x3DED68+1,b'\x02')
        elif label=='unaligned_stack':kw['entry_stack_address']=SP-1
        elif label=='missing_tid':kw['thread_id']=None
        elif label.endswith('_NULL'):
            old=model.allocate;index=[0];fail=0 if label=='wrapper_NULL' else 1
            def allocate(p,n):
                i=index[0];index[0]+=1;return 0 if i==fail else old(p,n)
            kw['allocate']=allocate
        else:kw['entry_stack_address']=G+0x100000
        before={k:bytes(v) for k,v in p.items()}
        try:model.execute(p,**kw)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS state service guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    cases=[];negative=[]
    if args.group in ('native','all'):
        for base in BASES:
            for label in ('cold','decoded_key','warm','warm_NULL_slot'):cases.append(compare(args.library,args.libc,base,label))
    if args.group in ('guards','all'):negative=guards(args.library,args.libc)
    args.output.write_text(json.dumps(dict(component='Lazy state service with warm singleton136',cases=cases,
        native_Python_controls=len(cases),negative_cases=negative,rollback_guards=len(negative),
        native_input_snapshot_used=False,uninitialized_singleton136_supported=False,
        actual_request_callback_restored=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS state service',len(cases),'controls',len(negative),'guards',flush=True)


if __name__=='__main__':main()
