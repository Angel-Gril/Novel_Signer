"""Fresh request version initializer/getter versus original ARM64 and libc atoi.

Allocation and strdup are explicit synthetic services. Native atoi and guard
mutexes execute matching libc code. Private constants stay in guest pages.
"""
from pathlib import Path
import argparse,hashlib,json,os,re
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_configuration_init as model
import vm9_objects as objects
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;DATA=G+0x2100;STATUS=G+0x2600;BASES=(0x122C0000,0x775C205000)


class Services(dependency.Services):
    def __init__(self,base,label):super().__init__();self.base=base;self.label=label;self.decimals=[]
    def mutate(self,write):
        if self.label=='reloaded_status_slot':write(self.base+0x379930,(STATUS+0x912040).to_bytes(8,'little'))
    def duplicate(self,c):
        a=c.reg_read(arm.UC_ARM64_REG_X0);n=0
        while c.mem_read(a+n,1)!=b'\0':n+=1
        pointer=self.native_malloc(c,n+1);c.mem_write(pointer,bytes(c.mem_read(a,n+1)))
        self.mutate(lambda a,b:c.mem_write(a,b));return pointer
    def allocate(self,p,n):
        pointer=self.malloc(p,n)
        if len(self.effects.calls)==1:self.mutate(lambda a,b:_write_span(p,a,b))
        return pointer
    def decimal(self,p,a):
        self.decimals.append(a);data=objects._cstring(p,a,1024)
        match=re.match(rb'[ \t\n\r\v\f]*([+-]?[0-9]+)',data)
        return (int(match.group(1)) if match else 0)&0xFFFFFFFF


def fixture(library,base,kind,label):
    p=dependency.fresh(library,base)
    version={'default':b'v12.34.56','signed':b'v-1.+2.-3','spaces':b'v 7. 9.17',
        'nonnumeric':b'vxx.yy.tail','large_component':b'v99.88.4294967295'}.get(label,b'v12.34.56')
    _write_span(p,DATA,version+b'\0');dependency.w(p,base+0x379908,DATA)
    # Warm the service owner except in the explicit cold-service profile.
    if label!='cold_service':
        dependency.w(p,base+0x3D18D8,0x101);dependency.w(p,base+0x3D18D0,G+0x2400);dependency.w(p,G+0x2400,G+0x2500)
    dependency.w(p,base+0x3DE4D8,1,4)
    _write_span(p,base+0x3DE4D4,b'e\0' if label=='environment_e' else b'x\0')
    destination=(dependency.u(p,base+0x379940)-0x912040)&model.MASK64
    flag=(dependency.u(p,base+0x379948)-0x912040)&model.MASK64
    dependency.w(p,flag,1,4)
    identifier={'platform_i':b'i','platform_l':b'l','platform_w':b'w'}.get(label,b'a')
    _write_span(p,destination,identifier+b'\0')
    _write_span(p,base+0x3D18F0,b'\xA5'*8)
    if kind=='warm':
        value={'zero':0,'small':17,'signed_max':0x7FFFFFFF,'signed_min':0x80000000,
            'all_bits':0xFFFFFFFF,'guard_byte_two':91,'completed_second_byte':123}[label]
        dependency.w(p,base+0x3D18EC,value,4)
        dependency.w(p,base+0x3D18F8,2 if label=='guard_byte_two' else 0x100 if label=='completed_second_byte' else 1)
        dependency.w(p,base+0x379908,0x66000000)
    return p


def native(library,libc,base,p,kind,label):
    service=Services(base,label);observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    with libc.open('rb') as f:
        elf=ELFFile(f);atoi=next(0x51000000+s['st_value'] for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='atoi' and s['st_shndx']!='SHN_UNDEF')
    def decimal(c):
        service.decimals.append(c.reg_read(arm.UC_ARM64_REG_X0));c.reg_write(arm.UC_ARM64_REG_PC,atoi)
    returned,memory,_,_=oracle.native(library,base,0x172F2C if kind=='initializer' else 0x172AF4,[],p,
        libc=libc,real_singletons=True,real_mutexes=True,thread_id=137,malloc_handler=service.native_malloc,
        host_imports={0x347F80:service.duplicate,0x347F90:decimal,0x347FA0:service.native_free},
        extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},observed_memory=observed,instruction_limit=100000)
    return returned,memory,observed,service


def invoke(p,s,base,kind,changes=None):
    kw=dict(image_base=base,allocate=s.allocate,free=s.free,parse_decimal=s.decimal,thread_id=137)
    kw.update(changes or {})
    return (model.initialize_request_version_word if kind=='initializer' else model.get_request_version_word)(p,**kw)


def compare(library,libc,base,kind,label):
    p=fixture(library,base,kind,label);returned,memory,observed,expected=native(library,libc,base,p,kind,label)
    actual=Services(base,label);result=invoke(p,actual,base,kind)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((kind,label,'guest',hex(i),own[i],memory[i]))
    for (a,n),data in observed.items():
        if _read_span(p,a,n)!=data:
            got=_read_span(p,a,n);i=next(i for i,(x,y) in enumerate(zip(got,data)) if x!=y)
            raise AssertionError((kind,label,'image',hex(a-base+i),got[i],data[i]))
    assert returned==result and actual.events==expected.events and actual.decimals==expected.decimals
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed
    if kind=='getter':assert dependency.u(p,STATUS if label=='reloaded_status_slot' else base+0x3D18F0,4)==1
    if kind=='warm':assert not actual.events and not actual.decimals
    print('PASS request version',hex(base),kind,label,flush=True)
    return dict(image_base=hex(base),operation=kind,case=label,original_returned=True,
        uint32_return_and_full_guest_ELF_bytes_match=True,ordered_string_allocator_and_atoi_effects_match=True,
        freed_duplicate_bytes_match=True,native_snapshot_input=False)


def profiles():
    return [('initializer',label) for label in ('default','signed','spaces','nonnumeric','large_component',
        'environment_e','platform_i','platform_l','platform_w','cold_service')]+[
        ('getter',label) for label in ('default','cold_service','reloaded_status_slot')]+[
        ('warm',label) for label in ('zero','small','signed_max','signed_min','all_bits','guard_byte_two','completed_second_byte')]


def guards(library):
    rows=[]
    for label in ('contended_guard','unmapped_version','short_version','scan_bound','missing_allocator',
            'missing_free','missing_decimal','NULL_duplicate','invalid_decimal','unmapped_status_slot'):
        base=BASES[0];p=fixture(library,base,'getter','default');service=Services(base,'default');kw={}
        if label=='contended_guard':dependency.w(p,base+0x3D18F8,0x200)
        elif label=='unmapped_version':dependency.w(p,base+0x379908,0x66000000)
        elif label=='short_version':_write_span(p,DATA,b'x\0')
        elif label=='scan_bound':kw['max_bytes']=8
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='missing_free':kw['free']=None
        elif label=='missing_decimal':kw['parse_decimal']=None
        elif label=='NULL_duplicate':kw['allocate']=lambda p,n:0
        elif label=='invalid_decimal':kw['parse_decimal']=lambda p,a:1<<32
        else:dependency.w(p,base+0x379930,0x66000000+0x912040)
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,service,base,'getter',kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS request version guard',label,flush=True)
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
    args.output.write_text(json.dumps(dict(component='Request packed version initializer and getter',cases=rows,
        native_Python_controls=len(rows),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
