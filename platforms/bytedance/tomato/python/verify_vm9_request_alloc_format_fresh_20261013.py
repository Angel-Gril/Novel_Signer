"""Fresh two-pass allocated printf versus the original request formatter.

Guest printf executes naturally. Allocation is an explicit synthetic input;
native output does not seed Python. Compare all guest/image bytes and effects.
"""
from pathlib import Path
import argparse,hashlib,json,os
from unicorn import arm64_const as arm
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import vm9_configuration_init as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OUT=G+0x1000;FMT=G+0x1800;DATA=G+0x2000;SECOND=G+0x2100
BASES=(0x122C0000,0x775C205000)


class Services(dependency.Services):
    def __init__(self,label):super().__init__(failures=(0,) if label=='NULL_malloc' else ());self.label=label
    def mutate(self,write):
        if self.label=='second_pass_longer':write(DATA,b'longer revised content\0')
        elif self.label=='second_pass_shorter':write(DATA,b'x\0')
        elif self.label=='format_changes':write(FMT,b'changed:%s!\0')
    def malloc(self,p,size):
        pointer=super().malloc(p,size);self.mutate(lambda a,b:_write_span(p,a,b));return pointer
    def native_malloc(self,c,size):
        pointer=super().native_malloc(c,size);self.mutate(lambda a,b:c.mem_write(a,b));return pointer


def fixture(library,base,label):
    p=dependency.fresh(library,base);destination=OUT;fmt=b'%s';data=b'fixture';arguments=(DATA,)
    if label.startswith('length_'):data=bytes(65+i%26 for i in range(int(label[7:])))
    elif label=='empty_format':fmt=b''
    elif label=='literal':fmt=b'literal';arguments=()
    elif label=='percent':fmt=b'%%:%s:%%'
    elif label=='two_strings':fmt=b'%s/%s';arguments=(DATA,SECOND)
    elif label=='decimal_signed':fmt=b'%d/%s';arguments=(0xFFFFFFFF,DATA)
    elif label=='decimal_min':fmt=b'%d';arguments=(0x1234567880000000,)
    elif label=='embedded_NUL':data=b'a\0tail'
    elif label=='output_source_alias':destination=DATA
    elif label=='output_cross_page':destination=G+0x1FFC
    _write_span(p,FMT,fmt+b'\0');_write_span(p,DATA,data+b'\0');_write_span(p,SECOND,b'second\0')
    return p,destination,arguments


def native(library,base,p,label,destination,arguments):
    service=Services(label);observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    returned,memory,_,_=oracle.native(library,base,0x278314,[destination,FMT,*arguments],p,
        malloc_handler=service.native_malloc,extra_registers={arm.UC_ARM64_REG_TPIDR_EL0:dependency.TP},
        observed_memory=observed,instruction_limit=150000)
    return returned,memory,observed,service


def compare(library,base,label):
    p,destination,arguments=fixture(library,base,label);returned,memory,observed,expected=native(library,base,p,label,destination,arguments)
    actual=Services(label)
    result=model.allocate_printf_cstring(p,output_pointer_address=destination,format_address=FMT,
        argument_addresses=arguments,allocate=actual.malloc)
    own=_read_span(p,G,0xA000)
    if own!=memory:
        i=next(i for i,(a,b) in enumerate(zip(own,memory)) if a!=b);raise AssertionError((label,'guest',hex(i),own[i],memory[i]))
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert returned&0xFFFFFFFF==result and actual.events==expected.events
    assert actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    print('PASS allocated printf',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_returned=True,
        uint32_return_and_full_guest_ELF_bytes_match=True,two_pass_live_inputs_match=True,
        allocator_effects_and_publication_match=True,native_snapshot_input=False)


def profiles():
    return tuple('length_'+str(n) for n in (0,1,7,32,128))+('empty_format','literal','percent','two_strings',
        'decimal_signed','decimal_min','embedded_NUL','second_pass_longer','second_pass_shorter','format_changes',
        'NULL_malloc','output_source_alias','output_cross_page')


def guards(library):
    rows=[]
    for label in ('unmapped_format','unmapped_argument','unmapped_output','unmapped_buffer',
            'unsupported_conversion','scan_bound','missing_allocator','invalid_allocation','invalid_bound'):
        base=BASES[0];p,destination,arguments=fixture(library,base,'length_32');s=Services('length_32')
        kw=dict(output_pointer_address=destination,format_address=FMT,argument_addresses=arguments,allocate=s.malloc)
        if label=='unmapped_format':kw['format_address']=0x66000000
        elif label=='unmapped_argument':kw['argument_addresses']=(0x66000000,)
        elif label=='unmapped_output':kw['output_pointer_address']=0x66000000
        elif label=='unmapped_buffer':kw['allocate']=lambda p,n:0x66000000
        elif label=='unsupported_conversion':_write_span(p,FMT,b'%x\0')
        elif label=='scan_bound':kw['max_bytes']=8
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='invalid_allocation':kw['allocate']=lambda p,n:1<<64
        else:kw['max_bytes']=-1
        before={k:bytes(v) for k,v in p.items()}
        try:model.allocate_printf_cstring(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS allocated printf guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','guards','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];negative=[]
    if args.group in ('native','all'):rows=[compare(args.library,base,label) for base in BASES for label in profiles()]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request allocated printf C string',cases=rows,
        native_Python_controls=len(rows),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
