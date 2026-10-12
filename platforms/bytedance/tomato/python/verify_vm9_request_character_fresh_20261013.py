"""Fresh single-byte StringObject construction and actual request consumer.

Compare the live ELF fields, malloc publication, pointer/field aliases and all
semantic guest/image bytes. Allocator effects are independent synthetic inputs.
Physical spills, actual JNI and whole-request signing remain outside this gate.
"""
from pathlib import Path
import argparse,ast,hashlib,inspect,json,os
from types import SimpleNamespace
import verify_vm9_reference_scopes_fresh_20261011 as dependency
import verify_vm9_signer_objects as oracle
import verify_vm9_request_prefix_fresh_20261007 as prefix
import vm9_objects as model
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;OUT=G+0x1000;BASES=(0x122C0000,0x775C205000)


def fixture(library,base,label):
    p=dependency.fresh(library,base);out=G+0x1FF8 if label=='object_cross_page' else OUT
    value={'zero':0,'one':1,'high7':0x7F,'high8':0x80,'all8':255,'wide_word':0x123456AB}.get(label,0x41)
    if label=='changed_ELF_word':_write_span(p,base+0x6E170,bytes(range(8)))
    return p,out,value


class Services:
    def __init__(self,base,label,out):self.base=base;self.label=label;self.out=out;self.events=[]
    def invoke(self,write,size):
        assert size==2
        pointer=0 if self.label=='NULL_malloc' else self.out+16 if self.label=='buffer_object_alias' else G+0x4000
        self.events.append([size,pointer])
        if self.label=='allocator_changes_fields':write(self.out+8,bytes(range(8)))
        elif self.label=='ELF_changes_after_read':write(self.base+0x6E170,bytes(range(8)))
        return pointer
    def malloc(self,p,n):return self.invoke(lambda a,b:_write_span(p,a,b),n)
    def native_malloc(self,c,n):return self.invoke(lambda a,b:c.mem_write(a,b),n)


def compare(library,base,label):
    p,out,value=fixture(library,base,label);actual=Services(base,label,out);expected=Services(base,label,out)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    returned,memory,_,_=oracle.native(library,base,0x2482EC,[out,value],p,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=10000)
    result=model.construct_character_string_object(p,object_address=out,value_u32=value,image_base=base,allocate=actual.malloc)
    assert _read_span(p,G,0xA000)==memory and result==returned and actual.events==expected.events
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    print('PASS character string',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_constructor_returned=True,
        pointer_return_and_all_guest_ELF_bytes_match=True,live_fields_low_byte_and_ordered_publication_match=True,native_snapshot_input=False)


def consumer(p,base,s,packed,source=None):
    tree=ast.parse(inspect.getsource(prefix.execute_prefix) if source is None else source)
    callback=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='callback')
    tx=prefix._PageTransaction(p);ns=dict(vars(prefix));ns.update(image=base,ledger=[],decoded=[],allocate=s.malloc,
        free=None,diagnostic_scope={})
    exec(compile(ast.Module(body=[callback],type_ignores=[]),str(Path(prefix.__file__).resolve()),'exec'),ns)
    ns['callback'](SimpleNamespace(m=SimpleNamespace(pages=tx,u64=lambda a:dependency.u(tx,a))),base+0x285E98,packed)
    tx.commit()


def compare_callback(library,base,label):
    p,out,value=fixture(library,base,label);packed=G+0x1200
    _write_span(p,packed,(base+0x2482EC).to_bytes(8,'little')+out.to_bytes(8,'little')+bytes([value&255])+b'\xA5'*15)
    actual=Services(base,label,out);expected=Services(base,label,out)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    _,memory,_,_=oracle.native(library,base,0x285E98,[packed],p,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_limit=10000)
    consumer(p,base,actual,packed)
    assert _read_span(p,G,0xA000)==memory and actual.events==expected.events
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    print('PASS character source callback',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,original_character_wrapper_returned=True,
        source_callback_executed=True,packed_bytes_and_all_guest_ELF_bytes_match=True,allocation_match=True,native_snapshot_input=False)


def guards(library):
    rows=[];base=BASES[0]
    for label in ('unmapped_ELF_fields','unmapped_output','missing_allocator','negative_word','oversized_word','invalid_pointer','unmapped_buffer'):
        p,out,value=fixture(library,base,'one');s=Services(base,'one',out)
        kw=dict(object_address=out,value_u32=value,image_base=base,allocate=s.malloc)
        if label=='unmapped_ELF_fields':del p[(base+0x6E170)>>12]
        elif label=='unmapped_output':kw['object_address']=0x66000000
        elif label=='missing_allocator':kw['allocate']=None
        elif label=='negative_word':kw['value_u32']=-1
        elif label=='oversized_word':kw['value_u32']=1<<32
        elif label=='invalid_pointer':kw['allocate']=lambda p,n:1<<64
        elif label=='unmapped_buffer':kw['allocate']=lambda p,n:0x66000000
        before={k:bytes(v) for k,v in p.items()}
        try:model.construct_character_string_object(p,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError('guard accepted '+label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_effects_rolled_back=False))
        print('PASS character guard',label,flush=True)
    return rows


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--group',choices=('native','guards','callback','all'),default='native');args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[];callbacks=[];negative=[]
    if args.group in ('native','all'):
        profiles=('zero','one','high7','high8','all8','wide_word','NULL_malloc','changed_ELF_word',
            'object_cross_page','allocator_changes_fields','buffer_object_alias','ELF_changes_after_read')
        rows=[compare(args.library,base,label) for base in BASES for label in profiles]
    if args.group in ('callback','all'):callbacks=[compare_callback(args.library,base,label) for base in BASES for label in ('zero','all8','NULL_malloc')]
    if args.group in ('guards','all'):negative=guards(args.library)
    args.output.write_text(json.dumps(dict(component='Request character StringObject',cases=rows,callback_cases=callbacks,
        native_Python_controls=len(rows)+len(callbacks),negative_cases=negative,rollback_guards=len(negative),native_input_snapshot_used=False,
        private_names_or_payloads_published=False,whole_physical_stack_bytes_compared=False,complete_request_transform_caller=False,
        constructed_prefix_native_differential_verified=False,whole_request_native_differential_verified=False,
        actual_URL_header_JNI_conversion_verified=False,live_Android_JVM_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
