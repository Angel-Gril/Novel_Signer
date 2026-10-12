"""Fresh actual request TLS uint32 setter with matching libc TLS execution."""
from pathlib import Path
import argparse,hashlib,json,os
import verify_vm9_request_TLS_word_fresh_20261012 as dependency
from vm9_allocator import _PageTransaction,_read_span,_write_span


def fresh(library,libc,base,warm,value):
    p,model=dependency.fresh(library,libc,base,'warm_small' if warm else 'cold')
    _write_span(p,dependency.PACKED,(base+0x27ED70).to_bytes(8,'little'))
    _write_span(p,dependency.PACKED+16,value.to_bytes(4,'little'))
    return p,model


def native(library,libc,base,p,model):
    old=dependency.oracle.native
    def original(lib,image,function,args,pages,**kw):
        assert function==0x285E54 and args==[dependency.PACKED]
        return old(lib,image,0x285E70,args,pages,**kw)
    try:
        dependency.oracle.native=original
        return dependency.native(library,libc,base,p,model)
    finally:dependency.oracle.native=old


def compare(library,libc,base,warm,value):
    p,model=fresh(library,libc,base,warm,value)
    returned,memory,observed,allocations,wakes=native(library,libc,base,p,model)
    n=len(model.allocator.calls);w=len(model.wakes)
    staged=_PageTransaction(p);pointer=model.get_tls(staged,base+dependency.CONTROL)
    _write_span(staged,pointer,value.to_bytes(4,'little'));staged.commit()
    assert pointer==returned and _read_span(p,dependency.G,0xA000)==memory
    assert all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert model.allocator.calls[n:]==allocations and model.wakes[w:]==wakes
    assert _read_span(p,dependency.PACKED+20,12)==b'\xA5'*12
    print('PASS request TLS store',hex(base),warm,hex(value),flush=True)
    return dict(image_base=hex(base),warm_TLS=warm,value_u32=hex(value),original_request_wrapper_returned=True,
        uint32_TLS_store_guest_ELF_and_packed_input_match=True,allocation_and_wake_order_match=True,
        original_TLS_and_matching_libc_executed=True,ignored_receiver_unmapped=True,native_snapshot_input=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--libc',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==dependency.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==dependency.LIBC_SHA256
    os.environ['TOMATO_LIBMETASEC']=str(args.library.resolve())
    import vm_full
    assert Path(vm_full.__file__).resolve().parent==Path(__file__).resolve().parent
    rows=[compare(args.library,args.libc,base,warm,value) for base in dependency.dependency.BASES
        for warm in (False,True) for value in (0,17,0x7FFFFFFF,0x80000000,0xFFFFFFFF)]
    args.output.write_text(json.dumps(dict(component='Actual request TLS uint32 setter',cases=rows,
        native_Python_controls=len(rows),native_input_snapshot_used=False,whole_physical_stack_bytes_compared=False,
        whole_request_native_differential_verified=False,complete_python_medusa=False,fresh_signer_output_verified=False,
        live_server_matrix_verified=False),indent=2)+'\n',encoding='utf-8',newline='\n')


if __name__=='__main__':main()
