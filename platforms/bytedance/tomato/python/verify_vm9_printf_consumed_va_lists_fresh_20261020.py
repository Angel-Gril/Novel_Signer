"""Second printf's two consumed AArch64 va_list copies at real boundaries.

Native output is comparison only. Other GP/FP spills remain outside this gate.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_printf_saved_varargs_fresh_20261020 as saved
from vm9_allocator import _read_span,_write_span,RefillUnsupported
G=saved.G;TP=saved.TP;BASES=saved.BASES
PROFILES=('literal','string','signed','unsigned_long_long','to_literal','to_string','output_format_alias','NULL_malloc')
def cells(stack):return ((stack-0xC0,32),(stack-0xE0,32))
def snapshot(pages,stack):return [_read_span(pages,a,n).hex() for a,n in cells(stack)]
def fixture(library,image,label):
    p,block=saved.setup.fixture(library,image,'literal' if label in ('literal','to_string') else 'length_32')
    if label=='literal':
        _write_span(p,saved.setup.FMT,b'%%s:literal\0')
        _write_span(p,block+24,(0xFEDCBA9876543210).to_bytes(8,'little'))
    if label=='to_string':_write_span(p,block+24,saved.setup.DATA.to_bytes(8,'little'))
    if label=='signed':
        _write_span(p,saved.setup.FMT,b'%d\0');_write_span(p,block+24,(0x12345678FFFFFFFF).to_bytes(8,'little'))
    if label=='unsigned_long_long':
        _write_span(p,saved.setup.FMT,b'%llu\0');_write_span(p,block+24,(0xFEDCBA9876543210).to_bytes(8,'little'))
    if label=='output_format_alias':_write_span(p,block+8,saved.setup.FMT.to_bytes(8,'little'))
    return p,block
def invoke(pages,image,block,stack,allocate):
    return saved.second.apply_request_287474_allocated_printf_callback(pages,argument_block_address=block,
        entry_stack_address=stack,image_base=image,thread_pointer=TP,allocate=allocate)
def compare(library,image,label,stack):
    p,block=fixture(library,image,label);before=[];after=[];model_before=[];stages=[]
    expected=saved.formatting.Services('NULL_malloc' if label=='NULL_malloc' else 'length_32')
    actual=saved.formatting.Services('NULL_malloc' if label=='NULL_malloc' else 'length_32')
    def mutate(write):
        if label=='to_literal':write(saved.setup.FMT,b'%%s:changed literal\0')
        elif label=='to_string':write(saved.setup.FMT,b'changed:%s\0')
    def observe(cpu,address):
        if address-image in (0x2772A4,0x2783AC,0x2783DC):
            stages.append(dict(PC=hex(address-image),X3=hex(cpu.reg_read(arm.UC_ARM64_REG_X3)),
                cells=[bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)]))
    def native_malloc(cpu,size):
        before.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
        value=expected.native_malloc(cpu,size);mutate(lambda a,b:cpu.mem_write(a,b))
        after.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)]);return value
    observed={cell:None for cell in cells(stack)}
    result,payload,_,_=saved.oracle.native(library,image,0x288AD4,[block],p,malloc_handler=native_malloc,
        extra_registers={arm.UC_ARM64_REG_SP:stack,arm.UC_ARM64_REG_TPIDR_EL0:TP},
        observed_memory=observed,instruction_observer=observe,instruction_limit=200000)
    def allocate(tx,size):
        model_before.append(snapshot(tx,stack));value=actual.malloc(tx,size)
        mutate(lambda a,b:_write_span(tx,a,b));return value
    value=invoke(p,image,block,stack,allocate)
    assert before==model_before,(label,'consumed va_list before malloc')
    final=snapshot(p,stack)
    assert final==[observed[cell].hex() for cell in cells(stack)],(label,'final consumed va_list copies')
    assert value==result&0xFFFFFFFF and _read_span(p,G,0xA000)==payload
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    assert stages[0]['X3']==hex(stack-0xC0)
    assert stages[1]['cells']==before[0] and len(stages)==(2 if label=='NULL_malloc' else 4)
    if label!='NULL_malloc':assert stages[2]['X3']==hex(stack-0xE0) and stages[3]['cells']==final
    print('PASS consumed va_list',hex(image),label,hex(stack),flush=True)
    return dict(image_base=hex(image),case=label,split_stack_layout=bool(stack&0xFFF),
        original_formatter_boundaries_observed=True,allocation_entry_state_equal=True,
        final_two_va_list_cells_equal=True,return_payload_allocator_effects_equal=True,
        native_snapshot_input=False)
def guards(library):
    import vm9_configuration_init as configuration
    rows=[];image=BASES[0];stack=G+0xC0D0
    for label in ('provider_failure','provider_changes_source','allocation_spill'):
        p,block=fixture(library,image,'string');calls=[]
        def allocate(tx,size):
            calls.append(size)
            if label=='provider_changes_source':
                _write_span(tx,stack-0x78+24,(-32).to_bytes(4,'little',signed=True));return G+0x9000
            if label=='allocation_spill':return stack-0xE0
            raise RefillUnsupported('declared provider exception')
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,image,block,stack,allocate)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label+' was accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    for label in ('bad_frame_shape','overlapping_frame','missing_source','missing_first','missing_second','wrong_GP_offset','too_many_GP_arguments'):
        p,block=fixture(library,image,'string');source=G+0xD000;first=G+0xE000;second=G+0xF000
        for address in (source,first,second):p[address>>12]=bytearray(4096)
        descriptor=b''.join(v.to_bytes(8,'little') for v in (stack-0x10,stack-0xE0,stack-0x110))
        descriptor+=(-48).to_bytes(4,'little',signed=True)+(-128).to_bytes(4,'little',signed=True)
        _write_span(p,source,descriptor)
        frame=(source,first,second);args=(saved.setup.DATA,)
        if label=='bad_frame_shape':frame=(source,first)
        elif label=='overlapping_frame':frame=(source,source,second)
        elif label.startswith('missing_'):del p[{'missing_source':source,'missing_first':first,'missing_second':second}[label]>>12]
        elif label=='wrong_GP_offset':_write_span(p,source+24,bytes(4))
        elif label=='too_many_GP_arguments':args=(saved.setup.DATA,)*7
        before={k:bytes(v) for k,v in p.items()}
        try:configuration.allocate_printf_cstring(p,output_pointer_address=G+0x1000,format_address=saved.setup.FMT,
            argument_addresses=args,allocate=lambda tx,n:G+0x9000,va_list_frame=frame)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label+' was accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==saved.oracle.LIBRARY_SHA256
    rows=[compare(a.library,image,label,G+top) for image in BASES for top in (0xC000,0xC0D0) for label in PROFILES]
    negative=guards(a.library)
    report=dict(native_Python_controls=len(rows),refusal_or_page_rollback_guards=len(negative),cases=rows,negative_cases=negative,
        library_sha256=saved.oracle.LIBRARY_SHA256,historical_native_groups_replayed=False,native_output_used_as_model_input=False,
        token_default_consumed_frame_extended=False,complete_physical_ABI_verified=False,complete_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS consumed va_list',len(rows),'native',len(negative),'guards',flush=True)
if __name__=='__main__':main()
