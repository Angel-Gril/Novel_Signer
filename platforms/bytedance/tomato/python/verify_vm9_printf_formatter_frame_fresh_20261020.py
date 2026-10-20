"""Original second allocated printf's bounded deterministic formatter frame.

Compare only eight declared words, plus the second pass's known X21 word.
Other physical register spills and formatter locals remain unmodeled.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_printf_saved_varargs_fresh_20261020 as saved
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=saved.G;TP=saved.TP;BASES=saved.BASES
PROFILES=('opaque_saved_argument','text_saved_argument','failed_allocation',
          'poison_success','poison_failure')
OFFSETS=(-0x210,-0x1F8,-0x1F0,-0x1E8,-0x1B8,-0x1B0,-0x1A0,-0x198)
def cells(stack):return tuple((stack+offset,8) for offset in OFFSETS)
def snapshot(pages,stack):return [_read_span(pages,a,n).hex() for a,n in cells(stack)]
def invoke(pages,image,block,stack,allocate):
    return saved.second.apply_request_287474_allocated_printf_callback(pages,
        argument_block_address=block,image_base=image,entry_stack_address=stack,
        thread_pointer=TP,allocate=allocate)

def compare(library,image,label,stack):
    p,block=saved.fixture(library,image,'opaque_saved_argument' if label=='opaque_saved_argument' else 'text_saved_argument')
    service_label='NULL_malloc' if label in ('failed_allocation','poison_failure') else 'length_32'
    expected=saved.formatting.Services(service_label);actual=saved.formatting.Services(service_label)
    observed={cell:None for cell in cells(stack)+((stack-0x1A8,8),)}
    native_before=[];model_before=[];native_initialized=[];sizes=[]
    def poison(pages):
        for index,(address,size) in enumerate(cells(stack)):
            _write_span(pages,address,(0xACE0000000000000+index).to_bytes(size,'little'))
    def observe(cpu,address):
        if address==image+0x2772F0:
            native_initialized.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
    # Native writes and the model page transaction are independent.
    def native_malloc(cpu,size):
        native_before.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
        result=expected.native_malloc(cpu,size)
        if label.startswith('poison_'):
            for index,(address,width) in enumerate(cells(stack)):
                cpu.mem_write(address,(0xACE0000000000000+index).to_bytes(width,'little'))
        return result
    registers={arm.UC_ARM64_REG_SP:stack,arm.UC_ARM64_REG_TPIDR_EL0:TP}
    registers.update({getattr(arm,'UC_ARM64_REG_X'+str(i)):0xC600000000000000+i for i in range(3,29)})
    result,payload,_,_=saved.oracle.native(library,image,0x288AD4,[block],p,
        malloc_handler=native_malloc,extra_registers=registers,observed_memory=observed,
        instruction_observer=observe,instruction_limit=200000)
    def allocate(tx,size):
        model_before.append(snapshot(tx,stack));sizes.append(size)
        value=actual.malloc(tx,size)
        if label.startswith('poison_'):poison(tx)
        return value
    value=invoke(p,image,block,stack,allocate)
    assert native_before==model_before,(label,'formatter frame before malloc')
    assert snapshot(p,stack)==[observed[cell].hex() for cell in cells(stack)],(label,'final formatter frame')
    assert native_initialized[0]==native_before[0]
    success=label not in ('failed_allocation','poison_failure')
    assert len(native_initialized)==(2 if success else 1)
    if success:
        assert int.from_bytes(_read_span(p,stack-0x1A8,8),'little')==sizes[0]
        assert _read_span(p,stack-0x1A8,8)==observed[(stack-0x1A8,8)]
        assert snapshot(p,stack)==native_initialized[-1]
    assert value==result&0xFFFFFFFF and _read_span(p,G,0xA000)==payload
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    print('PASS formatter frame',hex(image),label,hex(stack),flush=True)
    return dict(image_base=hex(image),case=label,split_stack_layout=bool(stack&0xFFF),
        declared_frame_before_allocation_equal=True,declared_final_frame_equal=True,
        successful_second_pass_size_equal=success,provider_stack_poisoning=label.startswith('poison_'),
        return_payload_and_allocator_effects_equal=True,native_snapshot_input=False)

def guards(library):
    rows=[];image=BASES[0];stack=G+0xC200
    for label in ('missing_formatter_frame','provider_failure','format_alias','output_alias','packed_alias','allocation_alias'):
        p,block=saved.fixture(library,image,'text_saved_argument');calls=[]
        def allocate(tx,size):
            calls.append(size)
            if label=='allocation_alias':return stack-0x210
            raise RefillUnsupported('declared provider failure')
        if label=='missing_formatter_frame':del p[(stack-0x210)>>12]
        if label in ('format_alias','output_alias'):
            offset=16 if label=='format_alias' else 8
            _write_span(p,block+offset,(stack-0x210).to_bytes(8,'little'))
        if label=='packed_alias':
            target=stack-0x210;_write_span(p,target,_read_span(p,block,40));block=target
        before={k:bytes(v) for k,v in p.items()}
        try:invoke(p,image,block,stack,allocate)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('missing frame or alias accepted')
        assert before=={k:bytes(v) for k,v in p.items()}
        assert bool(calls)==(label in ('provider_failure','allocation_alias'))
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,provider_effect_rollback_verified=False))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==saved.oracle.LIBRARY_SHA256
    rows=[compare(a.library,image,label,G+top) for image in BASES for top in (0xC000,0xC200) for label in PROFILES]
    negative=guards(a.library)
    report=dict(native_Python_controls=len(rows),refusal_or_page_rollback_guards=len(negative),cases=rows,
        negative_cases=negative,declared_frame_word_offsets=OFFSETS,successful_second_pass_size_offset=-0x1A8,
        library_sha256=saved.oracle.LIBRARY_SHA256,historical_native_groups_replayed=False,
        native_output_used_as_model_input=False,complete_physical_ABI_verified=False,complete_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS formatter frame',len(rows),'native',len(negative),'guards',flush=True)
if __name__=='__main__':main()
