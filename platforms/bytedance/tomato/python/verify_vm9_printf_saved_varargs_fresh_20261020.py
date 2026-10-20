"""Original allocated printf's saved X2 and unconsumed va_list stack slots.

Only the declared 72 bytes and existing canary are compared on the stack.
Physical GP/FP spills and consumed va_list copies remain outside this gate.
"""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_second_allocated_printf_fresh_20261019 as setup
import verify_vm9_request_alloc_format_fresh_20261013 as formatting
import vm9_request_287474_vm as second
import vm9_request_token_tail as token
from vm9_allocator import _read_span,_write_span,RefillUnsupported

G=oracle.GUEST;TP=setup.TP
BASES=(0x122C0000,0x775C205000)
WRAPPERS=(0x288AD4,0x288C28)
PROFILES=('opaque_saved_argument','text_saved_argument','failed_allocation')

def cells(stack):return ((stack-0x110,8),(stack-0x78,32),(stack-0xA0,32),(stack-0x58,8))
def snapshot(pages,stack):return [_read_span(pages,a,n).hex() for a,n in cells(stack)]

def fixture(library,image,label):
    p,block=setup.fixture(library,image,'literal' if label=='opaque_saved_argument' else 'length_32')
    if label=='opaque_saved_argument':
        _write_span(p,setup.FMT,b'varargs literal %% keeps opaque X2\0')
        _write_span(p,block+24,(0xFEDCBA9876543210).to_bytes(8,'little'))
    return p,block

def invoke(pages,image,wrapper,block,stack,allocate):
    fn=second.apply_request_287474_allocated_printf_callback if wrapper==0x288AD4 else token.apply_token_printf_callback
    return fn(pages,argument_block_address=block,image_base=image,entry_stack_address=stack,
        thread_pointer=TP,allocate=allocate)

def compare(library,image,wrapper,label,stack):
    p,block=fixture(library,image,label);native_states=[];model_states=[]
    service_label='NULL_malloc' if label=='failed_allocation' else 'length_32'
    expected=formatting.Services(service_label);actual=formatting.Services(service_label)
    observed={cell:None for cell in cells(stack)};stages=[]
    def observe(cpu,address):
        if address==image+0x2772A4:
            stages.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
    def native_malloc(cpu,size):
        native_states.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
        return expected.native_malloc(cpu,size)
    registers={arm.UC_ARM64_REG_SP:stack,arm.UC_ARM64_REG_TPIDR_EL0:TP}
    registers.update({getattr(arm,'UC_ARM64_REG_X'+str(i)):0xB700000000000000+i for i in range(3,8)})
    registers.update({getattr(arm,'UC_ARM64_REG_Q'+str(i)):((i+1)<<120)|0x123456789ABCDEF for i in range(8)})
    result,payload,_,_=oracle.native(library,image,wrapper,[block],p,malloc_handler=native_malloc,
        extra_registers=registers,observed_memory=observed,instruction_observer=observe,instruction_limit=200000)
    def allocate(tx,size):
        model_states.append(snapshot(tx,stack));return actual.malloc(tx,size)
    value=invoke(p,image,wrapper,block,stack,allocate)
    final=snapshot(p,stack)
    assert final==[observed[cell].hex() for cell in cells(stack)],(label,'saved variadic cells')
    assert native_states==model_states==[final],(label,'allocation-entry state')
    assert all(state==final for state in stages) and len(stages)==(1 if label=='failed_allocation' else 2)
    assert value==result&0xFFFFFFFF and _read_span(p,G,0xA000)==payload
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
    print('PASS saved varargs',hex(image),hex(wrapper),label,hex(stack),flush=True)
    return dict(image_base=hex(image),wrapper_offset=hex(wrapper),case=label,
        split_stack_layout=stack&0xFFF!=0,original_printf_returned=True,saved_72_stack_bytes_and_canary_equal=True,
        state_before_each_format_pass_and_allocation_equal=True,opaque_GP_FP_inputs_independent=True,
        return_payload_and_allocator_effects_equal=True,native_snapshot_input=False)

def guards(library):
    rows=[];image=BASES[0];stack=G+0xC100
    for wrapper in WRAPPERS:
        for label in ('missing_saved_argument','missing_va_lists','provider_failure'):
            p,block=fixture(library,image,'text_saved_argument');calls=[]
            def allocate(tx,size):calls.append(size);raise RefillUnsupported('declared allocation failure after saved frame')
            if label.startswith('missing_'):
                del p[(stack-0x110 if label=='missing_saved_argument' else stack-0x78)>>12]
            before={k:bytes(v) for k,v in p.items()}
            try:invoke(p,image,wrapper,block,stack,allocate)
            except (RefillUnsupported,ValueError):pass
            else:raise AssertionError('missing frame/failing provider accepted')
            assert before=={k:bytes(v) for k,v in p.items()}
            assert bool(calls)==(label=='provider_failure')
            rows.append(dict(wrapper_offset=hex(wrapper),case=label,rejected=True,all_pages_unchanged=True,
                provider_effect_rollback_verified=False))
    return rows

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
    assert hashlib.sha256(a.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[compare(a.library,image,wrapper,label,G+top) for image in BASES
        for wrapper in WRAPPERS for top in (0xC000,0xC100) for label in PROFILES]
    negative=guards(a.library)
    report=dict(native_Python_controls=len(rows),refusal_or_page_rollback_guards=len(negative),cases=rows,
        negative_cases=negative,saved_stack_bytes_per_control=72,library_sha256=oracle.LIBRARY_SHA256,
        historical_native_groups_replayed=False,native_output_used_as_model_input=False,
        consumed_va_lists_compared=False,complete_physical_ABI_verified=False,complete_signer_verified=False)
    a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS saved varargs',len(rows),'native',len(negative),'guards',flush=True)
if __name__=='__main__':main()
