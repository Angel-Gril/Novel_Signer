"""Compare original second printf's two known caller spills at live boundaries."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_printf_consumed_va_lists_fresh_20261020 as consumed
import verify_vm9_printf_formatter_frame_fresh_20261020 as frame
from vm9_allocator import _read_span,_write_span
G=consumed.G;TP=consumed.TP;BASES=consumed.BASES;PROFILES=consumed.PROFILES
def cells(stack):return ((stack-0x48,8),(stack-0x18,8))
def snapshot(pages,stack):return [_read_span(pages,a,n).hex() for a,n in cells(stack)]
def compare(library,image,label,stack):
 p,block=consumed.fixture(library,image,label)
 for i,(a,n) in enumerate(cells(stack)):_write_span(p,a,(0xA870000000000000+i).to_bytes(n,'little'))
 expected=consumed.saved.formatting.Services('NULL_malloc' if label=='NULL_malloc' else 'length_32')
 actual=consumed.saved.formatting.Services('NULL_malloc' if label=='NULL_malloc' else 'length_32')
 before=[];own=[];initialized=[]
 def mutate(write):
  if label=='to_literal':write(consumed.saved.setup.FMT,b'%%s:changed literal\0')
  elif label=='to_string':write(consumed.saved.setup.FMT,b'changed:%s\0')
 def observe(cpu,address):
  if address==image+0x27832C:initialized.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
 def native_malloc(cpu,size):
  before.append([bytes(cpu.mem_read(a,n)).hex() for a,n in cells(stack)])
  result=expected.native_malloc(cpu,size);mutate(lambda a,b:cpu.mem_write(a,b));return result
 observed={cell:None for cell in cells(stack)}
 registers={arm.UC_ARM64_REG_SP:stack,arm.UC_ARM64_REG_TPIDR_EL0:TP}
 registers.update({getattr(arm,'UC_ARM64_REG_X'+str(i)):0xD730000000000000+i for i in range(3,29)})
 result,payload,_,_=consumed.saved.oracle.native(library,image,0x288AD4,[block],p,
  malloc_handler=native_malloc,instruction_observer=observe,extra_registers=registers,
  observed_memory=observed,instruction_limit=200000)
 def allocate(tx,size):
  own.append(snapshot(tx,stack));value=actual.malloc(tx,size);mutate(lambda a,b:_write_span(tx,a,b));return value
 value=consumed.invoke(p,image,block,stack,allocate)
 assert before==own,(label,'caller spills before malloc')
 assert initialized==before and initialized==[[(image+0x288AE8).to_bytes(8,'little').hex(),block.to_bytes(8,'little').hex()]]
 assert snapshot(p,stack)==[observed[cell].hex() for cell in cells(stack)],(label,'final caller spills')
 assert value==result&0xFFFFFFFF and _read_span(p,G,0xA000)==payload
 assert actual.events==expected.events and actual.effects.calls==expected.effects.calls
 print('PASS caller spills',hex(image),label,hex(stack),flush=True)
 return dict(image_base=hex(image),case=label,split_spill_layout=bool(stack&0xFFF),
  original_initial_spills_observed=True,allocation_entry_spills_equal=True,final_spills_equal=True,
  return_payload_allocator_effects_equal=True,unrelated_incoming_registers_poisoned=True,native_snapshot_input=False)
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 assert hashlib.sha256(a.library.read_bytes()).hexdigest()==consumed.saved.oracle.LIBRARY_SHA256
 rows=[compare(a.library,image,label,G+top) for image in BASES for top in (0xC000,0xC040) for label in PROFILES]
 negative=frame.guards(a.library)
 report=dict(native_Python_controls=len(rows),new_refusal_or_page_rollback_guards=0,replayed_refusal_or_page_rollback_guards=len(negative),cases=rows,replayed_negative_cases=negative,
  known_LR_offset=-0x48,known_X19_offset=-0x18,library_sha256=consumed.saved.oracle.LIBRARY_SHA256,
  native_output_used_as_model_input=False,historical_native_groups_replayed=False,complete_physical_ABI_verified=False,complete_signer_verified=False)
 a.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
 print('PASS caller spills',len(rows),'native; existing',len(negative),'guards replayed; no new guard count',flush=True)
if __name__=='__main__':main()
