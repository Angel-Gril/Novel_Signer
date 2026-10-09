"""Fresh native B AST string-copy helper controls, including destination padding."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_alternative_ast_20261009 as fixture
import vm9_alternative_startup as alternative
from vm9_allocator import RefillUnsupported, _read_span, _write_span

DEST,SOURCE,DATA,HEAP=(oracle.GUEST+n for n in (0x1000,0x2000,0x3000,0x7000))

def specs():
    return [(mode,length,pad) for mode in ('short','long') for length in
        ((0,1,7,21,22) if mode=='short' else (0,1,7,21,22,23,24,31,32,63,64,127)) for pad in (0xA5,0xD3)]

def prepare(library,base,spec):
    mode,length,pad=spec; pages=oracle.fresh_pages()
    pages.update({k:bytearray(v) for k,v in fixture.fresh_image(library,base).items()})
    _write_span(pages,DEST,bytes([pad])*24)
    payload=bytes((i*17+3)&255 for i in range(length))+b'\x7e'
    if mode=='short':
        header=bytearray(b'\xb4'*24); header[0]=length*2; header[1:length+2]=payload
    else:
        # The source capacity is deliberately unrelated to the read length.
        header=(0x10001).to_bytes(8,'little')+length.to_bytes(8,'little')+DATA.to_bytes(8,'little')
        _write_span(pages,DATA,payload)
    _write_span(pages,SOURCE,header); return pages

def native(args,base,spec):
    pages=prepare(args.library,base,spec); effects=[]; restored=[]
    def malloc(cpu,size):
        effects.append(('allocate',HEAP,size,DEST,bytes(cpu.mem_read(DEST,24)))); return HEAP
    def observe(cpu,address):
        if address in (base+0x32AA04,base+0x32AA64):
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
            restored.append(True)
    value,memory,calls,ledger=oracle.native(args.library,base,0x32A9C4,[DEST,SOURCE],pages,
        malloc_handler=malloc,instruction_observer=observe)
    assert not calls and not ledger and restored==[True]
    _write_span(pages,oracle.GUEST,memory)
    return value,pages,effects

def compare(args,base,spec):
    value,native_pages,effects=native(args,base,spec); pages=prepare(args.library,base,spec)
    result=alternative.copy_reader_ast_string(pages,destination_address=DEST,source_address=SOURCE,
        image_base=base,allocate=lambda n:HEAP)
    assert result.status==value
    assert [(e.kind,e.address,e.size,e.owner_address,e.owner_bytes) for e in result.effects]==effects
    assert _read_span(pages,oracle.GUEST,0xA000)==_read_span(native_pages,oracle.GUEST,0xA000)
    mode,length,pad=spec; expected=bytearray(bytes([pad])*24)
    if mode=='short':
        expected[:]=_read_span(prepare(args.library,base,spec),SOURCE,24); returned=DEST
    else:
        payload=bytes((i*17+3)&255 for i in range(length))+b'\x7e'
        if length<=22: expected[0]=length*2; expected[1:length+2]=payload; returned=DEST+1
        else:
            capacity=(length+16)&~15
            expected[:]=(capacity|1).to_bytes(8,'little')+length.to_bytes(8,'little')+HEAP.to_bytes(8,'little')
            assert _read_span(pages,HEAP,length+1)==payload
            assert effects[0][2]==capacity; returned=HEAP
    assert _read_span(pages,DEST,24)==expected and value==returned
    return dict(label=f'{mode}_{length}_{pad}',image_base_hex=hex(base),source_representation=mode,length=length,
        natural_native_return_verified=True,native_Python_return_memory_and_effects_match=True,
        independent_padding_capacity_payload_and_return_expectations_match=True,allocation_count=len(effects),
        all_inputs_synthetic=True,native_input_snapshot_used=False,guest_bytes_masked=False)

def negatives(args):
    rows=[]; base=0x122C0000
    for label in ('header_alias','source_payload_alias','allocation_source','allocation_destination','allocation_payload',
        'allocation_image','allocation_unmapped','allocation_unaligned','missing_allocator','length_bound','allocation_bound','late_payload'):
        pages=prepare(args.library,base,('long',23,0xD3)); params=dict(destination_address=DEST,source_address=SOURCE,
            image_base=base,allocate=lambda n:HEAP)
        if label=='header_alias': params['source_address']=DEST
        if label=='source_payload_alias': _write_span(pages,SOURCE+16,DEST.to_bytes(8,'little'))
        targets=dict(allocation_source=SOURCE,allocation_destination=DEST,allocation_payload=DATA,
            allocation_image=base+0x1000,allocation_unmapped=0x90000000,allocation_unaligned=HEAP+1)
        if label in targets: params['allocate']=lambda n:targets[label]
        if label=='missing_allocator': params['allocate']=None
        if label=='length_bound': params['max_vector_bytes']=23
        if label=='allocation_bound': params['max_vector_bytes']=31
        before={k:bytes(v) for k,v in pages.items()}; original=alternative._write_span
        def fail(p,address,data):
            if address==HEAP: raise RefillUnsupported('injected string payload write')
            original(p,address,data)
        if label=='late_payload': alternative._write_span=fail
        try:
            try: alternative.copy_reader_ast_string(pages,**params)
            except (RefillUnsupported,ValueError): pass
            else: raise AssertionError('string guard accepted: '+label)
        finally: alternative._write_span=original
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_invalid_path_executed=False))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path); args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    rows=[compare(args,b,s) for b in (0x122C0000,0x775C205000) for s in specs()]; guards=negatives(args)
    evidence=dict(schema='vm9-alternative-ast-string-fresh-v1',evidence_date='2026-10-10',evidence_timezone='Asia/Shanghai',
        sample_sha256=oracle.LIBRARY_SHA256,native_Python_AST_string_controls=len(rows),rollback_negative_controls=len(guards),
        string_copy_offset_hex='0x32a9c4',string_header_size=24,pre_change_behavior_RED_controls=2,
        native_input_snapshot_used=False,private_payloads_published=False,import_export_callbacks_implemented=False,
        complete_python_reader_implemented=False,independent_Python_factory_implemented=False,
        complete_python_bootstrap_controls=0,fresh_signer_output_verified=False,cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print(len(rows),'native/Python string controls +',len(guards),'rollback checks passed',flush=True)

if __name__=='__main__': main()
