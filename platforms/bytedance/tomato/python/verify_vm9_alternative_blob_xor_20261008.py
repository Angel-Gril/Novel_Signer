"""Fresh Python/native B factory XOR prefix, before +0x31b360 reader.

Synthetic codec inputs exercise SIMD/tail/zero-count edges. Real-ELF cases
use the constructor's selected codec byte verified against its instruction
immediates; no native output is used to initialize the Python prefix.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from vm9_allocator import _read_span,_write_span,RefillUnsupported

SP=oracle.GUEST+0xEF00
TABLE=oracle.GUEST+0x4000


def put(p,address,value):_write_span(p,address,value.to_bytes(8,'little'))


def compare(args,base,size,count,key,*,actual_blob=False):
    pages=oracle.fresh_pages()
    if actual_blob:
        pages.update(oracle.image_pages(args.library,base))
        address=base+0x387D20
    else:
        address=oracle.GUEST+0x2000
        _write_span(pages,address,bytes((i*37+11)&255 for i in range(size)))
    row=size%count if count else size
    _write_span(pages,TABLE+row*24+2,bytes([key]))
    put(pages,SP,TABLE);put(pages,SP+8,count)
    model={k:bytearray(v) for k,v in pages.items()}
    result=alternative.decode_factory_blob_xor(model,blob_address=address,blob_size=size,
        codec_table_address=TABLE,codec_table_count=count)
    observed={(address,size):None}
    _,memory,calls,ledger=oracle.native(args.library,base,0x2CBDC8,
        [address,size,0,0,0,0,0,0],pages,stop_offset=0x2CBF24,
        extra_registers={arm.UC_ARM64_REG_X8:oracle.GUEST+0x6000},observed_memory=observed,
        instruction_limit=1000000)
    assert not calls and not ledger
    assert _read_span(model,address,size)==observed[address,size]
    assert _read_span(model,oracle.GUEST,0xA000)==memory
    assert result.selected_codec_row==(row if size else None)
    return dict(image_base_hex=hex(base),blob_size=size,codec_count=count,
        selected_codec_row=result.selected_codec_row,key_zero=(key==0),actual_ELF_blob=actual_blob,
        native_Python_blob_match=True,whole_guest_memory_match=True,
        native_stop_offset_hex='0x2cbf24',reader_executed=False,
        independent_Python_prefix_input=True,native_input_snapshot_used=False)


def constructor_codec_byte(library):
    # Read the actual MOV immediate feeding STRB [sp,#0x7a], which is
    # row 2 byte +2 of the constructor's three records starting sp+0x48.
    with library.open('rb') as stream:
        elf=ELFFile(stream);start=0x29F278
        segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD'
            and s['p_vaddr']<=start<s['p_vaddr']+s['p_filesz'])
        raw=segment.data()[start-segment['p_vaddr']:start-segment['p_vaddr']+8]
    ins=list(Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(raw,start))
    assert len(ins)==2 and ins[0].mnemonic=='mov' and ins[0].op_str.startswith('w8, #')
    assert ins[1].mnemonic=='strb' and ins[1].op_str=='w8, [sp, #0x7a]'
    key=int(ins[0].op_str.split('#')[1],0)
    assert 0x37FD0%3==2 and 0<=key<=255
    return key


def negatives():
    cases=[]
    specs=[dict(blob_address=0),dict(blob_size=-1),dict(blob_size=100,max_blob_bytes=99),
        dict(codec_table_count=-1),dict(codec_table_address=alternative.MASK64),
        dict(codec_table_address=0x77000000),dict(blob_address=0x77000000),
        dict(blob_address=oracle.GUEST+0xFFF8,blob_size=16)]
    for index,change in enumerate(specs):
        pages=oracle.fresh_pages();_write_span(pages,TABLE+8*24+2,b'\x5a')
        _write_span(pages,TABLE+16*24+2,b'\x5a')
        before={k:bytes(v) for k,v in pages.items()}
        options=dict(blob_address=oracle.GUEST+0x2000,blob_size=8,
            codec_table_address=TABLE,codec_table_count=0)
        options.update(change)
        try:alternative.decode_factory_blob_xor(pages,**options)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError('invalid XOR case accepted: '+str(index))
        assert {k:bytes(v) for k,v in pages.items()}==before
        cases.append(dict(case=index,rejected=True,all_pages_unchanged=True))
    # Native zero-size / zero-key branches do not dereference an unused blob.
    pages=oracle.fresh_pages();before={k:bytes(v) for k,v in pages.items()}
    result=alternative.decode_factory_blob_xor(pages,blob_address=0x77000000,blob_size=0,
        codec_table_address=0,codec_table_count=0)
    assert result.selected_codec_row is None and {k:bytes(v) for k,v in pages.items()}==before
    return cases


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    cases=[];key=constructor_codec_byte(args.library)
    for base in (0x122C0000,0x775C205000):
        for size in (0,1,7,8,9,31,32,33,63,65):
            for count in (0,3):
                for value in (0,0x5A):cases.append(compare(args,base,size,count,value))
        cases.append(compare(args,base,0x37FD0,3,key,actual_blob=True))
        print('B XOR prefix:',hex(base),'40 synthetic + 1 real ELF control passed',flush=True)
    failed=negatives()
    evidence=dict(schema='vm9-alternative-blob-xor-fresh-v1',evidence_date='2026-10-07',evidence_timezone='UTC',
        host_trial_label='20261008',sample_sha256=oracle.LIBRARY_SHA256,cases=cases,negative_cases=failed,
        native_Python_prefix_controls=len(cases),synthetic_codec_controls=80,actual_ELF_blob_controls=2,
        rollback_negative_controls=len(failed),native_input_snapshot_used=False,
        constructor_codec_selection_confirmed_from_ELF=True,reader_31B360_executed=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B XOR prefix: 82 native/Python + 8 rollback controls passed',flush=True)


if __name__=='__main__':main()
