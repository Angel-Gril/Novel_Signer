"""Fresh controls for the actual B +0x324f6c signed64 reader.

Synthetic bytes/output words only. Failures preserve output, including invalid
tenth terminators. ELF/native stack/TLS or AST values never enter the model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random

import verify_vm9_signer_objects as oracle
import vm9_alternative_startup as alternative
from verify_vm9_alternative_varint32_20261008 import encode
from vm9_allocator import RefillUnsupported, _read_span, _write_span

DATA, OUTPUT = oracle.GUEST+0x2000, oracle.GUEST+0x4000


def inputs():
    cases = []
    def add(label, data, extent=None, output=OUTPUT, start=DATA):
        cases.append((label,data,len(data) if extent is None else extent,output,start))
    values = {0,1,-1,-(1 << 63),(1 << 63)-1}
    for bit in range(6,63,7):
        for sign in (-1,1):
            for delta in (-1,0,1):
                values.add(sign*(1 << bit)+delta)
    for value in sorted(values):
        data = encode(value)
        add(f'canonical_{value}',data)
        add(f'truncated_last_{value}',data,len(data)-1)
    for prefix in (0x80,0xFF):
        for last in range(256):
            add(f'tenth_byte_{prefix}_{last}',bytes([prefix])*9+bytes([last]))
    for value in (-(1 << 63),(1 << 63)-1):
        for extent in range(9):
            add(f'boundary_truncation_{value}_{extent}',encode(value),extent)
    for width in range(1,11):
        for byte,label in ((0,'zero'),(127,'minus_one')):
            data=bytes([byte|128])*(width-1)+bytes([byte])
            add(f'redundant_{label}_{width}',data)
            add(f'trailing_{label}_{width}',data+b'\x80\xff')
    add('eleventh_terminator_ignored',b'\x80'*10+b'\0')
    add('reversed_bounds',b'\0',-1)
    add('empty_unmapped_input',b'',0,start=0x77000000)
    for label,data,extent in (('empty',b'',0),('truncated',b'\x80',1),
        ('tenth_overflow',b'\x80'*9+b'\1',10),('ten_continuations',b'\x80'*10,10)):
        for output,name in ((0,'null'),(0x77000000,'unmapped'),(alternative.MASK64,'top')):
            add(label+'_unused_output_'+name,data,extent,output)
    for displacement in (-1,0,1):
        add(f'output_alias_{displacement}',encode(-8193),output=DATA+displacement)
    add('input_crosses_page',encode(-(1 << 63)),start=oracle.GUEST+0x2FFE)
    add('output_crosses_page',encode((1 << 63)-1),output=oracle.GUEST+0x4FFE)
    rng=random.Random(0x324F6C)
    for index in range(16):
        add(f'generated_value_{index}',encode(rng.randrange(-(1 << 63),1 << 63)))
        add(f'generated_bytes_{index}',bytes(rng.randrange(256) for _ in range(rng.randrange(13))))
    return cases


def compare(library,base,label,data,extent,output,start):
    pages=oracle.fresh_pages()
    _write_span(pages,OUTPUT,(0x0123456789ABCDEF).to_bytes(8,'little'))
    _write_span(pages,start,data)
    mapped=oracle.GUEST <= output <= oracle.GUEST+oracle.GUEST_SIZE-8
    before=_read_span(pages,output,8) if mapped else None
    model={key:bytearray(value) for key,value in pages.items()}
    observed={(output,8):None} if mapped else {}
    returned,guest,calls,ledger=oracle.native(library,base,0x324F6C,[start,start+extent,output],pages,
        instruction_limit=400,observed_memory=observed)
    assert not calls and not ledger
    result=alternative.read_reader_varint64(model,start_address=start,
        end_address=start+extent,output_address=output)
    assert result.bytes_consumed==returned,label
    assert _read_span(model,oracle.GUEST,0xA000)==guest,label
    if returned:
        assert result.output_written and result.value==int.from_bytes(observed[output,8],'little',signed=True),label
    else:
        assert not result.output_written and result.value is None,label
        if mapped:
            assert observed[output,8]==before,label
    return dict(label=label,image_base_hex=hex(base),bytes_available=extent,
        bytes_consumed=result.bytes_consumed,output_written=result.output_written,
        output_mapped=mapped,failure_preserves_output=not bool(returned),
        native_Python_return_match=True,guest_input_output_region_match=True,native_input_snapshot_used=False)


def negatives():
    cases=[]
    for label,change in (
        ('negative_start',dict(start_address=-1)),
        ('wrapping_scan',dict(start_address=alternative.MASK64-8)),
        ('overflow_end',dict(end_address=alternative.MASK64+1)),
        ('negative_output',dict(output_address=-1)),
        ('null_success_output',dict(output_address=0)),
        ('overflow_success_output',dict(output_address=alternative.MASK64-6)),
        ('missing_success_output',dict(output_address=0x77000000)),
        ('partly_mapped_success_output',dict(output_address=oracle.GUEST+oracle.GUEST_SIZE-4)),
        ('missing_first_byte',dict(start_address=0x77000000,end_address=0x77000001)),
        ('missing_continuation_page',dict(start_address=oracle.GUEST+oracle.GUEST_SIZE-1,
            end_address=oracle.GUEST+oracle.GUEST_SIZE+1)),
    ):
        pages=oracle.fresh_pages()
        _write_span(pages,DATA,b'\x80\x01')
        before={key:bytes(value) for key,value in pages.items()}
        params=dict(start_address=DATA,end_address=DATA+2,output_address=OUTPUT)
        params.update(change)
        try:
            alternative.read_reader_varint64(pages,**params)
        except (RefillUnsupported,ValueError):
            pass
        else:
            raise AssertionError('signed64 guard accepted: '+label)
        assert {key:bytes(value) for key,value in pages.items()}==before,label
        cases.append(dict(label=label,rejected=True,all_pages_unchanged=True,native_fault_path_compared=False))
    return cases


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    digest=hashlib.sha256(args.library.read_bytes()).hexdigest()
    assert digest==oracle.LIBRARY_SHA256,'unexpected native sample'
    rejected=negatives()
    specs,cases=inputs(),[]
    for base in (0x122C0000,0x775C205000):
        for index,spec in enumerate(specs,1):
            cases.append(compare(args.library,base,*spec))
            if index%128==0:
                print('B signed64:',hex(base),index,'/',len(specs),'passed',flush=True)
        print('B signed64:',hex(base),len(specs),'controls passed',flush=True)
    evidence=dict(schema='vm9-alternative-reader-varint64-fresh-v1',evidence_date='2026-10-08',
        evidence_timezone='UTC',host_trial_label='20261008',sample_sha256=digest,
        native_function_offset_hex='0x324f6c',native_Python_helper_controls=len(cases),
        rollback_negative_controls=len(rejected),guest_input_output_bytes_compared=0xA000,
        tenth_byte_all_256_values_with_two_prefixes_checked_per_base=True,
        failure_preserves_output_and_does_not_access_unused_output=True,
        native_input_snapshot_used=False,reader_AST_native_Python_controls=0,
        complete_python_reader_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False,
        cases=cases,negative_cases=rejected)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B signed64:',len(cases),'native/Python +',len(rejected),'rollback controls passed')


if __name__=='__main__':
    main()
