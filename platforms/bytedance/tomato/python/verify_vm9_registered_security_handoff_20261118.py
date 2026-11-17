"""Verify the registered Metasec preamble up to either encoded callback target.

Default mode checks retained evidence only. --elf binds shipped bytes;
--replay additionally executes those bytes in isolated Unicorn memory with
explicit synthetic pthread_getspecific, malloc and strtol providers. Neither
callback body, Android nor a complete signer runs.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parents[1] / 'evidence/vm9_registered_security_handoff_20261118.json'
SHA256 = '712384bd0e310fded0ae9b6441c2a264dd356dfaf1ef42d2ebc3c790fdd9269c'
RANGES = [(0x27D288, 0x27D92C), (0x167E54, 0x167E7C), (0x27EC4C, 0x27ECBC),
          (0x276B50, 0x276B74), (0x258C00, 0x258C14), (0x24B2D4, 0x24B310),
          (0x15E694, 0x15E6C4), (0x27ED70, 0x27ED9C), (0x34377C, 0x343944),
          (0x17F4BC, 0x17F538), (0x27617C, 0x276198), (0x2765C4, 0x2766F4),
          (0x161068, 0x161098), (0x276AA0, 0x276B50), (0x261B98, 0x261C54),
          (0x271998, 0x271BA8)]
DATA_RANGES = [(0xA63E8, 0xA6417), (0xA5BB7, 0xA5CB7), (0x96548, 0x96D48)]
IMPORTS = {0x347FD0: ('malloc', 0x375278),
           0x3484B0: ('strtol', 0x3754E8),
           0x3485D0: ('pthread_getspecific', 0x375578)}
EXPECTED = [
    (0x27D2AC, 'mov', 'x20, x0'), (0x27D2C4, 'mov', 'x19, x1'),
    (0x27D39C, 'bl', '#0x167e54'), (0x27D4F4, 'bl', '#0x167e54'),
    (0x27D560, 'bl', '#0x167e54'), (0x27D45C, 'bl', '#0x27ec4c'),
    (0x27D474, 'ldr', 'x9, [x0, #8]'), (0x27D478, 'orr', 'x9, x9, #0x80'),
    (0x27D47C, 'str', 'x9, [x0, #8]'), (0x27D49C, 'bl', '#0x27ed70'),
    (0x27D4B0, 'bl', '#0x17f4bc'), (0x27D4B8, 'tbnz', 'w0, #0, #0x27d3dc'),
    (0x27D590, 'mov', 'x1, x19'), (0x27D598, 'bl', '#0x276aa0'),
    (0x27D5A4, 'bl', '#0x276aa0'), (0x27D5A8, 'mov', 'x1, x20'),
    (0x27D5AC, 'bl', '#0x276aa0'), (0x27D5BC, 'mov', 'w1, #1'),
    (0x27D638, 'bl', '#0x261b98'), (0x27D64C, 'bl', '#0x3484b0'),
    (0x27D660, 'sub', 'x8, x8, x0, asr #2'),
    (0x27D6F0, 'add', 'x0, x8, #0x522'), (0x27D6F4, 'bl', '#0x271998'),
    (0x27D724, 'mov', 'w1, #2'), (0x27D728, 'mov', 'x2, x20'),
    (0x27D72C, 'mov', 'x3, x19'), (0x27D7A4, 'bl', '#0x261b98'),
    (0x27D7B4, 'bl', '#0x3484b0'), (0x27D7B8, 'sub', 'x8, x22, x0, asr #2'),
    (0x27D7C0, 'add', 'x0, x8, #0x522'), (0x27D854, 'bl', '#0x271998'),
    (0x27ECD8, 'bl', '#0x27ed9c'), (0x27ED34, 'bl', '#0x27f84c'),
    (0x27ED2C, 'ldp', 'x8, x1, [x0]'), (0x27ED30, 'mov', 'x0, x8'),
    (0x27FBA8, 'bl', '#0x32d3a0'), (0x27FBC0, 'bl', '#0x1658e4'),
    (0x27FBC8, 'mov', 'x1, x0'), (0x27FBCC, 'add', 'x26, x26, #0x950'),
    (0x27FBD0, 'mov', 'x0, x26'), (0x27FBD4, 'bl', '#0x27c7dc'),
    (0x27FB34, 'ldr', 'x8, [x8, #0x950]'), (0x27FB38, 'ldr', 'x26, [x8, #0x18]'),
    (0x27FB4C, 'ldr', 'x8, [x26]'), (0x27FB58, 'mov', 'x0, x26'),
    (0x27FB5C, 'mov', 'w3, #0x171'), (0x27FB64, 'ldr', 'x9, [x8, #0x20]'),
    (0x27FB70, 'blr', 'x9'), (0x165900, 'tbz', 'w8, #0, #0x165914'),
    (0x165904, 'ldr', 'x0, [x19, #0x5d8]'),
    (0x27C814, 'ldr', 'x8, [x19]'), (0x27C818, 'str', 'x8, [x20]'),
]
DOWNSTREAM = dict(inner_function='0x27f84c',singleton_getter='0x1658e4',
                  shared_global_reference='0x3e0950',root_child_field='0x18',
                  virtual_call='0x27fb70',virtual_slot='0x20',native_mode='0x171',
                  prior_Java_facade_model_mode='0x138',known_child_vtable='0x35d5f0',
                  relative_relocation_slot='0x35d610',relative_relocation_target='0x27dd04',
                  prior_object_graph_evidence='vm9_outer_graph_object_provenance_20261028.json',
                  conditional_on_prior_initialized_object_graph_type=True,
                  actual_object_identity_or_virtual_call_observed=False,
                  native_and_Java_mode_equivalence_established=False)
CLAIMS = dict(registered_entry_to_encoded_callback_synthetic_path_verified=True,
              original_adapter_existing_python_frame_match_verified=True,
              downstream_native_mode_and_child_slot_static_bindings_verified=True,
              downstream_virtual_call_execution_verified=False,
              callback_bodies_executed=False,actual_business_callback_execution_verified=False,
              actual_business_arguments_observed=False,complete_callback_reconstructed=False,
              ordinary_cronet_six_head_chain_verified=False,
              whole_request_native_python_differential_verified=False,
              original_signature_runtime_equivalence_verified=False,
              complete_standalone_signer_verified=False,online_header_acceptance_verified=False)


def controls():
    inputs = [('plain', b'https://example.invalid/path', 'text'),
              ('query_opaque_second', b'https://example.invalid/p?a=1&b=2#tail', 'unmapped'),
              ('ws', b'ws://example.invalid/path', 'text'),
              ('mixed_ws_query', b'WsS://example.invalid/p?q=9#tail', 'text')]
    cases = [dict(base=base, initialization_mask=mask, label=label,
                  first_text=text.decode('ascii'), second_control=second)
             for base in (0x10000000, 0x6000000000) for mask in range(8)
             for label, text, second in inputs]
    for label, text, second in [('empty', b'', 'null'), ('short_w', b'w', 'unmapped'),
                                ('fragment_before_query', b'https://example.invalid/p#f?q=1', 'text'),
                                ('nonprefix', b'xws://example.invalid/p', 'null'),
                                ('bare_WS', b'WS', 'text'), ('prefix_without_scheme', b'wsx', 'text')]:
        cases.append(dict(base=0x6000000000, initialization_mask=7, label=label,
                          first_text=text.decode('ascii'), second_control=second))
    return cases


def is_digest(s):
    return isinstance(s, str) and len(s) == 64 and all(c in '0123456789abcdef' for c in s)


def validate(data):
    assert data['schema'] == 'vm9-registered-security-handoff-20261118-v1'
    assert data['provenance']['original_Metasec_ELF_sha256'] == SHA256
    assert data['provenance']['runtime_registration_evidence'] == 'vm9_cronet_native_security_selector_20261118.json'
    assert data['claims'] == CLAIMS
    assert data['static_downstream'] == DOWNSTREAM
    assert data['boundary'] == dict(entry='0x27d288', adapter='0x271998',
        prefix_test='first two bytes equal ws ignoring ASCII case',
        prefix_target='0x27ecbc', other_target='0x27ed14', decoded_decimal='5256',
        target_adjustment='anchor - (5256 >> 2) + 0x522',
        prefix_argument='second_text + CRLF + URL + CRLF + first_text',
        other_arguments='unchanged first and second input words')
    assert data['providers'] == ['synthetic pthread_getspecific', 'synthetic malloc', 'decimal strtol for decoded 5256 only']
    for name, ranges in (('original_code_ranges', RANGES), ('original_data_ranges', DATA_RANGES)):
        assert [(int(r['start'], 16), int(r['end_exclusive'], 16)) for r in data[name]] == ranges
        assert all(is_digest(r['sha256']) for r in data[name])
    assert data['static_instruction_bindings'] == [dict(offset=hex(o), mnemonic=m, operands=a) for o,m,a in EXPECTED]
    assert len(data['case_results']) == len(controls())
    for index, (row, control) in enumerate(zip(data['case_results'], controls())):
        assert row['control'] == control
        prefix = control['first_text'][:2].lower() == 'ws'
        assert row['target'] == ('0x27ecbc' if prefix else '0x27ed14')
        assert row['call_site'] == ('0x27d6f4' if prefix else '0x27d854')
        assert row['argument_word_count'] == (1 if prefix else 2)
        assert row['external_provider_calls'] == (3 if prefix else 2)
        for key in ('adapter_retained_frame_matches_python', 'adapter_registers_match_python',
                    'argument_block_and_text_match', 'query_checksum_and_context_fields_match',
                    'initialization_text_and_flags_match', 'original_code_unchanged',
                    'no_privileged_or_undecodable_instruction_executed'):
            assert row[key] is True
        assert row['callback_body_instructions_executed'] == 0
        assert row['instructions_executed'] > 200 and is_digest(row['trace_sha256'])
        assert row['salt_control'] == (0, 0x12345678, 0xFFFFFFFF)[index % 3]
    assert data['synthetic_memory_only'] is True and data['Android_execution'] is False
    assert data['privacy'] == dict(real_requests_headers_identifiers_or_runtime_addresses_published=False)
    assert is_digest(data['provenance']['producer_sha256'])


def load_elf(path):
    from elftools.elf.elffile import ELFFile
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SHA256, 'different Metasec sample'
    elf = ELFFile(BytesIO(raw))
    loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    def read(address, size):
        s = next(s for s in loads if s['p_vaddr'] <= address and address + size <= s['p_vaddr'] + s['p_filesz'])
        off = s['p_offset'] + address - s['p_vaddr']
        return raw[off:off + size]
    return elf, loads, read


def verify_elf(data, path):
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    elf, _, read = load_elf(path)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for off, mnemonic, operands in EXPECTED:
        ins, = decoder.disasm(read(off, 4), off)
        assert (ins.mnemonic, ins.op_str) == (mnemonic, operands), hex(off)
    for row in data['original_code_ranges'] + data['original_data_ranges']:
        start, end = int(row['start'], 16), int(row['end_exclusive'], 16)
        assert hashlib.sha256(read(start, end-start)).hexdigest() == row['sha256']
    symbols = elf.get_section_by_name('.dynsym')
    rela = elf.get_section_by_name('.rela.plt')
    imports = {r['r_offset']: symbols.get_symbol(r['r_info_sym']).name for r in rela.iter_relocations()}
    for name, slot in IMPORTS.values():
        assert imports[slot] == name
    refs = {r['r_offset']:r['r_addend'] for r in elf.get_section_by_name('.rela.dyn').iter_relocations()
            if r['r_info_type']==1027 and r['r_offset']==0x35D610}
    assert refs == {0x35D610:0x27DD04}
    return dict(instructions=len(EXPECTED), code_ranges=len(RANGES), data_ranges=len(DATA_RANGES),
                imports=3,relative_relocations=1)


def replay(path):
    """Run every original path to its first callback entry; no internal call stubs."""
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    from unicorn import arm64_const as arm
    from vm9_callbacks import prepare_encoded_callback_frame
    from vm9_allocator import _read_span
    _, loads, read = load_elf(path)
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    table = [int.from_bytes(read(0x96548+8*i,8),'little') for i in range(256)]
    results = []
    for index, control in enumerate(controls()):
        base = control['base']
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for s in loads:
            start = s['p_vaddr'] & ~4095
            end = (s['p_vaddr'] + s['p_memsz'] + 4095) & ~4095
            uc.mem_map(base+start, end-start)
            uc.mem_write(base+s['p_vaddr'], s.data())
        for start, size in ((0x80000000,0x10000),(0x90000000,0x1000),(0xA0000000,0x10000)):
            uc.mem_map(start,size)
        def write(a,v,n=8): uc.mem_write(a,v.to_bytes(n,'little'))
        def word(a,n=8): return int.from_bytes(uc.mem_read(a,n),'little')
        first = control['first_text'].encode('ascii')
        second = b'x-test: synthetic\r\n'
        second_word = dict(text=0xA0001000, unmapped=1, null=0)[control['second_control']]
        prefix = first[:2].lower() == b'ws'
        uc.mem_write(0xA0000000,first+b'\0')
        uc.mem_write(0xA0001000,second+b'\0')
        for bit, flag, dest, text in ((0,0x3E0914,0x3E0910,b'ws'),
                                     (1,0x3E0920,0x3E0918,b'\r\nURL\r\n'),
                                     (2,0x3E092C,0x3E0924,b'5256')):
            if control['initialization_mask'] & (1<<bit):
                write(base+flag,1,4); uc.mem_write(base+dest,text+b'\0')
        # Only initialized singleton and emutls fast paths are selected.
        for a,v,n in ((0x3D1558,1,1),(0x3D1550,0xA0002000,8),
                      (0x3D1680,1,1),(0x3D1678,0xA0007000,8),
                      (0x382930,1,8),(0x3E31F4,37,4)):
            write(base+a,v,n)
        for a,v in ((0xA0002000,0xA0003000),(0xA0003130,0xA0004000),
                    (0xA0007000,0xA0008000),(0xA0005008,1),(0xA0005010,0xA0006000),
                    (0x90000028,0x1122334455667788)):
            write(a,v)
        initial_flags = 0x1020304050607001
        write(0xA0004008,initial_flags)
        salt = (0,0x12345678,0xFFFFFFFF)[index%3]
        write(base+0x3D19A0,salt,4)
        for reg,value in ((arm.UC_ARM64_REG_X0,0xA0000000),(arm.UC_ARM64_REG_X1,second_word),
                          (arm.UC_ARM64_REG_X29,0x12345670),(arm.UC_ARM64_REG_X30,0x10000),
                          (arm.UC_ARM64_REG_X6,0x8877665544332211),
                          (arm.UC_ARM64_REG_SP,0x8000F000),(arm.UC_ARM64_REG_TPIDR_EL0,0x90000000)):
            uc.reg_write(reg,value)
        trace, executed, providers, adapter_inputs, stopped = [],[],[],[],[]
        target = 0x27ECBC if prefix else 0x27ED14
        call_site = 0x27D6F4 if prefix else 0x27D854
        def observe(engine,address,size,_):
            off = address-base
            trace.append(off)
            if off in (0x27ECBC,0x27ED14):
                assert off == target and len(adapter_inputs) == 1
                stopped.append(off); engine.emu_stop(); return
            if off in IMPORTS:
                name = IMPORTS[off][0]
                args = [engine.reg_read(r) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2)]
                if name == 'pthread_getspecific':
                    assert args[0] == 37
                    value = 0xA0005000
                elif name == 'malloc':
                    assert prefix and args[0] == len(first)+len(second)+12
                    value = 0xA0009000
                else:
                    assert args == [base+0x3E0924,0,10]
                    assert bytes(engine.mem_read(args[0],5)) == b'5256\0'
                    value = 5256
                providers.append(name)
                engine.reg_write(arm.UC_ARM64_REG_X0,value)
                engine.reg_write(arm.UC_ARM64_REG_PC,engine.reg_read(arm.UC_ARM64_REG_X30))
                return
            assert any(a<=off<b for a,b in RANGES), hex(off)
            ins, = decoder.disasm(bytes(engine.mem_read(address,4)),off)
            assert ins.mnemonic not in ('svc','hvc','smc','brk','hlt'), hex(off)
            executed.append(off)
            if off == call_site:
                adapter_inputs.append(dict(stack=engine.reg_read(arm.UC_ARM64_REG_SP),
                    target=engine.reg_read(arm.UC_ARM64_REG_X0),block=engine.reg_read(arm.UC_ARM64_REG_X1),
                    fp=engine.reg_read(arm.UC_ARM64_REG_X29),x6=engine.reg_read(arm.UC_ARM64_REG_X6),
                    pages={p:bytearray(engine.mem_read(p<<12,4096)) for p in range(0x80000,0x80010)}))
        def writes(engine,access,address,size,value,_):
            assert any(a<=address and address+size<=b for a,b in (
                (0x80000000,0x80010000),(0xA0000000,0xA0010000),
                (base+0x3E0910,base+0x3E0930))), hex(address)
        uc.hook_add(UC_HOOK_CODE,observe)
        uc.hook_add(UC_HOOK_MEM_WRITE,writes)
        uc.emu_start(base+0x27D288,base+0x27D92C,timeout=5000000,count=20000)
        assert stopped == [target] and len(adapter_inputs) == 1
        before, = adapter_inputs
        model = prepare_encoded_callback_frame(before['pages'],entry_stack_address=before['stack'],
            callback_address=before['target'],argument_block_address=before['block'],
            saved_frame_pointer=before['fp'],return_address=base+call_site+4,saved_x6=before['x6'])
        assert _read_span(before['pages'],before['stack']-0x50,0x50) == bytes(uc.mem_read(before['stack']-0x50,0x50))
        regs = tuple(uc.reg_read(r) for r in (arm.UC_ARM64_REG_X0,arm.UC_ARM64_REG_X1,arm.UC_ARM64_REG_X2,
                                             arm.UC_ARM64_REG_X29,arm.UC_ARM64_REG_X30,arm.UC_ARM64_REG_SP))
        assert regs == (*model.argument_words,0,base+target,before['stack'])
        assert before['target'] == base+target
        args = [0xA0009000] if prefix else [0xA0000000,second_word]
        expected_block = b''.join(v.to_bytes(8,'little') for v in args).ljust(0x40,b'\0')
        assert bytes(uc.mem_read(before['block'],0x40)) == expected_block
        if prefix:
            combined = second+b'\r\nURL\r\n'+first+b'\0'
            assert bytes(uc.mem_read(0xA0009000,len(combined))) == combined
        query = first.find(b'?'); fragment = first.find(b'#')
        checksum = 0
        if query>=0 and (fragment<0 or fragment>query):
            for c in first[query+1:fragment if fragment>=0 else len(first)]:
                checksum = table[(checksum&255)^c] ^ (checksum>>8)
        adjusted = (((checksum+(salt>>16))&0xFFFF) |
                    ((((checksum>>32)-(salt&0xFFFF))&0xFFFF)<<16))
        assert word(0xA0006000,4) == adjusted
        assert word(0xA0004008) == initial_flags|0x80
        for flag,dest,text in ((0x3E0914,0x3E0910,b'ws\0'),(0x3E0920,0x3E0918,b'\r\nURL\r\n\0'),
                               (0x3E092C,0x3E0924,b'5256\0')):
            assert word(base+flag,4) == 1 and bytes(uc.mem_read(base+dest,len(text))) == text
        assert providers == ['pthread_getspecific'] + (['malloc'] if prefix else []) + ['strtol']
        for a,b in RANGES:
            assert bytes(uc.mem_read(base+a,b-a)) == read(a,b-a)
        results.append(dict(control=control,target=hex(target),call_site=hex(call_site),
            argument_word_count=len(args),external_provider_calls=len(providers),salt_control=salt,
            adapter_retained_frame_matches_python=True,adapter_registers_match_python=True,
            argument_block_and_text_match=True,query_checksum_and_context_fields_match=True,
            initialization_text_and_flags_match=True,original_code_unchanged=True,
            no_privileged_or_undecodable_instruction_executed=True,callback_body_instructions_executed=0,
            instructions_executed=len(executed),trace_sha256=hashlib.sha256(
                b''.join(a.to_bytes(4,'little') for a in trace)).hexdigest()))
    return results


def negatives(data):
    rejected = 0
    mutations = [('claims',key,not value) for key,value in CLAIMS.items()]
    mutations += [('boundary','other_target','0x27dd04'),('boundary','decoded_decimal','5252')]
    mutations += [('privacy','real_requests_headers_identifiers_or_runtime_addresses_published',True)]
    mutations += [('static_downstream','native_mode','0x138')]
    for owner,key,value in mutations:
        bad=deepcopy(data); bad[owner][key]=value
        try: validate(bad)
        except AssertionError: rejected+=1
        else: raise AssertionError('damaged claim accepted')
    for index in range(len(controls())):
        bad=deepcopy(data); bad['case_results'][index]['target']='0x27dd04'
        try: validate(bad)
        except AssertionError: rejected+=1
        else: raise AssertionError('damaged target accepted')
    return rejected


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf',type=Path,help='Pinned original libmetasec_ml.so')
    parser.add_argument('--replay',action='store_true',help='Execute original preamble in isolated Unicorn memory; requires --elf')
    args=parser.parse_args()
    if args.replay and not args.elf: parser.error('--replay requires --elf')
    data=json.loads(EVIDENCE.read_text(encoding='utf-8'))
    validate(data)
    result=dict(retained_synthetic_cases=len(controls()),damaged_evidence_rejected=negatives(data),
                actual_business_callback_execution_verified=False)
    if args.elf: result['original_ELF_bindings']=verify_elf(data,args.elf)
    if args.replay:
        assert replay(args.elf)==data['case_results'], 'frozen replay differs'
        result['original_code_cases_replayed']=len(controls())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
