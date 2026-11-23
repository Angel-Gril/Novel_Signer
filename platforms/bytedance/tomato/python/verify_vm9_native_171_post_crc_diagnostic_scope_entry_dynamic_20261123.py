"""Verify post-CRC diagnostic scope entry and the held-lock next VM call boundary."""
from __future__ import annotations
from pathlib import Path
from copy import deepcopy
import argparse,json,hashlib
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
from vm9_allocator import _read_span,_write_span
import verify_vm9_native_171_post_md5_crc_return_dynamic_20261123 as previous
import verify_vm9_request_second_diagnostic_fresh_20261015 as controls
import vm9_diagnostics as diagnostic_model
VM_CALL,VM_RESUME,WRAPPER,TARGET=0x16AA48,0x16AA4C,0x288530,0x26C858
LIBC_BASE,MALLOC,LOCK,UNLOCK=0x51000000,0x1BB08,0x68CF8,0x68D5C
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_crc_diagnostic_scope_entry_dynamic_20261123.json')
SCHEMA='vm9-native-171-post-crc-diagnostic-scope-entry-dynamic-20261123-v1'
MAX_OBSERVATIONS=300000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
NEXT_WRAPPER,NEXT_TARGET,NEXT_WRAPPER_SIZE=2655760,3318372,12
PARENT_FIELDS=('CRC_arguments', 'CRC_computation', 'allocator_counts', 'control', 'guest_CRC_table', 'inherited_JNI_calls', 'inherited_libc_SVC', 'inherited_main_SVC', 'inherited_service_counts', 'inherited_syscall_172', 'inherited_syscall_173', 'instruction_observations', 'instruction_trace_sha256', 'java_dispatch', 'late_jni', 'native_writes', 'new_allocator_events', 'next_VM_call', 'observation_sites', 'observed_code', 'observed_code_sha256', 'packed_output_store', 'protected_ranges', 'protected_write_events', 'retained_MD5', 'snapshots', 'stop_boundary')
FIXED_RANGE_COUNT=37
CODE_RANGES={'main': ((1485384, 32), (2655536, 16), (2541656, 376), (1515616, 64), (3318256, 32), (1433256, 128), (1439608, 64), (3440384, 16), (3440400, 16), (3440592, 16), (2655760, 12), (3318372, 32)), 'libc': ((113416, 32), (429304, 32), (429404, 32))}
CODE_SHA256={'main:0x16aa48': 'c53f89ea694ed64ca8b5270d014ecf3bbd4777260ee7edee83a2e8e70b25178f', 'main:0x288530': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af', 'main:0x26c858': 'b75151cac29171eaa6ef6504fac3fcae1211fe272854b03409c011148f0394f1', 'main:0x172060': '2a92904883544d638eec3c4470560a81f41e5511d22b8fbbfd50f56f9ae16df4', 'main:0x32a1f0': 'd63c811bfd6c3d95319a36058d5dc054eba011685bf930cf8620cbd5d48624c7', 'main:0x15dea8': 'aaf6019e5e86e5ad15153ebc5f209238f6a000e35c66271773727502c230b7ae', 'main:0x15f778': '6ee702e722fed456e80a77922beb541e79b52ac6f6dc2b2b8c0785c44b35ca30', 'main:0x347f00': '2ac7a367e40a330d8bb1e5eb89346341047ba5cf60b95bb4a59a2c6b8c8c9dd5', 'main:0x347f10': '5093a04a7496eb70842ce509c9f340e4ece9f9432ffbe8402c364b7137c7dfb6', 'main:0x347fd0': 'f7210f98cdcb754c8f40d20e499862fbab2829c0adcf5049a2e6cc32828bd14f', 'main:0x288610': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x32a264': 'dda56ef5752d7bbb6b5798a1f5d1c85aa71a71a714e177e7f0f0d17ab5b28b78', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36', 'libc:0x68cf8': '30421d7e8389248cc52a7c96b6c904025b5d9f548e6da0016c5bb06787745aeb', 'libc:0x68d5c': '5c5ecefece76d6bcc2ebd2b50a09bd3799c1633c10e757344f02aa00af01d1d2'}
EXPECTED={'instruction_observations': 1249, 'instruction_trace_sha256': '9a17f78248abe0304859addb0f8207a97324e38113734feee02cbc0c19fcf933', 'observed_code_sha256': '48bb031813ebacdbdc7c7a347841634267620301e80f5a733de134e02cb1af72', 'snapshots': [{'kind': 'scope_VM_call', 'index': 1, 'pc': 'main:0x16aa48', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '962a09629f5d9e55b54d32a6b9839d71554b5152cda412e2e122e61314176ad7', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': False, 'scope_fields': {}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'wrapper_entry', 'index': 2, 'pc': 'main:0x288530', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '962a09629f5d9e55b54d32a6b9839d71554b5152cda412e2e122e61314176ad7', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': False, 'scope_fields': {}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'scope_entry', 'index': 6, 'pc': 'main:0x26c858', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '962a09629f5d9e55b54d32a6b9839d71554b5152cda412e2e122e61314176ad7', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': False, 'scope_fields': {}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'scope_fields_written', 'index': 26, 'pc': 'main:0x26c8a8', 'SP': '0x7004b8d0', 'callee_saved_sha256': 'aceb1e8ca1fa056121a25dd24836a506d6f96cc0a2cb68d6e8803ac28f2c3a83', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '119224c091d39f280de98bc8ffc82538d6fad48324c227a2ed437d67befaca7d', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': -233, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'before_entry_lock', 'index': 37, 'pc': 'main:0x26c95c', 'SP': '0x7004b8d0', 'callee_saved_sha256': 'fcf327abcd2742398f84e8f9953c2d31f68846cac213ef2597c837af7530ea77', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '119224c091d39f280de98bc8ffc82538d6fad48324c227a2ed437d67befaca7d', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': -233, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'entry_locked_before_result_store', 'index': 101, 'pc': 'main:0x26c964', 'SP': '0x7004b8d0', 'callee_saved_sha256': 'fcf327abcd2742398f84e8f9953c2d31f68846cac213ef2597c837af7530ea77', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '119224c091d39f280de98bc8ffc82538d6fad48324c227a2ed437d67befaca7d', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': -233, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'scope_lock_result_stored', 'index': 102, 'pc': 'main:0x26c968', 'SP': '0x7004b8d0', 'callee_saved_sha256': 'fcf327abcd2742398f84e8f9953c2d31f68846cac213ef2597c837af7530ea77', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '12bf8c9ffaaa85d01c26d9b22fc43ddb4772b3b749fbd1981d87a5a61aef6748', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': 0, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'scope_return', 'index': 111, 'pc': 'main:0x26c98c', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '12bf8c9ffaaa85d01c26d9b22fc43ddb4772b3b749fbd1981d87a5a61aef6748', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': 0, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'scope_callback_return', 'index': 112, 'pc': 'main:0x16aa4c', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '12bf8c9ffaaa85d01c26d9b22fc43ddb4772b3b749fbd1981d87a5a61aef6748', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': 0, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 1, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'VM_reference_count_store_complete', 'index': 523, 'pc': 'main:0x172090', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a390', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '12bf8c9ffaaa85d01c26d9b22fc43ddb4772b3b749fbd1981d87a5a61aef6748', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': 0, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 0, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}, {'kind': 'before_next_VM_call', 'index': 1249, 'pc': 'main:0x16aa48', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a3bc', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'scope_storage_sha256': '12bf8c9ffaaa85d01c26d9b22fc43ddb4772b3b749fbd1981d87a5a61aef6748', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_fields_written': True, 'scope_fields': {'vtable_offset': '0x35d410', 'lock_result_i32': 0, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'bucket': 104}, 'diagnostic': {'table_address': '0x136f8000', 'table_width': 2048, 'table_sha256': 'f968568f400ce6d4dd61960298001cf2b252b0d5309c5272e45591b4bc6d6d56', 'outside_slot_sha256': '363f9807753de0254ea27c4e23dc9bc4ac2b9869c4519d18b50406488c435a3d', 'bucket': 104, 'slot_address': '0x136f8340', 'entry_address': '0x136d40e0', 'global_lock_address': '0x136d3c60', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'entry_vtable_offset': '0x34c738', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'registers': {}, 'reference_counter_address': '0x136d8300', 'reference_counter_u32': 0, 'protected_regions_sha256': '28fac0d9941671914d5f5662d1508b074a9fb7b7cb1b384c345504653daad6bd'}], 'native_writes': [{'index': 7, 'PC': 'main:0x26c85c', 'address': '0x7004b8f0', 'size': 8}, {'index': 7, 'PC': 'main:0x26c85c', 'address': '0x7004b8f8', 'size': 8}, {'index': 9, 'PC': 'main:0x26c864', 'address': '0x7004b900', 'size': 8}, {'index': 9, 'PC': 'main:0x26c864', 'address': '0x7004b908', 'size': 8}, {'index': 10, 'PC': 'main:0x26c868', 'address': '0x7004b910', 'size': 8}, {'index': 10, 'PC': 'main:0x26c868', 'address': '0x7004b918', 'size': 8}, {'index': 11, 'PC': 'main:0x26c86c', 'address': '0x7004b920', 'size': 8}, {'index': 11, 'PC': 'main:0x26c86c', 'address': '0x7004b928', 'size': 8}, {'index': 20, 'PC': 'main:0x26c890', 'address': '0x7004b8e8', 'size': 8}, {'index': 23, 'PC': 'main:0x26c89c', 'address': '0x7004c660', 'size': 8}, {'index': 24, 'PC': 'main:0x26c8a0', 'address': '0x7004c668', 'size': 4}, {'index': 25, 'PC': 'main:0x26c8a4', 'address': '0x7004c670', 'size': 8}, {'index': 40, 'PC': 'libc:0x68cf8', 'address': '0x7004b8b0', 'size': 8}, {'index': 40, 'PC': 'libc:0x68cf8', 'address': '0x7004b8b8', 'size': 8}, {'index': 50, 'PC': 'libc:0x68890', 'address': '0x7004b800', 'size': 8}, {'index': 50, 'PC': 'libc:0x68890', 'address': '0x7004b808', 'size': 8}, {'index': 52, 'PC': 'libc:0x68898', 'address': '0x7004b820', 'size': 8}, {'index': 52, 'PC': 'libc:0x68898', 'address': '0x7004b828', 'size': 8}, {'index': 53, 'PC': 'libc:0x6889c', 'address': '0x7004b810', 'size': 8}, {'index': 53, 'PC': 'libc:0x6889c', 'address': '0x7004b818', 'size': 8}, {'index': 54, 'PC': 'libc:0x688a0', 'address': '0x7004b830', 'size': 8}, {'index': 54, 'PC': 'libc:0x688a0', 'address': '0x7004b838', 'size': 8}, {'index': 55, 'PC': 'libc:0x688a4', 'address': '0x7004b840', 'size': 8}, {'index': 55, 'PC': 'libc:0x688a4', 'address': '0x7004b848', 'size': 8}, {'index': 56, 'PC': 'libc:0x688a8', 'address': '0x7004b850', 'size': 8}, {'index': 56, 'PC': 'libc:0x688a8', 'address': '0x7004b858', 'size': 8}, {'index': 57, 'PC': 'libc:0x688ac', 'address': '0x7004b860', 'size': 8}, {'index': 62, 'PC': 'libc:0x688c0', 'address': '0x7004b89e', 'size': 2}, {'index': 83, 'PC': 'libc:0x68ba0', 'address': '0x136d40e8', 'size': 2}, {'index': 87, 'PC': 'libc:0x68bb8', 'address': '0x136d40ec', 'size': 4}, {'index': 101, 'PC': 'main:0x26c964', 'address': '0x7004c668', 'size': 4}, {'index': 144, 'PC': 'main:0x16a9f0', 'address': '0x7004d360', 'size': 8}, {'index': 193, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 196, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 197, 'PC': 'main:0x16f974', 'address': '0x7004d378', 'size': 8}, {'index': 199, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 212, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 254, 'PC': 'main:0x16eda4', 'address': '0x7004b9a0', 'size': 4}, {'index': 256, 'PC': 'main:0x16edac', 'address': '0x7004b990', 'size': 4}, {'index': 258, 'PC': 'main:0x16edb4', 'address': '0x7004b960', 'size': 2}, {'index': 290, 'PC': 'main:0x16ee34', 'address': '0x7004d360', 'size': 8}, {'index': 342, 'PC': 'main:0x1702fc', 'address': '0x7004b950', 'size': 4}, {'index': 343, 'PC': 'main:0x170300', 'address': '0x7004b990', 'size': 4}, {'index': 344, 'PC': 'main:0x170304', 'address': '0x7004b9b0', 'size': 2}, {'index': 346, 'PC': 'main:0x17030c', 'address': '0x7004d370', 'size': 8}, {'index': 348, 'PC': 'main:0x170314', 'address': '0x7004d360', 'size': 8}, {'index': 411, 'PC': 'main:0x16db28', 'address': '0x7004b9a0', 'size': 4}, {'index': 413, 'PC': 'main:0x16db30', 'address': '0x7004b990', 'size': 4}, {'index': 415, 'PC': 'main:0x16db38', 'address': '0x7004b960', 'size': 2}, {'index': 430, 'PC': 'main:0x16db74', 'address': '0x7004d370', 'size': 8}, {'index': 436, 'PC': 'main:0x16db8c', 'address': '0x7004d360', 'size': 8}, {'index': 502, 'PC': 'main:0x17203c', 'address': '0x7004b990', 'size': 4}, {'index': 504, 'PC': 'main:0x172044', 'address': '0x7004b950', 'size': 4}, {'index': 508, 'PC': 'main:0x172054', 'address': '0x7004b9b0', 'size': 2}, {'index': 522, 'PC': 'main:0x17208c', 'address': '0x136d8300', 'size': 4}, {'index': 527, 'PC': 'main:0x1720a0', 'address': '0x7004d360', 'size': 8}, {'index': 577, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 580, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 581, 'PC': 'main:0x16f974', 'address': '0x7004d378', 'size': 8}, {'index': 583, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 596, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 633, 'PC': 'main:0x1702fc', 'address': '0x7004b950', 'size': 4}, {'index': 634, 'PC': 'main:0x170300', 'address': '0x7004b990', 'size': 4}, {'index': 635, 'PC': 'main:0x170304', 'address': '0x7004b9b0', 'size': 2}, {'index': 637, 'PC': 'main:0x17030c', 'address': '0x7004d370', 'size': 8}, {'index': 639, 'PC': 'main:0x170314', 'address': '0x7004d360', 'size': 8}, {'index': 673, 'PC': 'main:0x16ebb8', 'address': '0x7004b9a0', 'size': 4}, {'index': 674, 'PC': 'main:0x16ebbc', 'address': '0x7004b990', 'size': 4}, {'index': 688, 'PC': 'main:0x16ec78', 'address': '0x7004b960', 'size': 2}, {'index': 699, 'PC': 'main:0x16eca4', 'address': '0x7004d360', 'size': 8}, {'index': 750, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 753, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 754, 'PC': 'main:0x16f974', 'address': '0x7004d370', 'size': 8}, {'index': 756, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 769, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 804, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 807, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 808, 'PC': 'main:0x16f974', 'address': '0x7004d370', 'size': 8}, {'index': 810, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 823, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 847, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 901, 'PC': 'main:0x171268', 'address': '0x7004cc88', 'size': 8}, {'index': 917, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 918, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 923, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 947, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 1001, 'PC': 'main:0x171268', 'address': '0x7004cc80', 'size': 8}, {'index': 1017, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 1018, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 1023, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 1076, 'PC': 'main:0x16d89c', 'address': '0x7004b9a0', 'size': 4}, {'index': 1078, 'PC': 'main:0x16d8a4', 'address': '0x7004d390', 'size': 8}, {'index': 1083, 'PC': 'main:0x16d8b8', 'address': '0x7004d360', 'size': 8}, {'index': 1095, 'PC': 'main:0x16d8e8', 'address': '0x7004b990', 'size': 4}, {'index': 1096, 'PC': 'main:0x16d8ec', 'address': '0x7004b960', 'size': 2}, {'index': 1133, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 1136, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 1137, 'PC': 'main:0x16f974', 'address': '0x7004d388', 'size': 8}, {'index': 1139, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 1152, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 1174, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 1176, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 1177, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 1181, 'PC': 'main:0x16a5d8', 'address': '0x7004d430', 'size': 8}, {'index': 1184, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 1194, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 1233, 'PC': 'main:0x16a93c', 'address': '0x7004b990', 'size': 4}, {'index': 1235, 'PC': 'main:0x16a944', 'address': '0x7004b9a0', 'size': 4}, {'index': 1236, 'PC': 'main:0x16a948', 'address': '0x7004b980', 'size': 4}, {'index': 1237, 'PC': 'main:0x16a94c', 'address': '0x7004b970', 'size': 4}, {'index': 1238, 'PC': 'main:0x16a950', 'address': '0x7004d460', 'size': 8}, {'index': 1244, 'PC': 'main:0x16aa34', 'address': '0x7004b9d0', 'size': 8}, {'index': 1244, 'PC': 'main:0x16aa34', 'address': '0x7004b9d8', 'size': 8}, {'index': 1246, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c0', 'size': 8}, {'index': 1246, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c8', 'size': 8}], 'scope_arguments': {'scope_storage_address': '0x7004c660', 'scope_storage_width': 24, 'input_word_width': 8, 'input_word_sha256': '7dde94e129b31d999c3a21666fff109f6552a91395b87e4fc7795374bd072f33', 'input_matches_retained_MD5_object': True, 'bucket': 104, 'selected_entry_preexisted': True, 'tail_wrapper_preserves_entry_SP_and_LR': True, 'raw_input_word_exported': False}, 'services': [{'index': 39, 'PC': 'main:0x347f00', 'kind': 'mutex_lock_PLT', 'argument_address': '0x136d40e8'}, {'index': 40, 'PC': 'libc:0x68cf8', 'kind': 'Bionic_mutex_lock_entry', 'argument_address': '0x136d40e8'}], 'next_VM_call': {'index': 1249, 'callsite_offset': '0x16aa48', 'VM_cursor_offset': '0x10a3bc', 'descriptor_address': '0x7004cc80', 'descriptor_width': 48, 'descriptor_sha256': '10e98104eda1d53426613971586abfac7ab74aff470316a920abe7058a402415', 'wrapper_offset': '0x288610', 'target_offset': '0x32a264', 'wrapper_code_hex': '012040a9e00308aa20001fd6', 'VM_call_executed': False, 'wrapper_executed': False, 'target_executed': False, 'argument_matches_reference_counter_storage': True, 'argument_matches_MD5_object': False, 'wrapper_code_sha256': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565'}, 'new_allocator_events': [], 'prefix_allocator_counts': {'malloc': 602, 'free': 272, 'gc': 3, 'flush': 4}, 'retired_prior_regions': [], 'protected_ranges': [{'label': 'prior_0', 'address': '0x7004d118', 'size': 24}, {'label': 'prior_1', 'address': '0x136d82c0', 'size': 8}, {'label': 'prior_2', 'address': '0x7004d130', 'size': 24}, {'label': 'prior_3', 'address': '0x136d82d0', 'size': 8}, {'label': 'prior_4', 'address': '0x7004d148', 'size': 24}, {'label': 'prior_5', 'address': '0x136d82d8', 'size': 8}, {'label': 'string_object', 'address': '0x136d9640', 'size': 24}, {'label': 'string_payload', 'address': '0x136d4050', 'size': 37}, {'label': 'output', 'address': '0x7004d178', 'size': 16}, {'label': 'cache', 'address': '0x136d73a0', 'size': 16}, {'label': 'counter', 'address': '0x136d82e0', 'size': 4}, {'label': 'cache_mutex', 'address': '0x136d4020', 'size': 48}, {'label': 'cache_globals', 'address': '0x1269e700', 'size': 64}, {'label': 'seed_constants', 'address': '0x1269e450', 'size': 128}, {'label': 'errno', 'address': '0x7000a010', 'size': 4}, {'label': 'prior_identifier_diagnostic_entry', 'address': '0x136d4080', 'size': 48}, {'label': 'diagnostic_guard', 'address': '0x1269eda0', 'size': 8}, {'label': 'diagnostic_global_lock_pointer', 'address': '0x1269ed98', 'size': 8}, {'label': 'diagnostic_table_pointer', 'address': '0x1269eda8', 'size': 8}, {'label': 'initialized_allocation', 'address': '0x136d82f0', 'size': 4}, {'label': 'selected_entry_vtable', 'address': '0x136d40b0', 'size': 8}, {'label': 'selected_entry_tail', 'address': '0x136d40c0', 'size': 32}, {'label': 'released_entry_header', 'address': '0x136d40b8', 'size': 8}, {'label': 'formatted_string_object', 'address': '0x136d9660', 'size': 24}, {'label': 'formatted_string_payload', 'address': '0x136d82e8', 'size': 8}, {'label': 'pair_destination_object', 'address': '0x7004d1d8', 'size': 24}, {'label': 'pair_destination_payload', 'address': '0x136df280', 'size': 64}, {'label': 'diagnostic_global_lock_vtable', 'address': '0x136d3c60', 'size': 8}, {'label': 'diagnostic_global_lock_tail', 'address': '0x136d3c70', 'size': 32}, {'label': 'MD5_output_pair', 'address': '0x7004c560', 'size': 16}, {'label': 'MD5_result_object', 'address': '0x136d9680', 'size': 24}, {'label': 'MD5_result_payload', 'address': '0x136df180', 'size': 64}, {'label': 'completed_MD5_diagnostic_table_part_0', 'address': '0x136f8000', 'size': 832}, {'label': 'completed_MD5_diagnostic_table_part_1', 'address': '0x136f8348', 'size': 1208}, {'label': 'completed_MD5_diagnostic_entry_104_part_0', 'address': '0x136d40e0', 'size': 8}, {'label': 'completed_MD5_diagnostic_entry_104_part_1', 'address': '0x136d40f0', 'size': 32}, {'label': 'guest_CRC_table', 'address': '0x12356144', 'size': 1024}, {'label': 'active_scope', 'address': '0x7004c660', 'size': 24}, {'label': 'held_diagnostic_entry', 'address': '0x136d40e0', 'size': 48}, {'label': 'completed_diagnostic_table', 'address': '0x136f8000', 'size': 2048}, {'label': 'completed_global_lock_header', 'address': '0x136d3c68', 'size': 8}, {'label': 'post_store_reference_counter_storage', 'address': '0x136d8300', 'size': 4}], 'reference_count_store': {'index': 522, 'PC': 'main:0x17208c', 'address': '0x136d8300', 'size': 4, 'before_u32': 1, 'after_u32': 0, 'decremented_by_one': True, 'incremented_by_one': False, 'before_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'post_store_index': 523, 'post_store_PC': 'main:0x172090', 'after_sha256': 'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119'}, 'ledgers': {'allocator_counts': {'malloc': 602, 'free': 272, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}}
WRAPPER_IDENTITY={'byte_count': 16, 'identical_to_existing_token_scope_wrapper': True, 'no_PC_relative_instructions': True}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'cold_zero', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'cold_high_bits', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'cold_cross_page', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'warm_nested', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'warm_saturated', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'packed_object_alias', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'warm_missing_entry', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'warm_existing', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'cold_zero', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'cold_high_bits', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'cold_cross_page', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'warm_nested', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'warm_saturated', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'packed_object_alias', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'warm_missing_entry', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'warm_existing', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'independent_warm_bucket_104_reused_storage', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'no_new_allocations': True, 'prior_object_padding_preserved': True, 'unlocked_to_owned_entry_verified': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'independent_warm_bucket_104_reused_storage', 'actual_wrapper': '0x288530', 'actual_scope': '0x26c858', 'original_wrapper_and_diagnostic_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_allocations_mutex_gettid_equal': True, 'actual_matching_libc_recursive_mutexes': True, 'no_new_allocations': True, 'prior_object_padding_preserved': True, 'unlocked_to_owned_entry_verified': True, 'native_snapshot_input': False}]
ROLLBACK_SPECS=[{'case': 'busy_guard', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}, {'case': 'NULL_allocation', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}, {'case': 'wrong_recursive_owner', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}, {'case': 'unmapped_scope', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}, {'case': 'bad_target', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}, {'case': 'missing_packed', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}, {'case': 'noncallable_allocate', 'rejected': True, 'all_pages_unchanged': True, 'external_allocator_effects_rolled_back': False}]

def subtract_ranges(regions,allowed):
    output=[]
    for label,address,size in regions:
        parts=[(address,address+size)]
        for a,n in allowed:
            next_parts=[]
            for first,last in parts:
                if first<a+n and a<last:
                    if first<a:next_parts.append((first,a))
                    if a+n<last:next_parts.append((a+n,last))
                else:next_parts.append((first,last))
            parts=next_parts
        output.extend((label if len(parts)==1 and parts[0]==(address,address+size) else label+'_part_'+str(i),a,b-a) for i,(a,b) in enumerate(parts))
    return output

def bucket_104_control(path,libc,image):
    p,obj,old,tid=controls.fixture(path,image,'warm_existing');table=controls.oracle.GUEST+0x3000
    entry=_read_span(p,table+((old>>4)&255)*8,8);word=0x1234000000000687
    _write_span(p,table+((old>>4)&255)*8,bytes(8));_write_span(p,table+104*8,entry)
    _write_span(p,controls.PACKED+16,word.to_bytes(8,'little'))
    # Independently prepared former StringObject storage, now the scope destination.
    _write_span(p,obj,(image+0x34F5F8).to_bytes(8,'little')+(64).to_bytes(4,'little')+(32).to_bytes(4,'little')+(controls.oracle.GUEST+0x5000).to_bytes(8,'little'))
    padding=_read_span(p,obj+12,4);memory,watch,calls,native_ledger=controls.original(path,libc,image,p,tid)
    allocation=controls.oracle.Allocator();ledger=[]
    controls.model.apply_token_diagnostic_callback(p,argument_block_address=controls.PACKED,image_base=image,
        thread_pointer=controls.TP,allocate=allocation.model,thread_id=tid,observer=lambda *e:ledger.append(list(e)))
    assert _read_span(p,controls.oracle.GUEST,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()) and allocation.calls==calls==[] and ledger==native_ledger
    assert _read_span(p,obj+12,4)==padding and int.from_bytes(_read_span(p,int.from_bytes(entry,'little')+8,2),'little')==0x4001
    print('PASS independent warm bucket104 reused storage',hex(image),flush=True)
    return dict(image_base=hex(image),case='independent_warm_bucket_104_reused_storage',actual_wrapper='0x288530',actual_scope='0x26c858',
        original_wrapper_and_diagnostic_returned=True,all_declared_guest_ELF_heap_and_packed_bytes_equal=True,ordered_allocations_mutex_gettid_equal=True,
        actual_matching_libc_recursive_mutexes=True,no_new_allocations=True,prior_object_padding_preserved=True,unlocked_to_owned_entry_verified=True,native_snapshot_input=False)

class PostCRCScopeScenario(previous.PostMD5CRCScenario):
    def __init__(self,control):
        super().__init__(control)
        self._cs_active=False;self._cs_done=False;self._cs_returned=False;self._cs_written=False
        self._cs_trace=[];self._cs_code={};self._cs_rows=[];self._cs_writes=[];self._cs_violations=[];self._cs_services=[]
        self._cs_allocation=0;self._cs_counter_event={};self._cs_counter_pending=False;self._cs_counter_checked=False

    def _cs_track(self,cpu,pc):
        assert len(self._cs_trace)<300000
        key=self._fmt_site(pc);self._cs_trace.append(key);self._cs_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _cs_diagnostic(self,cpu):
        raw=bytes(cpu.mem_read(self._cs_table,0x800));offset=self._cs_bucket*8;entry=self._u(cpu,self._cs_slot)
        row=dict(table_address=hex(self._cs_table),table_width=0x800,table_sha256=raw_hash(raw),outside_slot_sha256=raw_hash(raw[:offset]+raw[offset+8:]),
            bucket=self._cs_bucket,slot_address=hex(self._cs_slot),entry_address=hex(entry),global_lock_address=hex(self._cs_global),
            global_lock_sha256=raw_hash(bytes(cpu.mem_read(self._cs_global,48))),global_mutex_state_u16=self._u(cpu,self._cs_global+8,2))
        if entry:
            data=bytes(cpu.mem_read(entry,48));row.update(entry_sha256=raw_hash(data),entry_outside_header_sha256=raw_hash(data[:8]+data[16:]),
                entry_vtable_offset=hex(self._u(cpu,entry)-self.image),mutex_state_u16=self._u(cpu,entry+8,2),owner_u32=self._u(cpu,entry+12,4))
        return row

    def _cs_snapshot(self,cpu,pc,kind):
        raw=bytes(cpu.mem_read(self._cs_scope,24));fields={}
        if self._cs_written:
            fields=dict(vtable_offset=hex(self._u(cpu,self._cs_scope)-self.image),lock_result_i32=int.from_bytes(raw[8:12],'little',signed=True),
                input_word_sha256=raw_hash(raw[16:24]),bucket=(self._u(cpu,self._cs_scope+16)>>4)&255)
        self._cs_rows.append(dict(kind=kind,index=len(self._cs_trace),pc=self._fmt_site(pc),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_state_address=hex(self._postalloc_vmstate),VM_cursor=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(self._cs_descriptor),descriptor_width=48,descriptor_sha256=raw_hash(bytes(cpu.mem_read(self._cs_descriptor,48))),
            scope_storage_address=hex(self._cs_scope),scope_storage_width=24,scope_storage_sha256=raw_hash(raw),scope_padding_4_sha256=raw_hash(raw[12:16]),
            scope_fields_written=self._cs_written,scope_fields=fields,diagnostic=self._cs_diagnostic(cpu),registers={},
            reference_counter_address=hex(self._cs_counter),reference_counter_u32=self._u(cpu,self._cs_counter,4) if self._u(cpu,self._cs_counter,4)<=1024 else None,
            protected_regions_sha256=digest([dict(label=l,address=hex(a),size=n,sha256=raw_hash(bytes(cpu.mem_read(a,n)))) for l,a,n in self._cs_fixed])))

    def _cs_start(self,cpu,pc,state):
        self._crc_track(cpu,pc);self._crc_snapshot(cpu,pc,'before_next_VM_call')
        d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
        self._crc_next=previous.project_next_call(dict(index=len(self._crc_trace),callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(d),descriptor_width=48,descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False))
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);self._cs_old=data['case_result']
        self._crc_done=True;self._crc_active=False;self._cs_active=True
        assert wrapper==self.image+WRAPPER and int.from_bytes(raw[:8],'little')==self.image+TARGET
        self._cs_descriptor=d;self._cs_before=raw;self._cs_scope=int.from_bytes(raw[8:16],'little');self._cs_word=int.from_bytes(raw[16:24],'little')
        self._cs_table=self._u(cpu,self.image+0x3DEDA8);self._cs_global=self._u(cpu,self.image+0x3DED98)
        self._cs_bucket=(self._cs_word>>4)&255;self._cs_slot=self._cs_table+self._cs_bucket*8;self._cs_entry_before=self._u(cpu,self._cs_slot)
        self._cs_padding=bytes(cpu.mem_read(self._cs_scope+12,4));self._cs_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._cs_saved=self._idctor_saved_hash(cpu)
        self._cs_events=deepcopy(state['allocator_events_ref']);self._cs_counter=self._u(cpu,self._md5_output+8)
        assert self._u(cpu,self._md5_output)==self._cs_word and self._u(cpu,self._cs_counter,4)==1
        mutable=[(self._cs_scope,24),(self._cs_slot,8),(self._cs_global+8,8),(self._cs_counter,4)]
        if self._cs_entry_before:mutable.append((self._cs_entry_before+8,8))
        self._cs_retired=[dict(label=l,address=hex(a),size=n) for l,a,n in self._crc_ranges if a<self._cs_scope+24 and self._cs_scope<a+n]
        assert all(int(x['address'],16)==self._cs_scope and x['size']==24 for x in self._cs_retired),'scope partially overlaps retained object'
        assert self._cs_retired==EXPECTED['retired_prior_regions']
        self._cs_fixed=subtract_ranges(self._crc_ranges,mutable);self._cs_ranges=deepcopy(self._cs_fixed)
        self._cs_args=dict(scope_storage_address=hex(self._cs_scope),scope_storage_width=24,input_word_width=8,input_word_sha256=raw_hash(raw[16:24]),
            input_matches_retained_MD5_object=self._cs_word==int(self._crc_object['address'],16),bucket=self._cs_bucket,
            selected_entry_preexisted=bool(self._cs_entry_before),tail_wrapper_preserves_entry_SP_and_LR=True,raw_input_word_exported=False)
        self._cs_track(cpu,pc);self._cs_snapshot(cpu,pc,'scope_VM_call')

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._cs_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC);row=dict(index=len(self._cs_trace),PC=self._fmt_site(pc),address=hex(address),size=size)
                self._cs_writes.append(row);labels=[l for l,a,n in self._cs_ranges if address<a+n and a<address+size]
                if labels:raise AssertionError('post-CRC scope wrote protected live state')
                if address<self._cs_counter+4 and self._cs_counter<address+size:
                    assert self._cs_returned and pc==self.image+0x17208C and address==self._cs_counter and size==4 and not self._cs_counter_event
                    old=self._u(cpu,self._cs_counter,4);new=self._reg(cpu,11)&0xFFFFFFFF;self._cs_counter_candidate=new
                    assert old==1 and new==0 and self._cs_diagnostic(cpu)['mutex_state_u16']==0x4001 and self._cs_diagnostic(cpu)['owner_u32']==137
                    self._cs_counter_event=dict(index=len(self._cs_trace),PC=self._fmt_site(pc),address=hex(address),size=size,
                        before_u32=old if old<=1024 else None,after_u32=new if new<=1024 else None,
                        decremented_by_one=new==(old-1)&0xFFFFFFFF,incremented_by_one=new==(old+1)&0xFFFFFFFF,
                        before_sha256=raw_hash(bytes(cpu.mem_read(address,4))))
                    self._cs_counter_pending=True
                if not self._cs_returned:
                    entry=self._u(cpu,self._cs_slot)
                    if entry:assert not (address<entry+8 and entry<address+size or address<entry+48 and entry+16<address+size),'scope wrote published entry outside mutex header'
                    assert not (address<self._cs_descriptor+48 and self._cs_descriptor<address+size),'scope wrote packed descriptor'
                    assert not (address<self._cs_scope+16 and self._cs_scope+12<address+size),'scope overwrote padding'
                    if address<self._cs_table+0x800 and self._cs_table<address+size:
                        assert not self._cs_entry_before and address==self._cs_slot and size==8 and pc==self.image+0x26C94C
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._cs_active:
            if self._crc_active and self._crc_returned and pc==self.image+VM_CALL:
                self._cs_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._cs_track(cpu,pc);off=pc-self.image
        if self._cs_counter_pending and off==0x172090:
            assert self._u(cpu,self._cs_counter,4)==self._cs_counter_candidate
            self._cs_counter_event.update(post_store_index=len(self._cs_trace),post_store_PC=self._fmt_site(pc),after_sha256=raw_hash(bytes(cpu.mem_read(self._cs_counter,4))))
            self._cs_counter_pending=False;self._cs_counter_checked=True;self._cs_snapshot(cpu,pc,'VM_reference_count_store_complete')
            self._cs_ranges.append(('post_store_reference_counter_storage',self._cs_counter,4))
        if not self._cs_returned:
            labels={WRAPPER:'wrapper_entry',TARGET:'scope_entry',0x26C8A8:'scope_fields_written',0x26C938:'before_entry_allocation',0x26C940:'entry_allocation_return',
                0x26C94C:'entry_constructed_before_publication',0x26C950:'table_slot_published',0x26C95C:'before_entry_lock',0x26C964:'entry_locked_before_result_store',
                0x26C968:'scope_lock_result_stored',0x26C98C:'scope_return'}
            if off==TARGET:
                assert self._reg(cpu,0)==self._cs_scope and self._reg(cpu,1)==self._cs_word and self._reg(cpu,30)==self.image+VM_RESUME
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._cs_sp
            if off==0x26C8A8:self._cs_written=True
            if off==0x26C940:self._cs_allocation=self._reg(cpu,0);assert self._cs_allocation
            if off in labels:self._cs_snapshot(cpu,pc,labels[off])
            if off in (0x347F00,0x347F10,0x347FD0):
                row=dict(index=len(self._cs_trace),PC=self._fmt_site(pc),kind={0x347F00:'mutex_lock_PLT',0x347F10:'mutex_unlock_PLT',0x347FD0:'malloc_PLT'}[off])
                row.update({'size':self._reg(cpu,0)} if off==0x347FD0 else {'argument_address':hex(self._reg(cpu,0))});self._cs_services.append(row)
            if pc in (LIBC_BASE+MALLOC,LIBC_BASE+LOCK,LIBC_BASE+UNLOCK):
                off_libc=pc-LIBC_BASE;row=dict(index=len(self._cs_trace),PC=self._fmt_site(pc),kind={MALLOC:'Bionic_malloc_entry',LOCK:'Bionic_mutex_lock_entry',UNLOCK:'Bionic_mutex_unlock_entry'}[off_libc])
                row.update({'size':self._reg(cpu,0)} if off_libc==MALLOC else {'argument_address':hex(self._reg(cpu,0))});self._cs_services.append(row)
            if off==VM_RESUME:
                assert self._cs_written and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._cs_sp and self._idctor_saved_hash(cpu)==self._cs_saved
                assert bytes(cpu.mem_read(self._cs_descriptor,48))==self._cs_before and bytes(cpu.mem_read(self._cs_scope+12,4))==self._cs_padding
                self._cs_snapshot(cpu,pc,'scope_callback_return');self._cs_returned=True
                entry=self._u(cpu,self._cs_slot);assert entry
                self._cs_ranges.extend([('active_scope',self._cs_scope,24),('held_diagnostic_entry',entry,48),('completed_diagnostic_table',self._cs_table,0x800),
                    ('completed_global_lock_header',self._cs_global+8,8)])
        elif off==VM_CALL:
            self._cs_snapshot(cpu,pc,'before_next_VM_call');d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
            self._cs_next=dict(index=len(self._cs_trace),callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),descriptor_address=hex(d),descriptor_width=48,
                descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),
                VM_call_executed=False,wrapper_executed=False,target_executed=False,
                argument_matches_reference_counter_storage=int.from_bytes(raw[8:16],'little')==self._cs_counter,
                argument_matches_MD5_object=int.from_bytes(raw[8:16],'little')==self._cs_word)
            self._cs_next=project_next_call(self._cs_next)
            self._cs_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.controls.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._cs_done and self._cs_returned and self._cs_written and self._cs_counter_checked and self._cs_violations==[]
        assert result['allocator_events'][:len(self._cs_events)]==self._cs_events
        delta=result['allocator_events'][len(self._cs_events):];prefix=dict(result);counts=deepcopy(result['actual_allocator_counts'])
        for event in delta:
            assert event[0] in ('alloc','free');counts['malloc' if event[0]=='alloc' else 'free']-=1
        prefix.update(actual_allocator_counts=counts,allocator_events=self._cs_events)
        old=super().finish(prefix,state,proof);assert old==self._cs_old,'CRC parent changed'
        h=hashlib.sha256()
        for key in self._cs_trace:h.update(key.encode()+bytes.fromhex(self._cs_code[key]))
        ledgers={key:old[key] for key in previous.EXPECTED['ledgers']};ledgers['allocator_counts']=result['actual_allocator_counts'];assert ledgers==EXPECTED['ledgers']
        returned=next(x for x in self._cs_rows if x['kind']=='scope_callback_return')
        return dict(control=old['control'],retained_CRC=dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=len(self._cs_trace),instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._cs_code),snapshots=self._cs_rows,
            native_writes=self._cs_writes,scope_arguments=self._cs_args,services=self._cs_services,next_VM_call=self._cs_next,observation_sites=self._cs_trace,observed_code=self._cs_code,
            new_allocator_events=delta,prefix_allocator_counts=counts,retired_prior_regions=self._cs_retired,reference_count_store=self._cs_counter_event,**ledgers,
            protected_ranges=[dict(label=l,address=hex(a),size=n) for l,a,n in self._cs_ranges],protected_write_events=[],
            protection_activation=dict(retained_regions_from_index=1,scope_entry_table_and_global_header_after_index=returned['index'],reference_counter_after_index=self._cs_counter_event['post_store_index']),stop_boundary=stop_boundary())

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,fixture=controls,token_adapter=controls.model,token_fixture=controls.fixture_owner,
        diagnostic_fixture=controls.fixture_owner.dependency,diagnostic_model=diagnostic_model,mutex_model=diagnostic_model.mutex,oracle=controls.oracle)
    return dict(post_crc_scope_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        main_path='original diagnostic scope entry and inherited matching Bionic allocation/mutex routes',
        independent_controls='independently prepared pages; actual tail wrapper and recursive mutexes versus existing diagnostic owner',
        component_allocation='explicit synthetic allocation services; independent owning allocator parity is not claimed',
        parent_prefix='full parent serializer result compared; prefix allocator counters reconstructed by subtracting observed new allocation/free events from final native counters',
        scope_lifetime='scope fields interpreted only after constructor field stores; reused prior storage is retired explicitly',
        protection='only declared scope storage, selected table slot and required mutex headers may change during callback',
        returned_X0='incidental physical callback register; DiagnosticScope is model metadata',rollback_scope='guest pages only; external provider effects excluded',
        counter_lifetime='one observed VM uint32 decrement from one to zero while scope remains held; counter storage awaits the next unexecuted delete call',
        exported_output='hashes, defined fields and write locations/widths; no raw word/input/CRC/identifier/seed, allocation contents, packed descriptors, padding or register dumps',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',CRC_prefix_revalidated=True,full_parent_case_result_equal=True,
        original_tail_wrapper_and_diagnostic_scope_entry_returned=True,tail_wrapper_preserves_entry_SP_and_LR=True,
        input_word_bucket_and_selected_slot_verified=True,scope_vtable_input_and_lock_result_written=True,scope_padding_preserved=True,
        actual_matching_Bionic_recursive_mutex_returned=True,active_scope_and_held_entry_preserved_until_next_call=True,
        only_selected_table_slot_can_be_published=True,published_entry_outside_header_write_protected=True,
        unconstructed_scope_fields_not_decoded=True,retired_prior_object_fields_not_decoded=True,
        retained_live_regions_write_protected=True,packed_descriptor_preserved_through_return=True,
        caller_SP_and_callee_saved_restored=True,internal_GP_registers_omitted=True,
        original_VM_reference_count_decrement_verified=True,zero_count_counter_not_freed_yet=True,reference_counter_reprotected_after_store=True,
        next_VM_call_boundary_observed=True,next_VM_call_executed=False,next_wrapper_executed=False,next_target_executed=False,
        new_providers_added=False,native_snapshot_used_as_python_model_input=False,whole_physical_stack_GP_FP_and_PAC_ABI_compared=False,
        physical_return_X0_ABI_compared=False,independent_owning_allocator_parity_verified=False,native_NULL_new_handler_throw_paths_verified=False,
        contended_mutex_or_host_concurrency_verified=False,standalone_Python_VM_continuation_verified=False,complete_VM_suffix_return_verified=False,
        complete_standalone_signer_verified=False,real_ART_JVM_execution=False,Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def stop_boundary():
    return dict(kind='before_next_VM_call_after_post_CRC_scope_entry',stop_before=hex(VM_CALL),VM_call_executed=False,wrapper_executed=False,target_executed=False)

def project_next_call(row):
    row=deepcopy(row);raw=bytes.fromhex(row.pop('wrapper_code_hex'))[:NEXT_WRAPPER_SIZE]
    row['wrapper_code_hex']=raw.hex();row['wrapper_code_sha256']=raw_hash(raw);assert 'descriptor_hex' not in row
    return row

def read_static(path,libc):
    rows={}
    for domain,p in (('main',path),('libc',libc)):
        with p.open('rb') as f:
            elf=ELFFile(f)
            if domain=='libc':
                symbols={s.name:s['st_value'] for sec in elf.iter_sections() if sec['sh_type']=='SHT_DYNSYM' for s in sec.iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
                assert [symbols[x] for x in ('malloc','pthread_mutex_lock','pthread_mutex_unlock')]==[MALLOC,LOCK,UNLOCK]
            for off,size in CODE_RANGES[domain]:
                raw=previous.elf_bytes(elf,f,off,size);rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows

def independent_controls(path,libc):
    identity=controls.identity(path)
    cases=[controls.compare(path,libc,base,label) for base in controls.BASES for label in controls.PROFILES+('warm_missing_entry','warm_existing')]
    cases.extend(bucket_104_control(path,libc,base) for base in controls.BASES);guards=controls.guards(path)
    assert identity==WRAPPER_IDENTITY and cases==CONTROL_SPECS and guards==ROLLBACK_SPECS
    return identity,cases,guards

def run(path,libc):
    parent=prior_evidence();p=previous.bootstrap_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostCRCScopeScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    identity,cases,guards=independent_controls(path,libc)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),
        static_code=code,wrapper_identity=identity,native_controls=cases,component_rollback_checks=guards,case_result=rows[0],case_result_sha256=digest(rows[0]))

def overlaps(address,size,region):
    a=int(address,16);b=int(region['address'],16);return a<b+region['size'] and b<a+size

def _validate(data,parent):
    old=parent['case_result']
    assert set(data)=={'schema','claims','providers','source_fingerprints','input_provenance','static_code','wrapper_identity','native_controls','component_rollback_checks','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['wrapper_identity']==WRAPPER_IDENTITY and data['native_controls']==CONTROL_SPECS and len(CONTROL_SPECS)==18
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==7
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        assert len(ranges)==len({off for off,size in ranges})
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'hex','size','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_CRC','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots','native_writes',
        'scope_arguments','services','next_VM_call','observation_sites','observed_code','new_allocator_events','prefix_allocator_counts','retired_prior_regions',
        'protected_ranges','protected_write_events','protection_activation','reference_count_store','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_CRC']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS)) and list(PARENT_FIELDS)==sorted(old)
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[:6]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,WRAPPER+12,TARGET)]
    assert sites[-1]=='main:'+hex(VM_CALL) and sites.count('main:'+hex(VM_CALL))==2
    assert sites.count('main:'+hex(VM_RESUME))==sites.count('main:'+hex(TARGET))==1
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4;h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256'] and digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_writes','scope_arguments','services','next_VM_call','new_allocator_events','prefix_allocator_counts','retired_prior_regions','protected_ranges','reference_count_store'):
        assert row[key]==EXPECTED[key],key
    snapshots=row['snapshots'];first,last=snapshots[0],snapshots[-1];returned=next(x for x in snapshots if x['kind']=='scope_callback_return');prior=old['snapshots'][-1]
    assert first['kind']=='scope_VM_call' and last['kind']=='before_next_VM_call' and first['index']==1 and last['index']==len(sites)
    assert all(a['index']<b['index'] for a,b in zip(snapshots,snapshots[1:]))
    assert first['descriptor_address']==old['next_VM_call']['descriptor_address'] and first['descriptor_sha256']==old['next_VM_call']['descriptor_sha256']
    assert first['VM_cursor']==returned['VM_cursor']==prior['VM_cursor']=='0x10a37c'
    assert first['SP']==returned['SP']==prior['SP'] and first['callee_saved_sha256']==returned['callee_saved_sha256']==prior['callee_saved_sha256']
    args=row['scope_arguments'];assert args['scope_storage_width']==24 and args['input_word_width']==8 and args['tail_wrapper_preserves_entry_SP_and_LR'] is True
    assert args['raw_input_word_exported'] is False and args['bucket']==first['diagnostic']['bucket']
    assert args['input_matches_retained_MD5_object'] is args['selected_entry_preexisted'] is True
    assert args['input_word_sha256']==raw_hash(int(prior['source_object']['address'],16).to_bytes(8,'little'))
    assert args['bucket']==(int(prior['source_object']['address'],16)>>4)&255
    assert first['diagnostic']['mutex_state_u16']==0x4000 and first['diagnostic']['owner_u32']==0
    for x in snapshots:
        assert sites[x['index']-1]==x['pc'] and x['registers']=={} and x['VM_state_address']==prior['VM_state_address']
        assert x['scope_storage_address']==args['scope_storage_address'] and x['scope_storage_width']==24
        assert x['scope_padding_4_sha256']==first['scope_padding_4_sha256'] and x['protected_regions_sha256']==first['protected_regions_sha256']
        if x['index']<=returned['index']:assert x['descriptor_sha256']==first['descriptor_sha256']
        f=x['scope_fields']
        if not x['scope_fields_written']:assert f=={}
        else:
            assert f['vtable_offset']=='0x35d410' and f['input_word_sha256']==args['input_word_sha256'] and f['bucket']==args['bucket']
        d=x['diagnostic'];assert d['outside_slot_sha256']==first['diagnostic']['outside_slot_sha256']
        assert d['table_sha256']==first['diagnostic']['table_sha256'] and d['global_lock_sha256']==first['diagnostic']['global_lock_sha256']
        assert d['slot_address']==first['diagnostic']['slot_address'] and d['global_lock_address']==first['diagnostic']['global_lock_address']
        if 'entry_outside_header_sha256' in first['diagnostic']:assert d['entry_outside_header_sha256']==first['diagnostic']['entry_outside_header_sha256']
    assert returned['scope_fields']['lock_result_i32']==0 and returned['diagnostic']['mutex_state_u16']==0x4001 and returned['diagnostic']['owner_u32']==137
    assert returned['scope_fields']==last['scope_fields'] and returned['scope_storage_sha256']==last['scope_storage_sha256']
    assert returned['diagnostic']==last['diagnostic'] and returned['diagnostic']['global_mutex_state_u16']==0
    store=row['reference_count_store'];post=next(x for x in snapshots if x['kind']=='VM_reference_count_store_complete')
    assert store['before_u32']==returned['reference_counter_u32']==1 and store['after_u32']==post['reference_counter_u32']==last['reference_counter_u32']==0
    assert store['decremented_by_one'] is True and store['incremented_by_one'] is False and store['size']==4
    assert store['PC']=='main:0x17208c' and store['post_store_PC']=='main:0x172090'
    assert sites[store['index']-1]==store['PC'] and sites[store['post_store_index']-1]==store['post_store_PC']
    assert returned['index']<store['index']<store['post_store_index']==post['index']<last['index']
    assert store['before_sha256']==raw_hash((1).to_bytes(4,'little')) and store['after_sha256']==raw_hash(bytes(4))
    assert all(x['reference_counter_address']==store['address'] for x in snapshots)
    counter_writes=[]
    for w in row['native_writes']:
        assert set(w)=={'index','PC','address','size'} and sites[w['index']-1]==w['PC'] and w['size']>0
        limit=len(row['protected_ranges']) if w['index']>store['post_store_index'] else FIXED_RANGE_COUNT+4 if w['index']>returned['index'] else FIXED_RANGE_COUNT
        regions=row['protected_ranges'][:limit]
        assert not any(overlaps(w['address'],w['size'],r) for r in regions)
        if overlaps(w['address'],w['size'],dict(address=store['address'],size=4)):counter_writes.append(w)
        if w['index']<=returned['index']:
            assert not overlaps(w['address'],w['size'],dict(address=first['descriptor_address'],size=48))
            assert not overlaps(w['address'],w['size'],dict(address=hex(int(args['scope_storage_address'],16)+12),size=4))
        if overlaps(w['address'],w['size'],dict(address=first['diagnostic']['table_address'],size=0x800)):
            assert not args['selected_entry_preexisted'] and w['address']==first['diagnostic']['slot_address'] and w['size']==8 and w['PC']=='main:0x26c94c'
    assert counter_writes==[{k:store[k] for k in ('index','PC','address','size')}]
    for s in row['services']:assert sites[s['index']-1]==s['PC'] and first['index']<s['index']<returned['index']
    mutex_address=hex(int(first['diagnostic']['entry_address'],16)+8)
    assert [(s['kind'],s['PC'],s['argument_address']) for s in row['services']]==[('mutex_lock_PLT','main:0x347f00',mutex_address),('Bionic_mutex_lock_entry','libc:'+hex(LOCK),mutex_address)]
    assert row['new_allocator_events']==[] and row['retired_prior_regions']==[]
    assert row['protected_write_events']==[] and row['prefix_allocator_counts']==old['allocator_counts']
    counts=deepcopy(row['prefix_allocator_counts'])
    for event in row['new_allocator_events']:
        assert event[0] in ('alloc','free');counts['malloc' if event[0]=='alloc' else 'free']+=1
    assert counts==row['allocator_counts']
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value and (key=='allocator_counts' or row[key]==old[key]),key
    assert row['protection_activation']==dict(retained_regions_from_index=1,scope_entry_table_and_global_header_after_index=returned['index'],reference_counter_after_index=store['post_store_index'])
    call=row['next_VM_call'];assert call['index']==len(sites) and call['VM_cursor_offset']==last['VM_cursor'] and call['callsite_offset']==hex(VM_CALL) and call['descriptor_width']==48
    assert call['wrapper_offset']==hex(NEXT_WRAPPER) and call['target_offset']==hex(NEXT_TARGET) and call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert len(bytes.fromhex(call['wrapper_code_hex']))==NEXT_WRAPPER_SIZE and raw_hash(bytes.fromhex(call['wrapper_code_hex']))==call['wrapper_code_sha256']
    assert all('main:'+hex(x) not in sites[returned['index']:] for x in (NEXT_WRAPPER,NEXT_TARGET))
    assert call['VM_call_executed'] is call['wrapper_executed'] is call['target_executed'] is False and row['stop_boundary']==stop_boundary()
    assert call['argument_matches_reference_counter_storage'] is True and call['argument_matches_MD5_object'] is False

def validate(data):
    _validate(data,prior_evidence())

def damaged_evidence_rejected(data):
    parent=prior_evidence()
    changes=[(('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('claims','full_parent_case_result_equal'),False),(('claims','scope_padding_preserved'),False),(('claims','physical_return_X0_ABI_compared'),True),
        (('providers','new_providers'),['hidden']),(('source_fingerprints','owners','diagnostic_model'),'0'*64),
        (('case_result','retained_CRC','case_result_sha256'),'0'*64),(('case_result','retained_CRC','verified_fields'),[]),
        (('case_result','instruction_observations'),0),(('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-2,'SP'),'0x0'),(('case_result','snapshots',-2,'callee_saved_sha256'),'0'*64),
        (('case_result','snapshots',-1,'protected_regions_sha256'),'0'*64),(('case_result','snapshots',0,'scope_fields'),{'lock_result_i32':0}),
        (('case_result','snapshots',0,'scope_fields_written'),True),(('case_result','snapshots',-1,'scope_fields','lock_result_i32'),11),
        (('case_result','snapshots',-1,'scope_fields','input_word_sha256'),'0'*64),(('case_result','snapshots',-1,'scope_padding_4_sha256'),'0'*64),
        (('case_result','snapshots',-1,'diagnostic','mutex_state_u16'),0x4000),(('case_result','snapshots',-1,'diagnostic','owner_u32'),0),
        (('case_result','snapshots',-1,'diagnostic','outside_slot_sha256'),'0'*64),(('case_result','snapshots',-1,'registers'),{'x0':'0x1'}),
        (('case_result','scope_arguments','scope_storage_width'),16),(('case_result','scope_arguments','input_word_width'),4),
        (('case_result','reference_count_store','before_u32'),2),(('case_result','reference_count_store','after_u32'),1),
        (('case_result','reference_count_store','decremented_by_one'),False),(('case_result','reference_count_store','post_store_index'),0),
        (('case_result','snapshots',-1,'reference_counter_u32'),1),(('case_result','next_VM_call','argument_matches_reference_counter_storage'),False),
        (('case_result','scope_arguments','raw_input_word_exported'),True),(('case_result','scope_arguments','input_word_sha256'),'0'*64),
        (('case_result','scope_arguments','selected_entry_preexisted'),not data['case_result']['scope_arguments']['selected_entry_preexisted']),
        (('case_result','services',0,'index'),0),(('case_result','native_writes',0,'size'),99),
        (('case_result','prefix_allocator_counts'),{}),(('case_result','protected_ranges'),[]),(('case_result','retired_prior_regions'),[{'unexpected':True}]),
        (('case_result','protection_activation','scope_entry_table_and_global_header_after_index'),0),
        (('case_result','next_VM_call','target_offset'),'0x0'),(('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','wrapper_code_sha256'),'0'*64),(('case_result','next_VM_call','target_executed'),True),
        (('case_result','next_VM_call','descriptor_hex'),'omitted'),(('case_result','new_allocator_events'),[['hidden']]),
        (('case_result','protected_write_events'),['hidden']),(('case_result','stop_boundary','VM_call_executed'),True),
        (('case_result','raw_identifier'),'omitted'),(('case_result','raw_CRC'),'omitted'),(('raw_identifier',),'omitted'),
        (('native_controls',0,'native_snapshot_input'),True),(('component_rollback_checks',0,'all_pages_unchanged'),False),
        (('wrapper_identity','no_PC_relative_instructions'),False)]
    for key in EXPECTED['ledgers']:changes.append((('case_result',key),{}))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:_validate(bad,parent)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged post-CRC scope evidence accepted: {path}')
    return len(changes)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true');args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as out:out.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-CRC scope replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),
        damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],original_scope_entry_returned=True,
        next_VM_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
