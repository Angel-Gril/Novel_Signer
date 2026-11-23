"""Verify diagnostic scope cleanup through the original matching Bionic unlock."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_post_diagnostic_small_allocation_return_dynamic_20261123 as previous
import verify_vm9_request_token_scopes_fresh_20261013 as controls
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_diagnostic_scope_leave_return_dynamic_20261123.json')
SCHEMA='vm9-native-171-post-diagnostic-scope-leave-return-dynamic-20261123-v1'
LIBC_BASE,UNLOCK=0x51000000,0x68D5C
VM_CALL,VM_RESUME,WRAPPER,TARGET=0x16AA48,0x16AA4C,0x288540,0x26C9D0
MAX_OBSERVATIONS=100000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
IMAGE_BASE=previous.IMAGE_BASE
RETIRED_SCOPE_FIELDS=('scope_address','scope_width','scope_sha256','scope_padding_4_sha256','scope_fields_written','scope_vtable_offset','scope_lock_result_i32','scope_input_pointer')
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes','services','next_VM_call')
NEXT_WRAPPER,NEXT_TARGET,NEXT_WRAPPER_SIZE=2656268,2394376,20
CODE_RANGES={'main': ((1485384, 32), (2655552, 12), (2542032, 56), (3440400, 16), (2656268, 20), (2394376, 32)), 'libc': ((429404, 376),)}
CODE_SHA256={'main:0x16aa48': 'c53f89ea694ed64ca8b5270d014ecf3bbd4777260ee7edee83a2e8e70b25178f', 'main:0x288540': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x26c9d0': '42142fa411128645eae4a067794bd0fa3233096f476550a1957dff74059fb04e', 'main:0x347f10': '5093a04a7496eb70842ce509c9f340e4ece9f9432ffbe8402c364b7137c7dfb6', 'main:0x28880c': 'fd897e729d6f7bafd533609f568c3ea473d7d33f2086d77720d7b47e2fa51480', 'main:0x248908': '3b699f320dc76301f8e4b129ba852222fef80518bdc6c0a5851a60312ef3abfe', 'libc:0x68d5c': '4db5f25d0e8e07c60fecf044c555fc0620d8dca1a5689a035d40197deb69bd68'}
EXPECTED={'instruction_observations': 921, 'instruction_trace_sha256': '2876853268d71c9c6fd40f5dbec6a3b5caafa1e600a245b154636570c318062b', 'observed_code_sha256': '8b361e362160a8b2a49d735f4342090bb4581c9838361c8c51766a203a18b22a', 'snapshots': [{'kind': 'scope_leave_VM_call', 'index': 1, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cd70', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'wrapper_entry', 'index': 2, 'pc': '0x288540', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cd70', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'scope_leave_entry', 'index': 5, 'pc': '0x26c9d0', 'SP': '0x7004b930', 'registers': {'x0': '0x7004d1d8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'scope_vtable_store_completed', 'index': 9, 'pc': '0x26c9e0', 'SP': '0x7004b930', 'registers': {'x0': '0x7004d1d8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'before_tail_unlock', 'index': 17, 'pc': '0x26ca04', 'SP': '0x7004b930', 'registers': {'x0': '0x136d40b8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'Bionic_unlock_entry', 'index': 19, 'pc': 'libc:0x68d5c', 'SP': '0x7004b930', 'registers': {'x0': '0x136d40b8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'after_selected_entry_write_1', 'index': 42, 'pc': 'libc:0x68e4c', 'SP': '0x7004b8e0', 'registers': {}, 'callee_saved_sha256': 'b5249bf46291c112dbbdbc0483985f7cfa3a58a615ae7d2cfce134ef036d9791', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': 'b551bcf57e7bfa79089e905dc4842083ef6542f5ebcd4e1378f07daf31d04100', 'mutex_state_u16': 16385, 'owner_u32': 0}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'after_selected_entry_write_2', 'index': 45, 'pc': 'libc:0x68e58', 'SP': '0x7004b8e0', 'registers': {}, 'callee_saved_sha256': 'b5249bf46291c112dbbdbc0483985f7cfa3a58a615ae7d2cfce134ef036d9791', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': False, 'scope_fields': {'scope_vtable_offset': '0x35d410', 'scope_lock_result_i32': 0, 'scope_input_pointer': '0x136d9660'}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'scope_leave_callback_return', 'index': 55, 'pc': '0x16aa4c', 'SP': '0x7004b930', 'registers': {'x0': '0x0', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a29c', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': True, 'scope_fields': {}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}, {'kind': 'before_next_VM_call', 'index': 921, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004ca78', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a2c8', 'descriptor_address': '0x7004cd70', 'descriptor_sha256': 'dcbe5b36ee7ca4ed2c88da29e9fdba1405f07065f8709931312d0c5dc308fa7d', 'scope_storage_address': '0x7004d1d8', 'scope_storage_width': 24, 'scope_storage_sha256': '214ac709dab657f2712de0dba864e7724d273dd2abcdb79c0df4d5efef3baf34', 'scope_padding_4_sha256': 'fd3506c426bbe7ae149df3e83b94ac8d5c9860cd3db29a2f92f261ffb5defc55', 'scope_lifetime_ended': True, 'scope_fields': {}, 'live_state': {'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'heap_string_object_address': '0x136d9660', 'heap_string_object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'heap_string_payload_address': '0x136d82e8', 'heap_string_payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'errno': 2, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 102, 'slot': '0x136f8330', 'entry': '0x136d40b0', 'table_sha256': '89e3b554370adf3a4f66d4358730266230835ba9d91e2596ea62addb2da847f4', 'outside_slot_sha256': 'c980bbb4a3a1f4126656e50fd98d8df9e5c02f4f52779697b6fd32f7b163258f', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'global_mutex_state_u16': 0, 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'prior_identifier_entry': {'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}}, 'selected_entry_address': '0x136d40b0', 'entry_outside_header_sha256': '332201f54bb201c194a9f74bdabc64c164232f83b908badd232d1cf6f0a2d5f9', 'mutex_header_padding_2_sha256': '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', 'initialized_word_address': '0x136d82f0', 'initialized_word_width': 4, 'initialized_word_sha256': '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450', 'initialized_word_is_one': True}], 'native_writes': [{'index': 8, 'PC': 'main:0x26c9dc', 'address': '0x7004d1d8', 'size': 8}, {'index': 19, 'PC': 'libc:0x68d5c', 'address': '0x7004b8e0', 'size': 8}, {'index': 19, 'PC': 'libc:0x68d5c', 'address': '0x7004b8e8', 'size': 8}, {'index': 22, 'PC': 'libc:0x68d68', 'address': '0x7004b8f0', 'size': 8}, {'index': 22, 'PC': 'libc:0x68d68', 'address': '0x7004b8f8', 'size': 8}, {'index': 23, 'PC': 'libc:0x68d6c', 'address': '0x7004b900', 'size': 8}, {'index': 41, 'PC': 'libc:0x68e48', 'address': '0x136d40bc', 'size': 4}, {'index': 44, 'PC': 'libc:0x68e54', 'address': '0x136d40b8', 'size': 2}, {'index': 87, 'PC': 'main:0x16a9f0', 'address': '0x7004d360', 'size': 8}, {'index': 154, 'PC': 'main:0x16d89c', 'address': '0x7004b9a0', 'size': 4}, {'index': 156, 'PC': 'main:0x16d8a4', 'address': '0x7004d390', 'size': 8}, {'index': 161, 'PC': 'main:0x16d8b8', 'address': '0x7004d360', 'size': 8}, {'index': 173, 'PC': 'main:0x16d8e8', 'address': '0x7004b990', 'size': 4}, {'index': 174, 'PC': 'main:0x16d8ec', 'address': '0x7004b960', 'size': 2}, {'index': 211, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 214, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 215, 'PC': 'main:0x16f974', 'address': '0x7004d370', 'size': 8}, {'index': 217, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 230, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 283, 'PC': 'main:0x17203c', 'address': '0x7004b990', 'size': 4}, {'index': 285, 'PC': 'main:0x172044', 'address': '0x7004b950', 'size': 4}, {'index': 289, 'PC': 'main:0x172054', 'address': '0x7004b9b0', 'size': 2}, {'index': 303, 'PC': 'main:0x17208c', 'address': '0x7004c060', 'size': 4}, {'index': 308, 'PC': 'main:0x1720a0', 'address': '0x7004d360', 'size': 8}, {'index': 376, 'PC': 'main:0x17203c', 'address': '0x7004b990', 'size': 4}, {'index': 378, 'PC': 'main:0x172044', 'address': '0x7004b950', 'size': 4}, {'index': 382, 'PC': 'main:0x172054', 'address': '0x7004b9b0', 'size': 2}, {'index': 396, 'PC': 'main:0x17208c', 'address': '0x7004ca90', 'size': 4}, {'index': 401, 'PC': 'main:0x1720a0', 'address': '0x7004d360', 'size': 8}, {'index': 451, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 454, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 455, 'PC': 'main:0x16f974', 'address': '0x7004d378', 'size': 8}, {'index': 457, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 470, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 494, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 548, 'PC': 'main:0x171268', 'address': '0x7004ca88', 'size': 8}, {'index': 564, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 565, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 570, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 594, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 648, 'PC': 'main:0x171268', 'address': '0x7004ca80', 'size': 8}, {'index': 664, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 665, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 670, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 694, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 748, 'PC': 'main:0x171268', 'address': '0x7004ca78', 'size': 8}, {'index': 764, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 765, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 770, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 805, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 808, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 809, 'PC': 'main:0x16f974', 'address': '0x7004d388', 'size': 8}, {'index': 811, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 824, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 846, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 848, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 849, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 853, 'PC': 'main:0x16a5d8', 'address': '0x7004d430', 'size': 8}, {'index': 856, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 866, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 905, 'PC': 'main:0x16a93c', 'address': '0x7004b990', 'size': 4}, {'index': 907, 'PC': 'main:0x16a944', 'address': '0x7004b9a0', 'size': 4}, {'index': 908, 'PC': 'main:0x16a948', 'address': '0x7004b980', 'size': 4}, {'index': 909, 'PC': 'main:0x16a94c', 'address': '0x7004b970', 'size': 4}, {'index': 910, 'PC': 'main:0x16a950', 'address': '0x7004d460', 'size': 8}, {'index': 916, 'PC': 'main:0x16aa34', 'address': '0x7004b9d0', 'size': 8}, {'index': 916, 'PC': 'main:0x16aa34', 'address': '0x7004b9d8', 'size': 8}, {'index': 918, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c0', 'size': 8}, {'index': 918, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c8', 'size': 8}], 'services': [{'index': 18, 'PC': '0x347f10', 'kind': 'pthread_mutex_unlock_route', 'argument': '0x136d40b8'}, {'index': 19, 'PC': 'libc:0x68d5c', 'kind': 'actual_Bionic_mutex_unlock_entry', 'argument': '0x136d40b8'}], 'next_VM_call': {'index': 921, 'callsite_offset': '0x16aa48', 'VM_cursor_offset': '0x10a2c8', 'descriptor_address': '0x7004ca78', 'descriptor_sha256': '418291d9b289354903a84842d52098667013b29cd09013baf9394cd224923f10', 'wrapper_offset': '0x28880c', 'target_offset': '0x248908', 'wrapper_code_hex': '088440a9021840b9030040f9e00308aa60001fd6', 'VM_call_executed': False, 'wrapper_executed': False, 'target_executed': False, 'descriptor_width': 48, 'destination_object_address': '0x136d9660', 'format_address': '0x126a1358', 'argument_W2_width': 4, 'argument_W2_sha256': 'be140f952726d0de64218f7258014e98ae1ff9e6a512fb745bb151dc0d73ae36', 'W2_zero_extends_to_X2': True, 'static_supplied_argument_projection': {'x0': '0x136d9660', 'x1': '0x126a1358', 'W2_width': 4, 'W2_sha256': 'be140f952726d0de64218f7258014e98ae1ff9e6a512fb745bb151dc0d73ae36'}, 'wrapper_code_sha256': 'fd897e729d6f7bafd533609f568c3ea473d7d33f2086d77720d7b47e2fa51480'}, 'new_allocator_events': [], 'ledgers': {'allocator_counts': {'malloc': 593, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}, 'protected_ranges': [{'label': 'prior_0', 'address': '0x7004d118', 'size': 24}, {'label': 'prior_1', 'address': '0x136d82c0', 'size': 8}, {'label': 'prior_2', 'address': '0x7004d130', 'size': 24}, {'label': 'prior_3', 'address': '0x136d82d0', 'size': 8}, {'label': 'prior_4', 'address': '0x7004d148', 'size': 24}, {'label': 'prior_5', 'address': '0x136d82d8', 'size': 8}, {'label': 'string_object', 'address': '0x136d9640', 'size': 24}, {'label': 'string_payload', 'address': '0x136d4050', 'size': 37}, {'label': 'output', 'address': '0x7004d178', 'size': 16}, {'label': 'cache', 'address': '0x136d73a0', 'size': 16}, {'label': 'counter', 'address': '0x136d82e0', 'size': 4}, {'label': 'cache_mutex', 'address': '0x136d4020', 'size': 48}, {'label': 'cache_globals', 'address': '0x1269e700', 'size': 64}, {'label': 'seed_constants', 'address': '0x1269e450', 'size': 128}, {'label': 'errno', 'address': '0x7000a010', 'size': 4}, {'label': 'new_heap_string_object', 'address': '0x136d9660', 'size': 24}, {'label': 'new_heap_string_payload', 'address': '0x136d82e8', 'size': 8}, {'label': 'prior_identifier_diagnostic_entry', 'address': '0x136d4080', 'size': 48}, {'label': 'diagnostic_guard', 'address': '0x1269eda0', 'size': 8}, {'label': 'diagnostic_table', 'address': '0x136f8000', 'size': 2048}, {'label': 'diagnostic_global_lock', 'address': '0x136d3c60', 'size': 48}, {'label': 'diagnostic_global_lock_pointer', 'address': '0x1269ed98', 'size': 8}, {'label': 'diagnostic_table_pointer', 'address': '0x1269eda8', 'size': 8}, {'label': 'initialized_allocation', 'address': '0x136d82f0', 'size': 4}, {'label': 'selected_entry_vtable', 'address': '0x136d40b0', 'size': 8}, {'label': 'selected_entry_tail', 'address': '0x136d40c0', 'size': 32}, {'label': 'released_entry_header', 'address': '0x136d40b8', 'size': 8}]}
WRAPPER_IDENTITY={'byte_count': 12, 'identical_to_existing_leave_wrapper': True, 'no_PC_relative_instructions': True}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'cold_zero', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'cold_high_bits', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'cold_cross_page', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'warm_existing', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'warm_nested', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'warm_saturated', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': None, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'empty_entry', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': None, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x122c0000', 'case': 'wrong_owner', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 1, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'cold_zero', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'cold_high_bits', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'cold_cross_page', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'warm_existing', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'warm_nested', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 0, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'warm_saturated', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': None, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'empty_entry', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': None, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}, {'image_base': '0x775c205000', 'case': 'wrong_owner', 'actual_wrapper': '0x288540', 'actual_scope': '0x26c9d0', 'original_wrapper_and_scope_leave_returned': True, 'all_declared_guest_ELF_heap_and_packed_bytes_equal': True, 'ordered_mutex_effects_equal': True, 'no_allocation_or_free': True, 'actual_matching_libc_recursive_mutexes': True, 'model_result': 1, 'native_snapshot_input': False, 'physical_return_X0_ABI_compared': False}]
ROLLBACK_SPECS=[{'case': 'unmapped_scope', 'rejected': True, 'all_pages_unchanged': True, 'external_observer_effects_rolled_back': False}, {'case': 'unmapped_table', 'rejected': True, 'all_pages_unchanged': True, 'external_observer_effects_rolled_back': False}, {'case': 'unmapped_selected_entry', 'rejected': True, 'all_pages_unchanged': True, 'external_observer_effects_rolled_back': False}, {'case': 'missing_packed', 'rejected': True, 'all_pages_unchanged': True, 'external_observer_effects_rolled_back': False}, {'case': 'bad_target', 'rejected': True, 'all_pages_unchanged': True, 'external_observer_effects_rolled_back': False}, {'case': 'unmapped_thread_pointer', 'rejected': True, 'all_pages_unchanged': True, 'external_observer_effects_rolled_back': False}]

def project_next_call(row):
    row=deepcopy(row);descriptor=bytes.fromhex(row.pop('descriptor_hex'))
    assert len(descriptor)==48 and raw_hash(descriptor)==row['descriptor_sha256']
    assert row['wrapper_offset']=='0x28880c' and row['target_offset']=='0x248908'
    assert int.from_bytes(descriptor[:8],'little')==IMAGE_BASE+0x248908
    row['descriptor_width']=48;row['destination_object_address']=hex(int.from_bytes(descriptor[8:16],'little'))
    row['format_address']=hex(int.from_bytes(descriptor[16:24],'little'));row['argument_W2_width']=4
    row['argument_W2_sha256']=raw_hash(descriptor[24:28]);row['W2_zero_extends_to_X2']=True
    row['static_supplied_argument_projection']={'x0':row['destination_object_address'],'x1':row['format_address'],'W2_width':4,'W2_sha256':row['argument_W2_sha256']}
    code=bytes.fromhex(row['wrapper_code_hex'])[:20]
    assert code.hex()=='088440a9021840b9030040f9e00308aa60001fd6'
    row['wrapper_code_hex']=code.hex();row['wrapper_code_sha256']=raw_hash(code)
    return row

def stop_boundary():
    return dict(kind='before_next_VM_call_after_diagnostic_scope_leave',stop_before=hex(VM_CALL),VM_call_executed=False,wrapper_executed=False,target_executed=False)

def validate_release(row,data,returned):
    by_kind={x['kind']:x for x in row['snapshots']};first=row['snapshots'][0]
    one=by_kind['after_selected_entry_write_1'];two=by_kind['after_selected_entry_write_2'];entry=int(first['selected_entry_address'],16)
    assert one['pc']=='libc:0x68e4c' and one['index']==42 and two['pc']=='libc:0x68e58' and two['index']==45
    assert one['registers']==two['registers']=={}
    assert one['live_state']['diagnostic']['mutex_state_u16']==0x4001 and one['live_state']['diagnostic']['owner_u32']==0
    assert two['live_state']['diagnostic']['mutex_state_u16']==0x4000 and two['live_state']['diagnostic']['owner_u32']==0
    writes=[w for w in row['native_writes'] if overlaps(w['address'],w['size'],dict(address=hex(entry),size=48))]
    assert writes==[dict(index=one['index']-1,PC='libc:0x68e48',address=hex(entry+12),size=4),
        dict(index=two['index']-1,PC='libc:0x68e54',address=hex(entry+8),size=2)]
    assert row['observed_code']['libc:0x68e48']=='5f0100b9' and row['observed_code']['libc:0x68e54']=='2bfc0d48'
    assert first['index']<one['index']<two['index']<returned['index'] and returned['index']==55
    assert len(row['snapshots'])==10

def release_damage_cases():
    return [(('case_result','snapshots',6,'registers'),{'x10':'0x1'}),(('case_result','snapshots',6,'live_state','diagnostic','owner_u32'),137),
        (('case_result','snapshots',7,'live_state','diagnostic','mutex_state_u16'),0x4001)]

def validate_next_call(row,data,last):
    call=row['next_VM_call'];first=row['snapshots'][0];returned=row['snapshots'][-2]
    assert call['index']==row['instruction_observations'] and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']==last['VM_cursor']=='0x10a2c8'
    assert call['descriptor_width']==48 and call['descriptor_address']==last['registers']['x0']=='0x7004ca78'
    assert call['wrapper_offset']==hex(NEXT_WRAPPER)=='0x28880c' and call['target_offset']==hex(NEXT_TARGET)=='0x248908'
    assert call['destination_object_address']==first['live_state']['heap_string_object_address']=='0x136d9660' and call['format_address']==hex(IMAGE_BASE+0x3E1358)
    assert call['argument_W2_width']==4 and len(call['argument_W2_sha256'])==64 and call['W2_zero_extends_to_X2'] is True
    assert call['static_supplied_argument_projection']=={'x0':call['destination_object_address'],'x1':call['format_address'],'W2_width':4,'W2_sha256':call['argument_W2_sha256']}
    assert call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert len(bytes.fromhex(call['wrapper_code_hex']))==NEXT_WRAPPER_SIZE==20 and raw_hash(bytes.fromhex(call['wrapper_code_hex']))==call['wrapper_code_sha256']
    assert call['VM_call_executed'] is call['wrapper_executed'] is call['target_executed'] is False and 'descriptor_hex' not in call
    assert not any(key in call for key in ('argument_W2','W2_value','raw_format','format_hex'))
    suffix=row['observation_sites'][returned['index']:]
    assert 'main:'+hex(NEXT_WRAPPER) not in suffix and 'main:'+hex(NEXT_TARGET) not in suffix

LEAVE_PROFILES=('cold_zero','cold_high_bits','cold_cross_page','warm_existing','warm_nested','warm_saturated','empty_entry','wrong_owner')

def leave_fixture(path,base,label):
    pages,obj,word,tid=controls.fresh(path,base,'warm_existing' if label in ('empty_entry','wrong_owner') else label,'leave')
    table=controls.scopes._u(pages,base+controls.scopes.TABLE);slot=table+((word>>4)&255)*8;entry=controls.scopes._u(pages,slot)
    if label=='empty_entry':controls.dependency.w(pages,slot,0)
    if label=='wrong_owner':controls.dependency.w(pages,entry+12,88,4)
    return pages,obj,word,tid

def wrapper_identity(path):
    p=controls.oracle.image_pages(path,controls.BASES[0]);base=controls.BASES[0]
    assert controls._read_span(p,base+WRAPPER,12)==controls._read_span(p,base+0x288B40,12)==bytes.fromhex('012040a9e00308aa20001fd6')
    return dict(byte_count=12,identical_to_existing_leave_wrapper=True,no_PC_relative_instructions=True)

def compare_leave(path,libc,base,label):
    p,obj,word,tid=leave_fixture(path,base,label)
    watched={(page<<12,4096):None for page in p if not controls.oracle.GUEST+0xA000<=page<<12<controls.oracle.GUEST+0x10000}
    sites=[]
    _,memory,calls,native_ledger=controls.oracle.native(path,base,WRAPPER,[controls.PACKED],p,libc=libc,real_singletons=True,
        real_mutexes=True,real_recursive_mutexes=True,real_diagnostics=True,thread_id=tid,observed_memory=watched,
        instruction_observer=lambda cpu,pc:sites.append(pc-base),instruction_limit=20000)
    allocation=controls.oracle.Allocator();ledger=[]
    result=controls.model.apply_token_diagnostic_callback(p,argument_block_address=controls.PACKED,image_base=base,
        thread_pointer=controls.TP,allocate=allocation.model,thread_id=tid,observer=lambda *e:ledger.append(list(e)))
    assert sites[:4]==[WRAPPER,WRAPPER+4,WRAPPER+8,TARGET]
    assert controls._read_span(p,controls.oracle.GUEST,0xA000)==memory
    assert all(controls._read_span(p,a,n)==raw for (a,n),raw in watched.items())
    assert calls==allocation.calls==[] and ledger==native_ledger
    print('PASS scope leave',hex(base),label,flush=True)
    return dict(image_base=hex(base),case=label,actual_wrapper=hex(WRAPPER),actual_scope=hex(TARGET),original_wrapper_and_scope_leave_returned=True,
        all_declared_guest_ELF_heap_and_packed_bytes_equal=True,ordered_mutex_effects_equal=True,no_allocation_or_free=True,
        actual_matching_libc_recursive_mutexes=True,model_result=result,native_snapshot_input=False,physical_return_X0_ABI_compared=False)

def leave_guards(path):
    rows=[]
    for label in ('unmapped_scope','unmapped_table','unmapped_selected_entry','missing_packed','bad_target','unmapped_thread_pointer'):
        p,obj,word,tid=leave_fixture(path,controls.BASES[0],'warm_existing');base=controls.BASES[0]
        kw=dict(argument_block_address=controls.PACKED,image_base=base,thread_pointer=controls.TP,allocate=controls.oracle.Allocator().model,thread_id=tid)
        controls.dependency.w(p,obj,0xAABBCCDDEEFF0011)
        if label=='unmapped_scope':controls.dependency.w(p,controls.PACKED+8,0x64000000)
        elif label=='unmapped_table':controls.dependency.w(p,base+controls.scopes.TABLE,0x64000000)
        elif label=='unmapped_selected_entry':
            table=controls.scopes._u(p,base+controls.scopes.TABLE);controls.dependency.w(p,table+((word>>4)&255)*8,0x64000000)
        elif label=='missing_packed':del p[controls.PACKED>>12]
        elif label=='bad_target':controls.dependency.w(p,controls.PACKED,base+1)
        elif label=='unmapped_thread_pointer':kw['thread_pointer']=0x64000000
        before={k:bytes(v) for k,v in p.items()}
        try:controls.model.apply_token_diagnostic_callback(p,**kw)
        except (controls.RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True,external_observer_effects_rolled_back=False))
    return rows

class PostDiagnosticScopeLeaveScenario(previous.PostDiagnosticSmallAllocationScenario):
    def __init__(self,control):
        super().__init__(control)
        self._scopeleave_active=False;self._scopeleave_done=False;self._scopeleave_returned=False;self._scopeleave_lifetime_ended=False
        self._scopeleave_count=0;self._scopeleave_trace=[];self._scopeleave_code={};self._scopeleave_rows=[]
        self._scopeleave_writes=[];self._scopeleave_live_writes=[];self._scopeleave_services=[];self._scopeleave_pending=[];self._scopeleave_header_samples=0

    def _scopeleave_track(self,cpu,pc):
        self._scopeleave_count+=1;assert self._scopeleave_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._scopeleave_trace.append(key);self._scopeleave_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _scopeleave_parent_state(self,cpu,pc):
        written=self._heapscope_written
        try:
            if self._scopeleave_lifetime_ended:self._heapscope_written=False
            return self._smallalloc_scope_state(cpu,pc)
        finally:self._heapscope_written=written

    def _scopeleave_snapshot(self,cpu,pc,kind):
        state=self._scopeleave_parent_state(cpu,pc);scope=bytes(cpu.mem_read(self._scopeleave_object,24));entry=bytes(cpu.mem_read(self._scopeleave_entry,48))
        row=dict(kind=kind,index=self._scopeleave_count,pc=('libc:'+hex(pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else hex(pc-self.image)),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),registers={} if kind.startswith('after_selected_entry_write') else {f'x{n}':hex(self._reg(cpu,n)) for n in (0,30)},
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_state_address=hex(self._postalloc_vmstate),VM_cursor=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(self._scopeleave_descriptor),descriptor_sha256=raw_hash(bytes(cpu.mem_read(self._scopeleave_descriptor,48))),
            scope_storage_address=hex(self._scopeleave_object),scope_storage_width=24,scope_storage_sha256=raw_hash(scope),scope_padding_4_sha256=raw_hash(scope[12:16]),
            scope_lifetime_ended=self._scopeleave_lifetime_ended,scope_fields={} if self._scopeleave_lifetime_ended else {k:state[k] for k in ('scope_vtable_offset','scope_lock_result_i32','scope_input_pointer')},
            live_state={k:v for k,v in state.items() if k not in RETIRED_SCOPE_FIELDS},selected_entry_address=hex(self._scopeleave_entry),
            entry_outside_header_sha256=raw_hash(entry[:8]+entry[16:]),mutex_header_padding_2_sha256=raw_hash(entry[10:12]),
            initialized_word_address=hex(self._smallalloc_pointer),initialized_word_width=4,initialized_word_sha256=raw_hash(bytes(cpu.mem_read(self._smallalloc_pointer,4))),
            initialized_word_is_one=self._u(cpu,self._smallalloc_pointer,4)==1)
        self._scopeleave_rows.append(row)

    def _scopeleave_start(self,cpu,pc,state):
        self._smallalloc_track(cpu,pc);self._smallalloc_snapshot(cpu,pc,'before_next_VM_call')
        d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
        self._smallalloc_next=previous.project_next_call(dict(index=self._smallalloc_count,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False))
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data);old=data['case_result'];h=hashlib.sha256()
        for key in self._smallalloc_trace:h.update(key.encode()+bytes.fromhex(self._smallalloc_code[key]))
        for value,key in ((self._smallalloc_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),(digest(self._smallalloc_code),'observed_code_sha256'),
            (self._smallalloc_trace,'observation_sites'),(self._smallalloc_code,'observed_code'),(self._smallalloc_rows,'snapshots'),(self._smallalloc_writes,'native_writes'),
            (self._smallalloc_services,'services'),(self._smallalloc_next,'next_VM_call')):assert value==old[key],key
        assert state['allocator_events_ref']==self._smallalloc_events+old['new_allocator_events']
        self._scopeleave_events=deepcopy(state['allocator_events_ref']);self._scopeleave_old=old;self._scopeleave_descriptor=d;self._scopeleave_before=raw
        self._scopeleave_object=int.from_bytes(raw[8:16],'little');self._scopeleave_entry=int(self._heapscope_diagnostic(cpu)['entry'],16)
        assert wrapper==self.image+WRAPPER and int.from_bytes(raw[:8],'little')==self.image+TARGET and self._scopeleave_object==self._heapscope_object
        self._scopeleave_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._scopeleave_saved=self._idctor_saved_hash(cpu)
        self._scopeleave_ranges=[r for r in self._smallalloc_ranges if r[0] not in ('active_scope','held_diagnostic_entry')]
        self._scopeleave_ranges.extend([('selected_entry_vtable',self._scopeleave_entry,8),('selected_entry_tail',self._scopeleave_entry+16,32)])
        self._smallalloc_active=False;self._smallalloc_done=False;self._scopeleave_active=True
        self._scopeleave_track(cpu,pc);self._scopeleave_snapshot(cpu,pc,'scope_leave_VM_call')

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._scopeleave_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                row=dict(index=self._scopeleave_count,PC=('libc:'+hex(pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else 'main:'+hex(pc-self.image)),address=hex(address),size=size)
                self._scopeleave_writes.append(row)
                labels=[label for label,a,n in self._scopeleave_ranges if address<a+n and a<address+size]
                if labels:raise AssertionError('scope leave wrote protected live state')
                if not self._scopeleave_returned:assert not (address<self._scopeleave_descriptor+48 and self._scopeleave_descriptor<address+size), 'scope leave wrote packed descriptor'
                if address<self._scopeleave_entry+16 and self._scopeleave_entry+8<address+size:self._scopeleave_pending.append(row)
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._scopeleave_active:
            if self._smallalloc_active and self._smallalloc_returned and pc==self.image+VM_CALL:
                self._scopeleave_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._scopeleave_track(cpu,pc);off=pc-self.image
        if self._scopeleave_pending:
            self._scopeleave_header_samples+=1;self._scopeleave_snapshot(cpu,pc,'after_selected_entry_write_'+str(self._scopeleave_header_samples));self._scopeleave_pending=[]
        if not self._scopeleave_returned:
            if off in (WRAPPER,TARGET,0x26C9E0,0x26CA04):
                if off==TARGET:assert self._reg(cpu,0)==self._scopeleave_object and self._reg(cpu,30)==self.image+VM_RESUME
                self._scopeleave_snapshot(cpu,pc,{WRAPPER:'wrapper_entry',TARGET:'scope_leave_entry',0x26C9E0:'scope_vtable_store_completed',0x26CA04:'before_tail_unlock'}[off])
            if off==0x347F10 or pc==LIBC_BASE+UNLOCK:
                self._scopeleave_services.append(dict(index=self._scopeleave_count,PC=hex(off) if off==0x347F10 else 'libc:'+hex(UNLOCK),
                    kind='pthread_mutex_unlock_route' if off==0x347F10 else 'actual_Bionic_mutex_unlock_entry',argument=hex(self._reg(cpu,0))))
                if pc==LIBC_BASE+UNLOCK:self._scopeleave_snapshot(cpu,pc,'Bionic_unlock_entry')
            if off==VM_RESUME:
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._scopeleave_sp and self._idctor_saved_hash(cpu)==self._scopeleave_saved
                assert bytes(cpu.mem_read(self._scopeleave_descriptor,48))==self._scopeleave_before
                self._scopeleave_lifetime_ended=True;self._scopeleave_snapshot(cpu,pc,'scope_leave_callback_return');self._scopeleave_returned=True
                self._scopeleave_ranges.append(('released_entry_header',self._scopeleave_entry+8,8))
        elif off==VM_CALL:
            self._scopeleave_snapshot(cpu,pc,'before_next_VM_call');d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
            self._scopeleave_next=dict(index=self._scopeleave_count,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
                descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),
                target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False)
            self._scopeleave_next=project_next_call(self._scopeleave_next)
            self._scopeleave_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.controls.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._scopeleave_done and self._scopeleave_returned and self._scopeleave_lifetime_ended and self._scopeleave_live_writes==[]
        h=hashlib.sha256()
        for key in self._scopeleave_trace:h.update(key.encode()+bytes.fromhex(self._scopeleave_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],
            inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,
            late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        assert result['allocator_events']==self._scopeleave_events
        for key,value in ledgers.items():assert value==self._scopeleave_old[key],key
        returned=next(x for x in self._scopeleave_rows if x['kind']=='scope_leave_callback_return')
        return dict(control=self._scopeleave_old['control'],retained_small_allocation=dict(case_result_sha256=digest(self._scopeleave_old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._scopeleave_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._scopeleave_code),
            snapshots=self._scopeleave_rows,native_writes=self._scopeleave_writes,services=self._scopeleave_services,
            next_VM_call=self._scopeleave_next,observation_sites=self._scopeleave_trace,observed_code=self._scopeleave_code,new_allocator_events=[],**ledgers,
            protected_ranges=[dict(label=label,address=hex(a),size=n) for label,a,n in self._scopeleave_ranges],protected_write_events=[],
            protection_activation=dict(retained_regions_from_index=1,released_header_after_index=returned['index'],scope_lifetime_ends_at_index=returned['index']),stop_boundary=stop_boundary())

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,fixture=controls,diagnostic_fixture=controls.dependency,adapter=controls.model,
        diagnostic_model=controls.scopes,mutex_model=controls.scopes.mutex,object_model=controls.scopes.objects,oracle=controls.oracle)
    return dict(scope_leave_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        main_path_unlock='inherited original matching Bionic pthread_mutex_unlock entry and body',
        independent_controls='fresh scope states prepared independently by Python; actual leave wrapper versus existing scope adapter/model',
        component_services='synthetic allocation only while preparing component fixtures; leave callbacks do not allocate or free',
        rollback_scope='guest pages only; external observer effects excluded',returned_X0='incidental callback register; no general scope-constructor return ABI claim',
        lifetime_boundary='scope fields stop being decoded at callback return; its retired stack storage is retained only by hash',
        exported_output='hashes, lengths, defined live pointers/scalars and write locations/widths; no raw identifiers, seed, packed descriptors, padding or register dumps',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',four_byte_allocation_prefix_revalidated=True,original_scope_leave_wrapper_and_target_returned=True,
        matching_Bionic_unlock_entry_and_body_executed=True,selected_recursive_mutex_released=True,selected_scope_lifetime_closed=True,
        sample_scope_entry_and_leave_pair_verified=True,selected_entry_retained_in_process_table=True,scope_storage_preserved_through_return=True,
        scope_fields_not_interpreted_after_lifetime_end=True,internal_unlock_registers_omitted=True,initialized_word_one_preserved=True,
        old_live_objects_table_and_other_entries_write_protected=True,selected_entry_outside_header_write_protected=True,
        released_header_write_protected_after_return=True,caller_SP_and_callee_saved_restored=True,next_VM_call_boundary_observed=True,
        next_VM_call_executed=False,next_wrapper_executed=False,next_target_executed=False,new_providers_added=False,native_snapshot_used_as_python_model_input=False,
        whole_physical_stack_bytes_compared=False,contended_mutex_or_host_concurrency_verified=False,standalone_Python_VM_continuation_verified=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,real_ART_JVM_execution=False,
        Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def read_static(path,libc):
    rows={}
    for domain,p in (('main',path),('libc',libc)):
        with p.open('rb') as f:
            elf=ELFFile(f)
            for off,size in CODE_RANGES[domain]:
                raw=previous.previous.previous.elf_bytes(elf,f,off,size);rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows

def independent_controls(path,libc):
    identity=wrapper_identity(path)
    cases=[compare_leave(path,libc,base,label) for base in controls.BASES for label in LEAVE_PROFILES]
    guards=leave_guards(path)
    assert identity==WRAPPER_IDENTITY and cases==CONTROL_SPECS and guards==ROLLBACK_SPECS
    return identity,cases,guards

def run(path,libc):
    parent=prior_evidence();p=previous.previous.previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostDiagnosticScopeLeaveScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    identity,cases,guards=independent_controls(path,libc)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),
        static_code=code,wrapper_identity=identity,native_controls=cases,component_rollback_checks=guards,case_result=rows[0],case_result_sha256=digest(rows[0]))

def overlaps(address,size,region):
    a=int(address,16);b=int(region['address'],16);return a<b+region['size'] and b<a+size

def site(pc):return pc if pc.startswith('libc:') else 'main:'+pc

def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert set(data)=={'schema','claims','providers','source_fingerprints','input_provenance','static_code','wrapper_identity','native_controls','component_rollback_checks','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['wrapper_identity']==WRAPPER_IDENTITY and data['native_controls']==CONTROL_SPECS and len(CONTROL_SPECS)==16
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==6
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        assert len(ranges)==len({off for off,size in ranges})
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'hex','size','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_small_allocation','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots',
        'native_writes','services','next_VM_call','observation_sites','observed_code','new_allocator_events','protected_ranges','protected_write_events',
        'protection_activation','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_small_allocation']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[:5]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)] and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(VM_RESUME))==1 and sites.count('libc:'+hex(UNLOCK))==1
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4');h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256'] and digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    assert code['main:'+hex(VM_CALL)]=='00013fd6'
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_writes','services','next_VM_call','new_allocator_events','protected_ranges'):assert row[key]==EXPECTED[key],key
    snapshots=row['snapshots'];by_kind={x['kind']:x for x in snapshots};assert len(by_kind)==len(snapshots)
    first=snapshots[0];last=snapshots[-1];returned=by_kind['scope_leave_callback_return'];prior=old['snapshots'][-1];scope=prior['scope_state']
    assert first['kind']=='scope_leave_VM_call' and last['kind']=='before_next_VM_call' and first['index']==1 and last['index']==len(sites)
    assert all(a['index']<b['index'] for a,b in zip(snapshots,snapshots[1:]))
    for x in snapshots:assert sites[x['index']-1]==site(x['pc'])
    assert first['descriptor_address']==old['next_VM_call']['descriptor_address'] and first['descriptor_sha256']==old['next_VM_call']['descriptor_sha256']
    assert first['scope_storage_address']==old['next_VM_call']['scope_object_address']==scope['scope_address']
    assert first['scope_storage_sha256']==scope['scope_sha256'] and first['scope_storage_width']==24
    assert first['VM_cursor']==returned['VM_cursor']==prior['VM_cursor']=='0x10a29c'
    for x in (by_kind['scope_leave_entry'],returned):
        assert x['SP']==first['SP']==prior['SP'] and x['callee_saved_sha256']==first['callee_saved_sha256']==prior['callee_saved_sha256']
    assert by_kind['scope_leave_entry']['registers']['x0']==first['scope_storage_address'] and by_kind['scope_leave_entry']['registers']['x30']==hex(IMAGE_BASE+VM_RESUME)
    expected_live={k:v for k,v in scope.items() if k not in RETIRED_SCOPE_FIELDS}
    expected_fields={k:scope[k] for k in ('scope_vtable_offset','scope_lock_result_i32','scope_input_pointer')}
    assert expected_fields['scope_lock_result_i32']==0
    for x in snapshots:
        assert x['initialized_word_address']==prior['allocation_address'] and x['initialized_word_width']==4 and x['initialized_word_is_one'] is True
        assert x['initialized_word_sha256']==prior['allocation_sha256']==raw_hash((1).to_bytes(4,'little'))
        assert x['VM_state_address']==prior['VM_state_address'] and x['selected_entry_address']==scope['diagnostic']['entry']
        assert set(x['live_state'])==set(expected_live)
        for key,value in expected_live.items():
            if key!='diagnostic':assert x['live_state'][key]==value,key
        d=x['live_state']['diagnostic'];assert set(d)==set(scope['diagnostic'])
        for key,value in scope['diagnostic'].items():
            if key not in ('entry_sha256','mutex_state_u16','owner_u32'):assert d[key]==value,key
        assert x['entry_outside_header_sha256']==first['entry_outside_header_sha256'] and x['mutex_header_padding_2_sha256']==first['mutex_header_padding_2_sha256']
        assert x['scope_lifetime_ended'] is (x['index']>=returned['index'])
        assert x['scope_fields']==({} if x['scope_lifetime_ended'] else expected_fields)
        if x['index']<=returned['index']:
            assert x['scope_storage_sha256']==first['scope_storage_sha256'] and x['scope_padding_4_sha256']==first['scope_padding_4_sha256']
            assert x['descriptor_sha256']==first['descriptor_sha256']
        assert set(x['registers'])==(set() if x['kind'].startswith('after_selected_entry_write') else {'x0','x30'})
    for x in (first,by_kind['Bionic_unlock_entry']):assert x['live_state']['diagnostic']['mutex_state_u16']==0x4001 and x['live_state']['diagnostic']['owner_u32']==137
    for x in (returned,last):assert x['live_state']['diagnostic']['mutex_state_u16']==0x4000 and x['live_state']['diagnostic']['owner_u32']==0
    assert returned['live_state']['diagnostic']['entry_sha256']==last['live_state']['diagnostic']['entry_sha256']
    scope_writes=[w for w in row['native_writes'] if w['index']<=returned['index'] and overlaps(w['address'],w['size'],dict(address=first['scope_storage_address'],size=24))]
    assert len(scope_writes)==1 and scope_writes[0]['PC']=='main:0x26c9dc' and scope_writes[0]['address']==first['scope_storage_address'] and scope_writes[0]['size']==8
    validate_release(row,data,returned)
    expected_protected=[r for r in old['protected_ranges'] if r['label'] not in ('active_scope','held_diagnostic_entry')]
    entry=int(first['selected_entry_address'],16)
    expected_protected.extend([dict(label='selected_entry_vtable',address=hex(entry),size=8),dict(label='selected_entry_tail',address=hex(entry+16),size=32),
        dict(label='released_entry_header',address=hex(entry+8),size=8)])
    assert row['protected_ranges']==expected_protected and row['protected_write_events']==[]
    assert row['protection_activation']==dict(retained_regions_from_index=1,released_header_after_index=returned['index'],scope_lifetime_ends_at_index=returned['index'])
    for w in row['native_writes']:
        assert set(w)=={'index','PC','address','size'} and sites[w['index']-1]==w['PC'] and w['size']>0
        regions=row['protected_ranges'] if w['index']>returned['index'] else row['protected_ranges'][:-1]
        assert not any(overlaps(w['address'],w['size'],r) for r in regions)
        if w['index']<=returned['index']:assert not overlaps(w['address'],w['size'],dict(address=first['descriptor_address'],size=48))
    assert len(row['services'])==2
    for service,pc in zip(row['services'],('main:0x347f10','libc:'+hex(UNLOCK))):
        assert service['argument']==hex(entry+8) and sites[service['index']-1]==pc and first['index']<service['index']<returned['index']
    assert row['new_allocator_events']==[]
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value==old[key],key
    validate_next_call(row,data,last)
    assert row['stop_boundary']==stop_boundary()

def damaged_evidence_rejected(data):
    changes=[(('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('claims','scope_fields_not_interpreted_after_lifetime_end'),False),(('providers','new_providers'),['hidden']),
        (('source_fingerprints','owners','mutex_model'),'0'*64),(('case_result','retained_small_allocation','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),0),(('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'live_state','counter_u32'),1),(('case_result','snapshots',-1,'live_state','live_regions_sha256'),'0'*64),
        (('case_result','snapshots',-1,'live_state','heap_string_payload_sha256'),'0'*64),(('case_result','snapshots',-1,'live_state','cache_mutex_state_u16'),1),
        (('case_result','snapshots',-2,'SP'),'0x0'),(('case_result','snapshots',-2,'callee_saved_sha256'),'0'*64),
        (('case_result','snapshots',-1,'live_state','diagnostic','mutex_state_u16'),0x4001),(('case_result','snapshots',-1,'live_state','diagnostic','owner_u32'),137),
        (('case_result','snapshots',-1,'initialized_word_is_one'),False),(('case_result','snapshots',-1,'initialized_word_sha256'),'0'*64),
        (('case_result','snapshots',-1,'scope_lifetime_ended'),False),(('case_result','snapshots',-1,'scope_fields'),{'scope_lock_result_i32':0}),
        (('case_result','snapshots',-1,'entry_outside_header_sha256'),'0'*64),(('case_result','snapshots',-1,'mutex_header_padding_2_sha256'),'0'*64),
        (('case_result','snapshots',-1,'live_state','diagnostic','table_sha256'),'0'*64),
        (('case_result','services',0,'argument'),'0x0'),(('case_result','native_writes',0,'size'),99),
        (('case_result','protection_activation','scope_lifetime_ends_at_index'),0),(('case_result','next_VM_call','target_offset'),'0x0'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),(('case_result','next_VM_call','wrapper_code_sha256'),'0'*64),
        (('case_result','next_VM_call','target_executed'),True),(('case_result','next_VM_call','descriptor_hex'),'omitted'),
        (('case_result','new_allocator_events'),[['hidden']]),(('case_result','protected_write_events'),['hidden']),
        (('case_result','stop_boundary','VM_call_executed'),True),(('case_result','raw_identifier'),'omitted'),(('case_result','raw_allocation'),'omitted'),
        (('raw_identifier',),'omitted'),(('native_controls',0,'native_snapshot_input'),True),
        (('component_rollback_checks',0,'all_pages_unchanged'),False),(('wrapper_identity','no_PC_relative_instructions'),False)]
    changes.extend(release_damage_cases())
    for key in EXPECTED['ledgers']:changes.append((('case_result',key),{}))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged scope-leave evidence accepted: {path}')
    return len(changes)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--elf',type=Path);parser.add_argument('--libc',type=Path)
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--capture',action='store_true');mode.add_argument('--replay',action='store_true')
    args=parser.parse_args()
    if (args.capture or args.replay) and (not args.elf or not args.libc):parser.error('--capture and --replay require --elf and --libc')
    if args.capture:
        if EVIDENCE.exists():raise FileExistsError('frozen evidence already exists; refusing overwrite')
        data=run(args.elf,args.libc);validate(data);rejected=damaged_evidence_rejected(data)
        with EVIDENCE.open('x',encoding='utf-8',newline='\n') as out:out.write(json.dumps(data,indent=2)+'\n')
    else:
        data=json.loads(EVIDENCE.read_text(encoding='utf-8'));validate(data);rejected=damaged_evidence_rejected(data)
        if args.replay:assert run(args.elf,args.libc)==data,'fresh scope-leave replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),
        damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],
        original_scope_leave_returned=True,selected_recursive_mutex_released=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
