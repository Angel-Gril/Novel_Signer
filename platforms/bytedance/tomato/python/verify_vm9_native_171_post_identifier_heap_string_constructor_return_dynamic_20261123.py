"""Verify the default constructor on the post-identifier heap allocation."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_post_identifier_allocation_return_dynamic_20261123 as previous
import verify_vm9_native_171_resolve_next_vm_callback_dynamic_20261121 as bootstrap
import verify_vm9_native_171_default_string_constructor_return_dynamic_20261122 as constructor_owner
import verify_vm9_request_287474_consumers_fresh_20261013 as controls
import vm9_objects as object_model
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_identifier_heap_string_constructor_return_dynamic_20261123.json')
SCHEMA='vm9-native-171-post-identifier-heap-string-constructor-return-dynamic-20261123-v1'
LIBC_BASE,MALLOC,EMPTY=0x51000000,0x1BB08,0x6E168
VM_CALL,VM_RESUME,WRAPPER,TARGET=0x16AA48,0x16AA4C,0x2884CC,0x2481AC
MAX_OBSERVATIONS=100000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
IMAGE_BASE=previous.IMAGE_BASE
MODEL_PROFILES=('normal','allocation_failure','cross_page_object','object_packed_alias')
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes','services','next_VM_call')
NEXT_WRAPPER,NEXT_TARGET,NEXT_WRAPPER_SIZE=2655536,2541656,16
CODE_RANGES={'main': ((1485384, 32), (2655436, 12), (2392492, 80), (3440592, 16), (2655536, 16), (2541656, 32)), 'libc': ((113416, 32),)}
CODE_SHA256={'main:0x16aa48': 'c53f89ea694ed64ca8b5270d014ecf3bbd4777260ee7edee83a2e8e70b25178f', 'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2481ac': '67059ef8f1b623858ffe0c627379fefe2d9bdc4d04f44cfdbdc053cb8a9751fb', 'main:0x347fd0': 'f7210f98cdcb754c8f40d20e499862fbab2829c0adcf5049a2e6cc32828bd14f', 'main:0x288530': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af', 'main:0x26c858': '5a03c035e8f0323f26ad1fe602b4089b25781755ec0c4ee1465e908556d0103a', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36'}
EXPECTED={'instruction_observations': 858, 'instruction_trace_sha256': '352dd4cbca9105ecabf116811e88c3b88db7e2758433d8cf8d27a4eeedc7618b', 'observed_code_sha256': '011f75c2e38e8d633cec41b779d3a0ad7e4029c799f2bfc98886eea75d3164e0', 'snapshots': [{'kind': 'constructor_VM_call', 'index': 1, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cdf8', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'object_initialized': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'wrapper_entry', 'index': 2, 'pc': '0x2884cc', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cdf8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'object_initialized': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'constructor_entry', 'index': 5, 'pc': '0x2481ac', 'SP': '0x7004b930', 'registers': {'x0': '0x136d9660', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'object_initialized': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'malloc_return_before_pointer_store', 'index': 141, 'pc': '0x2481dc', 'SP': '0x7004b910', 'registers': {'x0': '0x136d82e8', 'x30': '0x125081dc'}, 'callee_saved_sha256': 'bf1149ea6c0eef447aa1e1de7b78b0fd5386894922e87e94af826e17be0fc801', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': 'ca98ec90cc9a3f580f5bc2df82ce1bfe40238cfaced1c252d2b1ab8a326f420a', 'object_initialized': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'payload_address': '0x136d82e8', 'payload_allocation_width': 8, 'payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'payload_tail_7_sha256': '837885c8f8091aeaeb9ec3c3f85a6ff470a415e610b8ba3e49f9b33c9cf9d619'}, {'kind': 'object_initialized', 'index': 145, 'pc': '0x2481f0', 'SP': '0x7004b910', 'registers': {'x0': '0x136d82e8', 'x30': '0x125081dc'}, 'callee_saved_sha256': 'bf1149ea6c0eef447aa1e1de7b78b0fd5386894922e87e94af826e17be0fc801', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'object_initialized': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'payload_address': '0x136d82e8', 'payload_allocation_width': 8, 'payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'payload_tail_7_sha256': '837885c8f8091aeaeb9ec3c3f85a6ff470a415e610b8ba3e49f9b33c9cf9d619', 'vtable_offset': '0x34f5f8', 'capacity_u32': 8, 'length_u32': 0, 'payload_pointer': '0x136d82e8', 'payload_first_byte_is_NUL': True}, {'kind': 'constructor_return', 'index': 147, 'pc': '0x2481f8', 'SP': '0x7004b930', 'registers': {'x0': '0x136d82e8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'object_initialized': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'payload_address': '0x136d82e8', 'payload_allocation_width': 8, 'payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'payload_tail_7_sha256': '837885c8f8091aeaeb9ec3c3f85a6ff470a415e610b8ba3e49f9b33c9cf9d619', 'vtable_offset': '0x34f5f8', 'capacity_u32': 8, 'length_u32': 0, 'payload_pointer': '0x136d82e8', 'payload_first_byte_is_NUL': True}, {'kind': 'constructor_callback_return', 'index': 148, 'pc': '0x16aa4c', 'SP': '0x7004b930', 'registers': {'x0': '0x136d82e8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'object_initialized': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'payload_address': '0x136d82e8', 'payload_allocation_width': 8, 'payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'payload_tail_7_sha256': '837885c8f8091aeaeb9ec3c3f85a6ff470a415e610b8ba3e49f9b33c9cf9d619', 'vtable_offset': '0x34f5f8', 'capacity_u32': 8, 'length_u32': 0, 'payload_pointer': '0x136d82e8', 'payload_first_byte_is_NUL': True}, {'kind': 'before_next_VM_call', 'index': 858, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cd80', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a250', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'object_address': '0x136d9660', 'object_width': 24, 'object_sha256': '2399edc2691960a1ddbc4b9d140e9430f1c927a3af0db04561e5cf05c9dbe626', 'object_initialized': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'identifier_payload_length': 36, 'identifier_payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'payload_address': '0x136d82e8', 'payload_allocation_width': 8, 'payload_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'payload_tail_7_sha256': '837885c8f8091aeaeb9ec3c3f85a6ff470a415e610b8ba3e49f9b33c9cf9d619', 'vtable_offset': '0x34f5f8', 'capacity_u32': 8, 'length_u32': 0, 'payload_pointer': '0x136d82e8', 'payload_first_byte_is_NUL': True}], 'native_reads': [{'index': 12, 'PC': 'main:0x2481c8', 'address': '0x1232e168', 'size': 8, 'sha256': '6cc16abd70eefb90dc0ba0d14fb088630873b2c6ad943f7442356735984c35a3'}], 'native_writes': [{'index': 5, 'PC': 'main:0x2481ac', 'address': '0x7004b910', 'size': 8}, {'index': 5, 'PC': 'main:0x2481ac', 'address': '0x7004b918', 'size': 8}, {'index': 6, 'PC': 'main:0x2481b0', 'address': '0x7004b920', 'size': 8}, {'index': 13, 'PC': 'main:0x2481cc', 'address': '0x136d9660', 'size': 8}, {'index': 14, 'PC': 'main:0x2481d0', 'address': '0x136d9668', 'size': 8}, {'index': 19, 'PC': 'libc:0x1bb0c', 'address': '0x7004b900', 'size': 8}, {'index': 19, 'PC': 'libc:0x1bb0c', 'address': '0x7004b908', 'size': 8}, {'index': 24, 'PC': 'libc:0x8f00c', 'address': '0x7004b7e0', 'size': 8}, {'index': 24, 'PC': 'libc:0x8f00c', 'address': '0x7004b7e8', 'size': 8}, {'index': 27, 'PC': 'libc:0x8f018', 'address': '0x7004b7f0', 'size': 8}, {'index': 27, 'PC': 'libc:0x8f018', 'address': '0x7004b7f8', 'size': 8}, {'index': 30, 'PC': 'libc:0x8f024', 'address': '0x7004b800', 'size': 8}, {'index': 30, 'PC': 'libc:0x8f024', 'address': '0x7004b808', 'size': 8}, {'index': 31, 'PC': 'libc:0x8f028', 'address': '0x7004b810', 'size': 8}, {'index': 31, 'PC': 'libc:0x8f028', 'address': '0x7004b818', 'size': 8}, {'index': 33, 'PC': 'libc:0x8f030', 'address': '0x7004b820', 'size': 8}, {'index': 33, 'PC': 'libc:0x8f030', 'address': '0x7004b828', 'size': 8}, {'index': 34, 'PC': 'libc:0x8f034', 'address': '0x7004b830', 'size': 8}, {'index': 34, 'PC': 'libc:0x8f034', 'address': '0x7004b838', 'size': 8}, {'index': 106, 'PC': 'libc:0x8f0f8', 'address': '0x136c2030', 'size': 4}, {'index': 122, 'PC': 'libc:0x8f138', 'address': '0x136c2020', 'size': 8}, {'index': 125, 'PC': 'libc:0x8f144', 'address': '0x136c2018', 'size': 4}, {'index': 131, 'PC': 'libc:0x8f15c', 'address': '0x136d6018', 'size': 8}, {'index': 141, 'PC': 'main:0x2481dc', 'address': '0x136d9670', 'size': 8}, {'index': 143, 'PC': 'main:0x2481e4', 'address': '0x136d82e8', 'size': 1}, {'index': 180, 'PC': 'main:0x16a9f0', 'address': '0x7004d360', 'size': 8}, {'index': 247, 'PC': 'main:0x16d89c', 'address': '0x7004b9a0', 'size': 4}, {'index': 249, 'PC': 'main:0x16d8a4', 'address': '0x7004d410', 'size': 8}, {'index': 254, 'PC': 'main:0x16d8b8', 'address': '0x7004d360', 'size': 8}, {'index': 266, 'PC': 'main:0x16d8e8', 'address': '0x7004b990', 'size': 4}, {'index': 267, 'PC': 'main:0x16d8ec', 'address': '0x7004b960', 'size': 2}, {'index': 304, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 307, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 308, 'PC': 'main:0x16f974', 'address': '0x7004d370', 'size': 8}, {'index': 310, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 323, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 347, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 401, 'PC': 'main:0x171268', 'address': '0x7004cd90', 'size': 8}, {'index': 417, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 418, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 423, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 447, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 501, 'PC': 'main:0x171268', 'address': '0x7004cd88', 'size': 8}, {'index': 517, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 518, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 523, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 547, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 601, 'PC': 'main:0x171268', 'address': '0x7004cd80', 'size': 8}, {'index': 617, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 618, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 623, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 658, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 661, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 662, 'PC': 'main:0x16f974', 'address': '0x7004d3f0', 'size': 8}, {'index': 664, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 677, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 699, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 701, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 702, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 706, 'PC': 'main:0x16a5d8', 'address': '0x7004d388', 'size': 8}, {'index': 709, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 719, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 741, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 743, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 744, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 748, 'PC': 'main:0x16a5d8', 'address': '0x7004d390', 'size': 8}, {'index': 751, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 761, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 783, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 785, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 786, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 790, 'PC': 'main:0x16a5d8', 'address': '0x7004d430', 'size': 8}, {'index': 793, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 803, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 842, 'PC': 'main:0x16a93c', 'address': '0x7004b990', 'size': 4}, {'index': 844, 'PC': 'main:0x16a944', 'address': '0x7004b9a0', 'size': 4}, {'index': 845, 'PC': 'main:0x16a948', 'address': '0x7004b980', 'size': 4}, {'index': 846, 'PC': 'main:0x16a94c', 'address': '0x7004b970', 'size': 4}, {'index': 847, 'PC': 'main:0x16a950', 'address': '0x7004d460', 'size': 8}, {'index': 853, 'PC': 'main:0x16aa34', 'address': '0x7004b9d0', 'size': 8}, {'index': 853, 'PC': 'main:0x16aa34', 'address': '0x7004b9d8', 'size': 8}, {'index': 855, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c0', 'size': 8}, {'index': 855, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c8', 'size': 8}], 'services': [{'index': 17, 'kind': 'actual_Bionic_malloc_route', 'PC': '0x347fd0', 'request': 8}, {'index': 18, 'kind': 'actual_Bionic_malloc_entry', 'PC': 'libc:0x1bb08', 'request': 8}], 'next_VM_call': {'index': 858, 'callsite_offset': '0x16aa48', 'VM_cursor_offset': '0x10a250', 'descriptor_address': '0x7004cd80', 'descriptor_sha256': '96340a0e20f7f70787432f8c2e8cae295c715e688a1c82fff27e30e6a70de1b7', 'wrapper_offset': '0x288530', 'target_offset': '0x26c858', 'wrapper_code_hex': '088440a9020040f9e00308aa40001fd6', 'VM_call_executed': False, 'wrapper_executed': False, 'target_executed': False, 'descriptor_width': 48, 'scope_object_address': '0x7004d1d8', 'source_object_address': '0x136d9660', 'static_expected_target_arguments': {'x0': '0x7004d1d8', 'x1': '0x136d9660'}, 'wrapper_code_sha256': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af'}, 'new_allocator_events': [['alloc', 8, 325944040, '0x2481dc']], 'ledgers': {'allocator_counts': {'malloc': 591, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}, 'protected_ranges': [{'label': 'prior_0', 'address': '0x7004d118', 'size': 24}, {'label': 'prior_1', 'address': '0x136d82c0', 'size': 8}, {'label': 'prior_2', 'address': '0x7004d130', 'size': 24}, {'label': 'prior_3', 'address': '0x136d82d0', 'size': 8}, {'label': 'prior_4', 'address': '0x7004d148', 'size': 24}, {'label': 'prior_5', 'address': '0x136d82d8', 'size': 8}, {'label': 'string_object', 'address': '0x136d9640', 'size': 24}, {'label': 'string_payload', 'address': '0x136d4050', 'size': 37}, {'label': 'output', 'address': '0x7004d178', 'size': 16}, {'label': 'cache', 'address': '0x136d73a0', 'size': 16}, {'label': 'counter', 'address': '0x136d82e0', 'size': 4}, {'label': 'cache_mutex', 'address': '0x136d4020', 'size': 48}, {'label': 'cache_globals', 'address': '0x1269e700', 'size': 64}, {'label': 'seed_constants', 'address': '0x1269e450', 'size': 128}, {'label': 'errno', 'address': '0x7000a010', 'size': 4}, {'label': 'new_heap_string_object', 'address': '0x136d9660', 'size': 24}, {'label': 'new_heap_string_payload', 'address': '0x136d82e8', 'size': 8}], 'initial_descriptor_sha256': '6cc16abd70eefb90dc0ba0d14fb088630873b2c6ad943f7442356735984c35a3'}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'normal', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'allocation_failure', 'allocation_requested': 8, 'allocation_succeeded': False, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'cross_page_object', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'object_packed_alias', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': False, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'custom_initial_descriptor', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '1700000007000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'custom_descriptor_failure', 'allocation_requested': 8, 'allocation_succeeded': False, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '1700000007000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'payload_object_alias', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'payload_packed_alias', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': False, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x122c0000', 'case': 'cross_page_payload', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'normal', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'allocation_failure', 'allocation_requested': 8, 'allocation_succeeded': False, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'cross_page_object', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'object_packed_alias', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': False, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'custom_initial_descriptor', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '1700000007000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'custom_descriptor_failure', 'allocation_requested': 8, 'allocation_succeeded': False, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '1700000007000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'payload_object_alias', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'payload_packed_alias', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': False, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}, {'image_base': '0x775c205000', 'case': 'cross_page_payload', 'allocation_requested': 8, 'allocation_succeeded': True, 'descriptor_preserved': True, 'expected_initial_descriptor_hex': '0800000000000000', 'original_wrapper_and_constructor_returned': True, 'full_guest_memory_and_store_widths_verified': True, 'SP_and_callee_saved_restored': True, 'allocator': 'explicit synthetic component provider'}]
MODEL_CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'normal', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'allocation_failure', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'cross_page_object', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'object_packed_alias', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'normal', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'allocation_failure', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'cross_page_object', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'case': 'object_packed_alias', 'kind': 'default', 'actual_wrapper': '0x2884cc', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'imported_memcpy_is_explicit_oracle_boundary': False, 'local_copy_instructions_executed': False, 'native_snapshot_input': False}]
ROLLBACK_SPECS=[{'case': 'wrong_target', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'wrong_wrapper', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_packed', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_object', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'allocator_late_failure', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'free_late_failure', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'filled_bound', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'copy_bound', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_copy_source', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_copy_destination', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_copy_result', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'imported_memcpy_overlap', 'rejected': True, 'all_pages_unchanged': True}]

def project_next_call(row):
    row=deepcopy(row);descriptor=bytes.fromhex(row.pop('descriptor_hex'))
    assert len(descriptor)==48 and raw_hash(descriptor)==row['descriptor_sha256']
    assert row['wrapper_offset']=='0x288530' and row['target_offset']=='0x26c858'
    assert int.from_bytes(descriptor[:8],'little')==IMAGE_BASE+0x26C858
    row['descriptor_width']=48
    row['scope_object_address']=hex(int.from_bytes(descriptor[8:16],'little'))
    row['source_object_address']=hex(int.from_bytes(descriptor[16:24],'little'))
    row['static_expected_target_arguments']={'x0':row['scope_object_address'],'x1':row['source_object_address']}
    code=bytes.fromhex(row['wrapper_code_hex'])[:16]
    assert code.hex()=='088440a9020040f9e00308aa40001fd6'
    row['wrapper_code_hex']=code.hex();row['wrapper_code_sha256']=raw_hash(code)
    return row

def stop_boundary():
    return dict(kind='before_VM_call_after_heap_string_constructor',stop_before=hex(VM_CALL),VM_call_executed=False,wrapper_executed=False,target_executed=False)

def validate_next_call(row,data,last):
    call=row['next_VM_call'];returned=row['snapshots'][-2]
    assert call['index']==row['instruction_observations'] and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']==last['VM_cursor']=='0x10a250'
    assert call['descriptor_width']==48 and call['descriptor_address']==last['registers']['x0']=='0x7004cd80'
    assert call['wrapper_offset']==hex(NEXT_WRAPPER)=='0x288530' and call['target_offset']==hex(NEXT_TARGET)=='0x26c858'
    assert call['scope_object_address']=='0x7004d1d8' and call['source_object_address']==returned['object_address']=='0x136d9660'
    assert call['static_expected_target_arguments']=={'x0':call['scope_object_address'],'x1':call['source_object_address']}
    assert call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert len(bytes.fromhex(call['wrapper_code_hex']))==NEXT_WRAPPER_SIZE==16 and raw_hash(bytes.fromhex(call['wrapper_code_hex']))==call['wrapper_code_sha256']
    assert call['VM_call_executed'] is call['wrapper_executed'] is call['target_executed'] is False and 'descriptor_hex' not in call
    suffix=row['observation_sites'][returned['index']:]
    assert 'main:'+hex(NEXT_WRAPPER) not in suffix and 'main:'+hex(NEXT_TARGET) not in suffix

class PostIdentifierHeapStringScenario(previous.PostIdentifierAllocationScenario):
    def __init__(self,control):
        super().__init__(control)
        self._heapctor_active=False;self._heapctor_done=False;self._heapctor_returned=False;self._heapctor_initialized=False
        self._heapctor_count=0;self._heapctor_trace=[];self._heapctor_code={};self._heapctor_rows=[]
        self._heapctor_reads=[];self._heapctor_writes=[];self._heapctor_live_writes=[];self._heapctor_services=[];self._heapctor_payload=0

    def _heapctor_track(self,cpu,pc):
        self._heapctor_count+=1;assert self._heapctor_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._heapctor_trace.append(key);self._heapctor_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _heapctor_snapshot(self,cpu,pc,kind):
        raw=bytes(cpu.mem_read(self._heapctor_object,24))
        row=dict(kind=kind,index=self._heapctor_count,pc=hex(pc-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            registers={f'x{n}':hex(self._reg(cpu,n)) for n in (0,30)},callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_state_address=hex(self._postalloc_vmstate),VM_cursor=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            live_regions_sha256=self._idvm_live_hash(cpu),descriptor_address=hex(self._heapctor_descriptor),
            descriptor_sha256=raw_hash(bytes(cpu.mem_read(self._heapctor_descriptor,48))),
            object_address=hex(self._heapctor_object),object_width=24,object_sha256=raw_hash(raw),object_initialized=self._heapctor_initialized,
            output=self._idpub_pair(cpu,self._idopen_output),cache=self._idpub_pair(cpu,self._seedfail_pair),
            counter_address=hex(self._idref_counter),counter_u32=self._u(cpu,self._idref_counter,4),
            identifier_payload_length=36,identifier_payload_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_payload,37))),
            cache_mutex_state_u16=self._u(cpu,self._seedfail_mutex+8,2),diagnostic=self._idref_diagnostic(cpu),errno=self._u(cpu,self._seedfail_errno,4))
        if self._heapctor_payload:
            payload=bytes(cpu.mem_read(self._heapctor_payload,8))
            row.update(payload_address=hex(self._heapctor_payload),payload_allocation_width=8,payload_sha256=raw_hash(payload),payload_tail_7_sha256=raw_hash(payload[1:]))
        if self._heapctor_initialized:
            row.update(vtable_offset=hex(int.from_bytes(raw[:8],'little')-self.image),capacity_u32=int.from_bytes(raw[8:12],'little'),
                length_u32=int.from_bytes(raw[12:16],'little'),payload_pointer=hex(int.from_bytes(raw[16:],'little')),payload_first_byte_is_NUL=self._u(cpu,self._heapctor_payload,1)==0)
        self._heapctor_rows.append(row)

    def _heapctor_start(self,cpu,pc,state):
        self._postalloc_track(cpu,pc);self._postalloc_snapshot(cpu,pc,'before_next_VM_call')
        d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
        self._postalloc_next=previous.project_next_call(dict(index=self._postalloc_count,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False))
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data);old=data['case_result'];h=hashlib.sha256()
        for key in self._postalloc_trace:h.update(key.encode()+bytes.fromhex(self._postalloc_code[key]))
        for value,key in ((self._postalloc_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),(digest(self._postalloc_code),'observed_code_sha256'),
            (self._postalloc_trace,'observation_sites'),(self._postalloc_code,'observed_code'),(self._postalloc_rows,'snapshots'),(self._postalloc_writes,'native_writes'),
            (self._postalloc_services,'services'),(self._postalloc_next,'next_VM_call')):assert value==old[key],key
        assert state['allocator_events_ref']==self._postalloc_events+old['new_allocator_events']
        self._heapctor_events=deepcopy(state['allocator_events_ref']);self._heapctor_old=old
        self._heapctor_descriptor=d;self._heapctor_before=raw;self._heapctor_object=int.from_bytes(raw[8:16],'little')
        assert wrapper==self.image+WRAPPER and int.from_bytes(raw[:8],'little')==self.image+TARGET and self._heapctor_object==self._postalloc_pointer
        self._heapctor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._heapctor_saved=self._idctor_saved_hash(cpu)
        self._heapctor_empty=bytes(cpu.mem_read(self.image+EMPTY,8));self._heapctor_ranges=deepcopy(self._idvm_ranges)
        self._postalloc_active=False;self._postalloc_done=False;self._heapctor_active=True
        self._heapctor_track(cpu,pc);self._heapctor_snapshot(cpu,pc,'constructor_VM_call')

    def native_runner(self,*args,**kwargs):
        assert kwargs.get('real_malloc') is True and not kwargs.get('malloc_handler')
        old_read,old_write=kwargs['memory_read_observer'],kwargs['memory_write_observer']
        def read(cpu,address,size):
            if self._heapctor_active and cpu.reg_read(arm.UC_ARM64_REG_PC)==self.image+0x2481C8:
                assert address==self.image+EMPTY and size==8
                self._heapctor_reads.append(dict(index=self._heapctor_count,PC='main:0x2481c8',address=hex(address),size=size,sha256=raw_hash(bytes(cpu.mem_read(address,size)))))
            if old_read:old_read(cpu,address,size)
        def write(cpu,address,size):
            if self._heapctor_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                row=dict(index=self._heapctor_count,PC=('libc:'+hex(pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else 'main:'+hex(pc-self.image)),address=hex(address),size=size)
                self._heapctor_writes.append(row)
                labels=[label for label,a,n in self._heapctor_ranges if address<a+n and a<address+size]
                if labels:raise AssertionError('heap constructor wrote protected live state')
                if not self._heapctor_returned:assert not (address<self._heapctor_descriptor+48 and self._heapctor_descriptor<address+size), 'constructor wrote packed descriptor'
            if old_write:old_write(cpu,address,size)
        kwargs.update(memory_read_observer=read,memory_write_observer=write);return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._heapctor_active:
            if self._postalloc_active and self._postalloc_returned and pc==self.image+VM_CALL:
                self._heapctor_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._heapctor_track(cpu,pc);off=pc-self.image
        if not self._heapctor_returned:
            if off in (WRAPPER,TARGET):
                if off==TARGET:assert self._reg(cpu,0)==self._heapctor_object and self._reg(cpu,30)==self.image+VM_RESUME
                self._heapctor_snapshot(cpu,pc,'wrapper_entry' if off==WRAPPER else 'constructor_entry')
            if off==0x347FD0:self._heapctor_services.append(dict(index=self._heapctor_count,kind='actual_Bionic_malloc_route',PC=hex(off),request=self._reg(cpu,0)))
            if pc==LIBC_BASE+MALLOC:self._heapctor_services.append(dict(index=self._heapctor_count,kind='actual_Bionic_malloc_entry',PC='libc:'+hex(MALLOC),request=self._reg(cpu,0)))
            if off==0x2481DC:
                self._heapctor_payload=self._reg(cpu,0);assert self._heapctor_payload
                self._heapctor_tail=bytes(cpu.mem_read(self._heapctor_payload+1,7));self._heapctor_snapshot(cpu,pc,'malloc_return_before_pointer_store')
            if off==0x2481F0:
                assert bytes(cpu.mem_read(self._heapctor_object,24))==(self.image+0x34F5F8).to_bytes(8,'little')+self._heapctor_empty+self._heapctor_payload.to_bytes(8,'little')
                assert self._u(cpu,self._heapctor_payload,1)==0 and bytes(cpu.mem_read(self._heapctor_payload+1,7))==self._heapctor_tail
                self._heapctor_initialized=True;self._heapctor_snapshot(cpu,pc,'object_initialized')
            if off==0x2481F8:self._heapctor_snapshot(cpu,pc,'constructor_return')
            if off==VM_RESUME:
                assert self._heapctor_initialized and self._reg(cpu,0)==self._heapctor_payload
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._heapctor_sp and self._idctor_saved_hash(cpu)==self._heapctor_saved
                assert bytes(cpu.mem_read(self._heapctor_descriptor,48))==self._heapctor_before
                self._heapctor_snapshot(cpu,pc,'constructor_callback_return');self._heapctor_returned=True
                self._heapctor_ranges.extend([('new_heap_string_object',self._heapctor_object,24),('new_heap_string_payload',self._heapctor_payload,8)])
        elif off==VM_CALL:
            self._heapctor_snapshot(cpu,pc,'before_next_VM_call');d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
            self._heapctor_next=dict(index=self._heapctor_count,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
                descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),
                target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False)
            self._heapctor_next=project_next_call(self._heapctor_next)
            self._heapctor_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.previous.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._heapctor_done and self._heapctor_returned and self._heapctor_initialized and self._heapctor_live_writes==[]
        h=hashlib.sha256()
        for key in self._heapctor_trace:h.update(key.encode()+bytes.fromhex(self._heapctor_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],
            inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,
            late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        assert result['allocator_events'][:len(self._heapctor_events)]==self._heapctor_events
        counts=deepcopy(self._heapctor_old['allocator_counts']);counts['malloc']+=1
        for key,value in ledgers.items():assert value==(counts if key=='allocator_counts' else self._heapctor_old[key]),key
        return dict(control=self._heapctor_old['control'],retained_allocation_segment=dict(case_result_sha256=digest(self._heapctor_old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._heapctor_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._heapctor_code),
            snapshots=self._heapctor_rows,native_reads=self._heapctor_reads,native_writes=self._heapctor_writes,services=self._heapctor_services,
            next_VM_call=self._heapctor_next,observation_sites=self._heapctor_trace,observed_code=self._heapctor_code,
            new_allocator_events=result['allocator_events'][len(self._heapctor_events):],**ledgers,
            protected_ranges=[dict(label=label,address=hex(a),size=n) for label,a,n in self._heapctor_ranges],protected_write_events=[],
            protection_activation=dict(retained_regions_from_index=1,new_heap_regions_after_index=self._heapctor_rows[-2]['index']),stop_boundary=stop_boundary())

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,constructor_observer=constructor_owner,consumer_fixture=controls,consumer_model=controls.model,
        object_model=object_model,bootstrap=bootstrap,oracle=constructor_owner.oracle)
    return dict(heap_string_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        main_path_malloc='inherited matching original Bionic malloc; no synthetic allocation callback added',
        native_layout_controls='existing independent original constructor layout/store-width/SP controls with explicit synthetic malloc',
        native_Python_controls='fresh original wrapper versus existing consumer/object model; explicit synthetic component malloc',
        component_rollback_scope='existing consumer-family guest-page rollback checks; external provider effects excluded',
        returned_X0='observed payload pointer only, not an independent constructor success status',
        exported_output='hashes, lengths, defined pointers/scalars and native write locations/widths; no raw identifier, seed, packed descriptor or allocation contents',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',allocation_prefix_revalidated=True,original_VM_tail_wrapper_and_default_constructor_returned=True,
        inherited_original_Bionic_malloc_executed=True,eight_byte_payload_allocation_verified=True,one_byte_NUL_store_verified=True,
        ELF_initial_descriptor_loaded=True,packed_descriptor_preserved_through_callback_return=True,caller_SP_and_callee_saved_restored=True,
        published_identifier_and_three_prior_defaults_write_protected=True,new_heap_object_and_payload_write_protected_after_return=True,
        next_VM_call_boundary_observed=True,next_VM_call_executed=False,next_wrapper_executed=False,next_target_executed=False,
        new_providers_added=False,native_snapshot_used_as_python_model_input=False,independent_owning_allocator_parity_verified=False,
        actual_Bionic_NULL_allocation_path_verified=False,standalone_Python_VM_continuation_verified=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,real_ART_JVM_execution=False,
        Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def read_static(path,libc):
    rows={};initial=None
    for domain,p in (('main',path),('libc',libc)):
        with p.open('rb') as f:
            elf=ELFFile(f)
            if domain=='main':
                raw=elf_bytes(elf,f,EMPTY,8);initial=dict(offset=hex(EMPTY),hex=raw.hex(),sha256=raw_hash(raw))
            for off,size in CODE_RANGES[domain]:
                raw=elf_bytes(elf,f,off,size);rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows,initial

def elf_bytes(elf,f,off,size):
    s=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off and off+size<=s['p_vaddr']+s['p_filesz'])
    f.seek(s['p_offset']+off-s['p_vaddr']);raw=f.read(size);assert len(raw)==size;return raw

def independent_controls(path):
    layout=constructor_owner.independent_controls(path)
    model=[controls.compare(path,base,'default',label) for base in controls.BASES for label in MODEL_PROFILES]
    guards=controls.guards(path)
    assert layout==CONTROL_SPECS and model==MODEL_CONTROL_SPECS and guards==ROLLBACK_SPECS
    return layout,model,guards

def run(path,libc):
    parent=prior_evidence();p=bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code,initial=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostIdentifierHeapStringScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    layout,model,guards=independent_controls(path)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),
        static_code=code,static_initial_descriptor=initial,native_layout_controls=layout,native_Python_controls=model,component_rollback_checks=guards,
        case_result=rows[0],case_result_sha256=digest(rows[0]))

def overlaps(address,size,region):
    a=int(address,16);b=int(region['address'],16);return a<b+region['size'] and b<a+size

def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert set(data)=={'schema','claims','providers','source_fingerprints','input_provenance','static_code','static_initial_descriptor',
        'native_layout_controls','native_Python_controls','component_rollback_checks','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_layout_controls']==CONTROL_SPECS==constructor_owner.control_specs() and len(CONTROL_SPECS)==18
    assert data['native_Python_controls']==MODEL_CONTROL_SPECS and len(MODEL_CONTROL_SPECS)==8
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==12
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'hex','size','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    initial=data['static_initial_descriptor']
    assert initial==dict(offset=hex(EMPTY),hex='0800000000000000',sha256=EXPECTED['initial_descriptor_sha256']) and raw_hash(bytes.fromhex(initial['hex']))==initial['sha256']
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_allocation_segment','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots',
        'native_reads','native_writes','services','next_VM_call','observation_sites','observed_code','new_allocator_events','protected_ranges',
        'protected_write_events','protection_activation','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_allocation_segment']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[:5]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,TARGET)] and sites[-1]=='main:'+hex(VM_CALL)
    assert sites.count('main:'+hex(VM_CALL))==2 and sites.count('main:'+hex(VM_RESUME))==1 and sites.count('libc:'+hex(MALLOC))==1
    assert 'main:0x2481ec' not in sites
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4');h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256'] and digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    assert code['main:'+hex(VM_CALL)]=='00013fd6'
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_reads','native_writes','services','next_VM_call','new_allocator_events','protected_ranges'):assert row[key]==EXPECTED[key],key
    snapshots=row['snapshots'];assert [x['kind'] for x in snapshots]==['constructor_VM_call','wrapper_entry','constructor_entry','malloc_return_before_pointer_store',
        'object_initialized','constructor_return','constructor_callback_return','before_next_VM_call']
    first,wrapper,target,malloc,initialized,ret,returned,last=snapshots;prior=old['snapshots'][-1]
    assert [x['pc'] for x in snapshots]==[hex(x) for x in (VM_CALL,WRAPPER,TARGET,0x2481DC,0x2481F0,0x2481F8,VM_RESUME,VM_CALL)]
    assert first['index']==1 and last['index']==len(sites) and all(a['index']<b['index'] for a,b in zip(snapshots,snapshots[1:]))
    for x in snapshots:assert sites[x['index']-1]=='main:'+x['pc']
    assert first['object_address']==old['next_VM_call']['object_address']==prior['allocation_address']
    assert first['object_sha256']==prior['allocation_sha256'] and first['descriptor_sha256']==old['next_VM_call']['descriptor_sha256']
    assert first['descriptor_address']==old['next_VM_call']['descriptor_address']
    for x in snapshots:
        assert x['live_regions_sha256']==prior['live_regions_sha256'] and x['object_address']==first['object_address'] and x['object_width']==24
        assert x['output']==prior['output'] and x['cache']==prior['cache'] and x['counter_u32']==prior['counter_u32']==2
        assert x['identifier_payload_length']==36 and x['identifier_payload_including_NUL_sha256']==prior['payload_including_NUL_sha256']
        assert x['cache_mutex_state_u16']==0 and x['diagnostic']==prior['diagnostic'] and x['errno']==prior['errno']==2
        assert x['VM_state_address']==prior['VM_state_address'] and set(x['registers'])=={'x0','x30'}
    assert wrapper['registers']['x0']==first['descriptor_address'] and target['registers']['x0']==first['object_address']
    assert target['registers']['x30']==hex(IMAGE_BASE+VM_RESUME)
    for x in (target,ret,returned):assert x['SP']==first['SP']==prior['SP'] and x['callee_saved_sha256']==first['callee_saved_sha256']==prior['callee_saved_sha256']
    assert first['VM_cursor']==returned['VM_cursor']==prior['VM_cursor']=='0x10a228'
    for x in snapshots[:7]:assert x['descriptor_sha256']==first['descriptor_sha256']
    assert all(x['object_initialized'] is False for x in snapshots[:4]) and all(x['object_initialized'] is True for x in snapshots[4:])
    payload=malloc['payload_address'];assert int(payload,16)!=0 and malloc['registers']['x0']==payload
    for x in snapshots[4:]:
        assert x['vtable_offset']=='0x34f5f8' and x['capacity_u32']==8 and x['length_u32']==0 and x['payload_pointer']==payload
        assert x['object_sha256']==returned['object_sha256'] and x['payload_address']==payload and x['payload_allocation_width']==8
        assert x['payload_first_byte_is_NUL'] is True and x['payload_sha256']==returned['payload_sha256'] and x['payload_tail_7_sha256']==malloc['payload_tail_7_sha256']
    assert returned['registers']['x0']==payload
    assert row['native_reads']==[dict(index=sites.index('main:0x2481c8')+1,PC='main:0x2481c8',address=hex(IMAGE_BASE+EMPTY),size=8,sha256=initial['sha256'])]
    critical=[w for w in row['native_writes'] if w['PC'] in ('main:0x2481cc','main:0x2481d0','main:0x2481dc','main:0x2481e4','main:0x2481ec')]
    obj=int(first['object_address'],16)
    assert [(w['PC'],w['address'],w['size']) for w in critical]==[
        ('main:0x2481cc',hex(obj),8),('main:0x2481d0',hex(obj+8),8),('main:0x2481dc',hex(obj+16),8),('main:0x2481e4',payload,1)]
    assert row['protection_activation']==dict(retained_regions_from_index=1,new_heap_regions_after_index=returned['index'])
    assert row['protected_ranges'][:-2]==old['protected_ranges'] and row['protected_ranges'][-2:]==[
        dict(label='new_heap_string_object',address=first['object_address'],size=24),dict(label='new_heap_string_payload',address=payload,size=8)]
    for w in row['native_writes']:
        assert set(w)=={'index','PC','address','size'} and sites[w['index']-1]==w['PC'] and w['size']>0
        regions=row['protected_ranges'] if w['index']>returned['index'] else row['protected_ranges'][:-2]
        assert not any(overlaps(w['address'],w['size'],region) for region in regions)
        if w['index']<=returned['index']:assert not overlaps(w['address'],w['size'],dict(address=first['descriptor_address'],size=48))
    assert row['protected_write_events']==[] and len(row['services'])==2
    for service,pc in zip(row['services'],('main:0x347fd0','libc:'+hex(MALLOC))):
        assert service['request']==8 and sites[service['index']-1]==pc and target['index']<service['index']<malloc['index']
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=1
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value==(counts if key=='allocator_counts' else old[key]),key
    assert row['new_allocator_events']==[['alloc',8,int(payload,16),'0x2481dc']]
    validate_next_call(row,data,last)
    assert row['stop_boundary']==stop_boundary()

def damaged_evidence_rejected(data):
    changes=[(('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('claims','independent_owning_allocator_parity_verified'),True),(('providers','new_providers'),['hidden']),
        (('source_fingerprints','owners','object_model'),'0'*64),(('case_result','retained_allocation_segment','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),0),(('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'counter_u32'),1),(('case_result','snapshots',-1,'live_regions_sha256'),'0'*64),
        (('case_result','snapshots',-1,'identifier_payload_including_NUL_sha256'),'0'*64),(('case_result','snapshots',-1,'cache_mutex_state_u16'),1),
        (('case_result','snapshots',6,'SP'),'0x0'),(('case_result','snapshots',6,'callee_saved_sha256'),'0'*64),
        (('case_result','snapshots',4,'capacity_u32'),0),(('case_result','snapshots',4,'length_u32'),1),
        (('case_result','snapshots',4,'payload_pointer'),'0x0'),(('case_result','snapshots',4,'payload_first_byte_is_NUL'),False),
        (('case_result','snapshots',4,'payload_tail_7_sha256'),'0'*64),(('case_result','native_reads',0,'sha256'),'0'*64),
        (('static_initial_descriptor','hex'),'00'*8),(('case_result','services',1,'request'),0),(('case_result','native_writes',0,'size'),99),
        (('case_result','protection_activation','new_heap_regions_after_index'),0),(('case_result','next_VM_call','target_offset'),'0x0'),
        (('case_result','next_VM_call','descriptor_sha256'),'0'*64),(('case_result','next_VM_call','wrapper_code_sha256'),'0'*64),
        (('case_result','next_VM_call','target_executed'),True),(('case_result','next_VM_call','descriptor_hex'),'omitted'),
        (('case_result','new_allocator_events'),[]),(('case_result','protected_write_events'),['hidden']),
        (('case_result','stop_boundary','VM_call_executed'),True),(('case_result','raw_identifier'),'omitted'),(('case_result','raw_allocation'),'omitted'),
        (('raw_identifier',),'omitted'),(('native_Python_controls',0,'native_snapshot_input'),True),
        (('component_rollback_checks',0,'all_pages_unchanged'),False)]
    for key in EXPECTED['ledgers']:changes.append((('case_result',key),{}))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged heap-string evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh heap-string replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_layout_controls=len(data['native_layout_controls']),native_Python_controls=len(data['native_Python_controls']),
        component_rollback_checks=len(data['component_rollback_checks']),damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],original_default_constructor_returned=True,
        next_VM_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
