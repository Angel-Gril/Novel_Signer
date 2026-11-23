"""Verify the original post-identifier allocation and stop before the next VM call."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_post_identifier_vm_boundary_dynamic_20261123 as previous
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_identifier_allocation_return_dynamic_20261123.json')
SCHEMA='vm9-native-171-post-identifier-allocation-return-dynamic-20261123-v1'
LIBC_BASE,MALLOC=0x51000000,0x1BB08
VM_CALL,VM_RESUME,WRAPPER,TARGET=0x16AA48,0x16AA4C,0x288508,0x32A1F0
MAX_OBSERVATIONS=100000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
IMAGE_BASE=previous.IMAGE_BASE
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes','next_VM_call')
NEXT_WRAPPER,NEXT_TARGET,NEXT_WRAPPER_SIZE=2655436,2392492,12
CODE_RANGES={'main': ((1485384, 32), (2655496, 28), (3318256, 72), (3440592, 16), (2655436, 12), (2392492, 32)), 'libc': ((113416, 48),)}
CODE_SHA256={'main:0x16aa48': 'c53f89ea694ed64ca8b5270d014ecf3bbd4777260ee7edee83a2e8e70b25178f', 'main:0x288508': '89dff6609a3af925ec6fb49b533294966a3036bec5a610457b9660cc73af8375', 'main:0x32a1f0': '9079c8ef954ec289b55ed741ccf28144bfa2736082e526cd09c921bcfa8e4de0', 'main:0x347fd0': 'f7210f98cdcb754c8f40d20e499862fbab2829c0adcf5049a2e6cc32828bd14f', 'main:0x2884cc': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565', 'main:0x2481ac': '0d92ed9ce47f4e42a2e0273ddd2337c55f5fbc33b41558f61bd52583b0f00157', 'libc:0x1bb08': '5ab83c58da6e00025fe13268ece10986cf0551e9dbd314dae2cc20e903eca45c'}
EXPECTED={'instruction_observations': 681, 'instruction_trace_sha256': '77b747f66bf692e9a0dedcd3200940d5ee25f961e49bb6f63d12506612485c1a', 'observed_code_sha256': '491bdc197d421f9a92f2db027f57cdcf57302636f482f69d9e40949e370ca701', 'snapshots': [{'kind': 'allocation_VM_call', 'index': 1, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cda8', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '469e7c85be9fd201b52fc69c1e78e7291a2af05c638ffd7c98d96f3666cd3115', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': 'dbba0579494c420a22eea545dd7c8b45e8a75cff2ac5ac578f3ca07e20a901a9', 'result_store_completed': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'wrapper_entry', 'index': 2, 'pc': '0x288508', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cda8', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '469e7c85be9fd201b52fc69c1e78e7291a2af05c638ffd7c98d96f3666cd3115', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': 'dbba0579494c420a22eea545dd7c8b45e8a75cff2ac5ac578f3ca07e20a901a9', 'result_store_completed': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'operator_new_entry', 'index': 6, 'pc': '0x32a1f0', 'SP': '0x7004b920', 'registers': {'x0': '0x18', 'x30': '0x12548518'}, 'callee_saved_sha256': 'ad2afc70a6cfbf8ca3c7f17871184ef02b8248376c4f3f40b17863861349df00', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '469e7c85be9fd201b52fc69c1e78e7291a2af05c638ffd7c98d96f3666cd3115', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': 'dbba0579494c420a22eea545dd7c8b45e8a75cff2ac5ac578f3ca07e20a901a9', 'result_store_completed': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'malloc_return', 'index': 138, 'pc': '0x32a210', 'SP': '0x7004b900', 'registers': {'x0': '0x136d9660', 'x30': '0x125ea210'}, 'callee_saved_sha256': 'feb852743caed34228be6eb4a5530bf65c46648b90a55eb73e8c3580e909b588', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '469e7c85be9fd201b52fc69c1e78e7291a2af05c638ffd7c98d96f3666cd3115', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': 'dbba0579494c420a22eea545dd7c8b45e8a75cff2ac5ac578f3ca07e20a901a9', 'result_store_completed': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'allocation_address': '0x136d9660', 'allocation_width': 24, 'allocation_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0'}, {'kind': 'operator_new_return_before_store', 'index': 143, 'pc': '0x288518', 'SP': '0x7004b920', 'registers': {'x0': '0x136d9660', 'x30': '0x12548518'}, 'callee_saved_sha256': 'ad2afc70a6cfbf8ca3c7f17871184ef02b8248376c4f3f40b17863861349df00', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '469e7c85be9fd201b52fc69c1e78e7291a2af05c638ffd7c98d96f3666cd3115', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': 'dbba0579494c420a22eea545dd7c8b45e8a75cff2ac5ac578f3ca07e20a901a9', 'result_store_completed': False, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'allocation_address': '0x136d9660', 'allocation_width': 24, 'allocation_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0'}, {'kind': 'packed_result_stored', 'index': 144, 'pc': '0x28851c', 'SP': '0x7004b920', 'registers': {'x0': '0x136d9660', 'x30': '0x12548518'}, 'callee_saved_sha256': 'ad2afc70a6cfbf8ca3c7f17871184ef02b8248376c4f3f40b17863861349df00', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '1018b08f1388eaf24277c37bce77d4fea8ac18e85711ad9f115968df46aa4a1d', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': '818d15743c8790c4fbdcf8468947dd733be274d9a1084c5859415b3336ee0cf8', 'result_store_completed': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'allocation_address': '0x136d9660', 'allocation_width': 24, 'allocation_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'result_slot_pointer': '0x136d9660'}, {'kind': 'allocation_callback_return', 'index': 146, 'pc': '0x16aa4c', 'SP': '0x7004b930', 'registers': {'x0': '0x136d9660', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a208', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '1018b08f1388eaf24277c37bce77d4fea8ac18e85711ad9f115968df46aa4a1d', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': '818d15743c8790c4fbdcf8468947dd733be274d9a1084c5859415b3336ee0cf8', 'result_store_completed': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'allocation_address': '0x136d9660', 'allocation_width': 24, 'allocation_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'result_slot_pointer': '0x136d9660'}, {'kind': 'before_next_VM_call', 'index': 681, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cdf8', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a228', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '1018b08f1388eaf24277c37bce77d4fea8ac18e85711ad9f115968df46aa4a1d', 'input_16_sha256': '220614aeecb7a05fc06f24eea23a5dd45dcbce2fb28080e30fedd0d5aa736f07', 'tail_24_sha256': '4965f494d80b6bb660c6a5924583994aed6f5f8d899b6ac594c3dd401053473c', 'result_slot_address': '0x7004cdb8', 'result_slot_sha256': '818d15743c8790c4fbdcf8468947dd733be274d9a1084c5859415b3336ee0cf8', 'result_store_completed': True, 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'allocation_address': '0x136d9660', 'allocation_width': 24, 'allocation_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'result_slot_pointer': '0x136d9660'}], 'native_writes': [{'index': 2, 'PC': 'main:0x288508', 'address': '0x7004b920', 'size': 8}, {'index': 2, 'PC': 'main:0x288508', 'address': '0x7004b928', 'size': 8}, {'index': 7, 'PC': 'main:0x32a1f4', 'address': '0x7004b900', 'size': 8}, {'index': 7, 'PC': 'main:0x32a1f4', 'address': '0x7004b908', 'size': 8}, {'index': 8, 'PC': 'main:0x32a1f8', 'address': '0x7004b910', 'size': 8}, {'index': 16, 'PC': 'libc:0x1bb0c', 'address': '0x7004b8f0', 'size': 8}, {'index': 16, 'PC': 'libc:0x1bb0c', 'address': '0x7004b8f8', 'size': 8}, {'index': 21, 'PC': 'libc:0x8f00c', 'address': '0x7004b7d0', 'size': 8}, {'index': 21, 'PC': 'libc:0x8f00c', 'address': '0x7004b7d8', 'size': 8}, {'index': 24, 'PC': 'libc:0x8f018', 'address': '0x7004b7e0', 'size': 8}, {'index': 24, 'PC': 'libc:0x8f018', 'address': '0x7004b7e8', 'size': 8}, {'index': 27, 'PC': 'libc:0x8f024', 'address': '0x7004b7f0', 'size': 8}, {'index': 27, 'PC': 'libc:0x8f024', 'address': '0x7004b7f8', 'size': 8}, {'index': 28, 'PC': 'libc:0x8f028', 'address': '0x7004b800', 'size': 8}, {'index': 28, 'PC': 'libc:0x8f028', 'address': '0x7004b808', 'size': 8}, {'index': 30, 'PC': 'libc:0x8f030', 'address': '0x7004b810', 'size': 8}, {'index': 30, 'PC': 'libc:0x8f030', 'address': '0x7004b818', 'size': 8}, {'index': 31, 'PC': 'libc:0x8f034', 'address': '0x7004b820', 'size': 8}, {'index': 31, 'PC': 'libc:0x8f034', 'address': '0x7004b828', 'size': 8}, {'index': 103, 'PC': 'libc:0x8f0f8', 'address': '0x136c2070', 'size': 4}, {'index': 119, 'PC': 'libc:0x8f138', 'address': '0x136c2060', 'size': 8}, {'index': 122, 'PC': 'libc:0x8f144', 'address': '0x136c2018', 'size': 4}, {'index': 128, 'PC': 'libc:0x8f15c', 'address': '0x136d6018', 'size': 8}, {'index': 143, 'PC': 'main:0x288518', 'address': '0x7004cdb8', 'size': 8}, {'index': 178, 'PC': 'main:0x16a9f0', 'address': '0x7004d360', 'size': 8}, {'index': 227, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 230, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 231, 'PC': 'main:0x16f974', 'address': '0x7004d370', 'size': 8}, {'index': 233, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 246, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 281, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 284, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 285, 'PC': 'main:0x16f974', 'address': '0x7004d400', 'size': 8}, {'index': 287, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 300, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 324, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 378, 'PC': 'main:0x171268', 'address': '0x7004ce00', 'size': 8}, {'index': 394, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 395, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 400, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 424, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 478, 'PC': 'main:0x171268', 'address': '0x7004cdf8', 'size': 8}, {'index': 494, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 495, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 500, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 522, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 524, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 525, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 529, 'PC': 'main:0x16a5d8', 'address': '0x7004d388', 'size': 8}, {'index': 532, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 542, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 564, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 566, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 567, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 571, 'PC': 'main:0x16a5d8', 'address': '0x7004d390', 'size': 8}, {'index': 574, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 584, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 606, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 608, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 609, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 613, 'PC': 'main:0x16a5d8', 'address': '0x7004d430', 'size': 8}, {'index': 616, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 626, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 665, 'PC': 'main:0x16a93c', 'address': '0x7004b990', 'size': 4}, {'index': 667, 'PC': 'main:0x16a944', 'address': '0x7004b9a0', 'size': 4}, {'index': 668, 'PC': 'main:0x16a948', 'address': '0x7004b980', 'size': 4}, {'index': 669, 'PC': 'main:0x16a94c', 'address': '0x7004b970', 'size': 4}, {'index': 670, 'PC': 'main:0x16a950', 'address': '0x7004d460', 'size': 8}, {'index': 676, 'PC': 'main:0x16aa34', 'address': '0x7004b9d0', 'size': 8}, {'index': 676, 'PC': 'main:0x16aa34', 'address': '0x7004b9d8', 'size': 8}, {'index': 678, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c0', 'size': 8}, {'index': 678, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c8', 'size': 8}], 'services': [{'index': 14, 'kind': 'actual_Bionic_malloc_route', 'PC': '0x347fd0', 'request': 24}, {'index': 15, 'kind': 'actual_Bionic_malloc_entry', 'PC': 'libc:0x1bb08', 'request': 24}], 'next_VM_call': {'index': 681, 'callsite_offset': '0x16aa48', 'VM_cursor_offset': '0x10a228', 'descriptor_address': '0x7004cdf8', 'descriptor_sha256': 'bc58d9bbf24fe1d778dc428b50a1357948512396d4d26e04f819a20edef5f9f0', 'wrapper_offset': '0x2884cc', 'target_offset': '0x2481ac', 'wrapper_code_hex': '012040a9e00308aa20001fd6', 'VM_call_executed': False, 'wrapper_executed': False, 'target_executed': False, 'descriptor_width': 48, 'object_address': '0x136d9660', 'static_expected_target_arguments': {'x0': '0x136d9660'}, 'wrapper_code_sha256': '82295168e4332fdd8ee754ea9b86ffc5a592a6e6c42c0e1592ea18f55c95c565'}, 'new_allocator_events': [['alloc', 24, 325949024, '0x32a210']], 'ledgers': {'allocator_counts': {'malloc': 590, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}, 'protected_ranges': [{'label': 'prior_0', 'address': '0x7004d118', 'size': 24}, {'label': 'prior_1', 'address': '0x136d82c0', 'size': 8}, {'label': 'prior_2', 'address': '0x7004d130', 'size': 24}, {'label': 'prior_3', 'address': '0x136d82d0', 'size': 8}, {'label': 'prior_4', 'address': '0x7004d148', 'size': 24}, {'label': 'prior_5', 'address': '0x136d82d8', 'size': 8}, {'label': 'string_object', 'address': '0x136d9640', 'size': 24}, {'label': 'string_payload', 'address': '0x136d4050', 'size': 37}, {'label': 'output', 'address': '0x7004d178', 'size': 16}, {'label': 'cache', 'address': '0x136d73a0', 'size': 16}, {'label': 'counter', 'address': '0x136d82e0', 'size': 4}, {'label': 'cache_mutex', 'address': '0x136d4020', 'size': 48}, {'label': 'cache_globals', 'address': '0x1269e700', 'size': 64}, {'label': 'seed_constants', 'address': '0x1269e450', 'size': 128}, {'label': 'errno', 'address': '0x7000a010', 'size': 4}]}

def project_next_call(row):
    row=deepcopy(row);descriptor=bytes.fromhex(row.pop('descriptor_hex'))
    assert len(descriptor)==48 and raw_hash(descriptor)==row['descriptor_sha256']
    assert row['wrapper_offset']=='0x2884cc' and row['target_offset']=='0x2481ac'
    assert int.from_bytes(descriptor[:8],'little')==IMAGE_BASE+0x2481AC
    row['descriptor_width']=48
    row['object_address']=hex(int.from_bytes(descriptor[8:16],'little'))
    row['static_expected_target_arguments']={'x0':row['object_address']}
    code=bytes.fromhex(row['wrapper_code_hex'])[:12]
    assert code.hex()=='012040a9e00308aa20001fd6'
    row['wrapper_code_hex']=code.hex();row['wrapper_code_sha256']=raw_hash(code)
    return row

def stop_boundary():
    return dict(kind='before_VM_call_after_post_identifier_allocation',stop_before=hex(VM_CALL),VM_call_executed=False,wrapper_executed=False,target_executed=False)

def validate_next_call(row,data,last):
    call=row['next_VM_call'];last=row['snapshots'][-1];returned=row['snapshots'][-2]
    assert call['index']==row['instruction_observations'] and call['callsite_offset']==hex(VM_CALL) and call['VM_cursor_offset']==last['VM_cursor']=='0x10a228'
    assert call['descriptor_width']==48 and call['descriptor_address']=='0x7004cdf8'
    assert call['descriptor_address']==last['registers']['x0']
    assert call['wrapper_offset']==hex(NEXT_WRAPPER)=='0x2884cc' and call['target_offset']==hex(NEXT_TARGET)=='0x2481ac'
    assert call['object_address']==returned['allocation_address']=='0x136d9660' and call['static_expected_target_arguments']=={'x0':call['object_address']}
    assert call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert len(bytes.fromhex(call['wrapper_code_hex']))==NEXT_WRAPPER_SIZE==12 and raw_hash(bytes.fromhex(call['wrapper_code_hex']))==call['wrapper_code_sha256']
    assert call['VM_call_executed'] is call['wrapper_executed'] is call['target_executed'] is False and 'descriptor_hex' not in call
    suffix=row['observation_sites'][returned['index']:]
    assert 'main:'+hex(NEXT_WRAPPER) not in suffix and 'main:'+hex(NEXT_TARGET) not in suffix

class PostIdentifierAllocationScenario(previous.PostIdentifierVMScenario):
    def __init__(self,control):
        super().__init__(control)
        self._postalloc_active=False;self._postalloc_done=False;self._postalloc_returned=False;self._postalloc_stored=False
        self._postalloc_count=0;self._postalloc_trace=[];self._postalloc_code={};self._postalloc_rows=[];self._postalloc_writes=[]
        self._postalloc_live_writes=[];self._postalloc_services=[];self._postalloc_pointer=0

    def _postalloc_track(self,cpu,pc):
        self._postalloc_count+=1;assert self._postalloc_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._postalloc_trace.append(key);self._postalloc_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _postalloc_snapshot(self,cpu,pc,kind):
        descriptor=bytes(cpu.mem_read(self._postalloc_descriptor,48))
        row=dict(kind=kind,index=self._postalloc_count,pc=hex(pc-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            registers={f'x{n}':hex(self._reg(cpu,n)) for n in (0,30)},callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_state_address=hex(self._postalloc_vmstate),VM_cursor=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            live_regions_sha256=self._idvm_live_hash(cpu),descriptor_address=hex(self._postalloc_descriptor),descriptor_sha256=raw_hash(descriptor),
            input_16_sha256=raw_hash(descriptor[:16]),tail_24_sha256=raw_hash(descriptor[24:]),result_slot_address=hex(self._postalloc_descriptor+16),
            result_slot_sha256=raw_hash(descriptor[16:24]),result_store_completed=self._postalloc_stored,
            output=self._idpub_pair(cpu,self._idopen_output),cache=self._idpub_pair(cpu,self._seedfail_pair),
            counter_address=hex(self._idref_counter),counter_u32=self._u(cpu,self._idref_counter,4),
            payload_length=36,payload_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_payload,37))),
            cache_mutex_state_u16=self._u(cpu,self._seedfail_mutex+8,2),diagnostic=self._idref_diagnostic(cpu),errno=self._u(cpu,self._seedfail_errno,4))
        if self._postalloc_pointer:row.update(allocation_address=hex(self._postalloc_pointer),allocation_width=24,allocation_sha256=raw_hash(bytes(cpu.mem_read(self._postalloc_pointer,24))))
        if self._postalloc_stored:row['result_slot_pointer']=hex(self._u(cpu,self._postalloc_descriptor+16))
        self._postalloc_rows.append(row)

    def _postalloc_start(self,cpu,pc,state):
        self._idvm_track(cpu,pc);self._idvm_snapshot(cpu,pc,'before_next_VM_call')
        descriptor=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(descriptor,48))
        self._idvm_next=previous.project_next_call(dict(index=self._idvm_count,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
            descriptor_address=hex(descriptor),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),
            target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False))
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data);old=data['case_result']
        h=hashlib.sha256()
        for key in self._idvm_trace:h.update(key.encode()+bytes.fromhex(self._idvm_code[key]))
        for value,key in ((self._idvm_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),(digest(self._idvm_code),'observed_code_sha256'),
            (self._idvm_trace,'observation_sites'),(self._idvm_code,'observed_code'),(self._idvm_rows,'snapshots'),(self._idvm_writes,'native_writes'),(self._idvm_next,'next_VM_call')):assert value==old[key],key
        assert self._idvm_live_writes==[] and state['allocator_events_ref']==self._idvm_events
        assert wrapper==self.image+WRAPPER and int.from_bytes(raw[:8],'little')==self.image+TARGET and int.from_bytes(raw[8:16],'little')==24
        self._postalloc_old=old;self._postalloc_events=deepcopy(state['allocator_events_ref'])
        self._postalloc_descriptor=descriptor;self._postalloc_before=raw
        self._postalloc_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._postalloc_saved=self._idctor_saved_hash(cpu);self._postalloc_vmstate=self._reg(cpu,19)
        self._idvm_active=False;self._idvm_done=False;self._postalloc_active=True
        self._postalloc_track(cpu,pc);self._postalloc_snapshot(cpu,pc,'allocation_VM_call')

    def native_runner(self,*args,**kwargs):
        assert kwargs.get('real_malloc') is True and not kwargs.get('malloc_handler')
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._postalloc_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                row=dict(index=self._postalloc_count,PC=('libc:'+hex(pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else 'main:'+hex(pc-self.image)),address=hex(address),size=size)
                self._postalloc_writes.append(row)
                labels=[label for label,a,n in self._idvm_ranges if address<a+n and a<address+size]
                if labels:raise AssertionError('post identifier allocation wrote protected live state')
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._postalloc_active:
            if self._idvm_active and pc==self.image+VM_CALL:
                self._postalloc_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._postalloc_track(cpu,pc);off=pc-self.image
        if not self._postalloc_returned:
            if off in (WRAPPER,TARGET):self._postalloc_snapshot(cpu,pc,'wrapper_entry' if off==WRAPPER else 'operator_new_entry')
            if off==0x347FD0:self._postalloc_services.append(dict(index=self._postalloc_count,kind='actual_Bionic_malloc_route',PC=hex(off),request=self._reg(cpu,0)))
            if pc==LIBC_BASE+MALLOC:self._postalloc_services.append(dict(index=self._postalloc_count,kind='actual_Bionic_malloc_entry',PC='libc:'+hex(MALLOC),request=self._reg(cpu,0)))
            if off==0x32A210:
                self._postalloc_pointer=self._reg(cpu,0);assert self._postalloc_pointer
                self._postalloc_snapshot(cpu,pc,'malloc_return')
            if off==0x288518:
                assert self._reg(cpu,0)==self._postalloc_pointer and self._reg(cpu,19)==self._postalloc_descriptor
                self._postalloc_snapshot(cpu,pc,'operator_new_return_before_store')
            if off==0x28851C:
                assert self._u(cpu,self._postalloc_descriptor+16)==self._postalloc_pointer
                self._postalloc_stored=True;self._postalloc_snapshot(cpu,pc,'packed_result_stored')
            if off==VM_RESUME:
                assert self._postalloc_stored and self._reg(cpu,0)==self._postalloc_pointer
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._postalloc_sp and self._idctor_saved_hash(cpu)==self._postalloc_saved
                now=bytes(cpu.mem_read(self._postalloc_descriptor,48));assert now[:16]==self._postalloc_before[:16] and now[24:]==self._postalloc_before[24:]
                self._postalloc_snapshot(cpu,pc,'allocation_callback_return');self._postalloc_returned=True
        elif off==VM_CALL:
            self._postalloc_snapshot(cpu,pc,'before_next_VM_call')
            d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
            self._postalloc_next=dict(index=self._postalloc_count,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
                descriptor_address=hex(d),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),
                target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),
                VM_call_executed=False,wrapper_executed=False,target_executed=False)
            self._postalloc_next=project_next_call(self._postalloc_next)
            self._postalloc_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._postalloc_done and self._postalloc_returned and self._postalloc_stored and self._postalloc_live_writes==[]
        h=hashlib.sha256()
        for key in self._postalloc_trace:h.update(key.encode()+bytes.fromhex(self._postalloc_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],
            inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],
            inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        assert result['allocator_events'][:len(self._postalloc_events)]==self._postalloc_events
        counts=deepcopy(self._postalloc_old['allocator_counts']);counts['malloc']+=1
        assert ledgers['allocator_counts']==counts
        for key,value in ledgers.items():
            if key!='allocator_counts':assert value==self._postalloc_old[key],key
        return dict(control=self._postalloc_old['control'],retained_VM_segment=dict(case_result_sha256=digest(self._postalloc_old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._postalloc_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._postalloc_code),
            snapshots=self._postalloc_rows,native_writes=self._postalloc_writes,services=self._postalloc_services,
            next_VM_call=self._postalloc_next,observation_sites=self._postalloc_trace,observed_code=self._postalloc_code,
            new_allocator_events=result['allocator_events'][len(self._postalloc_events):],**ledgers,
            protected_ranges=[dict(label=label,address=hex(a),size=n) for label,a,n in self._idvm_ranges],protected_write_events=[],stop_boundary=stop_boundary())

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    return dict(allocation_return_verifier_sha256=sha256(Path(__file__)),
        owners={k:sha256(Path(v.__file__)) for k,v in dict(parent=previous,allocation_fixture=previous.allocation_controls,
            allocation_model=previous.allocation_controls.model,oracle=previous.oracle).items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        main_path_malloc='inherited matching original Bionic malloc, not a synthetic allocation callback',
        component_controls='existing fresh allocation wrapper controls use an explicit synthetic malloc provider',
        exported_output='hashes, lengths, defined pointers/scalars and write locations/widths; raw identifier, seed, descriptor and allocation contents omitted',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',post_identifier_VM_prefix_revalidated=True,original_VM_allocation_call_executed=True,
        original_wrapper_and_operator_new_executed=True,inherited_original_Bionic_malloc_executed=True,
        packed_result_store_observed=True,allocation_callback_returned=True,caller_SP_and_callee_saved_restored=True,
        next_VM_call_boundary_observed=True,next_VM_call_executed=False,next_wrapper_executed=False,next_target_executed=False,
        published_identifier_and_prior_default_objects_write_protected=True,new_providers_added=False,
        native_snapshot_used_as_python_model_input=False,independent_owning_allocator_parity_verified=False,
        native_NULL_new_handler_throw_verified=False,standalone_Python_VM_continuation_verified=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,real_ART_JVM_execution=False,
        Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def read_static(path,libc):
    rows={}
    for domain,p in (('main',path),('libc',libc)):
        with p.open('rb') as f:
            elf=ELFFile(f)
            for off,size in CODE_RANGES[domain]:
                segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off and off+size<=s['p_vaddr']+s['p_filesz'])
                f.seek(segment['p_offset']+off-segment['p_vaddr']);raw=f.read(size)
                rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows

def independent_controls(path,libc):
    return previous.independent_controls(path,libc)

def run(path,libc):
    parent=prior_evidence();p=previous.previous.previous.previous.previous.previous.previous.previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostIdentifierAllocationScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    components,negative=independent_controls(path,libc)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),static_code=code,
        native_controls=components,component_rollback_checks=negative,case_result=rows[0],case_result_sha256=digest(rows[0]))

def validate(data):
    old=prior_evidence()['case_result']
    assert set(data)=={'schema','claims','providers','source_fingerprints','input_provenance','static_code','native_controls','component_rollback_checks','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(prior_evidence())
    assert data['native_controls']==previous.CONTROL_SPECS and len(data['native_controls'])==20
    assert data['component_rollback_checks']==previous.ROLLBACK_SPECS and len(data['component_rollback_checks'])==9
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'hex','size','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_VM_segment','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots','native_writes','services','next_VM_call',
        'observation_sites','observed_code','new_allocator_events','protected_ranges','protected_write_events','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_VM_segment']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[0]==sites[-1]=='main:'+hex(VM_CALL) and sites.count('main:'+hex(VM_CALL))==2
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
    snapshots=row['snapshots'];assert [x['kind'] for x in snapshots]==[
        'allocation_VM_call','wrapper_entry','operator_new_entry','malloc_return','operator_new_return_before_store',
        'packed_result_stored','allocation_callback_return','before_next_VM_call']
    first,wrapper,target,malloc,before,stored,returned,last=snapshots
    assert [x['pc'] for x in snapshots]==[hex(x) for x in (VM_CALL,WRAPPER,TARGET,0x32A210,0x288518,0x28851C,VM_RESUME,VM_CALL)]
    assert first['index']==1 and last['index']==len(sites) and all(a['index']<b['index'] for a,b in zip(snapshots,snapshots[1:]))
    for x in snapshots:assert sites[x['index']-1]=='main:'+x['pc']
    prior=old['snapshots'][-1]
    assert first['SP']==returned['SP']==prior['SP'] and first['callee_saved_sha256']==returned['callee_saved_sha256']==prior['callee_saved_sha256']
    assert target['registers']['x0']=='0x18' and wrapper['registers']['x0']==first['descriptor_address']==old['next_VM_call']['descriptor_address']
    assert first['VM_cursor']==returned['VM_cursor']==prior['VM_cursor']=='0x10a208'
    assert first['descriptor_sha256']==old['next_VM_call']['descriptor_sha256']
    assert first['result_slot_address']==old['next_VM_call']['result_slot_address'] and first['result_slot_sha256']==old['next_VM_call']['result_slot_before_sha256']
    for x in snapshots:
        assert x['live_regions_sha256']==prior['live_regions_sha256'] and x['counter_u32']==prior['counter_u32']==2
        assert x['output']==prior['output'] and x['cache']==prior['cache'] and x['payload_length']==36
        assert x['payload_including_NUL_sha256']==prior['payload_including_NUL_sha256'] and x['cache_mutex_state_u16']==0
        assert x['diagnostic']==prior['diagnostic'] and x['errno']==prior['errno']==2
        assert x['VM_state_address']==prior['VM_state_address'] and set(x['registers'])=={'x0','x30'}
    for x in snapshots[:7]:
        assert x['input_16_sha256']==first['input_16_sha256'] and x['tail_24_sha256']==first['tail_24_sha256']
    for x in snapshots[:5]:assert x['result_store_completed'] is False and 'result_slot_pointer' not in x
    pointer=malloc['allocation_address'];assert int(pointer,16)!=0
    for x in (malloc,before,stored,returned):
        assert x['allocation_address']==pointer and x['allocation_width']==24
        assert x['allocation_sha256']==malloc['allocation_sha256']
        assert x['registers']['x0']==pointer
    for x in (stored,returned):assert x['result_store_completed'] is True and x['result_slot_pointer']==pointer
    assert stored['result_slot_sha256']==raw_hash(int(pointer,16).to_bytes(8,'little'))
    assert len(row['services'])==2
    for service,pc in zip(row['services'],('main:0x347fd0','libc:'+hex(MALLOC))):
        assert service['request']==24 and sites[service['index']-1]==pc
        assert target['index']<service['index']<malloc['index']
    assert any(w['PC']=='main:0x288518' and w['address']==first['result_slot_address'] and w['size']==8 and w['index']==before['index'] for w in row['native_writes'])
    for w in row['native_writes']:
        assert set(w)=={'index','PC','address','size'} and sites[w['index']-1]==w['PC'] and w['size']>0
        for region in row['protected_ranges']:
            a=int(w['address'],16);b=int(region['address'],16);assert not (a<b+region['size'] and b<a+w['size'])
    assert row['protected_ranges']==old['protected_ranges'] and row['protected_write_events']==[]
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=1
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value==(counts if key=='allocator_counts' else old[key]),key
    assert len(row['new_allocator_events'])==1
    validate_next_call(row,data,last)
    assert row['stop_boundary']==stop_boundary()

def damaged_evidence_rejected(data):
    changes=[(('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('claims','independent_owning_allocator_parity_verified'),True),(('providers','new_providers'),['hidden']),
        (('source_fingerprints','owners','oracle'),'0'*64),(('case_result','retained_VM_segment','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),0),(('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'counter_u32'),1),(('case_result','snapshots',-1,'live_regions_sha256'),'0'*64),
        (('case_result','snapshots',-1,'payload_including_NUL_sha256'),'0'*64),(('case_result','snapshots',-1,'cache_mutex_state_u16'),1),
        (('case_result','snapshots',6,'SP'),'0x0'),(('case_result','snapshots',6,'callee_saved_sha256'),'0'*64),
        (('case_result','snapshots',5,'result_slot_pointer'),'0x0'),(('case_result','snapshots',5,'result_store_completed'),False),
        (('case_result','snapshots',3,'allocation_address'),'0x0'),(('case_result','snapshots',3,'allocation_sha256'),'0'*64),
        (('case_result','services',1,'request'),0),(('case_result','native_writes',0,'size'),99),
        (('case_result','next_VM_call','target_offset'),'0x0'),(('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','wrapper_code_sha256'),'0'*64),(('case_result','next_VM_call','target_executed'),True),
        (('case_result','next_VM_call','descriptor_hex'),'omitted'),(('case_result','new_allocator_events'),[]),
        (('case_result','protected_write_events'),['hidden']),(('case_result','stop_boundary','VM_call_executed'),True),
        (('case_result','raw_identifier'),'omitted'),(('case_result','raw_allocation'),'omitted'),(('raw_identifier',),'omitted'),
        (('native_controls',0,'native_snapshot_input'),True),(('component_rollback_checks',0,'all_pages_unchanged'),False)]
    for key in EXPECTED['ledgers']:changes.append((('case_result',key),{}))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged post-identifier allocation evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-identifier allocation replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),
        damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],
        actual_Bionic_allocation_returned=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
