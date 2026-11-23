"""Verify VM resumption after identifier publication and stop before its next call."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_identifier_cache_publication_dynamic_20261123 as previous
import verify_vm9_signer_objects as oracle
import verify_vm9_second_allocation_fresh_20261015 as allocation_controls
import vm9_request_identifier as identifier_model
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_identifier_vm_boundary_dynamic_20261123.json')
SCHEMA='vm9-native-171-post-identifier-vm-boundary-dynamic-20261123-v1'
LIBC_BASE,START,NEXT=0x51000000,0x16AA4C,0x16AA48
MAX_OBSERVATIONS=100000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes','services','getter_saved_sha256')
NEXT_WRAPPER,NEXT_TARGET,WRAPPER_SIZE,IMAGE_BASE=2655496,3318256,28,304873472
CODE_RANGES={'main': ((1485388, 28), (1485384, 4), (2655496, 28), (3318256, 32)), 'libc': ()}
CODE_SHA256={'main:0x16aa4c': '93e67985d076122f1508f8c790d19fceb8738947f9fc4dc79706da818a126519', 'main:0x16aa48': '439b39c74301583dce0abc4e5868de8507f7f06163800bfd8d61009571e9d28d', 'main:0x288508': '89dff6609a3af925ec6fb49b533294966a3036bec5a610457b9660cc73af8375', 'main:0x32a1f0': 'd63c811bfd6c3d95319a36058d5dc054eba011685bf930cf8620cbd5d48624c7'}
EXPECTED={'instruction_observations': 686, 'instruction_trace_sha256': 'eb8b0d89722e2ac6e84d6be65349a658780cadfba31c2c74eb933ea1924011a1', 'observed_code_sha256': 'f740dd54c86952482740e195c1b81a7e5b20764e6c90df3d7db2879cd7826da3', 'snapshots': [{'kind': 'before_VM_resume', 'index': 1, 'pc': '0x16aa4c', 'SP': '0x7004b930', 'registers': {'x0': '0x0', 'x30': '0x1242aa4c'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_cursor': '0x10a1e0', 'VM_state_address': '0x7004d360', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'packed_descriptor_address': '0x7004cbe8', 'packed_descriptor_sha256': 'd8c2fdaace9a906583559c7b77b1d9df541de6b4b4a1b23c56a2ed1af6a22239', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}, {'kind': 'before_next_VM_call', 'index': 686, 'pc': '0x16aa48', 'SP': '0x7004b930', 'registers': {'x0': '0x7004cda8', 'x30': '0x7004b960'}, 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_cursor': '0x10a208', 'VM_state_address': '0x7004d360', 'live_regions_sha256': 'abddb599259e0ec8f6f9f7fad4ceb511547f8621f52660e7cfb2b3497decdec2', 'packed_descriptor_address': '0x7004cbe8', 'packed_descriptor_sha256': 'd8c2fdaace9a906583559c7b77b1d9df541de6b4b4a1b23c56a2ed1af6a22239', 'output': {'address': '0x7004d178', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'cache': {'address': '0x136d73a0', 'pointer': '0x136d9640', 'counter': '0x136d82e0', 'pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7'}, 'counter_address': '0x136d82e0', 'counter_u32': 2, 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'cache_mutex_state_u16': 0, 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2}], 'native_writes': [{'index': 33, 'PC': 'main:0x16a9f0', 'address': '0x7004d360', 'size': 8}, {'index': 100, 'PC': 'main:0x16d89c', 'address': '0x7004b9a0', 'size': 4}, {'index': 102, 'PC': 'main:0x16d8a4', 'address': '0x7004d418', 'size': 8}, {'index': 107, 'PC': 'main:0x16d8b8', 'address': '0x7004d360', 'size': 8}, {'index': 119, 'PC': 'main:0x16d8e8', 'address': '0x7004b990', 'size': 4}, {'index': 120, 'PC': 'main:0x16d8ec', 'address': '0x7004b960', 'size': 2}, {'index': 175, 'PC': 'main:0x16d89c', 'address': '0x7004b9a0', 'size': 4}, {'index': 177, 'PC': 'main:0x16d8a4', 'address': '0x7004d370', 'size': 8}, {'index': 182, 'PC': 'main:0x16d8b8', 'address': '0x7004d360', 'size': 8}, {'index': 194, 'PC': 'main:0x16d8e8', 'address': '0x7004b990', 'size': 4}, {'index': 195, 'PC': 'main:0x16d8ec', 'address': '0x7004b960', 'size': 2}, {'index': 232, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 235, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 236, 'PC': 'main:0x16f974', 'address': '0x7004d378', 'size': 8}, {'index': 238, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 251, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 275, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 329, 'PC': 'main:0x171268', 'address': '0x7004cdb0', 'size': 8}, {'index': 345, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 346, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 351, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 375, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 429, 'PC': 'main:0x171268', 'address': '0x7004cda8', 'size': 8}, {'index': 445, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 446, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 451, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 486, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 489, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 490, 'PC': 'main:0x16f974', 'address': '0x7004d3e8', 'size': 8}, {'index': 492, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 505, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 527, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 529, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 530, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 534, 'PC': 'main:0x16a5d8', 'address': '0x7004d388', 'size': 8}, {'index': 537, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 547, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 569, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 571, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 572, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 576, 'PC': 'main:0x16a5d8', 'address': '0x7004d390', 'size': 8}, {'index': 579, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 589, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 611, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 613, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 614, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 618, 'PC': 'main:0x16a5d8', 'address': '0x7004d430', 'size': 8}, {'index': 621, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 631, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 670, 'PC': 'main:0x16a93c', 'address': '0x7004b990', 'size': 4}, {'index': 672, 'PC': 'main:0x16a944', 'address': '0x7004b9a0', 'size': 4}, {'index': 673, 'PC': 'main:0x16a948', 'address': '0x7004b980', 'size': 4}, {'index': 674, 'PC': 'main:0x16a94c', 'address': '0x7004b970', 'size': 4}, {'index': 675, 'PC': 'main:0x16a950', 'address': '0x7004d460', 'size': 8}, {'index': 681, 'PC': 'main:0x16aa34', 'address': '0x7004b9d0', 'size': 8}, {'index': 681, 'PC': 'main:0x16aa34', 'address': '0x7004b9d8', 'size': 8}, {'index': 683, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c0', 'size': 8}, {'index': 683, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c8', 'size': 8}], 'next_VM_call': {'index': 686, 'callsite_offset': '0x16aa48', 'VM_cursor_offset': '0x10a208', 'descriptor_address': '0x7004cda8', 'descriptor_sha256': '469e7c85be9fd201b52fc69c1e78e7291a2af05c638ffd7c98d96f3666cd3115', 'wrapper_offset': '0x288508', 'target_offset': '0x32a1f0', 'wrapper_code_hex': 'fe4fbfa9f30300aa080040a900013fd6600a00f9fe4fc1a8c0035fd6', 'VM_call_executed': False, 'wrapper_executed': False, 'target_executed': False, 'descriptor_width': 48, 'allocation_request_size': 24, 'static_expected_target_arguments': {'x0': '0x18'}, 'result_slot_address': '0x7004cdb8', 'result_slot_before_sha256': 'dbba0579494c420a22eea545dd7c8b45e8a75cff2ac5ac578f3ca07e20a901a9', 'wrapper_code_sha256': '89dff6609a3af925ec6fb49b533294966a3036bec5a610457b9660cc73af8375'}, 'protected_ranges': [{'label': 'prior_0', 'address': '0x7004d118', 'size': 24}, {'label': 'prior_1', 'address': '0x136d82c0', 'size': 8}, {'label': 'prior_2', 'address': '0x7004d130', 'size': 24}, {'label': 'prior_3', 'address': '0x136d82d0', 'size': 8}, {'label': 'prior_4', 'address': '0x7004d148', 'size': 24}, {'label': 'prior_5', 'address': '0x136d82d8', 'size': 8}, {'label': 'string_object', 'address': '0x136d9640', 'size': 24}, {'label': 'string_payload', 'address': '0x136d4050', 'size': 37}, {'label': 'output', 'address': '0x7004d178', 'size': 16}, {'label': 'cache', 'address': '0x136d73a0', 'size': 16}, {'label': 'counter', 'address': '0x136d82e0', 'size': 4}, {'label': 'cache_mutex', 'address': '0x136d4020', 'size': 48}, {'label': 'cache_globals', 'address': '0x1269e700', 'size': 64}, {'label': 'seed_constants', 'address': '0x1269e450', 'size': 128}, {'label': 'errno', 'address': '0x7000a010', 'size': 4}], 'ledgers': {'allocator_counts': {'malloc': 589, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'size_zero', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'size_one', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'size24', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'size4097', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'max_size', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'high_pointer', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'cross_page_input', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'cross_page_result', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'provider_rewrites_packed', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'allocation_packed_alias', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'size_zero', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'size_one', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'size24', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'size4097', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'max_size', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'high_pointer', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'cross_page_input', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'cross_page_result', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'provider_rewrites_packed', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'allocation_packed_alias', 'native_instructions': 21, 'original_wrapper_and_operator_new_returned': True, 'declared_image_and_guest_bytes_equal': True, 'X64_size_and_result_store_equal': True, 'ordered_explicit_allocation_effects_equal': True, 'zero_size_normalization_equal': True, 'no_JNI_lock_file_or_syscall_services': True, 'component_malloc_provider_explicit': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}]
ROLLBACK_SPECS=[{'case': 'wrong_target', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_packed', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_result_after_allocation', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'unaligned_stack', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'packed_stack_alias', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_provider', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'NULL_allocation', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'invalid_pointer', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'provider_raises_after_effect', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}]
def project_snapshot(row):
    row=deepcopy(row);row['registers'].pop('x8',None);return row

def project_next_call(row):
    row=deepcopy(row);descriptor=bytes.fromhex(row.pop('descriptor_hex'))
    assert len(descriptor)==48 and raw_hash(descriptor)==row['descriptor_sha256']
    assert int.from_bytes(descriptor[:8],'little')==IMAGE_BASE+NEXT_TARGET
    row['descriptor_width']=48
    request=int.from_bytes(descriptor[8:16],'little')
    row['allocation_request_size']=request
    row['static_expected_target_arguments']={'x0':hex(request)}
    row['result_slot_address']=hex(int(row['descriptor_address'],16)+16)
    row['result_slot_before_sha256']=raw_hash(descriptor[16:24])
    code=bytes.fromhex(row['wrapper_code_hex'])[:WRAPPER_SIZE]
    row['wrapper_code_hex']=code.hex();row['wrapper_code_sha256']=raw_hash(code)
    return row

def stop_boundary():
    return dict(kind='before_post_identifier_next_VM_call',stop_before=hex(NEXT),VM_call_executed=False,wrapper_executed=False,target_executed=False)

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,allocation_fixture=allocation_controls,allocation_model=allocation_controls.model,identifier_model=identifier_model,oracle=oracle)
    return dict(post_identifier_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        component_controls='fresh allocation-wrapper success controls with explicit synthetic malloc; actual next main-path call remains unexecuted',
        packed_arguments='VM may reuse its packed argument area; descriptor bytes are retained by hash only',
        exported_output='lengths, hashes, initialized pointers/counters and native write locations only; no raw identifier or seed bytes',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',identifier_publication_prefix_revalidated=True,original_VM_resumption_executed=True,
        next_VM_call_boundary_observed=True,next_VM_call_executed=False,next_wrapper_executed=False,next_target_executed=False,
        published_identifier_output_cache_counter_and_mutex_write_protected=True,three_prior_default_strings_write_protected=True,
        new_providers_added=False,native_snapshot_used_as_python_model_input=False,standalone_Python_VM_continuation_verified=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,real_ART_JVM_execution=False,
        Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def read_static(path,libc):
    rows={}
    with path.open('rb') as f:
        elf=ELFFile(f)
        for off,size in CODE_RANGES['main']:
            segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off and off+size<=s['p_vaddr']+s['p_filesz'])
            f.seek(segment['p_offset']+off-segment['p_vaddr']);raw=f.read(size);assert len(raw)==size
            rows['main:'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows
class PostIdentifierVMScenario(previous.IdentifierCachePublicationScenario):
    def __init__(self,control):
        super().__init__(control)
        self._idvm_active=False;self._idvm_done=False;self._idvm_count=0
        self._idvm_trace=[];self._idvm_code={};self._idvm_rows=[];self._idvm_writes=[];self._idvm_live_writes=[]

    def _idvm_track(self,cpu,pc):
        self._idvm_count+=1;assert self._idvm_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._idvm_trace.append(key);self._idvm_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _idvm_live_hash(self,cpu):
        h=hashlib.sha256()
        for label,a,n in self._idvm_ranges:h.update(label.encode()+a.to_bytes(8,'little')+n.to_bytes(8,'little')+bytes(cpu.mem_read(a,n)))
        return h.hexdigest()

    def _idvm_snapshot(self,cpu,pc,kind):
        self._idvm_rows.append(project_snapshot(dict(kind=kind,index=self._idvm_count,pc=hex(pc-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            registers={f'x{n}':hex(self._reg(cpu,n)) for n in (0,8,30)},callee_saved_sha256=self._idctor_saved_hash(cpu),
            VM_cursor=hex(self._u(cpu,self._reg(cpu,19))-self.image),VM_state_address=hex(self._reg(cpu,19)),
            live_regions_sha256=self._idvm_live_hash(cpu),packed_descriptor_address=hex(self._idopen_descriptor),
            packed_descriptor_sha256=raw_hash(bytes(cpu.mem_read(self._idopen_descriptor,48))),
            output=self._idpub_pair(cpu,self._idopen_output),cache=self._idpub_pair(cpu,self._seedfail_pair),
            counter_address=hex(self._idref_counter),counter_u32=self._u(cpu,self._idref_counter,4),
            payload_length=36,payload_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_payload,37))),
            cache_mutex_state_u16=self._u(cpu,self._seedfail_mutex+8,2),diagnostic=self._idref_diagnostic(cpu),errno=self._u(cpu,self._seedfail_errno,4))))

    def _idvm_start(self,cpu,pc,state):
        self._idpub_track(cpu,pc);self._idpub_snapshot(cpu,pc,'callback_return_before_VM_resume')
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data);old=data['case_result']
        h=hashlib.sha256()
        for key in self._idpub_trace:h.update(key.encode()+bytes.fromhex(self._idpub_code[key]))
        for value,key in ((self._idpub_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),
            (digest(self._idpub_code),'observed_code_sha256'),(self._idpub_trace,'observation_sites'),(self._idpub_code,'observed_code'),
            (self._idpub_rows,'snapshots'),(self._idpub_writes,'native_writes'),(self._idpub_services,'services'),(self._idpub_getter_saved,'getter_saved_sha256')):assert value==old[key],key
        assert state['allocator_events_ref']==self._idpub_events
        self._idvm_old=old;self._idvm_events=deepcopy(state['allocator_events_ref'])
        self._idvm_ranges=[(f'prior_{i}',a,n) for i,(a,n) in enumerate(self._idopen_ranges)]+[
            ('string_object',self._idctor_object,24),('string_payload',self._idctor_payload,37),('output',self._idopen_output,16),
            ('cache',self._seedfail_pair,16),('counter',self._idref_counter,4),('cache_mutex',self._seedfail_mutex,48),
            ('cache_globals',self.image+0x3DE700,64),('seed_constants',self.image+0x3DE450,128),('errno',self._seedfail_errno,4)]
        self._idpub_active=False;self._idpub_done=False;self._idvm_active=True
        self._idvm_track(cpu,pc);self._idvm_snapshot(cpu,pc,'before_VM_resume')

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._idvm_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)
                labels=[label for label,a,n in self._idvm_ranges if address<a+n and a<address+size]
                row=dict(index=self._idvm_count,PC=('libc:'+hex(pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else 'main:'+hex(pc-self.image)),address=hex(address),size=size)
                self._idvm_writes.append(row)
                if labels:raise AssertionError('post identifier VM wrote protected live state')
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._idvm_active:
            if self._idpub_active and pc==self.image+START:
                self._idvm_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._idvm_track(cpu,pc)
        if pc==self.image+NEXT:
            self._idvm_snapshot(cpu,pc,'before_next_VM_call')
            descriptor=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(descriptor,48))
            self._idvm_next=dict(index=self._idvm_count,callsite_offset=hex(NEXT),VM_cursor_offset=hex(self._u(cpu,self._reg(cpu,19))-self.image),
                descriptor_address=hex(descriptor),descriptor_hex=raw.hex(),descriptor_sha256=raw_hash(raw),
                wrapper_offset=hex(wrapper-self.image),target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),
                wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False)
            self._idvm_next=project_next_call(self._idvm_next)
            self._idvm_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._idvm_done and self._idvm_live_writes==[]
        h=hashlib.sha256()
        for key in self._idvm_trace:h.update(key.encode()+bytes.fromhex(self._idvm_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        assert result['allocator_events']==self._idvm_events
        for key,value in ledgers.items():assert value==self._idvm_old[key],key
        return dict(control=self._idvm_old['control'],retained_publication=dict(case_result_sha256=digest(self._idvm_old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._idvm_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._idvm_code),
            snapshots=self._idvm_rows,native_writes=self._idvm_writes,next_VM_call=self._idvm_next,observation_sites=self._idvm_trace,observed_code=self._idvm_code,
            new_allocator_events=[],**ledgers,protected_ranges=[dict(label=label,address=hex(a),size=n) for label,a,n in self._idvm_ranges],protected_write_events=[],stop_boundary=stop_boundary())

def independent_controls(path,libc):
    cases=[allocation_controls.compare(path,libc,base,label) for base in allocation_controls.BASES for label in allocation_controls.PROFILES]
    guards=allocation_controls.guards(path)
    assert cases==CONTROL_SPECS and guards==ROLLBACK_SPECS
    return cases,guards

def run(path,libc):
    parent=prior_evidence();p=previous.previous.previous.previous.previous.previous.previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostIdentifierVMScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    components,negative=independent_controls(path,libc)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),static_code=code,
        native_controls=components,component_rollback_checks=negative,case_result=rows[0],case_result_sha256=digest(rows[0]))

def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert set(data)=={'schema','claims','providers','source_fingerprints','input_provenance','static_code','native_controls','component_rollback_checks','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_controls']==CONTROL_SPECS and len(CONTROL_SPECS)==20
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==9
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'hex','size','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_publication','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots','native_writes','next_VM_call',
        'observation_sites','observed_code','new_allocator_events','protected_ranges','protected_write_events','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_publication']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[0]=='main:'+hex(START) and sites[-1]=='main:'+hex(NEXT) and sites.count('main:'+hex(NEXT))==1
    assert 'main:'+hex(NEXT_WRAPPER) not in sites and 'main:'+hex(NEXT_TARGET) not in sites
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4');h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256'] and digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    assert code['main:'+hex(NEXT)]=='00013fd6'
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_writes','next_VM_call','protected_ranges'):assert row[key]==EXPECTED[key],key
    first,last=row['snapshots'];prior=old['snapshots'][-1]
    assert first['kind']=='before_VM_resume' and last['kind']=='before_next_VM_call'
    assert first['pc']==hex(START) and last['pc']==hex(NEXT)
    assert first['VM_cursor']=='0x10a1e0' and last['VM_cursor']=='0x10a208'
    assert first['VM_state_address']==last['VM_state_address']
    assert first['SP']==last['SP']==prior['SP'] and first['callee_saved_sha256']==last['callee_saved_sha256']==prior['callee_saved_sha256']
    assert first['packed_descriptor_sha256']==last['packed_descriptor_sha256']
    for x in row['snapshots']:
        assert x['live_regions_sha256']==first['live_regions_sha256'] and x['counter_u32']==prior['counter_u32']==2
        assert x['payload_length']==36 and x['payload_including_NUL_sha256']==prior['payload_including_NUL_sha256']
        assert x['output']==prior['output'] and x['cache']==prior['cache']
        assert x['cache_mutex_state_u16']==prior['cache_mutex_state_u16']==0 and x['diagnostic']==prior['diagnostic'] and x['errno']==prior['errno']==2
        assert set(x['registers'])=={'x0','x30'}
    call=row['next_VM_call']
    assert call['index']==row['instruction_observations'] and call['callsite_offset']==hex(NEXT) and call['VM_cursor_offset']==last['VM_cursor']
    assert call['descriptor_address']==last['registers']['x0'] and call['descriptor_width']==48
    assert call['wrapper_offset']==hex(NEXT_WRAPPER)=='0x288508' and call['target_offset']==hex(NEXT_TARGET)=='0x32a1f0'
    assert call['allocation_request_size']==24 and call['static_expected_target_arguments']=={'x0':'0x18'}
    assert call['result_slot_address']==hex(int(call['descriptor_address'],16)+16)
    assert call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert len(bytes.fromhex(call['wrapper_code_hex']))==WRAPPER_SIZE==28 and raw_hash(bytes.fromhex(call['wrapper_code_hex']))==call['wrapper_code_sha256']
    assert call['VM_call_executed'] is call['wrapper_executed'] is call['target_executed'] is False
    assert 'descriptor_hex' not in call
    assert all(set(w)=={'index','PC','address','size'} for w in row['native_writes'])
    assert row['new_allocator_events']==row['protected_write_events']==[]
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value==old[key],key
    assert row['stop_boundary']==stop_boundary()

def damaged_evidence_rejected(data):
    changes=[(('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('providers','new_providers'),['hidden']),(('source_fingerprints','owners','oracle'),'0'*64),
        (('case_result','retained_publication','case_result_sha256'),'0'*64),(('case_result','instruction_observations'),0),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'counter_u32'),1),(('case_result','snapshots',-1,'live_regions_sha256'),'0'*64),
        (('case_result','snapshots',-1,'payload_including_NUL_sha256'),'0'*64),(('case_result','snapshots',-1,'cache_mutex_state_u16'),1),
        (('case_result','snapshots',-1,'VM_cursor'),'0x0'),(('case_result','snapshots',-1,'packed_descriptor_sha256'),'0'*64),
        (('case_result','native_writes',0,'size'),99),(('case_result','next_VM_call','allocation_request_size'),0),
        (('case_result','next_VM_call','result_slot_address'),'0x0'),(('case_result','next_VM_call','descriptor_sha256'),'0'*64),
        (('case_result','next_VM_call','wrapper_code_sha256'),'0'*64),(('case_result','next_VM_call','target_offset'),'0x0'),
        (('case_result','next_VM_call','target_executed'),True),(('case_result','next_VM_call','descriptor_hex'),'omitted'),
        (('case_result','new_allocator_events'),[['hidden']]),(('case_result','protected_write_events'),['hidden']),
        (('case_result','stop_boundary','VM_call_executed'),True),(('case_result','raw_identifier'),'omitted'),(('raw_identifier',),'omitted'),
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
        raise AssertionError(f'damaged post-identifier evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh post-identifier replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),damaged_evidence_rejected=rejected,
        instruction_observations=data['case_result']['instruction_observations'],original_VM_resumption_executed=True,next_VM_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
