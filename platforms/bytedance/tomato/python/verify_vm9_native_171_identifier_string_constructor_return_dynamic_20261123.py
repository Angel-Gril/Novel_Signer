"""Verify original identifier StringObject allocation and construction."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_identifier_formatter_return_dynamic_20261122 as previous
import verify_vm9_request_environment_strings_fresh_20261014 as controls
import vm9_objects as objects
import verify_vm9_signer_objects as oracle

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_identifier_string_constructor_return_dynamic_20261123.json')
SCHEMA='vm9-native-171-identifier-string-constructor-return-dynamic-20261123-v1'
LIBC_BASE,MALLOC=0x51000000,0x1BB08
START,CONSTRUCTOR,RETURN,NEXT,NEXT_TARGET=0x25BD24,0x248344,0x25BD34,0x25BD3C,0x1625A4
MAX_OBSERVATIONS=50000
sha256,digest,raw_hash=previous.sha256,previous.digest,previous.raw_hash
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes')
CODE_RANGES={'main': ((2473252, 28), (3318256, 68), (2392900, 156), (1451428, 16), (3440592, 16), (3440448, 16), (3440480, 16)), 'libc': ((113416, 32),)}
CODE_SHA256={'main:0x25bd24': '8171348a13d185630c04c227703397b58fd0aa5cd02ab3576cd569f53ea02f30', 'main:0x32a1f0': '1285abf973bc20a918e0476d0a8132f5085bf3666e7f62356aff3d69c76ccfe0', 'main:0x248344': 'f73af655d3e97f1da0d870dfaaea43bae7a33fc3403a4a26cfab43eb0e0559fd', 'main:0x1625a4': '7911a034e6c0161335f6891aad482181ffe2472ec5b7ee91a1bacb9573274d71', 'main:0x347fd0': 'f7210f98cdcb754c8f40d20e499862fbab2829c0adcf5049a2e6cc32828bd14f', 'main:0x347f40': '0c940edd920e96a815c4a27cb192f85cd71669b4b6ef24ad5c59847f8e01a519', 'main:0x347f60': '950f6abcd90eaa3ea396832bc983169e0f22002b7aeba21b76c3b4be76a87748', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36'}
EXPECTED={'instruction_observations': 295, 'instruction_trace_sha256': 'd2546592e15134ea1308db6e91cc16b87f61f57e8e7ce2ae9e1119bcbbceadd5', 'observed_code_sha256': 'a4f896de5ba1c59937e9a585f3b2c18f8021086adc6e40853b745505e9669e95', 'snapshots': [{'kind': 'new24_BL', 'index': 1, 'pc': 'main:0x25bd24', 'SP': '0x7004b850', 'registers': {'x0': '0x18', 'x30': '0x1251bd20'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2}, {'kind': 'new_entry', 'index': 2, 'pc': 'main:0x32a1f0', 'SP': '0x7004b850', 'registers': {'x0': '0x18', 'x30': '0x1251bd28'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2}, {'kind': 'new24_return', 'index': 139, 'pc': 'main:0x25bd28', 'SP': '0x7004b850', 'registers': {'x0': '0x136d9640', 'x30': '0x1251bd28'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc'}, {'kind': 'constructor_BL', 'index': 141, 'pc': 'main:0x25bd30', 'SP': '0x7004b850', 'registers': {'x0': '0x136d9640', 'x30': '0x1251bd28'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc'}, {'kind': 'constructor_entry', 'index': 142, 'pc': 'main:0x248344', 'SP': '0x7004b850', 'registers': {'x0': '0x136d9640', 'x30': '0x1251bd34'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': '9d908ecfb6b256def8b49a7c504e6c889c4b0e41fe6ce3e01863dd7b61a20aa0', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc'}, {'kind': 'strlen_return', 'index': 155, 'pc': 'main:0x248374', 'SP': '0x7004b820', 'registers': {'x0': '0x24', 'x30': '0x12508374'}, 'callee_saved_sha256': 'a7ba8b9548ab142a67b82519d9408fd1cfe6254df3fd3cbd83fd1e8100a682fb', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': 'd70590c0d670892681b0c5bc72ecd906c728be9aec8354cd0e797c345959f1ff', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc'}, {'kind': 'payload_allocation_return', 'index': 284, 'pc': 'main:0x248388', 'SP': '0x7004b820', 'registers': {'x0': '0x136d4050', 'x30': '0x12508388'}, 'callee_saved_sha256': '8c583d35e3dc3cbad301e6020d38040d874537377352ffe4fedea33a99c55c9e', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': 'bcf8dc17086fd74ea72e13684e5188ad894e2244330dd5c89cd344af3d58c330', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc'}, {'kind': 'constructor_return', 'index': 293, 'pc': 'main:0x25bd34', 'SP': '0x7004b850', 'registers': {'x0': '0x136d4050', 'x30': '0x1251bd34'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': 'b02120cb78d7b74468f7d5a908926b342962afa19c9a024697335d85f797a648', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'vtable': '0x1260f5f8', 'capacity': 37, 'length': 36, 'payload_address': '0x136d4050', 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'payload_matches_source': True, 'SP_restored': True, 'callee_saved_restored': True}, {'kind': 'before_reference_BL', 'index': 295, 'pc': 'main:0x25bd3c', 'SP': '0x7004b850', 'registers': {'x0': '0x7004b8c0', 'x30': '0x1251bd34'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'source_address': '0x7004b850', 'source_length': 36, 'source_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'source_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'protected_regions_sha256': 'e69f111eefa34e10bb928dad2012f05dbd44b6091e34daff3d1aa9f2af6bbee2', 'errno': 2, 'object_address': '0x136d9640', 'object_24_sha256': 'b02120cb78d7b74468f7d5a908926b342962afa19c9a024697335d85f797a648', 'object_neighbor_8_sha256': 'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc', 'vtable': '0x1260f5f8', 'capacity': 37, 'length': 36, 'payload_address': '0x136d4050', 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'payload_matches_source': True, 'SP_restored': True, 'callee_saved_restored': True}], 'native_writes': [{'index': 149, 'PC': '0x248360', 'address': '0x136d9640', 'size': 8}, {'index': 157, 'PC': '0x24837c', 'address': '0x136d9648', 'size': 4}, {'index': 157, 'PC': '0x24837c', 'address': '0x136d964c', 'size': 4}, {'index': 284, 'PC': '0x248388', 'address': '0x136d9650', 'size': 8}], 'services': [{'kind': 'actual_Bionic_malloc_route', 'index': 10, 'PC': '0x347fd0', 'request': 24}, {'kind': 'actual_Bionic_malloc_entry', 'index': 11, 'PC': 'libc:0x1bb08', 'request': 24}, {'kind': 'inherited_strlen', 'index': 154, 'PC': '0x347f40', 'source': '0x7004b850'}, {'kind': 'actual_Bionic_malloc_route', 'index': 160, 'PC': '0x347fd0', 'request': 37}, {'kind': 'actual_Bionic_malloc_entry', 'index': 161, 'PC': 'libc:0x1bb08', 'request': 37}, {'kind': 'inherited_memcpy', 'index': 292, 'PC': '0x347f60', 'target': '0x136d4050', 'source': '0x7004b850', 'size': 37, 'original_Bionic_body_executed': False}], 'copy_provider_effects': [{'index': 292, 'PC': '0x347f60', 'address': '0x136d4050', 'size': 37, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'observer_timing': 'after inherited host write', 'original_Bionic_body_executed': False}], 'protected_ranges': [{'address': '0x7004d118', 'size': 24}, {'address': '0x136d82c0', 'size': 8}, {'address': '0x7004d130', 'size': 24}, {'address': '0x136d82d0', 'size': 8}, {'address': '0x7004d148', 'size': 24}, {'address': '0x136d82d8', 'size': 8}, {'address': '0x7004cbe8', 'size': 48}, {'address': '0x136d4020', 'size': 48}, {'address': '0x136d73a0', 'size': 16}, {'address': '0x7004d178', 'size': 16}, {'address': '0x1269e700', 'size': 64}, {'address': '0x1269e450', 'size': 128}, {'address': '0x7004b850', 'size': 64}, {'address': '0x7000a010', 'size': 4}], 'new_allocator_events': [['alloc', 24, 325948992, '0x32a210'], ['alloc', 37, 325926992, '0x248388']], 'ledgers': {'allocator_counts': {'malloc': 587, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'kind': 'construct', 'case': 'normal', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'kind': 'construct', 'case': 'empty', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'kind': 'construct', 'case': 'NULL_source', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'kind': 'construct', 'case': 'allocation_failure', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'kind': 'construct', 'case': 'cross_page_object', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'kind': 'construct', 'case': 'embedded_NUL', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'kind': 'construct', 'case': 'normal', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'kind': 'construct', 'case': 'empty', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'kind': 'construct', 'case': 'NULL_source', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'kind': 'construct', 'case': 'allocation_failure', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'kind': 'construct', 'case': 'cross_page_object', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x775c205000', 'kind': 'construct', 'case': 'embedded_NUL', 'actual_wrapper': '0x205064', 'original_wrapper_returned': True, 'all_declared_guest_bytes_and_packed_padding_equal': True, 'allocation_requests_and_free_calls_equal': True, 'native_snapshot_input': False}, {'image_base': '0x122c0000', 'case': 'operator_new24', 'original_wrapper_returned': True, 'explicit_synthetic_allocator': True, 'request_and_result_equal': True, 'declared_guest_payload_unchanged': True, 'SP_and_callee_saved_restored': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'operator_new24', 'original_wrapper_returned': True, 'explicit_synthetic_allocator': True, 'request_and_result_equal': True, 'declared_guest_payload_unchanged': True, 'SP_and_callee_saved_restored': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}]
ROLLBACK_SPECS=[{'case': 'wrong_target', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'wrong_wrapper', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_packed', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_object', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_source', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'source_bound', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'allocator_late_failure', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'free_late_failure', 'rejected': True, 'all_pages_unchanged': True}, {'case': 'missing_empty_descriptor', 'rejected': True, 'all_pages_unchanged': True}]

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,fixture=controls,string_model=objects,callback_model=controls.model,oracle=oracle)
    return dict(constructor_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        allocator='inherited matching original Bionic malloc route; both entries observed',
        strlen_memcpy='inherited host providers; original Bionic strlen/memcpy bodies do not execute',
        component_allocator='explicit synthetic malloc for fresh independent controls only',
        exported_output='lengths, hashes and write locations only; no raw identifier, seed or per-byte write values',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',formatter_prefix_revalidated=True,original_new24_returned=True,
        original_string_constructor_returned=True,two_matching_Bionic_malloc_entries_observed=True,
        inherited_strlen_memcpy_providers_used=True,payload_including_NUL_matches_formatter=True,
        object_header_and_native_store_widths_verified=True,SP_and_callee_saved_restored=True,
        prior_objects_descriptor_cache_output_and_errno_write_protected=True,
        next_reference_call_executed=False,current_identifier_callback_returned=False,current_identifier_published=False,
        original_Bionic_strlen_memcpy_bodies_executed=False,new_providers_added=False,
        native_snapshot_used_as_python_model_input=False,complete_VM_suffix_return_verified=False,
        complete_standalone_signer_verified=False,real_ART_JVM_execution=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def read_static(path,libc):
    rows={}
    for domain,sample in (('main',path),('libc',libc)):
        with sample.open('rb') as f:
            elf=ELFFile(f)
            if domain=='libc':assert [(s['st_value'],s['st_size']) for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='malloc']==[(MALLOC,32)]
            for off,size in CODE_RANGES[domain]:
                segment=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=off and off+size<=s['p_vaddr']+s['p_filesz'])
                f.seek(segment['p_offset']+off-segment['p_vaddr']);raw=f.read(size);assert len(raw)==size
                rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows
PROFILES=('normal','empty','NULL_source','allocation_failure','cross_page_object','embedded_NUL')

def new_control(path,base):
    pages=oracle.image_pages(path,base);pages.update(oracle.fresh_pages())
    pointer=oracle.GUEST+0x4000;requests=[]
    saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x770000+n for n in range(19,30)}
    before=controls._read_span(pages,oracle.GUEST,0xA000)
    def allocate(cpu,size):requests.append(size);return pointer
    result,memory,allocations,ledger=oracle.native(path,base,0x32A1F0,[24],pages,
        malloc_handler=allocate,extra_registers=saved,instruction_limit=1000,
        instruction_observer=lambda cpu,pc: check_return(cpu,saved) if pc==base+0x32A230 else None)
    actual=[]
    def model_allocate(p,size):actual.append(size);return pointer
    assert objects._allocate(pages,model_allocate,24)==result==pointer
    assert requests==actual==[24] and memory==before and allocations==ledger==[]
    return dict(image_base=hex(base),case='operator_new24',original_wrapper_returned=True,
        explicit_synthetic_allocator=True,request_and_result_equal=True,declared_guest_payload_unchanged=True,
        SP_and_callee_saved_restored=True,native_snapshot_input=False,physical_PAC_compared=False)

def check_return(cpu,saved):
    assert cpu.reg_read(arm.UC_ARM64_REG_SP)==oracle.GUEST+0xEF00
    assert all(cpu.reg_read(r)==v for r,v in saved.items())


def independent_controls(path):
    rows=[controls.compare(path,base,'construct',label) for base in controls.BASES for label in PROFILES]
    rows.extend(new_control(path,base) for base in controls.BASES)
    guards=controls.guards(path)
    assert rows==CONTROL_SPECS and guards==ROLLBACK_SPECS
    return rows,guards

class IdentifierStringConstructorScenario(previous.IdentifierFormatterScenario):
    def __init__(self,control):
        super().__init__(control)
        self._idctor_active=False;self._idctor_done=False;self._idctor_returned=False
        self._idctor_count=0;self._idctor_trace=[];self._idctor_code={}
        self._idctor_rows=[];self._idctor_writes=[];self._idctor_services=[];self._idctor_copies=[]
        self._idctor_object=0;self._idctor_payload=0

    def _idctor_track(self,cpu,pc):
        self._idctor_count+=1;assert self._idctor_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._idctor_trace.append(key);self._idctor_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _idctor_protected_hash(self,cpu):
        h=hashlib.sha256()
        for address,width in self._idctor_protected:
            h.update(address.to_bytes(8,'little')+width.to_bytes(8,'little')+bytes(cpu.mem_read(address,width)))
        return h.hexdigest()

    def _idctor_saved_hash(self,cpu):
        return raw_hash(b''.join(self._reg(cpu,n).to_bytes(8,'little') for n in range(19,30)))

    def _idctor_snapshot(self,cpu,pc,kind):
        assert self._idctor_protected_hash(cpu)==self._idctor_initial_protected
        row=dict(kind=kind,index=self._idctor_count,pc=('libc:' if LIBC_BASE<=pc<LIBC_BASE+0x200000 else 'main:')+hex(pc-LIBC_BASE if LIBC_BASE<=pc<LIBC_BASE+0x200000 else pc-self.image),
            SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),registers={f'x{n}':hex(self._reg(cpu,n)) for n in (0,30)},
            callee_saved_sha256=self._idctor_saved_hash(cpu),source_address=hex(self._idctor_source),source_length=36,
            source_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_source,37))),
            source_window_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_source,64))),
            protected_regions_sha256=self._idctor_protected_hash(cpu),errno=self._u(cpu,self._seedfail_errno,4))
        if self._idctor_object:
            row.update(object_address=hex(self._idctor_object),object_24_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_object,24))),
                object_neighbor_8_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_object+24,8))))
        if kind in ('constructor_return','before_reference_BL'):
            row.update(vtable=hex(self._u(cpu,self._idctor_object)),capacity=self._u(cpu,self._idctor_object+8,4),
                length=self._u(cpu,self._idctor_object+12,4),payload_address=hex(self._u(cpu,self._idctor_object+16)),
                payload_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_payload,37))),
                payload_matches_source=bytes(cpu.mem_read(self._idctor_payload,37))==self._idctor_source_bytes,
                SP_restored=cpu.reg_read(arm.UC_ARM64_REG_SP)==self._idctor_sp,
                callee_saved_restored=self._idctor_saved_hash(cpu)==self._idctor_constructor_saved)
        self._idctor_rows.append(row)

    def _idctor_start(self,cpu,pc,state):
        self._idfmt_track(cpu,pc);self._idfmt_snapshot(cpu,pc,'before_new24_BL')
        old=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(old);old=old['case_result']
        h=hashlib.sha256()
        for key in self._idfmt_trace:h.update(key.encode()+bytes.fromhex(self._idfmt_code[key]))
        for value,key in ((self._idfmt_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),
            (digest(self._idfmt_code),'observed_code_sha256'),(self._idfmt_trace,'observation_sites'),(self._idfmt_code,'observed_code'),
            (self._idfmt_rows,'snapshots'),(self._idfmt_writes,'native_writes')):assert value==old[key],key
        self._idctor_old=old;self._idctor_events=deepcopy(state['allocator_events_ref'])
        assert self._idctor_events==self._idfmt_events
        self._idctor_source=self._idfmt_output;self._idctor_source_bytes=bytes(cpu.mem_read(self._idctor_source,37))
        assert len(self._idctor_source_bytes.split(b'\0',1)[0])==36
        assert raw_hash(self._idctor_source_bytes)==old['snapshots'][-1]['payload_including_NUL_sha256']
        self._idctor_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._idctor_protected=self._idopen_ranges+[(self._idopen_descriptor,48),(self._seedfail_mutex,48),(self._seedfail_pair,16),
            (self._idopen_output,16),(self.image+0x3DE700,64),(self.image+0x3DE450,128),(self._idctor_source,64),(self._seedfail_errno,4)]
        self._idctor_initial_protected=self._idctor_protected_hash(cpu)
        self._idfmt_active=False;self._idfmt_done=False;self._idctor_active=True
        self._idctor_track(cpu,pc);self._idctor_snapshot(cpu,pc,'new24_BL')

    def native_runner(self,*args,**kwargs):
        assert kwargs.get('real_malloc') is True and not kwargs.get('malloc_handler')
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._idctor_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image
                if any(address<a+n and a<address+size for a,n in self._idctor_protected):raise AssertionError('identifier constructor wrote protected state')
                if self._idctor_object and address<self._idctor_object+24 and self._idctor_object<address+size:
                    self._idctor_writes.append(dict(index=self._idctor_count,PC=hex(pc),address=hex(address),size=size))
                if pc==0x347F60:
                    assert (address,size)==(self._idctor_payload,37)
                    raw=bytes(cpu.mem_read(address,size));assert raw==self._idctor_source_bytes
                    self._idctor_copies.append(dict(index=self._idctor_count,PC=hex(pc),address=hex(address),size=size,
                        payload_including_NUL_sha256=raw_hash(raw),observer_timing='after inherited host write',original_Bionic_body_executed=False))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._idctor_active:
            if self._idfmt_active and pc==self.image+START:
                self._idctor_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._idctor_track(cpu,pc);off=pc-self.image
        if off==0x25BD28:
            self._idctor_object=self._reg(cpu,0);assert self._idctor_object
            self._idctor_neighbor=bytes(cpu.mem_read(self._idctor_object+24,8))
            self._idctor_snapshot(cpu,pc,'new24_return')
        if off==0x25BD30:
            assert (self._reg(cpu,0),self._reg(cpu,1))==(self._idctor_object,self._idctor_source)
            self._idctor_constructor_saved=self._idctor_saved_hash(cpu);self._idctor_snapshot(cpu,pc,'constructor_BL')
        if off in (0x32A1F0,CONSTRUCTOR):self._idctor_snapshot(cpu,pc,'new_entry' if off==0x32A1F0 else 'constructor_entry')
        if off==0x347F40:
            assert self._reg(cpu,0)==self._idctor_source
            self._idctor_services.append(dict(kind='inherited_strlen',index=self._idctor_count,PC=hex(off),source=hex(self._idctor_source)))
        if off==0x248374:
            assert self._reg(cpu,0)==36;self._idctor_snapshot(cpu,pc,'strlen_return')
        if off==0x347FD0:
            self._idctor_services.append(dict(kind='actual_Bionic_malloc_route',index=self._idctor_count,PC=hex(off),request=self._reg(cpu,0)))
        if pc==LIBC_BASE+MALLOC:
            self._idctor_services.append(dict(kind='actual_Bionic_malloc_entry',index=self._idctor_count,PC='libc:'+hex(MALLOC),request=self._reg(cpu,0)))
        if off==0x248388:
            self._idctor_payload=self._reg(cpu,0);assert self._idctor_payload
            self._idctor_snapshot(cpu,pc,'payload_allocation_return')
        if off==0x347F60:
            assert [self._reg(cpu,n) for n in range(3)]==[self._idctor_payload,self._idctor_source,37]
            self._idctor_services.append(dict(kind='inherited_memcpy',index=self._idctor_count,PC=hex(off),target=hex(self._idctor_payload),source=hex(self._idctor_source),size=37,original_Bionic_body_executed=False))
        if off==RETURN:
            assert self._reg(cpu,0)==self._idctor_payload
            self._idctor_snapshot(cpu,pc,'constructor_return');self._idctor_returned=True
        if off==NEXT:
            assert self._idctor_returned
            assert self._reg(cpu,0)==self._reg(cpu,19) and self._reg(cpu,1)==self._idctor_object
            self._idctor_snapshot(cpu,pc,'before_reference_BL');self._idctor_done=True
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._idctor_done and self._idctor_returned
        h=hashlib.sha256()
        for key in self._idctor_trace:h.update(key.encode()+bytes.fromhex(self._idctor_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        for key,value in ledgers.items():
            if key!='allocator_counts':assert value==self._idctor_old[key],key
        counts=deepcopy(self._idctor_old['allocator_counts']);counts['malloc']+=2
        assert ledgers['allocator_counts']==counts
        assert result['allocator_events'][:len(self._idctor_events)]==self._idctor_events
        events=result['allocator_events'][len(self._idctor_events):]
        assert events==[['alloc',24,self._idctor_object,'0x32a210'],['alloc',37,self._idctor_payload,'0x248388']]
        return dict(control=self._idctor_old['control'],retained_formatter=dict(case_result_sha256=digest(self._idctor_old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._idctor_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._idctor_code),
            snapshots=self._idctor_rows,native_writes=self._idctor_writes,services=self._idctor_services,copy_provider_effects=self._idctor_copies,
            observation_sites=self._idctor_trace,observed_code=self._idctor_code,new_allocator_events=events,**ledgers,
            protected_ranges=[dict(address=hex(a),size=n) for a,n in self._idctor_protected],protected_write_events=[],
            stop_boundary=dict(kind='before_identifier_reference_BL',stop_before=hex(NEXT),target=hex(NEXT_TARGET),call_executed=False,target_executed=False))

def run(path,libc):
    parent=prior_evidence();p=previous.previous.previous.previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=IdentifierStringConstructorScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    components,guards=independent_controls(path)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),
        static_code=code,native_controls=components,component_rollback_checks=guards,case_result=rows[0],case_result_sha256=digest(rows[0]))

def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_controls']==CONTROL_SPECS and len(CONTROL_SPECS)==14
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==9
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_formatter']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[0]=='main:'+hex(START) and sites[-1]=='main:'+hex(NEXT)
    for key,count in (('main:0x32a1f0',1),('main:'+hex(CONSTRUCTOR),1),('main:0x347fd0',2),('libc:'+hex(MALLOC),2),('main:0x347f40',1),('main:0x347f60',1),('main:'+hex(RETURN),1)):
        assert sites.count(key)==count,(key,count)
    assert 'main:0x1625a4' not in sites
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4');h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256']
    assert digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_writes','services','copy_provider_effects','new_allocator_events','protected_ranges'):
        assert row[key]==EXPECTED[key],key
    first=row['snapshots'][0];allocated=next(x for x in row['snapshots'] if x['kind']=='new24_return')
    call=next(x for x in row['snapshots'] if x['kind']=='constructor_BL');returned=next(x for x in row['snapshots'] if x['kind']=='constructor_return');stop=row['snapshots'][-1]
    assert first['kind']=='new24_BL' and first['registers']['x0']=='0x18'
    assert stop['kind']=='before_reference_BL' and stop['pc']=='main:'+hex(NEXT)
    assert first['SP']==allocated['SP']==call['SP']==returned['SP']==stop['SP']
    assert first['callee_saved_sha256']==allocated['callee_saved_sha256']
    assert call['callee_saved_sha256']==returned['callee_saved_sha256']==stop['callee_saved_sha256']
    old_stop=old['snapshots'][-1]
    for x in row['snapshots']:
        assert x['source_address']==old_stop['output_address'] and x['source_length']==36
        assert x['source_including_NUL_sha256']==old_stop['payload_including_NUL_sha256']
        assert x['source_window_sha256']==old_stop['output_window_sha256'] and x['errno']==old_stop['errno']==2
        assert x['protected_regions_sha256']==first['protected_regions_sha256']
        assert set(x['registers'])=={'x0','x30'}
    for x in (returned,stop):
        assert x['capacity']==37 and x['length']==36 and x['vtable']==hex(row['control']['base']+0x34F5F8)
        assert x['payload_including_NUL_sha256']==x['source_including_NUL_sha256']
        assert x['payload_matches_source'] is x['SP_restored'] is x['callee_saved_restored'] is True
        assert x['object_address']==allocated['object_address'] and x['payload_address']==returned['registers']['x0']
    obj=int(returned['object_address'],16);payload=int(returned['payload_address'],16)
    assert [(x['PC'],int(x['address'],16)-obj,x['size']) for x in row['native_writes']]==[
        ('0x248360',0,8),('0x24837c',8,4),('0x24837c',12,4),('0x248388',16,8)]
    assert all(set(x)=={'index','PC','address','size'} for x in row['native_writes'])
    assert row['new_allocator_events']==[['alloc',24,obj,'0x32a210'],['alloc',37,payload,'0x248388']]
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=2
    assert row['allocator_counts']==counts
    for key,value in EXPECTED['ledgers'].items():
        assert row[key]==value,key
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['protected_write_events']==[]
    assert row['stop_boundary']==dict(kind='before_identifier_reference_BL',stop_before=hex(NEXT),target='0x1625a4',call_executed=False,target_executed=False)

def damaged_evidence_rejected(data):
    changes=[(('claims','next_reference_call_executed'),True),(('claims','current_identifier_published'),True),
        (('claims','complete_standalone_signer_verified'),True),(('providers','new_import_bindings'),['hidden']),
        (('source_fingerprints','owners','string_model'),'0'*64),(('case_result','retained_formatter','case_result_sha256'),'0'*64),
        (('case_result','instruction_observations'),0),(('case_result','instruction_trace_sha256'),'0'*64),
        (('case_result','observed_code_sha256'),'0'*64),(('case_result','snapshots',-1,'capacity'),0),
        (('case_result','snapshots',-1,'length'),0),(('case_result','snapshots',-1,'payload_matches_source'),False),
        (('case_result','snapshots',-1,'payload_including_NUL_sha256'),'0'*64),
        (('case_result','snapshots',-1,'protected_regions_sha256'),'0'*64),
        (('case_result','snapshots',-1,'SP_restored'),False),(('case_result','snapshots',-1,'callee_saved_restored'),False),
        (('case_result','native_writes',0,'size'),1),(('case_result','copy_provider_effects',0,'size'),36),
        (('case_result','copy_provider_effects',0,'original_Bionic_body_executed'),True),
        (('case_result','services',0,'request'),0),(('case_result','new_allocator_events'),[]),
        (('case_result','protected_write_events'),['hidden']),(('case_result','stop_boundary','call_executed'),True),
        (('native_controls',-1,'native_snapshot_input'),True),(('component_rollback_checks',0,'all_pages_unchanged'),False)]
    for key in EXPECTED['ledgers']:changes.append((('case_result',key),{}))
    for key in CODE_SHA256:changes.append((('static_code',key,'sha256'),'0'*64))
    for path,value in changes:
        bad=deepcopy(data);obj=bad
        for key in path[:-1]:obj=obj[key]
        obj[path[-1]]=value
        if path[0]=='case_result':bad['case_result_sha256']=digest(bad['case_result'])
        try:validate(bad)
        except (AssertionError,KeyError,ValueError,TypeError):continue
        raise AssertionError(f'damaged identifier constructor evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh identifier constructor replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),
        damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],
        original_string_constructor_returned=True,next_reference_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
