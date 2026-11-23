"""Verify the post-MD5 CRC wrapper, four-byte result and next VM call boundary."""
from __future__ import annotations
from pathlib import Path
from copy import deepcopy
import argparse,json,hashlib,binascii
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from vm9_allocator import _read_span,_write_span
import verify_vm9_native_171_post_pair_md5_return_dynamic_20261123 as previous
import verify_vm9_second_crc_fresh_20261015 as controls
import vm9_jni_followup as crc_owner
import vm9_objects as objects_owner
import vm9_allocator as allocator_owner
VM_CALL,VM_RESUME,WRAPPER,TARGET,CORE=0x16AA48,0x16AA4C,0x288820,0x258BAC,0x24B298
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_post_md5_crc_return_dynamic_20261123.json')
SCHEMA='vm9-native-171-post-md5-crc-return-dynamic-20261123-v1'
MAX_OBSERVATIONS=300000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
NEXT_WRAPPER,NEXT_TARGET,NEXT_WRAPPER_SIZE=2655536,2541656,16
PARENT_FIELDS=('MD5_arguments', 'MD5_computation', 'allocator_counts', 'allowed_table_slots', 'control', 'inherited_JNI_calls', 'inherited_libc_SVC', 'inherited_main_SVC', 'inherited_service_counts', 'inherited_syscall_172', 'inherited_syscall_173', 'instruction_observations', 'instruction_trace_sha256', 'java_dispatch', 'late_jni', 'native_writes', 'new_allocator_events', 'next_VM_call', 'observation_sites', 'observed_code', 'observed_code_sha256', 'protected_ranges', 'protected_write_events', 'protection_activation', 'reference_events', 'retained_pair', 'scope_events', 'services', 'snapshots', 'stop_boundary')
CODE_RANGES={'main': ((1485384, 32), (2656288, 28), (2460588, 32), (2405016, 60), (2655536, 16), (2541656, 32)), 'libc': ()}
CODE_SHA256={'main:0x16aa48': 'c53f89ea694ed64ca8b5270d014ecf3bbd4777260ee7edee83a2e8e70b25178f', 'main:0x288820': '9008864fc0873b88fe474d250ec4c0d05d7028e7eef484c94ec234851d3bae61', 'main:0x258bac': '0a64e4bef9d390aa0d21cce669e7e909675fe875264198e51fe5fa53fe176d78', 'main:0x24b298': 'bbbb834211e2236f96d8b4d28739624ba505f24ddcde0683c5f9977c179348f3', 'main:0x288530': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af', 'main:0x26c858': '5a03c035e8f0323f26ad1fe602b4089b25781755ec0c4ee1465e908556d0103a'}
EXPECTED={'instruction_observations': 1206, 'instruction_trace_sha256': 'de2da77d1ec205e54610b6f99dad004b742214f22aa0762c6f35a3274018393d', 'observed_code_sha256': 'f56431a1a8ccd00bfc06139cf8a2462255d08f81b10bf6947176d50fb10450f6', 'snapshots': [{'kind': 'CRC_VM_call', 'index': 1, 'pc': 'main:0x16aa48', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': 'a1fe0936e636685c45064ad73b30ac90ca8f9e8279b1d87410f256b3a5cbdcf8', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': '1003bbf47f63fe89a957ab3802f01a91a701fdb6ec5292d7f3bc361c2d452dce', 'output_ready': False, 'output_matches_same_run_input': None, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'wrapper_entry', 'index': 2, 'pc': 'main:0x288820', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': 'a1fe0936e636685c45064ad73b30ac90ca8f9e8279b1d87410f256b3a5cbdcf8', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': '1003bbf47f63fe89a957ab3802f01a91a701fdb6ec5292d7f3bc361c2d452dce', 'output_ready': False, 'output_matches_same_run_input': None, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'CRC_object_entry', 'index': 6, 'pc': 'main:0x258bac', 'SP': '0x7004b920', 'callee_saved_sha256': '094eb87fef54f4f7bb6d0a5a0285796b6353d4ed9c01517d7396859921fbf69b', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': 'a1fe0936e636685c45064ad73b30ac90ca8f9e8279b1d87410f256b3a5cbdcf8', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': '1003bbf47f63fe89a957ab3802f01a91a701fdb6ec5292d7f3bc361c2d452dce', 'output_ready': False, 'output_matches_same_run_input': None, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'CRC_buffer_entry', 'index': 12, 'pc': 'main:0x24b298', 'SP': '0x7004b910', 'callee_saved_sha256': '66b814977cb3893db5fbe548f271a471900b4687a09eb381a14f2fe3717f71dc', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': 'a1fe0936e636685c45064ad73b30ac90ca8f9e8279b1d87410f256b3a5cbdcf8', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': '1003bbf47f63fe89a957ab3802f01a91a701fdb6ec5292d7f3bc361c2d452dce', 'output_ready': False, 'output_matches_same_run_input': None, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'CRC_buffer_return', 'index': 244, 'pc': 'main:0x258bc4', 'SP': '0x7004b910', 'callee_saved_sha256': '66b814977cb3893db5fbe548f271a471900b4687a09eb381a14f2fe3717f71dc', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': 'a1fe0936e636685c45064ad73b30ac90ca8f9e8279b1d87410f256b3a5cbdcf8', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': '1003bbf47f63fe89a957ab3802f01a91a701fdb6ec5292d7f3bc361c2d452dce', 'output_ready': False, 'output_matches_same_run_input': None, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'CRC_output_store_complete', 'index': 247, 'pc': 'main:0x288834', 'SP': '0x7004b920', 'callee_saved_sha256': '094eb87fef54f4f7bb6d0a5a0285796b6353d4ed9c01517d7396859921fbf69b', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': '765853e9d612b6fc4de6c683def5fd1f5ab2a91187f375b0750ee828a451faf3', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': 'ea0d1a74831bf5e694a46de25597afd27ac03b0af5ccad56878cceaf0268e2cf', 'output_ready': True, 'output_matches_same_run_input': True, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'CRC_callback_return', 'index': 249, 'pc': 'main:0x16aa4c', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a348', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': '765853e9d612b6fc4de6c683def5fd1f5ab2a91187f375b0750ee828a451faf3', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': 'ea0d1a74831bf5e694a46de25597afd27ac03b0af5ccad56878cceaf0268e2cf', 'output_ready': True, 'output_matches_same_run_input': True, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}, {'kind': 'before_next_VM_call', 'index': 1206, 'pc': 'main:0x16aa48', 'SP': '0x7004b930', 'callee_saved_sha256': '1dfcf39e697485c9789eaf1f5667782d682043ac2a66bc54fafb8587c49e2af9', 'VM_state_address': '0x7004d360', 'VM_cursor': '0x10a37c', 'descriptor_address': '0x7004ca60', 'descriptor_width': 48, 'descriptor_sha256': '765853e9d612b6fc4de6c683def5fd1f5ab2a91187f375b0750ee828a451faf3', 'descriptor_input_16_sha256': '091dee6522d5889cb5598b1dfb51afb25cfab155f3013a4c0a97e03c6f5a6da8', 'descriptor_tail_28_sha256': '179207a48df8f16998e20998c79fd4f9c5a4d50651ee6f044d7863acf91e3c3c', 'output_storage_address': '0x7004ca70', 'output_storage_width': 4, 'output_storage_sha256': 'ea0d1a74831bf5e694a46de25597afd27ac03b0af5ccad56878cceaf0268e2cf', 'output_ready': True, 'output_matches_same_run_input': True, 'source_object': {'address': '0x136d9680', 'vtable_offset': '0x34f5f8', 'capacity_u32': 64, 'length_u32': 32, 'payload_address': '0x136df180', 'object_sha256': 'bd2d35a617d5bcce54289adc20929fbfa3e09316365e137f19b40d4ac8887d5e', 'payload_capacity_sha256': '7513888cc4a40a0449d79066eb93dc73cc260d05d8d8b5547e9063b112331c6f', 'payload_including_NUL_sha256': '91e3018bc20bf0f238e076bd003954c87c92fd2d431c01ef7195a8a63844c8aa', 'payload_terminated': True, 'payload_tail_sha256': '91c4c905d78fb2612445e8efe91847577ec1714bfc8f91392b11e72a8c3f3556'}, 'protected_regions_sha256': 'de1eef8759bafb0b2e0d7ec1059a514b3b6df0d9fecb6c00620d286568d474e7', 'registers': {}}], 'native_writes': [{'index': 2, 'PC': 'main:0x288820', 'address': '0x7004b920', 'size': 8}, {'index': 2, 'PC': 'main:0x288820', 'address': '0x7004b928', 'size': 8}, {'index': 6, 'PC': 'main:0x258bac', 'address': '0x7004b910', 'size': 8}, {'index': 6, 'PC': 'main:0x258bac', 'address': '0x7004b918', 'size': 8}, {'index': 246, 'PC': 'main:0x288830', 'address': '0x7004ca70', 'size': 4}, {'index': 281, 'PC': 'main:0x16a9f0', 'address': '0x7004d360', 'size': 8}, {'index': 348, 'PC': 'main:0x16d89c', 'address': '0x7004b9a0', 'size': 4}, {'index': 350, 'PC': 'main:0x16d8a4', 'address': '0x7004d380', 'size': 8}, {'index': 355, 'PC': 'main:0x16d8b8', 'address': '0x7004d360', 'size': 8}, {'index': 367, 'PC': 'main:0x16d8e8', 'address': '0x7004b990', 'size': 4}, {'index': 368, 'PC': 'main:0x16d8ec', 'address': '0x7004b960', 'size': 2}, {'index': 407, 'PC': 'main:0x1702fc', 'address': '0x7004b950', 'size': 4}, {'index': 408, 'PC': 'main:0x170300', 'address': '0x7004b990', 'size': 4}, {'index': 409, 'PC': 'main:0x170304', 'address': '0x7004b9b0', 'size': 2}, {'index': 411, 'PC': 'main:0x17030c', 'address': '0x7004d370', 'size': 8}, {'index': 413, 'PC': 'main:0x170314', 'address': '0x7004d360', 'size': 8}, {'index': 477, 'PC': 'main:0x17203c', 'address': '0x7004b990', 'size': 4}, {'index': 479, 'PC': 'main:0x172044', 'address': '0x7004b950', 'size': 4}, {'index': 483, 'PC': 'main:0x172054', 'address': '0x7004b9b0', 'size': 2}, {'index': 497, 'PC': 'main:0x17208c', 'address': '0x7004c068', 'size': 4}, {'index': 502, 'PC': 'main:0x1720a0', 'address': '0x7004d360', 'size': 8}, {'index': 552, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 555, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 556, 'PC': 'main:0x16f974', 'address': '0x7004d370', 'size': 8}, {'index': 558, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 571, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 606, 'PC': 'main:0x16f964', 'address': '0x7004b950', 'size': 4}, {'index': 609, 'PC': 'main:0x16f970', 'address': '0x7004b990', 'size': 4}, {'index': 610, 'PC': 'main:0x16f974', 'address': '0x7004d378', 'size': 8}, {'index': 612, 'PC': 'main:0x16f97c', 'address': '0x7004d360', 'size': 8}, {'index': 625, 'PC': 'main:0x16f9b0', 'address': '0x7004b9b0', 'size': 2}, {'index': 649, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 703, 'PC': 'main:0x171268', 'address': '0x7004cd90', 'size': 8}, {'index': 719, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 720, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 725, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 749, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 803, 'PC': 'main:0x171268', 'address': '0x7004c448', 'size': 8}, {'index': 819, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 820, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 825, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 849, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 903, 'PC': 'main:0x171268', 'address': '0x7004cd88', 'size': 8}, {'index': 919, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 920, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 925, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 949, 'PC': 'main:0x171190', 'address': '0x7004d360', 'size': 8}, {'index': 1003, 'PC': 'main:0x171268', 'address': '0x7004cd80', 'size': 8}, {'index': 1019, 'PC': 'main:0x1712a8', 'address': '0x7004b950', 'size': 4}, {'index': 1020, 'PC': 'main:0x1712ac', 'address': '0x7004b990', 'size': 4}, {'index': 1025, 'PC': 'main:0x1712c0', 'address': '0x7004b9b0', 'size': 2}, {'index': 1047, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 1049, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 1050, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 1054, 'PC': 'main:0x16a5d8', 'address': '0x7004d388', 'size': 8}, {'index': 1057, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 1067, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 1089, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 1091, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 1092, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 1096, 'PC': 'main:0x16a5d8', 'address': '0x7004d390', 'size': 8}, {'index': 1099, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 1109, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 1131, 'PC': 'main:0x16a5bc', 'address': '0x7004b9a0', 'size': 4}, {'index': 1133, 'PC': 'main:0x16a5c4', 'address': '0x7004b990', 'size': 4}, {'index': 1134, 'PC': 'main:0x16a5c8', 'address': '0x7004b980', 'size': 4}, {'index': 1138, 'PC': 'main:0x16a5d8', 'address': '0x7004d430', 'size': 8}, {'index': 1141, 'PC': 'main:0x16a5e4', 'address': '0x7004d360', 'size': 8}, {'index': 1151, 'PC': 'main:0x16a60c', 'address': '0x7004b970', 'size': 4}, {'index': 1190, 'PC': 'main:0x16a93c', 'address': '0x7004b990', 'size': 4}, {'index': 1192, 'PC': 'main:0x16a944', 'address': '0x7004b9a0', 'size': 4}, {'index': 1193, 'PC': 'main:0x16a948', 'address': '0x7004b980', 'size': 4}, {'index': 1194, 'PC': 'main:0x16a94c', 'address': '0x7004b970', 'size': 4}, {'index': 1195, 'PC': 'main:0x16a950', 'address': '0x7004d460', 'size': 8}, {'index': 1201, 'PC': 'main:0x16aa34', 'address': '0x7004b9d0', 'size': 8}, {'index': 1201, 'PC': 'main:0x16aa34', 'address': '0x7004b9d8', 'size': 8}, {'index': 1203, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c0', 'size': 8}, {'index': 1203, 'PC': 'main:0x16aa3c', 'address': '0x7004b9c8', 'size': 8}], 'CRC_arguments': {'source_object_address': '0x136d9680', 'source_payload_address': '0x136df180', 'source_length_u32': 32, 'signed_length_i32': 32, 'consumed_length': 32, 'packed_output_address': '0x7004ca70', 'packed_output_width': 4, 'raw_input_and_CRC_exported': False}, 'guest_CRC_table': {'image_offset': '0x96144', 'size': 1024, 'entries': 256, 'sha256': '12f3e0576d447eb37b36d82ba0c1c5481b8f0d12fdc70347ce4a076b229d4c86', 'standard_reflected_table_matches': True, 'standard_polynomial': '0xedb88320', 'initial_u32': '0xffffffff', 'final_xor_u32': '0xffffffff'}, 'CRC_computation': {'entry_index': 12, 'entry_PC': 'main:0x24b298', 'input_address': '0x136df180', 'input_length_u32': 32, 'return_index': 244, 'return_PC': 'main:0x258bc4', 'returned_u32_sha256': 'ea0d1a74831bf5e694a46de25597afd27ac03b0af5ccad56878cceaf0268e2cf', 'guest_table_CRC_matches_same_run_input': True, 'binascii_CRC32_matches_same_run_input': True}, 'packed_output_store': {'index': 246, 'PC': 'main:0x288830', 'address': '0x7004ca70', 'size': 4, 'returned_W0_matches_same_run_CRC': True, 'post_store_index': 247, 'post_store_PC': 'main:0x288834', 'stored_u32_sha256': 'ea0d1a74831bf5e694a46de25597afd27ac03b0af5ccad56878cceaf0268e2cf'}, 'next_VM_call': {'index': 1206, 'callsite_offset': '0x16aa48', 'VM_cursor_offset': '0x10a37c', 'descriptor_address': '0x7004cd80', 'descriptor_width': 48, 'descriptor_sha256': '22ce5b84b20f1a64903cd9ad04fea0011f91e520297e8f4f2b0647e4ee582f49', 'wrapper_offset': '0x288530', 'target_offset': '0x26c858', 'wrapper_code_hex': '088440a9020040f9e00308aa40001fd6', 'VM_call_executed': False, 'wrapper_executed': False, 'target_executed': False, 'wrapper_code_sha256': '14d9ed527789cfea4669cc452adab89d302cd67f24dc06b1de12d4ca1b71a7af'}, 'new_allocator_events': [], 'protected_ranges': [{'label': 'prior_0', 'address': '0x7004d118', 'size': 24}, {'label': 'prior_1', 'address': '0x136d82c0', 'size': 8}, {'label': 'prior_2', 'address': '0x7004d130', 'size': 24}, {'label': 'prior_3', 'address': '0x136d82d0', 'size': 8}, {'label': 'prior_4', 'address': '0x7004d148', 'size': 24}, {'label': 'prior_5', 'address': '0x136d82d8', 'size': 8}, {'label': 'string_object', 'address': '0x136d9640', 'size': 24}, {'label': 'string_payload', 'address': '0x136d4050', 'size': 37}, {'label': 'output', 'address': '0x7004d178', 'size': 16}, {'label': 'cache', 'address': '0x136d73a0', 'size': 16}, {'label': 'counter', 'address': '0x136d82e0', 'size': 4}, {'label': 'cache_mutex', 'address': '0x136d4020', 'size': 48}, {'label': 'cache_globals', 'address': '0x1269e700', 'size': 64}, {'label': 'seed_constants', 'address': '0x1269e450', 'size': 128}, {'label': 'errno', 'address': '0x7000a010', 'size': 4}, {'label': 'prior_identifier_diagnostic_entry', 'address': '0x136d4080', 'size': 48}, {'label': 'diagnostic_guard', 'address': '0x1269eda0', 'size': 8}, {'label': 'diagnostic_global_lock_pointer', 'address': '0x1269ed98', 'size': 8}, {'label': 'diagnostic_table_pointer', 'address': '0x1269eda8', 'size': 8}, {'label': 'initialized_allocation', 'address': '0x136d82f0', 'size': 4}, {'label': 'selected_entry_vtable', 'address': '0x136d40b0', 'size': 8}, {'label': 'selected_entry_tail', 'address': '0x136d40c0', 'size': 32}, {'label': 'released_entry_header', 'address': '0x136d40b8', 'size': 8}, {'label': 'formatted_string_object', 'address': '0x136d9660', 'size': 24}, {'label': 'formatted_string_payload', 'address': '0x136d82e8', 'size': 8}, {'label': 'pair_destination_object', 'address': '0x7004d1d8', 'size': 24}, {'label': 'pair_destination_payload', 'address': '0x136df280', 'size': 64}, {'label': 'diagnostic_global_lock_vtable', 'address': '0x136d3c60', 'size': 8}, {'label': 'diagnostic_global_lock_tail', 'address': '0x136d3c70', 'size': 32}, {'label': 'MD5_output_pair', 'address': '0x7004c560', 'size': 16}, {'label': 'MD5_result_object', 'address': '0x136d9680', 'size': 24}, {'label': 'MD5_result_counter', 'address': '0x136d8300', 'size': 4}, {'label': 'MD5_result_payload', 'address': '0x136df180', 'size': 64}, {'label': 'completed_MD5_diagnostic_table', 'address': '0x136f8000', 'size': 2048}, {'label': 'completed_MD5_global_lock_header', 'address': '0x136d3c68', 'size': 8}, {'label': 'completed_MD5_diagnostic_entry_104', 'address': '0x136d40e0', 'size': 48}, {'label': 'guest_CRC_table', 'address': '0x12356144', 'size': 1024}], 'ledgers': {'allocator_counts': {'malloc': 602, 'free': 272, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}}
WRAPPER_IDENTITY={'wrapper_offset': '0x288820', 'target_offset': '0x258bac', 'size': 28, 'sha256': '9008864fc0873b88fe474d250ec4c0d05d7028e7eef484c94ec234851d3bae61', 'equivalent_prior_wrapper_offset': '0x204464', 'complete_code_equal': True, 'no_PC_relative_instructions': True}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'empty', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'empty_NULL', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'negative_NULL', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'minimum_negative_NULL', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'digits', 'steps': 86, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'binary_NUL', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'all_bytes', 'steps': 1815, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'long_binary', 'steps': 28702, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'cross_payload', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'cross_object', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'cross_packed', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'result_alias', 'steps': 107, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'object_fields_alias', 'steps': 107, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'mutated_guest_table', 'steps': 3607, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'unaligned_payload', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'length_ignores_tail', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'empty', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'empty_NULL', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'negative_NULL', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'minimum_negative_NULL', 'steps': 23, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'digits', 'steps': 86, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'binary_NUL', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'all_bytes', 'steps': 1815, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'long_binary', 'steps': 28702, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'cross_payload', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'cross_object', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'cross_packed', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'result_alias', 'steps': 107, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'object_fields_alias', 'steps': 107, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'mutated_guest_table', 'steps': 3607, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'unaligned_payload', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'length_ignores_tail', 'steps': 58, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'independent_length_32', 'steps': 247, 'source_length': 32, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'binascii_CRC32_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'independent_length_42', 'steps': 317, 'source_length': 42, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'binascii_CRC32_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'independent_length_32', 'steps': 247, 'source_length': 32, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'binascii_CRC32_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'independent_length_42', 'steps': 317, 'source_length': 42, 'original_new_wrapper_and_guest_table_crc_returned': True, 'W0_and_all_guest_and_image_bytes_equal': True, 'binascii_CRC32_equal': True, 'packed_uint32_only_and_padding_preserved': True, 'no_allocator_JNI_or_service_effects': True, 'native_snapshot_input': False, 'physical_saved_registers_and_PAC_compared': False}]
ROLLBACK_SPECS=[{'image_base': '0x122c0000', 'case': 'wrong_target', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'unaligned_stack', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'unmapped_object', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'unmapped_payload', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'length_bound', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'partial_output', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'packed_stack_alias', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'object_stack_alias', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x122c0000', 'case': 'payload_stack_alias', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'wrong_target', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'unaligned_stack', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'unmapped_object', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'unmapped_payload', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'length_bound', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'partial_output', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'packed_stack_alias', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'object_stack_alias', 'rejected': True, 'all_pages_unchanged': True}, {'image_base': '0x775c205000', 'case': 'payload_stack_alias', 'rejected': True, 'all_pages_unchanged': True}]

def bootstrap_prefix():
    owner=previous
    while not hasattr(owner,'bootstrap'):owner=owner.previous
    return owner.bootstrap.module_prefix()

def standard_crc_table():
    out=[]
    for n in range(256):
        for _ in range(8):n=(n>>1)^(0xEDB88320 if n&1 else 0)
        out.append(n)
    return b''.join(n.to_bytes(4,'little') for n in out)

def wrapper_identity(path):
    controls.equivalent_wrappers(path)
    p=controls.oracle.image_pages(path,controls.BASES[0]);raw=_read_span(p,controls.BASES[0]+0x288820,28)
    code=list(Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN).disasm(raw,0x288820))
    assert len(code)==7 and code[-1].mnemonic=='ret' and code[3].mnemonic=='blr'
    assert not any(x.mnemonic in ('adr','adrp','b','bl','cbz','cbnz','tbz','tbnz') or x.mnemonic.startswith('b.') for x in code)
    return dict(wrapper_offset='0x288820',target_offset='0x258bac',size=28,sha256=hashlib.sha256(raw).hexdigest(),
        equivalent_prior_wrapper_offset='0x204464',complete_code_equal=True,no_PC_relative_instructions=True)

def bounded_length_control(path,image,length):
    p,packed,obj,pointer=controls.fresh(path,image,'binary_NUL');data=bytes((i*37+3)&255 for i in range(length))
    _write_span(p,obj+12,length.to_bytes(4,'little'));_write_span(p,pointer,data+b'\xCA')
    before=_read_span(p,packed,32);value,memory,watch,steps=controls.original(path,image,p,packed)
    result=controls.second.apply_request_287474_crc_callback(p,argument_block_address=packed,entry_stack_address=controls.SP,image_base=image)
    assert result==value==binascii.crc32(data) and _read_span(p,controls.G,0xA000)==memory
    assert all(_read_span(p,a,n)==raw for (a,n),raw in watch.items()) and _read_span(p,packed+20,12)==before[20:]
    print('PASS CRC independent bounded length',hex(image),length,flush=True)
    return dict(image_base=hex(image),case='independent_length_'+str(length),steps=steps,source_length=length,
        original_new_wrapper_and_guest_table_crc_returned=True,W0_and_all_guest_and_image_bytes_equal=True,
        binascii_CRC32_equal=True,packed_uint32_only_and_padding_preserved=True,no_allocator_JNI_or_service_effects=True,
        native_snapshot_input=False,physical_saved_registers_and_PAC_compared=False)

class PostMD5CRCScenario(previous.PostPairMD5Scenario):
    def __init__(self,control):
        super().__init__(control)
        self._crc_active=False;self._crc_returned=False;self._crc_done=False;self._crc_ready=False
        self._crc_trace=[];self._crc_code={};self._crc_rows=[];self._crc_writes=[];self._crc_violations=[]
        self._crc_core={};self._crc_store={};self._crc_services=[]

    def _crc_track(self,cpu,pc):
        assert len(self._crc_trace)<300000
        key=self._fmt_site(pc);self._crc_trace.append(key);self._crc_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _crc_live_hash(self,cpu):
        return digest([dict(label=l,address=hex(a),size=n,sha256=raw_hash(bytes(cpu.mem_read(a,n)))) for l,a,n in self._crc_ranges])

    def _crc_snapshot(self,cpu,pc,kind):
        raw=bytes(cpu.mem_read(self._crc_descriptor,48))
        self._crc_rows.append(dict(kind=kind,index=len(self._crc_trace),pc=self._fmt_site(pc),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            callee_saved_sha256=self._idctor_saved_hash(cpu),VM_state_address=hex(self._postalloc_vmstate),VM_cursor=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(self._crc_descriptor),descriptor_width=48,descriptor_sha256=raw_hash(raw),descriptor_input_16_sha256=raw_hash(raw[:16]),
            descriptor_tail_28_sha256=raw_hash(raw[20:]),output_storage_address=hex(self._crc_descriptor+16),output_storage_width=4,output_storage_sha256=raw_hash(raw[16:20]),
            output_ready=self._crc_ready,output_matches_same_run_input=self._u(cpu,self._crc_descriptor+16,4)==self._crc_expected if self._crc_ready else None,
            source_object=self._pair_object(cpu,self._crc_source),protected_regions_sha256=self._crc_live_hash(cpu),registers={}))

    def _crc_start(self,cpu,pc,state):
        self._md5_track(cpu,pc);self._md5_snapshot(cpu,pc,'before_next_VM_call')
        d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
        self._md5_next=previous.project_next_call(dict(index=len(self._md5_trace),callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),
            descriptor_address=hex(d),descriptor_width=48,descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),
            wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False))
        data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);self._crc_old=data['case_result']
        self._md5_done=True;self._md5_active=False;self._crc_active=True
        self._crc_descriptor=d;self._crc_before=raw;self._crc_source=int.from_bytes(raw[8:16],'little')
        assert wrapper==self.image+WRAPPER and int.from_bytes(raw[:8],'little')==self.image+TARGET
        self._crc_object=self._pair_object(cpu,self._crc_source);length=self._crc_object['length_u32']
        assert self._crc_object==self._crc_old['snapshots'][-1]['output_reference']['string_object'] and length==32
        signed=length if length<0x80000000 else length-0x100000000
        self._crc_input=bytes(cpu.mem_read(int(self._crc_object['payload_address'],16),max(signed,0)))
        table=bytes(cpu.mem_read(self.image+0x96144,1024));self._crc_table=table
        value=0xFFFFFFFF
        for b in self._crc_input:value=int.from_bytes(table[((value^b)&255)*4:((value^b)&255)*4+4],'little')^(value>>8)
        self._crc_expected=value^0xFFFFFFFF
        assert table==standard_crc_table() and self._crc_expected==binascii.crc32(self._crc_input)
        self._crc_arguments=dict(source_object_address=hex(self._crc_source),source_payload_address=self._crc_object['payload_address'],source_length_u32=length,
            signed_length_i32=signed,consumed_length=len(self._crc_input),packed_output_address=hex(d+16),packed_output_width=4,raw_input_and_CRC_exported=False)
        self._crc_table_meta=dict(image_offset='0x96144',size=1024,entries=256,sha256=raw_hash(table),standard_reflected_table_matches=True,
            standard_polynomial='0xedb88320',initial_u32='0xffffffff',final_xor_u32='0xffffffff')
        self._crc_ranges=deepcopy(self._md5_ranges)+[('guest_CRC_table',self.image+0x96144,1024)]
        self._crc_sp=cpu.reg_read(arm.UC_ARM64_REG_SP);self._crc_saved=self._idctor_saved_hash(cpu)
        self._crc_events=deepcopy(state['allocator_events_ref'])
        self._crc_track(cpu,pc);self._crc_snapshot(cpu,pc,'CRC_VM_call')

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._crc_active:
                pc=cpu.reg_read(arm.UC_ARM64_REG_PC);row=dict(index=len(self._crc_trace),PC=self._fmt_site(pc),address=hex(address),size=size)
                self._crc_writes.append(row);labels=[l for l,a,n in self._crc_ranges if address<a+n and a<address+size]
                if labels:raise AssertionError('CRC wrote protected live state')
                if not self._crc_returned and address<self._crc_descriptor+48 and self._crc_descriptor<address+size:
                    assert pc==self.image+WRAPPER+16 and address==self._crc_descriptor+16 and size==4
                    assert self._reg(cpu,0)==self._crc_expected
                    self._crc_store=dict(index=len(self._crc_trace),PC=self._fmt_site(pc),address=hex(address),size=4,returned_W0_matches_same_run_CRC=True)
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write
        return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._crc_active:
            if self._md5_active and self._md5_returned and pc==self.image+VM_CALL:
                self._crc_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._crc_track(cpu,pc);off=pc-self.image;index=len(self._crc_trace)
        if not self._crc_returned:
            if off in (WRAPPER,TARGET,CORE):
                if off==TARGET:
                    assert self._reg(cpu,0)==self._crc_source and self._reg(cpu,30)==self.image+WRAPPER+16
                    assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._crc_sp-16
                if off==CORE:
                    assert self._reg(cpu,0)==int(self._crc_object['payload_address'],16) and self._reg(cpu,1)==self._crc_object['length_u32']
                    self._crc_core=dict(entry_index=index,entry_PC=self._fmt_site(pc),input_address=hex(self._reg(cpu,0)),input_length_u32=self._reg(cpu,1))
                self._crc_snapshot(cpu,pc,{WRAPPER:'wrapper_entry',TARGET:'CRC_object_entry',CORE:'CRC_buffer_entry'}[off])
            if off==TARGET+24:
                assert self._reg(cpu,0)==self._crc_expected
                self._crc_core.update(return_index=index,return_PC=self._fmt_site(pc),returned_u32_sha256=raw_hash(self._crc_expected.to_bytes(4,'little')),
                    guest_table_CRC_matches_same_run_input=True,binascii_CRC32_matches_same_run_input=True)
                self._crc_snapshot(cpu,pc,'CRC_buffer_return')
            if off==WRAPPER+20:
                assert self._crc_store and self._u(cpu,self._crc_descriptor+16,4)==self._crc_expected
                self._crc_ready=True;self._crc_store.update(post_store_index=index,post_store_PC=self._fmt_site(pc),stored_u32_sha256=raw_hash(bytes(cpu.mem_read(self._crc_descriptor+16,4))))
                self._crc_snapshot(cpu,pc,'CRC_output_store_complete')
            if off==VM_RESUME:
                assert self._crc_ready and self._reg(cpu,0)==self._crc_expected
                assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._crc_sp and self._idctor_saved_hash(cpu)==self._crc_saved
                raw=bytes(cpu.mem_read(self._crc_descriptor,48));assert raw[:16]==self._crc_before[:16] and raw[20:]==self._crc_before[20:]
                self._crc_snapshot(cpu,pc,'CRC_callback_return');self._crc_returned=True
        elif off==VM_CALL:
            self._crc_snapshot(cpu,pc,'before_next_VM_call');d=self._reg(cpu,0);wrapper=self._reg(cpu,8);raw=bytes(cpu.mem_read(d,48))
            self._crc_next=dict(index=index,callsite_offset=hex(VM_CALL),VM_cursor_offset=hex(self._u(cpu,self._postalloc_vmstate)-self.image),descriptor_address=hex(d),descriptor_width=48,
                descriptor_sha256=raw_hash(raw),wrapper_offset=hex(wrapper-self.image),target_offset=hex(int.from_bytes(raw[:8],'little')-self.image),
                wrapper_code_hex=bytes(cpu.mem_read(wrapper,64)).hex(),VM_call_executed=False,wrapper_executed=False,target_executed=False)
            self._crc_next=project_next_call(self._crc_next)
            self._crc_done=True;cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.controls.dependency.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._crc_done and self._crc_returned and self._crc_ready and self._crc_violations==[]
        old=super().finish(result,state,proof);assert old==self._crc_old,'MD5 parent changed'
        h=hashlib.sha256()
        for key in self._crc_trace:h.update(key.encode()+bytes.fromhex(self._crc_code[key]))
        assert result['allocator_events']==self._crc_events
        ledgers={key:old[key] for key in previous.EXPECTED['ledgers']};assert ledgers==EXPECTED['ledgers']
        return dict(control=old['control'],retained_MD5=dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=len(self._crc_trace),instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._crc_code),
            snapshots=self._crc_rows,native_writes=self._crc_writes,CRC_arguments=self._crc_arguments,guest_CRC_table=self._crc_table_meta,
            CRC_computation=self._crc_core,packed_output_store=self._crc_store,next_VM_call=self._crc_next,observation_sites=self._crc_trace,
            observed_code=self._crc_code,new_allocator_events=[],**ledgers,protected_ranges=[dict(label=l,address=hex(a),size=n) for l,a,n in self._crc_ranges],
            protected_write_events=[],stop_boundary=stop_boundary())

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,fixture=controls,request_model=controls.second,CRC_model=crc_owner,object_model=objects_owner,allocator_model=allocator_owner,oracle=controls.oracle)
    return dict(post_md5_crc_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),
        inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        main_path='original CRC wrapper/object/buffer path; guest ELF supplies its lookup table',
        independent_controls='independently prepared inputs; actual wrapper versus existing guest-table CRC owner',
        runtime_relations='same-run bytes used only for native CRC assertions, never as semantic-model inputs',
        CRC_table='guest bytes verified against independently generated reflected polynomial table; binascii used as an additional relation',
        output_contract='defined W0 and packed four-byte store; descriptor prefix and following bytes preserved through callback return',
        rollback_scope='guest pages only; external provider effects excluded',
        exported_output='lengths, hashes, pointers and write locations/widths; no raw input/CRC/identifier/seed, allocation contents, descriptors, padding or register dumps',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',MD5_reference_prefix_revalidated=True,original_CRC_wrapper_object_and_buffer_returned=True,
        packed_receiver_and_declared_signed_length_verified=True,guest_table_verified_and_write_protected=True,
        native_guest_table_CRC_and_binascii_relation_verified=True,returned_W0_and_packed_uint32_store_verified=True,
        only_four_output_bytes_written_in_descriptor=True,descriptor_prefix_and_tail_preserved_through_return=True,
        source_and_all_retained_live_regions_write_protected=True,no_new_allocator_JNI_or_service_effects=True,
        full_parent_case_result_equal=True,caller_SP_and_callee_saved_restored=True,internal_GP_registers_omitted=True,
        next_VM_call_boundary_observed=True,next_VM_call_executed=False,next_wrapper_executed=False,next_target_executed=False,
        new_providers_added=False,native_snapshot_used_as_python_model_input=False,whole_physical_stack_GP_FP_and_PAC_ABI_compared=False,
        standalone_Python_VM_continuation_verified=False,complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,
        real_ART_JVM_execution=False,Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

def stop_boundary():
    return dict(kind='before_next_VM_call_after_CRC',stop_before=hex(VM_CALL),VM_call_executed=False,wrapper_executed=False,target_executed=False)

def project_next_call(row):
    row=deepcopy(row);raw=bytes.fromhex(row.pop('wrapper_code_hex'))[:NEXT_WRAPPER_SIZE]
    row['wrapper_code_hex']=raw.hex();row['wrapper_code_sha256']=raw_hash(raw);assert 'descriptor_hex' not in row
    return row

def elf_bytes(elf,stream,offset,size):
    for seg in elf.iter_segments():
        if seg['p_type']=='PT_LOAD' and seg['p_vaddr']<=offset and offset+size<=seg['p_vaddr']+seg['p_filesz']:
            stream.seek(seg['p_offset']+offset-seg['p_vaddr']);raw=stream.read(size);assert len(raw)==size;return raw
    raise AssertionError('ELF range outside file-backed LOAD segments')

def read_static(path,libc):
    rows={}
    for domain,p in (('main',path),('libc',libc)):
        with p.open('rb') as f:
            elf=ELFFile(f)
            for off,size in CODE_RANGES[domain]:
                raw=elf_bytes(elf,f,off,size);rows[domain+':'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
            if domain=='main':
                table=elf_bytes(elf,f,0x96144,1024);assert table==standard_crc_table() and raw_hash(table)==EXPECTED['guest_CRC_table']['sha256']
    return rows

def independent_controls(path,libc):
    identity=wrapper_identity(path)
    cases=[controls.compare(path,base,label) for base in controls.BASES for label in controls.PROFILES]
    cases.extend(bounded_length_control(path,base,length) for base in controls.BASES for length in (32,42))
    guards=controls.guards(path)
    assert identity==WRAPPER_IDENTITY and cases==CONTROL_SPECS and guards==ROLLBACK_SPECS
    return identity,cases,guards

def run(path,libc):
    parent=prior_evidence();p=bootstrap_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=PostMD5CRCScenario(control);s.path=path;s.continue_to_svc=True;return s
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
    assert data['wrapper_identity']==WRAPPER_IDENTITY and data['native_controls']==CONTROL_SPECS and len(CONTROL_SPECS)==36
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==18
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        assert len(ranges)==len({off for off,size in ranges})
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'hex','size','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_MD5','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots','native_writes',
        'CRC_arguments','guest_CRC_table','CRC_computation','packed_output_store','next_VM_call','observation_sites','observed_code',
        'new_allocator_events','protected_ranges','protected_write_events','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_MD5']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS)) and list(PARENT_FIELDS)==sorted(old)
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[:6]==['main:'+hex(x) for x in (VM_CALL,WRAPPER,WRAPPER+4,WRAPPER+8,WRAPPER+12,TARGET)]
    assert all(x.startswith('main:') for x in sites)
    assert sites[-1]=='main:'+hex(VM_CALL) and sites.count('main:'+hex(VM_CALL))==2
    assert all(sites.count('main:'+hex(x))==1 for x in (VM_RESUME,TARGET,CORE,WRAPPER+16,WRAPPER+20))
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4;h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256']
    assert digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_writes','CRC_arguments','guest_CRC_table','CRC_computation','packed_output_store','next_VM_call','new_allocator_events','protected_ranges'):
        assert row[key]==EXPECTED[key],key
    snapshots=row['snapshots'];first,last=snapshots[0],snapshots[-1];returned=next(x for x in snapshots if x['kind']=='CRC_callback_return');prior=old['snapshots'][-1]
    assert first['kind']=='CRC_VM_call' and last['kind']=='before_next_VM_call'
    assert first['index']==1 and last['index']==len(sites) and all(a['index']<b['index'] for a,b in zip(snapshots,snapshots[1:]))
    assert first['descriptor_address']==old['next_VM_call']['descriptor_address'] and first['descriptor_sha256']==old['next_VM_call']['descriptor_sha256']
    assert first['VM_cursor']==returned['VM_cursor']==prior['VM_cursor']=='0x10a348'
    assert first['SP']==returned['SP']==prior['SP'] and first['callee_saved_sha256']==returned['callee_saved_sha256']==prior['callee_saved_sha256']
    args=row['CRC_arguments'];assert args['source_object_address']==first['source_object']['address']
    assert first['source_object']==prior['output_reference']['string_object'] and args['source_length_u32']==32
    assert args['source_payload_address']==first['source_object']['payload_address'] and args['source_length_u32']==first['source_object']['length_u32']
    assert args['consumed_length']==max(args['signed_length_i32'],0) and args['packed_output_width']==4 and args['raw_input_and_CRC_exported'] is False
    assert args['packed_output_address']==hex(int(first['descriptor_address'],16)+16)
    for x in snapshots:
        assert sites[x['index']-1]==x['pc'] and x['registers']=={} and x['source_object']==first['source_object']
        assert x['protected_regions_sha256']==first['protected_regions_sha256'] and x['VM_state_address']==prior['VM_state_address']
        assert x['descriptor_width']==48 and x['output_storage_address']==args['packed_output_address'] and x['output_storage_width']==4
        if not x['output_ready']:assert x['output_matches_same_run_input'] is None
        else:assert x['output_matches_same_run_input'] is True
        if x['index']<=returned['index']:
            assert x['descriptor_input_16_sha256']==first['descriptor_input_16_sha256'] and x['descriptor_tail_28_sha256']==first['descriptor_tail_28_sha256']
    assert returned['output_ready'] is True and returned['output_matches_same_run_input'] is True
    computation=row['CRC_computation'];assert computation['input_length_u32']==args['source_length_u32'] and computation['input_address']==args['source_payload_address']
    assert computation['entry_PC']=='main:'+hex(CORE) and computation['return_PC']=='main:'+hex(TARGET+24)
    assert sites[computation['entry_index']-1]==computation['entry_PC'] and sites[computation['return_index']-1]==computation['return_PC']
    assert computation['entry_index']<computation['return_index']<returned['index']
    assert computation['guest_table_CRC_matches_same_run_input'] is computation['binascii_CRC32_matches_same_run_input'] is True
    table=row['guest_CRC_table'];assert table['size']==1024 and table['entries']==256 and table['image_offset']=='0x96144'
    assert table['sha256']==raw_hash(standard_crc_table()) and table['standard_reflected_table_matches'] is True
    store=row['packed_output_store'];assert store['address']==args['packed_output_address'] and store['size']==4
    assert store['PC']=='main:'+hex(WRAPPER+16) and store['post_store_PC']=='main:'+hex(WRAPPER+20)
    assert sites[store['index']-1]==store['PC'] and sites[store['post_store_index']-1]==store['post_store_PC']
    assert computation['return_index']<store['index']<store['post_store_index']<returned['index']
    assert store['returned_W0_matches_same_run_CRC'] is True and store['stored_u32_sha256']==computation['returned_u32_sha256']==returned['output_storage_sha256']
    descriptor=dict(address=first['descriptor_address'],size=48);descriptor_writes=[]
    for w in row['native_writes']:
        assert set(w)=={'index','PC','address','size'} and sites[w['index']-1]==w['PC'] and w['size']>0
        assert not any(overlaps(w['address'],w['size'],r) for r in row['protected_ranges'])
        if w['index']<=returned['index'] and overlaps(w['address'],w['size'],descriptor):descriptor_writes.append(w)
    assert descriptor_writes==[{k:store[k] for k in ('index','PC','address','size')}]
    assert row['new_allocator_events']==[] and row['protected_write_events']==[]
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value==old[key],key
    call=row['next_VM_call'];assert call['index']==len(sites) and call['VM_cursor_offset']==last['VM_cursor'] and call['callsite_offset']==hex(VM_CALL) and call['descriptor_width']==48
    assert call['wrapper_offset']==hex(NEXT_WRAPPER) and call['target_offset']==hex(NEXT_TARGET)
    assert call['wrapper_code_hex']==data['static_code']['main:'+hex(NEXT_WRAPPER)]['hex']
    assert len(bytes.fromhex(call['wrapper_code_hex']))==NEXT_WRAPPER_SIZE and raw_hash(bytes.fromhex(call['wrapper_code_hex']))==call['wrapper_code_sha256']
    assert call['VM_call_executed'] is call['wrapper_executed'] is call['target_executed'] is False and row['stop_boundary']==stop_boundary()

def validate(data):
    _validate(data,prior_evidence())

def damaged_evidence_rejected(data):
    parent=prior_evidence()
    changes=[(('claims','next_VM_call_executed'),True),(('claims','complete_standalone_signer_verified'),True),
        (('claims','whole_physical_stack_GP_FP_and_PAC_ABI_compared'),True),(('claims','returned_W0_and_packed_uint32_store_verified'),False),
        (('claims','full_parent_case_result_equal'),False),(('providers','new_providers'),['hidden']),
        (('source_fingerprints','owners','CRC_model'),'0'*64),(('case_result','retained_MD5','case_result_sha256'),'0'*64),
        (('case_result','retained_MD5','verified_fields'),[]),(('case_result','instruction_observations'),0),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'protected_regions_sha256'),'0'*64),(('case_result','snapshots',-2,'SP'),'0x0'),
        (('case_result','snapshots',-2,'callee_saved_sha256'),'0'*64),(('case_result','snapshots',-1,'source_object','length_u32'),0),
        (('case_result','snapshots',-1,'source_object','payload_including_NUL_sha256'),'0'*64),
        (('case_result','snapshots',0,'output_matches_same_run_input'),True),(('case_result','snapshots',0,'output_ready'),True),
        (('case_result','snapshots',-2,'output_storage_sha256'),'0'*64),(('case_result','snapshots',-2,'output_matches_same_run_input'),False),
        (('case_result','snapshots',-1,'registers'),{'x0':'0x1'}),(('case_result','snapshots',-2,'descriptor_tail_28_sha256'),'0'*64),
        (('case_result','CRC_arguments','source_length_u32'),0),(('case_result','CRC_arguments','consumed_length'),0),
        (('case_result','CRC_arguments','raw_input_and_CRC_exported'),True),(('case_result','CRC_arguments','packed_output_width'),8),
        (('case_result','CRC_computation','input_length_u32'),0),(('case_result','CRC_computation','entry_PC'),'main:0x24b2d4'),
        (('case_result','CRC_computation','guest_table_CRC_matches_same_run_input'),False),
        (('case_result','CRC_computation','binascii_CRC32_matches_same_run_input'),False),(('case_result','CRC_computation','returned_u32_sha256'),'0'*64),
        (('case_result','guest_CRC_table','sha256'),'0'*64),(('case_result','guest_CRC_table','entries'),0),
        (('case_result','packed_output_store','size'),8),(('case_result','packed_output_store','stored_u32_sha256'),'0'*64),
        (('case_result','packed_output_store','returned_W0_matches_same_run_CRC'),False),(('case_result','packed_output_store','post_store_index'),0),
        (('case_result','native_writes',0,'size'),99),(('case_result','protected_ranges'),[]),
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
        raise AssertionError(f'damaged CRC evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh CRC replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),
        damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],original_CRC_returned=True,
        next_VM_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
