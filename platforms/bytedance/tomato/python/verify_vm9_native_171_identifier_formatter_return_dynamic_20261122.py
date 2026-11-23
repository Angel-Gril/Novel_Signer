"""Verify original identifier formatting after the failed seed-file initialization."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_identifier_seed_open_failure_dynamic_20261122 as previous
import verify_vm9_request_identifier_fresh_20261015 as controls
import vm9_request_identifier as identifier_owner
import vm9_configuration_init as constants_owner
import verify_vm9_signer_objects as oracle
EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_identifier_formatter_return_dynamic_20261122.json')
SCHEMA='vm9-native-171-identifier-formatter-return-dynamic-20261122-v1'
FORMAT_CALL,FORMAT_TARGET,FORMAT_RETURN,NEXT_CALL,NEXT_TARGET=0x25BD1C,0x255D84,0x25BD20,0x25BD24,0x32A1F0
OUTPUT_BYTES=37
MAX_OBSERVATIONS=50000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes','syscalls')
CODE_RANGES={'main': ((2473244, 12), (2448772, 316), (2449088, 64), (3318256, 16)), 'libc': ()}
CODE_SHA256={'main:0x25bd1c': '73ee4d8de225472442c903f8639bd1e7b5f9ede8ffd4590a7955ab41de007986', 'main:0x255d84': '9f4157c4b2ce4d7db59c208b4ad05e6c59c2be6fb82f6ede9c649039c8419c78', 'main:0x255ec0': 'f02e5e20fd2856a5fde9a80ae6963ba0924256a5d7cbd83654c581e02b5d84a9', 'main:0x32a1f0': '0c22b2d931f62564b4e6371ae5c96b40423cdd41cbb74066ee56259ca91b621d'}
EXPECTED={'instruction_observations': 1140, 'instruction_trace_sha256': 'c7b16aef84163a86202eafc69331d5c48f9753f42b0dc3bbb78a34153dc3da68', 'observed_code_sha256': 'd5a18ff616f535a66a73b67787ad31a87a123c98e067df2d69730d3eedc40ad2', 'snapshots': [{'kind': 'formatter_BL', 'index': 1, 'pc': '0x25bd1c', 'SP': '0x7004b850', 'output_address': '0x7004b850', 'descriptor_hex': '8cbd51120000000078d1047000000000c402fe0c000000000300000000000000a43352120000000008d0047000000000', 'cache_globals_hex': '010000000000000000000000000000000000000000000000010100008900000020406d13000000000101000089000000a0736d13000000000101000089000000', 'cache_mutex_hex': '38c760120000000001000000000000000000000000000000000000000000000000000000000000000000000000000000', 'cache_pair_hex': '00000000000000000000000000000000', 'output_reference_hex': '00000000000000000000000000000000', 'errno': 2, 'prior_objects': [{'object_address': '0x7004d118', 'payload_address': '0x136d82c0', 'object_hex': 'f8f56012000000000800000000000000c0826d1300000000', 'payload_hex': '0000000006060000'}, {'object_address': '0x7004d130', 'payload_address': '0x136d82d0', 'object_hex': 'f8f56012000000000800000000000000d0826d1300000000', 'payload_hex': '0000000000000000'}, {'object_address': '0x7004d148', 'payload_address': '0x136d82d8', 'object_hex': 'f8f56012000000000800000000000000d8826d1300000000', 'payload_hex': '0000000000000000'}], 'registers': {'x0': '0x7004b850', 'x30': '0x1251bd84'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'output_width': 64, 'output_window_sha256': 'a5f099a08070c7694f80c5e7381663b14c191cffe4d5f7ce6d2bbd5b821aaf83', 'output_tail_sha256': '02e81be3ef1f6fcb44de2fd4a6e9efc8624d080fb67b9725dbcac0223ca736fe', 'constants_width': 128, 'constants_sha256': 'a3d3ba9397687fb386ad00c7794de6369d59cad2c846b1f4a8efe26158db8506', 'seed_width': 16, 'seed_all_zero': True, 'template_guard': 0, 'alphabet_guard': 0}, {'kind': 'path', 'index': 2, 'pc': '0x255d84', 'SP': '0x7004b850', 'output_address': '0x7004b850', 'descriptor_hex': '8cbd51120000000078d1047000000000c402fe0c000000000300000000000000a43352120000000008d0047000000000', 'cache_globals_hex': '010000000000000000000000000000000000000000000000010100008900000020406d13000000000101000089000000a0736d13000000000101000089000000', 'cache_mutex_hex': '38c760120000000001000000000000000000000000000000000000000000000000000000000000000000000000000000', 'cache_pair_hex': '00000000000000000000000000000000', 'output_reference_hex': '00000000000000000000000000000000', 'errno': 2, 'prior_objects': [{'object_address': '0x7004d118', 'payload_address': '0x136d82c0', 'object_hex': 'f8f56012000000000800000000000000c0826d1300000000', 'payload_hex': '0000000006060000'}, {'object_address': '0x7004d130', 'payload_address': '0x136d82d0', 'object_hex': 'f8f56012000000000800000000000000d0826d1300000000', 'payload_hex': '0000000000000000'}, {'object_address': '0x7004d148', 'payload_address': '0x136d82d8', 'object_hex': 'f8f56012000000000800000000000000d8826d1300000000', 'payload_hex': '0000000000000000'}], 'registers': {'x0': '0x7004b850', 'x30': '0x1251bd20'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'output_width': 64, 'output_window_sha256': 'a5f099a08070c7694f80c5e7381663b14c191cffe4d5f7ce6d2bbd5b821aaf83', 'output_tail_sha256': '02e81be3ef1f6fcb44de2fd4a6e9efc8624d080fb67b9725dbcac0223ca736fe', 'constants_width': 128, 'constants_sha256': 'a3d3ba9397687fb386ad00c7794de6369d59cad2c846b1f4a8efe26158db8506', 'seed_width': 16, 'seed_all_zero': True, 'template_guard': 0, 'alphabet_guard': 0}, {'kind': 'path', 'index': 467, 'pc': '0x255ec0', 'SP': '0x7004b800', 'output_address': '0x7004b850', 'descriptor_hex': '8cbd51120000000078d1047000000000c402fe0c000000000300000000000000a43352120000000008d0047000000000', 'cache_globals_hex': '010000000000000000000000000000000000000000000000010100008900000020406d13000000000101000089000000a0736d13000000000101000089000000', 'cache_mutex_hex': '38c760120000000001000000000000000000000000000000000000000000000000000000000000000000000000000000', 'cache_pair_hex': '00000000000000000000000000000000', 'output_reference_hex': '00000000000000000000000000000000', 'errno': 2, 'prior_objects': [{'object_address': '0x7004d118', 'payload_address': '0x136d82c0', 'object_hex': 'f8f56012000000000800000000000000c0826d1300000000', 'payload_hex': '0000000006060000'}, {'object_address': '0x7004d130', 'payload_address': '0x136d82d0', 'object_hex': 'f8f56012000000000800000000000000d0826d1300000000', 'payload_hex': '0000000000000000'}, {'object_address': '0x7004d148', 'payload_address': '0x136d82d8', 'object_hex': 'f8f56012000000000800000000000000d8826d1300000000', 'payload_hex': '0000000000000000'}], 'registers': {'x0': '0x12357f00', 'x30': '0x12515e20'}, 'callee_saved_sha256': '81ceb2d4bba3314fef6022d973d769b57beb3d34564df4ec1e506c7caff6ea43', 'output_width': 64, 'output_window_sha256': 'a5f099a08070c7694f80c5e7381663b14c191cffe4d5f7ce6d2bbd5b821aaf83', 'output_tail_sha256': '02e81be3ef1f6fcb44de2fd4a6e9efc8624d080fb67b9725dbcac0223ca736fe', 'constants_width': 128, 'constants_sha256': 'd95e1a50fd450c4ddde01970b5c9edddb0c460449576a32fbfd9593e60e6af69', 'seed_width': 16, 'seed_all_zero': True, 'template_guard': 1, 'alphabet_guard': 1}, {'kind': 'path', 'index': 479, 'pc': '0x255ec0', 'SP': '0x7004b800', 'output_address': '0x7004b850', 'descriptor_hex': '8cbd51120000000078d1047000000000c402fe0c000000000300000000000000a43352120000000008d0047000000000', 'cache_globals_hex': '010000000000000000000000000000000000000000000000010100008900000020406d13000000000101000089000000a0736d13000000000101000089000000', 'cache_mutex_hex': '38c760120000000001000000000000000000000000000000000000000000000000000000000000000000000000000000', 'cache_pair_hex': '00000000000000000000000000000000', 'output_reference_hex': '00000000000000000000000000000000', 'errno': 2, 'prior_objects': [{'object_address': '0x7004d118', 'payload_address': '0x136d82c0', 'object_hex': 'f8f56012000000000800000000000000c0826d1300000000', 'payload_hex': '0000000006060000'}, {'object_address': '0x7004d130', 'payload_address': '0x136d82d0', 'object_hex': 'f8f56012000000000800000000000000d0826d1300000000', 'payload_hex': '0000000000000000'}, {'object_address': '0x7004d148', 'payload_address': '0x136d82d8', 'object_hex': 'f8f56012000000000800000000000000d8826d1300000000', 'payload_hex': '0000000000000000'}], 'registers': {'x0': '0x0', 'x30': '0x12515e28'}, 'callee_saved_sha256': '81ceb2d4bba3314fef6022d973d769b57beb3d34564df4ec1e506c7caff6ea43', 'output_width': 64, 'output_window_sha256': 'a5f099a08070c7694f80c5e7381663b14c191cffe4d5f7ce6d2bbd5b821aaf83', 'output_tail_sha256': '02e81be3ef1f6fcb44de2fd4a6e9efc8624d080fb67b9725dbcac0223ca736fe', 'constants_width': 128, 'constants_sha256': 'd95e1a50fd450c4ddde01970b5c9edddb0c460449576a32fbfd9593e60e6af69', 'seed_width': 16, 'seed_all_zero': True, 'template_guard': 1, 'alphabet_guard': 1}, {'kind': 'returned', 'index': 1139, 'pc': '0x25bd20', 'SP': '0x7004b850', 'output_address': '0x7004b850', 'descriptor_hex': '8cbd51120000000078d1047000000000c402fe0c000000000300000000000000a43352120000000008d0047000000000', 'cache_globals_hex': '010000000000000000000000000000000000000000000000010100008900000020406d13000000000101000089000000a0736d13000000000101000089000000', 'cache_mutex_hex': '38c760120000000001000000000000000000000000000000000000000000000000000000000000000000000000000000', 'cache_pair_hex': '00000000000000000000000000000000', 'output_reference_hex': '00000000000000000000000000000000', 'errno': 2, 'prior_objects': [{'object_address': '0x7004d118', 'payload_address': '0x136d82c0', 'object_hex': 'f8f56012000000000800000000000000c0826d1300000000', 'payload_hex': '0000000006060000'}, {'object_address': '0x7004d130', 'payload_address': '0x136d82d0', 'object_hex': 'f8f56012000000000800000000000000d0826d1300000000', 'payload_hex': '0000000000000000'}, {'object_address': '0x7004d148', 'payload_address': '0x136d82d8', 'object_hex': 'f8f56012000000000800000000000000d8826d1300000000', 'payload_hex': '0000000000000000'}], 'registers': {'x0': '0x0', 'x30': '0x1251bd20'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'output_width': 64, 'output_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'output_tail_sha256': '02e81be3ef1f6fcb44de2fd4a6e9efc8624d080fb67b9725dbcac0223ca736fe', 'constants_width': 128, 'constants_sha256': 'd95e1a50fd450c4ddde01970b5c9edddb0c460449576a32fbfd9593e60e6af69', 'seed_width': 16, 'seed_all_zero': True, 'template_guard': 1, 'alphabet_guard': 1, 'rendered_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scratch_after_all_zero': True}, {'kind': 'before_new24_BL', 'index': 1140, 'pc': '0x25bd24', 'SP': '0x7004b850', 'output_address': '0x7004b850', 'descriptor_hex': '8cbd51120000000078d1047000000000c402fe0c000000000300000000000000a43352120000000008d0047000000000', 'cache_globals_hex': '010000000000000000000000000000000000000000000000010100008900000020406d13000000000101000089000000a0736d13000000000101000089000000', 'cache_mutex_hex': '38c760120000000001000000000000000000000000000000000000000000000000000000000000000000000000000000', 'cache_pair_hex': '00000000000000000000000000000000', 'output_reference_hex': '00000000000000000000000000000000', 'errno': 2, 'prior_objects': [{'object_address': '0x7004d118', 'payload_address': '0x136d82c0', 'object_hex': 'f8f56012000000000800000000000000c0826d1300000000', 'payload_hex': '0000000006060000'}, {'object_address': '0x7004d130', 'payload_address': '0x136d82d0', 'object_hex': 'f8f56012000000000800000000000000d0826d1300000000', 'payload_hex': '0000000000000000'}, {'object_address': '0x7004d148', 'payload_address': '0x136d82d8', 'object_hex': 'f8f56012000000000800000000000000d8826d1300000000', 'payload_hex': '0000000000000000'}], 'registers': {'x0': '0x18', 'x30': '0x1251bd20'}, 'callee_saved_sha256': 'f428aa0d826aa1bfef9d581eaba9c200e149f31f69ab2102751f52dc2dffdf4c', 'output_width': 64, 'output_window_sha256': '836751eadb5058852cd23a1addb46ebcdaaf6dc7d37b85388685511fccc2c7dd', 'output_tail_sha256': '02e81be3ef1f6fcb44de2fd4a6e9efc8624d080fb67b9725dbcac0223ca736fe', 'constants_width': 128, 'constants_sha256': 'd95e1a50fd450c4ddde01970b5c9edddb0c460449576a32fbfd9593e60e6af69', 'seed_width': 16, 'seed_all_zero': True, 'template_guard': 1, 'alphabet_guard': 1, 'rendered_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scratch_after_all_zero': True}], 'native_writes': [{'index': 29, 'PC': '0x167e70', 'address': '0x1269e480', 'size': 1}, {'index': 37, 'PC': '0x167e70', 'address': '0x1269e481', 'size': 1}, {'index': 45, 'PC': '0x167e70', 'address': '0x1269e482', 'size': 1}, {'index': 53, 'PC': '0x167e70', 'address': '0x1269e483', 'size': 1}, {'index': 61, 'PC': '0x167e70', 'address': '0x1269e484', 'size': 1}, {'index': 69, 'PC': '0x167e70', 'address': '0x1269e485', 'size': 1}, {'index': 77, 'PC': '0x167e70', 'address': '0x1269e486', 'size': 1}, {'index': 85, 'PC': '0x167e70', 'address': '0x1269e487', 'size': 1}, {'index': 93, 'PC': '0x167e70', 'address': '0x1269e488', 'size': 1}, {'index': 101, 'PC': '0x167e70', 'address': '0x1269e489', 'size': 1}, {'index': 109, 'PC': '0x167e70', 'address': '0x1269e48a', 'size': 1}, {'index': 117, 'PC': '0x167e70', 'address': '0x1269e48b', 'size': 1}, {'index': 125, 'PC': '0x167e70', 'address': '0x1269e48c', 'size': 1}, {'index': 133, 'PC': '0x167e70', 'address': '0x1269e48d', 'size': 1}, {'index': 141, 'PC': '0x167e70', 'address': '0x1269e48e', 'size': 1}, {'index': 149, 'PC': '0x167e70', 'address': '0x1269e48f', 'size': 1}, {'index': 157, 'PC': '0x167e70', 'address': '0x1269e490', 'size': 1}, {'index': 165, 'PC': '0x167e70', 'address': '0x1269e491', 'size': 1}, {'index': 173, 'PC': '0x167e70', 'address': '0x1269e492', 'size': 1}, {'index': 181, 'PC': '0x167e70', 'address': '0x1269e493', 'size': 1}, {'index': 189, 'PC': '0x167e70', 'address': '0x1269e494', 'size': 1}, {'index': 197, 'PC': '0x167e70', 'address': '0x1269e495', 'size': 1}, {'index': 205, 'PC': '0x167e70', 'address': '0x1269e496', 'size': 1}, {'index': 213, 'PC': '0x167e70', 'address': '0x1269e497', 'size': 1}, {'index': 221, 'PC': '0x167e70', 'address': '0x1269e498', 'size': 1}, {'index': 229, 'PC': '0x167e70', 'address': '0x1269e499', 'size': 1}, {'index': 237, 'PC': '0x167e70', 'address': '0x1269e49a', 'size': 1}, {'index': 245, 'PC': '0x167e70', 'address': '0x1269e49b', 'size': 1}, {'index': 253, 'PC': '0x167e70', 'address': '0x1269e49c', 'size': 1}, {'index': 261, 'PC': '0x167e70', 'address': '0x1269e49d', 'size': 1}, {'index': 269, 'PC': '0x167e70', 'address': '0x1269e49e', 'size': 1}, {'index': 277, 'PC': '0x167e70', 'address': '0x1269e49f', 'size': 1}, {'index': 285, 'PC': '0x167e70', 'address': '0x1269e4a0', 'size': 1}, {'index': 293, 'PC': '0x167e70', 'address': '0x1269e4a1', 'size': 1}, {'index': 301, 'PC': '0x167e70', 'address': '0x1269e4a2', 'size': 1}, {'index': 309, 'PC': '0x167e70', 'address': '0x1269e4a3', 'size': 1}, {'index': 316, 'PC': '0x255dd8', 'address': '0x1269e4a8', 'size': 4}, {'index': 335, 'PC': '0x167e70', 'address': '0x1269e4b0', 'size': 1}, {'index': 343, 'PC': '0x167e70', 'address': '0x1269e4b1', 'size': 1}, {'index': 351, 'PC': '0x167e70', 'address': '0x1269e4b2', 'size': 1}, {'index': 359, 'PC': '0x167e70', 'address': '0x1269e4b3', 'size': 1}, {'index': 367, 'PC': '0x167e70', 'address': '0x1269e4b4', 'size': 1}, {'index': 375, 'PC': '0x167e70', 'address': '0x1269e4b5', 'size': 1}, {'index': 383, 'PC': '0x167e70', 'address': '0x1269e4b6', 'size': 1}, {'index': 391, 'PC': '0x167e70', 'address': '0x1269e4b7', 'size': 1}, {'index': 399, 'PC': '0x167e70', 'address': '0x1269e4b8', 'size': 1}, {'index': 407, 'PC': '0x167e70', 'address': '0x1269e4b9', 'size': 1}, {'index': 415, 'PC': '0x167e70', 'address': '0x1269e4ba', 'size': 1}, {'index': 423, 'PC': '0x167e70', 'address': '0x1269e4bb', 'size': 1}, {'index': 431, 'PC': '0x167e70', 'address': '0x1269e4bc', 'size': 1}, {'index': 439, 'PC': '0x167e70', 'address': '0x1269e4bd', 'size': 1}, {'index': 447, 'PC': '0x167e70', 'address': '0x1269e4be', 'size': 1}, {'index': 455, 'PC': '0x167e70', 'address': '0x1269e4bf', 'size': 1}, {'index': 462, 'PC': '0x255e0c', 'address': '0x1269e4c4', 'size': 4}, {'index': 475, 'PC': '0x255ee0', 'address': '0x1269e470', 'size': 8}, {'index': 475, 'PC': '0x255ee0', 'address': '0x1269e478', 'size': 8}, {'index': 477, 'PC': '0x255e20', 'address': '0x7004b800', 'size': 8}, {'index': 487, 'PC': '0x255ee0', 'address': '0x1269e470', 'size': 8}, {'index': 487, 'PC': '0x255ee0', 'address': '0x1269e478', 'size': 8}, {'index': 494, 'PC': '0x255e3c', 'address': '0x7004b808', 'size': 8}, {'index': 510, 'PC': '0x255e88', 'address': '0x7004b850', 'size': 1}, {'index': 528, 'PC': '0x255e88', 'address': '0x7004b851', 'size': 1}, {'index': 546, 'PC': '0x255e88', 'address': '0x7004b852', 'size': 1}, {'index': 564, 'PC': '0x255e88', 'address': '0x7004b853', 'size': 1}, {'index': 582, 'PC': '0x255e88', 'address': '0x7004b854', 'size': 1}, {'index': 600, 'PC': '0x255e88', 'address': '0x7004b855', 'size': 1}, {'index': 618, 'PC': '0x255e88', 'address': '0x7004b856', 'size': 1}, {'index': 636, 'PC': '0x255e88', 'address': '0x7004b857', 'size': 1}, {'index': 651, 'PC': '0x255e88', 'address': '0x7004b858', 'size': 1}, {'index': 669, 'PC': '0x255e88', 'address': '0x7004b859', 'size': 1}, {'index': 687, 'PC': '0x255e88', 'address': '0x7004b85a', 'size': 1}, {'index': 705, 'PC': '0x255e88', 'address': '0x7004b85b', 'size': 1}, {'index': 723, 'PC': '0x255e88', 'address': '0x7004b85c', 'size': 1}, {'index': 738, 'PC': '0x255e88', 'address': '0x7004b85d', 'size': 1}, {'index': 753, 'PC': '0x255e88', 'address': '0x7004b85e', 'size': 1}, {'index': 771, 'PC': '0x255e88', 'address': '0x7004b85f', 'size': 1}, {'index': 789, 'PC': '0x255e88', 'address': '0x7004b860', 'size': 1}, {'index': 807, 'PC': '0x255e88', 'address': '0x7004b861', 'size': 1}, {'index': 822, 'PC': '0x255e88', 'address': '0x7004b862', 'size': 1}, {'index': 839, 'PC': '0x255e88', 'address': '0x7004b863', 'size': 1}, {'index': 857, 'PC': '0x255e88', 'address': '0x7004b864', 'size': 1}, {'index': 875, 'PC': '0x255e88', 'address': '0x7004b865', 'size': 1}, {'index': 893, 'PC': '0x255e88', 'address': '0x7004b866', 'size': 1}, {'index': 908, 'PC': '0x255e88', 'address': '0x7004b867', 'size': 1}, {'index': 926, 'PC': '0x255e88', 'address': '0x7004b868', 'size': 1}, {'index': 944, 'PC': '0x255e88', 'address': '0x7004b869', 'size': 1}, {'index': 962, 'PC': '0x255e88', 'address': '0x7004b86a', 'size': 1}, {'index': 980, 'PC': '0x255e88', 'address': '0x7004b86b', 'size': 1}, {'index': 998, 'PC': '0x255e88', 'address': '0x7004b86c', 'size': 1}, {'index': 1016, 'PC': '0x255e88', 'address': '0x7004b86d', 'size': 1}, {'index': 1034, 'PC': '0x255e88', 'address': '0x7004b86e', 'size': 1}, {'index': 1052, 'PC': '0x255e88', 'address': '0x7004b86f', 'size': 1}, {'index': 1070, 'PC': '0x255e88', 'address': '0x7004b870', 'size': 1}, {'index': 1088, 'PC': '0x255e88', 'address': '0x7004b871', 'size': 1}, {'index': 1106, 'PC': '0x255e88', 'address': '0x7004b872', 'size': 1}, {'index': 1124, 'PC': '0x255e88', 'address': '0x7004b873', 'size': 1}, {'index': 1129, 'PC': '0x255e94', 'address': '0x7004b874', 'size': 1}], 'ledgers': {'allocator_counts': {'malloc': 585, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}}
NORMAL_CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'format_32_nibbles', 'component': 'formatter', 'native_instructions': 637, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'format_literal', 'component': 'formatter', 'native_instructions': 259, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'format_mixed', 'component': 'formatter', 'native_instructions': 161, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'format_template_alias', 'component': 'formatter', 'native_instructions': 693, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'format_alphabet_alias', 'component': 'formatter', 'native_instructions': 693, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'format_seed_alias', 'component': 'formatter', 'native_instructions': 693, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'format_32_nibbles', 'component': 'formatter', 'native_instructions': 637, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'format_literal', 'component': 'formatter', 'native_instructions': 259, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'format_mixed', 'component': 'formatter', 'native_instructions': 161, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'format_template_alias', 'component': 'formatter', 'native_instructions': 693, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'format_alphabet_alias', 'component': 'formatter', 'native_instructions': 693, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'format_seed_alias', 'component': 'formatter', 'native_instructions': 693, 'original_formatter_and_two_state_advances_returned': True, 'declared_guest_image_and_entropy_scratch_equal': True, 'explicit_template_alphabet_and_output_alias_order_equal': True, 'no_file_allocator_or_JNI_services': True, 'native_snapshot_input': False, 'physical_spills_and_PAC_compared': False}]
ROLLBACK_SPECS=[{'case': 'wrong_target', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_packed', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'unaligned_stack', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_output', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'output_spill_alias', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'packed_spill_alias', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'first_guard_wait', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'second_guard_wait', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_thread_id', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_file_services', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'mutex_allocation_NULL', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'cache_allocation_NULL', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'file_open_failure', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'file_read_failure', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'file_close_failure', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'invalid_read_count', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'template_bound', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'entropy_bound', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'mutex_contention', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}]
def project_snapshot(row):
    row=dict(row);output=bytes.fromhex(row.pop('output_hex'));constants=bytes.fromhex(row.pop('globals_hex'));scratch=bytes.fromhex(row.pop('scratch_hex'))
    registers=row.pop('registers')
    row['registers']={f'x{n}':registers[n] for n in (0,30)}
    row['callee_saved_sha256']=hashlib.sha256(b''.join(int(registers[n],16).to_bytes(8,'little') for n in range(19,30))).hexdigest()
    row['output_width']=64;row['output_window_sha256']=hashlib.sha256(output).hexdigest()
    row['output_tail_sha256']=hashlib.sha256(output[OUTPUT_BYTES:]).hexdigest()
    row['constants_width']=128;row['constants_sha256']=hashlib.sha256(constants).hexdigest()
    row['seed_width']=16;row['seed_all_zero']=constants[32:48]==bytes(16)
    row['template_guard']=int.from_bytes(constants[88:92],'little');row['alphabet_guard']=int.from_bytes(constants[116:120],'little')
    if row['kind'] in ('returned','before_new24_BL'):
        payload=output.split(b'\0',1)[0]+b'\0'
        row['rendered_length']=len(payload)-1;row['payload_including_NUL_sha256']=hashlib.sha256(payload).hexdigest()
        row['scratch_after_all_zero']=scratch==bytes(16)
    return row

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data
def source_fingerprints():
    owners=dict(parent=previous,fixture=controls,identifier_model=identifier_owner,constants_model=constants_owner,oracle=oracle)
    return dict(formatter_return_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())
def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)
def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],
        component_inputs='fresh ELF fixtures with independent normal/zero seed inputs; no native snapshots supplied to semantic models',
        returned_X0='incidental formatter register value; no success-status meaning',
        exported_output='length, hashes and native write locations only; identifier bytes and raw seed are not exported',
        maximum_instruction_observations=MAX_OBSERVATIONS)
def claims_for():
    return dict(evidence_label='Sample verified',seed_failure_prefix_revalidated=True,original_formatter_returned=True,
        two_original_state_advances_verified=True,zero_seed_and_scratch_verified=True,output_byte_stores_and_tail_verified=True,
        SP_and_callee_saved_restored=True,three_prior_default_strings_write_protected=True,
        next_allocation_call_executed=False,current_identifier_callback_returned=False,current_identifier_published=False,
        new_providers_added=False,native_snapshot_used_as_python_model_input=False,real_ART_JVM_execution=False,
        complete_VM_suffix_return_verified=False,complete_standalone_signer_verified=False,Android_execution=False,
        physical_PAC_authentication_verified=False,online_acceptance_verified=False)
def read_static(path,libc):
    rows={}
    with path.open('rb') as f:
        elf=ELFFile(f)
        for off,size in CODE_RANGES['main']:
            raw=previous.previous.previous.elf_bytes(elf,f,off,size);rows['main:'+hex(off)]=dict(size=size,hex=raw.hex(),sha256=raw_hash(raw))
    return rows
def zero_specs():
    return [dict(image_base=hex(base),case='format_zero_seed',component='formatter',fresh_zero_input=True,
        original_formatter_and_two_state_advances_returned=True,declared_guest_image_and_entropy_scratch_equal=True,
        native_snapshot_input=False,physical_spills_and_PAC_compared=False) for base in controls.BASES]
def zero_control(path,libc,base):
    p=controls.fresh(path,base);controls._write_span(p,base+0x3DE470,bytes(16))
    constants_owner._lazy_constant(p,base,0x3DE4A8,0x97ED0,0x3DE480,0x97F40)
    constants_owner._lazy_constant(p,base,0x3DE4C4,0x97F00,0x3DE4B0,0x97F20)
    watch={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000}
    watch.update({(controls.G,0xA000):None,(controls.SP-0x50,16):None});advances=[]
    def observe(cpu,pc):
        if pc==base+0x255EC0:advances.append(True)
    oracle.native(path,base,FORMAT_TARGET,[controls.OUT],p,libc=libc,observed_memory=watch,
        instruction_observer=observe,instruction_limit=10000,
        extra_registers={arm.UC_ARM64_REG_SP:controls.SP,arm.UC_ARM64_REG_TPIDR_EL0:controls.TP})
    assert identifier_owner.generate_identifier(p,output_address=controls.OUT,entry_stack_address=controls.SP,image_base=base)==36
    assert advances==[True,True] and all(controls._read_span(p,a,n)==b for (a,n),b in watch.items())
    return next(x for x in zero_specs() if x['image_base']==hex(base))
def independent_controls(path,libc):
    rows=[controls.compare_format(path,libc,base,label) for base in controls.BASES for label in controls.FORMAT_PROFILES]
    rows.extend(zero_control(path,libc,base) for base in controls.BASES)
    rejected=controls.guards(path)
    assert rows==NORMAL_CONTROL_SPECS+zero_specs() and rejected==ROLLBACK_SPECS
    return rows,rejected

class IdentifierFormatterScenario(previous.IdentifierSeedOpenFailureScenario):
    def __init__(self,control):
        super().__init__(control)
        self._idfmt_active=False;self._idfmt_done=False;self._idfmt_returned=False
        self._idfmt_count=0;self._idfmt_trace=[];self._idfmt_code={};self._idfmt_rows=[];self._idfmt_writes=[]

    def _idfmt_track(self,cpu,pc):
        self._idfmt_count+=1;assert self._idfmt_count<20000
        domain,off=('libc',pc-0x51000000) if 0x51000000<=pc<0x51200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._idfmt_trace.append(key);self._idfmt_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _idfmt_snapshot(self,cpu,pc,kind):
        row=dict(kind=kind,index=self._idfmt_count,pc=hex(pc-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            registers=[hex(self._reg(cpu,n)) for n in range(31)],output_address=hex(self._idfmt_output),
            output_hex=bytes(cpu.mem_read(self._idfmt_output,64)).hex(),scratch_hex=bytes(cpu.mem_read(self._idfmt_sp-0x50,16)).hex(),
            globals_hex=bytes(cpu.mem_read(self.image+0x3DE450,0x80)).hex(),
            descriptor_hex=bytes(cpu.mem_read(self._idopen_descriptor,48)).hex(),
            cache_globals_hex=bytes(cpu.mem_read(self.image+0x3DE700,64)).hex(),
            cache_mutex_hex=bytes(cpu.mem_read(self._seedfail_mutex,48)).hex(),cache_pair_hex=bytes(cpu.mem_read(self._seedfail_pair,16)).hex(),
            output_reference_hex=bytes(cpu.mem_read(self._idopen_output,16)).hex(),errno=self._u(cpu,self._seedfail_errno,4),
            prior_objects=[dict(object_address=x['object_address'],payload_address=x['payload_address'],object_hex=bytes(cpu.mem_read(int(x['object_address'],16),24)).hex(),payload_hex=bytes(cpu.mem_read(int(x['payload_address'],16),8)).hex()) for x in self._idopen_prior])
        self._idfmt_rows.append(project_snapshot(row))

    def _idfmt_start(self,cpu,pc,state):
        self._seedfail_track(cpu,pc);self._seedfail_snapshot(cpu,pc,'before_formatter_BL')
        old=prior_evidence()['case_result'];self._idfmt_old=old
        h=hashlib.sha256()
        for key in self._seedfail_trace:h.update(key.encode()+bytes.fromhex(self._seedfail_code[key]))
        pairs=((self._seedfail_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),(previous.digest(self._seedfail_code),'observed_code_sha256'),
            (self._seedfail_trace,'observation_sites'),(self._seedfail_code,'observed_code'),(self._seedfail_rows,'snapshots'),(self._seedfail_writes,'native_writes'),(self._seedfail_syscalls,'syscalls'))
        for value,key in pairs:assert value==old[key],key
        self._idfmt_events=deepcopy(state['allocator_events_ref']);assert self._idfmt_events[len(self._seedfail_events):]==old['new_allocator_events']
        self._idfmt_output=self._reg(cpu,0);self._idfmt_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        self._seedfail_active=False;self._seedfail_done=False;self._idfmt_active=True
        self._idfmt_track(cpu,pc);self._idfmt_snapshot(cpu,pc,'formatter_BL')

    def native_runner(self,*args,**kwargs):
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._idfmt_active:
                protected=self._idopen_ranges+[(self._idopen_descriptor,48),(self._seedfail_mutex,48),(self._seedfail_pair,16),(self._idopen_output,16)]
                if any(address<a+n and a<address+size for a,n in protected):raise AssertionError('formatter wrote protected state')
                spans=((self._idfmt_output,64),(self._idfmt_sp-0x50,16),(self.image+0x3DE450,0x80))
                if any(address<a+n and a<address+size for a,n in spans):
                    self._idfmt_writes.append(dict(index=self._idfmt_count,PC=hex(cpu.reg_read(arm.UC_ARM64_REG_PC)-self.image),address=hex(address),size=size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._idfmt_active:
            if self._seedfail_active and pc==self.image+previous.FORMAT_CALL:
                self._idfmt_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._idfmt_track(cpu,pc);off=pc-self.image
        if off in (0x255D84,0x255EC0,0x25BD20):
            self._idfmt_snapshot(cpu,pc,'returned' if off==0x25BD20 else 'path')
            if off==0x25BD20:assert bytes(cpu.mem_read(self._idfmt_sp-0x50,16))==bytes(16)
        if off==0x25BD20:self._idfmt_returned=True
        if off==0x25BD24:
            assert self._idfmt_returned
            self._idfmt_snapshot(cpu,pc,'before_new24_BL');self._idfmt_done=True
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.previous.previous.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._idfmt_done
        h=hashlib.sha256()
        for key in self._idfmt_trace:h.update(key.encode()+bytes.fromhex(self._idfmt_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        old=self._idfmt_old
        assert result['allocator_events']==self._idfmt_events
        for key,value in ledgers.items():assert value==old[key],key
        return dict(control=old['control'],retained_seed_failure=dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._idfmt_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._idfmt_code),
            snapshots=self._idfmt_rows,native_writes=self._idfmt_writes,observation_sites=self._idfmt_trace,observed_code=self._idfmt_code,
            new_allocator_events=[],protected_write_events=[],**ledgers,
            stop_boundary=dict(kind='before_identifier_new24_BL',stop_before=hex(NEXT_CALL),call_executed=False,target_executed=False))

def run(path,libc):
    parent=prior_evidence();p=previous.previous.previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=IdentifierFormatterScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    controls,guards=independent_controls(path,libc)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),
        static_code=code,native_controls=controls,component_rollback_checks=guards,case_result=rows[0],case_result_sha256=digest(rows[0]))
def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_controls']==NORMAL_CONTROL_SPECS+zero_specs() and data['component_rollback_checks']==ROLLBACK_SPECS
    assert len(data['native_controls'])==14 and len(ROLLBACK_SPECS)==19
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert row['retained_seed_failure']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[0]=='main:'+hex(FORMAT_CALL) and sites[-1]=='main:'+hex(NEXT_CALL)
    assert sites.count('main:'+hex(FORMAT_TARGET))==1 and sites.count('main:0x255ec0')==2
    assert 'main:'+hex(NEXT_TARGET) not in sites
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4 and raw!=bytes.fromhex('010000d4');h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256'] and digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    assert row['snapshots']==EXPECTED['snapshots'] and row['native_writes']==EXPECTED['native_writes']
    before=row['snapshots'][0];returned=next(x for x in row['snapshots'] if x['kind']=='returned');stop=row['snapshots'][-1]
    output=int(before['output_address'],16);base=row['control']['base'];stack=int(before['SP'],16)
    stores=[x for x in row['native_writes'] if output<=int(x['address'],16)<output+64]
    assert [(int(x['address'],16)-output,x['size']) for x in stores]==[(i,1) for i in range(OUTPUT_BYTES)]
    seed_stores=[x for x in row['native_writes'] if base+0x3DE470<=int(x['address'],16)<base+0x3DE480]
    assert [(int(x['address'],16)-(base+0x3DE470),x['size']) for x in seed_stores]==[(0,8),(8,8)]*2
    scratch_stores=[x for x in row['native_writes'] if stack-0x50<=int(x['address'],16)<stack-0x40]
    assert [(int(x['address'],16)-(stack-0x50),x['size']) for x in scratch_stores]==[(0,8),(8,8)]
    assert before['kind']=='formatter_BL' and stop['kind']=='before_new24_BL' and stop['registers']['x0']=='0x18'
    assert returned['pc']==hex(FORMAT_RETURN) and before['SP']==returned['SP']==stop['SP']
    assert before['callee_saved_sha256']==returned['callee_saved_sha256']==stop['callee_saved_sha256']
    assert before['output_tail_sha256']==returned['output_tail_sha256']==stop['output_tail_sha256']
    assert returned['rendered_length']==stop['rendered_length']==36 and returned['payload_including_NUL_sha256']==stop['payload_including_NUL_sha256']
    assert returned['scratch_after_all_zero'] is stop['scratch_after_all_zero'] is True
    assert all(x['seed_all_zero'] is True for x in row['snapshots'])
    assert before['template_guard']==before['alphabet_guard']==0 and returned['template_guard']==returned['alphabet_guard']==1
    parent_stop=old['snapshots'][-1]
    for x in row['snapshots']:
        for key in ('descriptor_hex','cache_mutex_hex','cache_pair_hex','prior_objects','errno'):assert x[key]==parent_stop[key],key
        assert x['output_reference_hex']==parent_stop['output_hex']
        assert x['cache_globals_hex']==parent_stop['globals_3de700_hex']
    output=int(before['registers']['x0'],16);base=row['control']['base'];scratch=int(before['SP'],16)-0x50
    stores=[x for x in row['native_writes'] if output<=int(x['address'],16)<output+OUTPUT_BYTES]
    assert [int(x['address'],16)-output for x in stores]==list(range(OUTPUT_BYTES)) and all(x['size']==1 for x in stores)
    seed_stores=[x for x in row['native_writes'] if base+0x3DE470<=int(x['address'],16)<base+0x3DE480]
    assert len(seed_stores)==4 and all(x['size']==8 for x in seed_stores)
    scratch_stores=[x for x in row['native_writes'] if scratch<=int(x['address'],16)<scratch+16]
    assert len(scratch_stores)==2 and all(x['size']==8 for x in scratch_stores)
    for key,value in EXPECTED['ledgers'].items():assert row[key]==value==old[key],key
    assert row['new_allocator_events']==row['protected_write_events']==[]
    assert row['stop_boundary']==dict(kind='before_identifier_new24_BL',stop_before=hex(NEXT_CALL),call_executed=False,target_executed=False)
def damaged_evidence_rejected(data):
    changes=[(('claims','next_allocation_call_executed'),True),(('claims','current_identifier_callback_returned'),True),(('claims','complete_standalone_signer_verified'),True),
        (('providers','new_providers'),['hidden']),(('source_fingerprints','owners','identifier_model'),'0'*64),
        (('case_result','retained_seed_failure','case_result_sha256'),'0'*64),(('case_result','instruction_observations'),0),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'rendered_length'),0),(('case_result','snapshots',-1,'payload_including_NUL_sha256'),'0'*64),
        (('case_result','snapshots',-1,'seed_all_zero'),False),(('case_result','snapshots',-1,'callee_saved_sha256'),'0'*64),
        (('case_result','snapshots',-1,'output_tail_sha256'),'0'*64),(('case_result','snapshots',-1,'scratch_after_all_zero'),False),
        (('case_result','snapshots',-1,'template_guard'),0),(('case_result','native_writes',0,'size'),99),
        (('case_result','protected_write_events'),['hidden']),(('case_result','new_allocator_events'),[['alloc',24,0,'0x0']]),
        (('case_result','stop_boundary','call_executed'),True),(('native_controls',-1,'fresh_zero_input'),False),
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
        raise AssertionError(f'damaged formatter evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh formatter replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],original_formatter_returned=True,next_allocation_call_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
