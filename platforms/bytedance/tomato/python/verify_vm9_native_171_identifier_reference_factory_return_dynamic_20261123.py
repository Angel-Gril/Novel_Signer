"""Verify original identifier reference construction and factory return."""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib,json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import arm64_const as arm
import verify_vm9_native_171_identifier_string_constructor_return_dynamic_20261123 as previous
import verify_vm9_reference_scopes_fresh_20261011 as controls
import verify_vm9_signer_objects as oracle
import vm9_reference_scopes as model
import vm9_diagnostics as diagnostics
import vm9_libc_stdio as mutex_owner
import vm9_objects as objects
from vm9_allocator import RefillUnsupported,_read_span

EVIDENCE=previous.EVIDENCE.with_name('vm9_native_171_identifier_reference_factory_return_dynamic_20261123.json')
SCHEMA='vm9-native-171-identifier-reference-factory-return-dynamic-20261123-v1'
LIBC_BASE,MALLOC=0x51000000,0x1BB08
START,TARGET,REFERENCE_RETURN,FACTORY_RETURN,NEXT,NEXT_TARGET=0x25BD3C,0x1625A4,0x25BD40,0x25BE10,0x25BE18,0x162620
MAX_OBSERVATIONS=100000
sha256,raw_hash,digest=previous.sha256,previous.raw_hash,previous.digest
PARENT_FIELDS=('instruction_observations','instruction_trace_sha256','observed_code_sha256','observation_sites','observed_code','snapshots','native_writes','services','copy_provider_effects')
CODE_RANGES={'main': ((2473276, 40), (1451428, 124), (2541656, 376), (2542032, 56), (3318256, 68), (2473488, 12), (1451552, 16)), 'libc': ((113416, 32),)}
CODE_SHA256={'main:0x25bd3c': '2b87ce68dd64f027dc10e8b39d8842a34423ce913441d2de1598dd1170e25870', 'main:0x1625a4': '81b1e07c037a75bb2351d272601cd8105a0e5e3a075a9e7b78dbb793dd1dcc12', 'main:0x26c858': 'b75151cac29171eaa6ef6504fac3fcae1211fe272854b03409c011148f0394f1', 'main:0x26c9d0': '42142fa411128645eae4a067794bd0fa3233096f476550a1957dff74059fb04e', 'main:0x32a1f0': '1285abf973bc20a918e0476d0a8132f5085bf3666e7f62356aff3d69c76ccfe0', 'main:0x25be10': '778f8b1346344edf0006c941147ed6a99f944d4637ea912595153e093f810f43', 'main:0x162620': '7911a034e6c0161335f6891aad482181ffe2472ec5b7ee91a1bacb9573274d71', 'libc:0x1bb08': '5f183f5bc3ff80cac083022481d5449cfdceaa89cc15ff71781be915fc836b36'}
EXPECTED={'instruction_observations': 1485, 'instruction_trace_sha256': '31ef567d22aaac8a2a752b610b2551dccae6e4213606dc5aca381d13dd625a91', 'observed_code_sha256': '7a232403d3be44928e8026909a6ca1260cb8a51d0aedba2e4e7537f1367ebe04', 'snapshots': [{'kind': 'reference_BL', 'index': 1, 'pc': '0x25bd3c', 'SP': '0x7004b850', 'registers': {'x0': '0x7004b8c0', 'x30': '0x1251bd34'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pair_sha256': '41f4affe829f6dd3a916ee86b43efb48c63a59b47b2b6a85b06d20ed8be399bd', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': 'b91d595594d1c83da22777beb7ad3846988f65ecb584be3a2391c2a491b1900f', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x0', 'table_sha256': 'd9c1f9f0755700ccf2c8ab5f4783a28b81667f24f04e953ee6c4b25ba359f996', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468'}, 'errno': 2}, {'kind': 'reference_entry', 'index': 2, 'pc': '0x1625a4', 'SP': '0x7004b850', 'registers': {'x0': '0x7004b8c0', 'x30': '0x1251bd40'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pair_sha256': '41f4affe829f6dd3a916ee86b43efb48c63a59b47b2b6a85b06d20ed8be399bd', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': 'b91d595594d1c83da22777beb7ad3846988f65ecb584be3a2391c2a491b1900f', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x0', 'table_sha256': 'd9c1f9f0755700ccf2c8ab5f4783a28b81667f24f04e953ee6c4b25ba359f996', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468'}, 'errno': 2}, {'kind': 'scope_enter', 'index': 15, 'pc': '0x26c858', 'SP': '0x7004b800', 'registers': {'x0': '0x7004b800', 'x30': '0x124225d8'}, 'callee_saved_sha256': 'd54664542fb4453d879db7a1b6a93aaae3c31dc57fd3ee4d2675ccb70bbea464', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x0', 'reference_counter': '0x0', 'reference_pair_sha256': '374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': 'b91d595594d1c83da22777beb7ad3846988f65ecb584be3a2391c2a491b1900f', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x0', 'table_sha256': 'd9c1f9f0755700ccf2c8ab5f4783a28b81667f24f04e953ee6c4b25ba359f996', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468'}, 'errno': 2}, {'kind': 'scope_entered', 'index': 835, 'pc': '0x1625d8', 'SP': '0x7004b800', 'registers': {'x0': '0x0', 'x30': '0x124225d8'}, 'callee_saved_sha256': 'd54664542fb4453d879db7a1b6a93aaae3c31dc57fd3ee4d2675ccb70bbea464', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x0', 'reference_counter': '0x0', 'reference_pair_sha256': '374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'errno': 2, 'scope_vtable': '0x1261d410', 'scope_lock_result': 0, 'scope_input': '0x136d9640'}, {'kind': 'counter_allocation_return', 'index': 1410, 'pc': '0x1625e4', 'SP': '0x7004b800', 'registers': {'x0': '0x136d82e0', 'x30': '0x124225e4'}, 'callee_saved_sha256': 'd54664542fb4453d879db7a1b6a93aaae3c31dc57fd3ee4d2675ccb70bbea464', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x0', 'reference_pair_sha256': '90e0533da84ac690422c5ab8d6460cd15dcd73c4b79f846e7e71e10d7ad8de4e', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_before_sha256': 'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119'}, {'kind': 'counter_published', 'index': 1413, 'pc': '0x1625f0', 'SP': '0x7004b800', 'registers': {'x0': '0x136d82e0', 'x30': '0x124225e4'}, 'callee_saved_sha256': 'd54664542fb4453d879db7a1b6a93aaae3c31dc57fd3ee4d2675ccb70bbea464', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x136d82e0', 'reference_pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_u32': 1, 'scope_vtable': '0x1261d410', 'scope_lock_result': 0, 'scope_input': '0x136d9640'}, {'kind': 'scope_leave', 'index': 1415, 'pc': '0x26c9d0', 'SP': '0x7004b800', 'registers': {'x0': '0x7004b800', 'x30': '0x124225f8'}, 'callee_saved_sha256': 'd54664542fb4453d879db7a1b6a93aaae3c31dc57fd3ee4d2675ccb70bbea464', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x136d82e0', 'reference_pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': 'd43b28afb0a49f6346653166966d967b92078bd470c47cfb2fd28e757f12bf88', 'mutex_state_u16': 16385, 'owner_u32': 137}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_u32': 1}, {'kind': 'scope_left', 'index': 1465, 'pc': '0x1625f8', 'SP': '0x7004b800', 'registers': {'x0': '0x0', 'x30': '0x124225f8'}, 'callee_saved_sha256': 'd54664542fb4453d879db7a1b6a93aaae3c31dc57fd3ee4d2675ccb70bbea464', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x136d82e0', 'reference_pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_u32': 1, 'scope_vtable': '0x1261d410', 'scope_lock_result': 0, 'scope_input': '0x136d9640'}, {'kind': 'reference_return', 'index': 1474, 'pc': '0x25bd40', 'SP': '0x7004b850', 'registers': {'x0': '0x0', 'x30': '0x1251bd40'}, 'callee_saved_sha256': 'b2ac24a9d43089425e2035ffb26a087cc998958fd8e19de1f19486d0190e21ae', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x136d82e0', 'reference_pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_u32': 1, 'scope_vtable': '0x1261d410', 'scope_lock_result': 0, 'scope_input': '0x136d9640'}, {'kind': 'factory_return', 'index': 1483, 'pc': '0x25be10', 'SP': '0x7004b8b0', 'registers': {'x0': '0x0', 'x30': '0x1251be10'}, 'callee_saved_sha256': '3a127a8e0b61623c7efa05f768a073d016bb0547773cde3792c4ab902d676580', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x136d82e0', 'reference_pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_u32': 1, 'scope_vtable': '0x1261d410', 'scope_lock_result': 0, 'scope_input': '0x136d9640'}, {'kind': 'before_output_assign_BL', 'index': 1485, 'pc': '0x25be18', 'SP': '0x7004b8b0', 'registers': {'x0': '0x7004d178', 'x30': '0x1251be10'}, 'callee_saved_sha256': '3a127a8e0b61623c7efa05f768a073d016bb0547773cde3792c4ab902d676580', 'protected_regions_sha256': 'a8f519d46e4b7a26504b303c522a4bb1fa4e2ce44f7745802fc4cfb61214271d', 'reference_address': '0x7004b8c0', 'reference_pointer': '0x136d9640', 'reference_counter': '0x136d82e0', 'reference_pair_sha256': '6211c6b9b9c7de14d4b8f444d0bdebb6a72dce169791ef030027235e3cd6abc7', 'string_address': '0x136d9640', 'payload_length': 36, 'payload_including_NUL_sha256': '4cc2531a26c0713055a47506664a952cf941a2a65ae6c4c14c9782b0a71b898c', 'scope_address': '0x7004b800', 'scope_sha256': '0670dfcb14c22a9320d622fcd5311ba212b31f6e6226eac74210b7a9be342f66', 'diagnostic': {'global_lock': '0x136d3c60', 'guard': '0x8900000101', 'table': '0x136f8000', 'index': 100, 'slot': '0x136f8320', 'entry': '0x136d4080', 'table_sha256': '634bc15d623492307c9cafb0ef9c70e9aacc9d1691c783d491787cc9c010264c', 'global_lock_sha256': 'efc34a131ef2b8eee1cb12852fac9699ec62dbdc3b78d4eb1a14e61024aed468', 'entry_sha256': '71d5fb7cc4c9d71afe67552cc86ae29869e38f65815223d0356447b08155dc84', 'mutex_state_u16': 16384, 'owner_u32': 0}, 'errno': 2, 'counter_address': '0x136d82e0', 'counter_u32': 1, 'scope_vtable': '0x1261d410', 'scope_lock_result': 0, 'scope_input': '0x136d9640'}], 'native_writes': [{'index': 12, 'PC': 'main:0x1625cc', 'address': '0x7004b8c0', 'size': 8}, {'index': 12, 'PC': 'main:0x1625cc', 'address': '0x7004b8c8', 'size': 8}, {'index': 32, 'PC': 'main:0x26c89c', 'address': '0x7004b800', 'size': 8}, {'index': 33, 'PC': 'main:0x26c8a0', 'address': '0x7004b808', 'size': 4}, {'index': 34, 'PC': 'main:0x26c8a4', 'address': '0x7004b810', 'size': 8}, {'index': 65, 'PC': 'libc:0x68d3c', 'address': '0x136d3c68', 'size': 2}, {'index': 661, 'PC': 'main:0x15ded0', 'address': '0x136d4080', 'size': 8}, {'index': 688, 'PC': 'libc:0x68c8c', 'address': '0x136d4088', 'size': 8}, {'index': 688, 'PC': 'libc:0x68c8c', 'address': '0x136d4090', 'size': 8}, {'index': 689, 'PC': 'libc:0x68c90', 'address': '0x136d4098', 'size': 8}, {'index': 689, 'PC': 'libc:0x68c90', 'address': '0x136d40a0', 'size': 8}, {'index': 690, 'PC': 'libc:0x68c94', 'address': '0x136d40a8', 'size': 8}, {'index': 702, 'PC': 'libc:0x68ce0', 'address': '0x136d4088', 'size': 2}, {'index': 704, 'PC': 'libc:0x68ce8', 'address': '0x136d408c', 'size': 4}, {'index': 724, 'PC': 'main:0x26c94c', 'address': '0x136f8320', 'size': 8}, {'index': 748, 'PC': 'libc:0x68dc0', 'address': '0x136d3c68', 'size': 2}, {'index': 806, 'PC': 'libc:0x68ba0', 'address': '0x136d4088', 'size': 2}, {'index': 810, 'PC': 'libc:0x68bb8', 'address': '0x136d408c', 'size': 4}, {'index': 824, 'PC': 'main:0x26c964', 'address': '0x7004b808', 'size': 4}, {'index': 836, 'PC': 'main:0x1625dc', 'address': '0x7004b8c0', 'size': 8}, {'index': 1411, 'PC': 'main:0x1625e8', 'address': '0x7004b8c8', 'size': 8}, {'index': 1412, 'PC': 'main:0x1625ec', 'address': '0x136d82e0', 'size': 4}, {'index': 1418, 'PC': 'main:0x26c9dc', 'address': '0x7004b800', 'size': 8}, {'index': 1451, 'PC': 'libc:0x68e48', 'address': '0x136d408c', 'size': 4}, {'index': 1454, 'PC': 'libc:0x68e54', 'address': '0x136d4088', 'size': 2}], 'services': [{'index': 51, 'PC': '0x347f00', 'kind': 'pthread_mutex_lock', 'argument': '0x136d3c68'}, {'index': 84, 'PC': '0x347fd0', 'kind': 'actual_Bionic_malloc_route', 'argument': '0x30'}, {'index': 85, 'PC': 'libc:0x1bb08', 'kind': 'actual_Bionic_malloc_entry', 'request': 48}, {'index': 735, 'PC': '0x347f10', 'kind': 'pthread_mutex_unlock', 'argument': '0x136d3c68'}, {'index': 762, 'PC': '0x347f00', 'kind': 'pthread_mutex_lock', 'argument': '0x136d4088'}, {'index': 846, 'PC': '0x347fd0', 'kind': 'actual_Bionic_malloc_route', 'argument': '0x4'}, {'index': 847, 'PC': 'libc:0x1bb08', 'kind': 'actual_Bionic_malloc_entry', 'request': 4}, {'index': 1428, 'PC': '0x347f10', 'kind': 'pthread_mutex_unlock', 'argument': '0x136d4088'}], 'new_allocator_events': [['alloc', 48, 325927040, '0x32a210'], ['alloc', 4, 325944032, '0x32a210']], 'ledgers': {'allocator_counts': {'malloc': 589, 'free': 268, 'gc': 3, 'flush': 4}, 'inherited_service_counts': {'syscall_214': 1, 'syscall_222': 4, 'syscall_167': 3, 'syscall_226': 9, 'syscall_56': 6, 'syscall_80': 1, 'syscall_215': 2, 'syscall_63': 2, 'syscall_57': 4, 'clock': 11, 'virtual_pthread_create': 3, 'destructor_registration': 6, 'syscall_98': 18, 'property_find': 1, 'syscall_48': 4, 'syscall_79': 4, 'mkdir_exists': 2, 'syscall_169': 1}, 'inherited_JNI_calls': [{'slot': '0x30', 'result': 'NULL_or_false', 'caller': '0x28b720', 'name_length': 16, 'name_sha256': '674974bfb306a63dffbadadb01e512fed1a7b123b621e95b0ab7eb1df382b953'}, {'slot': '0x720', 'result': 'NULL_or_false', 'caller': '0x28b7a8'}], 'inherited_libc_SVC': [{'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x1bf1c', 'number': 98}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a550', 'number': 226}, {'libc_pc': '0x6a6a0', 'number': 56}], 'inherited_main_SVC': [{'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 30, 'pathname_sha256': '65b853a9305efa071073838f3717c76cb024434ea62b2fa43839d220bc58a522', 'mode': 4}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 29, 'pathname_sha256': 'd939e7f74a175391b0c9842e9b124f06fce6f1f3492172d33e85aa223c25ad0d', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 79, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 5, 'pathname_sha256': 'bd47413b5c03dfc6e4b5b8143fe205eae10ecaf0c28b426be98d74cff48c7453', 'stat_buffer_in_native_stack': True, 'stat_buffer_size': 128, 'stat_buffer_SP_offset': 88, 'return_pc': '0x272d68'}, {'native_pc': '0x271dbc', 'bytecode': '0xfca40', 'number': 48, 'dirfd_u32': 4294967196, 'flags': 0, 'pathname_length': 76, 'pathname_sha256': '8779738fdeb7040b32e1a49384bb7c459ea7d249005cd732e07bd2953f5a95c5', 'mode': 4, 'return_pc': '0x27308c'}], 'inherited_syscall_172': [{'libc_svc_offset': '0x6b030', 'number': 172, 'provider': 'explicit synthetic result', 'result': 919}], 'inherited_syscall_173': [{'libc_svc_offset': '0x6a370', 'number': 173, 'provider': 'explicit synthetic parent PID', 'result': 17}], 'late_jni': [{'slot': '0x388', 'label': 'GetStaticMethodID_method_fixture', 'caller': '0x204d84', 'args': ['0x70007800', '0x0', '0x1269a014', '0x1269a01c'], 'result': '0x70006a00', 'name_length': 1, 'name_sha256': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', 'signature_length': 3, 'signature_sha256': 'da8c82d5d4030588e2a67b1a25ad09d678e03e02b7d22a6f7b214e880ccb0c1c', 'return_kind': 'void', 'class_argument_is_null': True}, {'slot': '0x720', 'label': 'ExceptionCheck_clear', 'caller': '0x204d94', 'args': ['0x70007800'], 'result': '0x0'}], 'java_dispatch': [{'arguments': ['0x1000011', '0x0', '0x0', '0x0', '0x0'], 'entry_sp': '0x7004b850', 'caller': '0x1cf6c8'}]}, 'protected_ranges': [{'address': '0x7004d118', 'size': 24}, {'address': '0x136d82c0', 'size': 8}, {'address': '0x7004d130', 'size': 24}, {'address': '0x136d82d0', 'size': 8}, {'address': '0x7004d148', 'size': 24}, {'address': '0x136d82d8', 'size': 8}, {'address': '0x7004cbe8', 'size': 48}, {'address': '0x136d4020', 'size': 48}, {'address': '0x136d73a0', 'size': 16}, {'address': '0x7004d178', 'size': 16}, {'address': '0x1269e700', 'size': 64}, {'address': '0x1269e450', 'size': 128}, {'address': '0x7004b850', 'size': 64}, {'address': '0x7000a010', 'size': 4}, {'address': '0x136d9640', 'size': 24}, {'address': '0x136d4050', 'size': 37}], 'factory_saved_sha256': '3a127a8e0b61623c7efa05f768a073d016bb0547773cde3792c4ab902d676580'}
CONTROL_SPECS=[{'image_base': '0x122c0000', 'case': 'string', 'warm_locks': False, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'NULL_string', 'warm_locks': False, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'string', 'warm_locks': True, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x122c0000', 'case': 'NULL_string', 'warm_locks': True, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'string', 'warm_locks': False, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'NULL_string', 'warm_locks': False, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'string', 'warm_locks': True, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}, {'image_base': '0x775c205000', 'case': 'NULL_string', 'warm_locks': True, 'original_reference_constructor_returned': True, 'declared_guest_payload_image_and_scope_equal': True, 'ordered_allocations_and_lock_effects_equal': True, 'counter_initial_value': 1, 'SP_and_callee_saved_restored': True, 'explicit_synthetic_allocator': True, 'native_snapshot_input': False, 'physical_PAC_compared': False}]
ROLLBACK_SPECS=[{'case': 'unaligned_stack', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'unmapped_scope', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'guard_wait', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}, {'case': 'missing_allocator', 'rejected': True, 'all_pages_unchanged': True, 'external_provider_effects_rolled_back': False}]
def project_snapshot(row):
    row=dict(row)
    if row['kind'] in ('reference_BL','reference_entry'):
        row.pop('reference_pointer');row.pop('reference_counter')
    if row['kind']=='counter_allocation_return':
        row['counter_before_sha256']=raw_hash(row.pop('counter_u32').to_bytes(4,'little'))
    return row

def prior_evidence():
    data=json.loads(previous.EVIDENCE.read_text(encoding='utf-8'));previous.validate(data);return data

def source_fingerprints():
    owners=dict(parent=previous,fixture=controls,reference_model=model,diagnostics_model=diagnostics,mutex_model=mutex_owner,objects_model=objects,oracle=oracle)
    return dict(reference_factory_verifier_sha256=sha256(Path(__file__)),owners={k:sha256(Path(v.__file__)) for k,v in owners.items()},inherited=previous.source_fingerprints())

def provenance(parent):
    return dict(parent_evidence_sha256=sha256(previous.EVIDENCE),parent_case_result_sha256=digest(parent['case_result']),inherited_input_provenance=parent['input_provenance'],native_snapshot_used_as_python_model_input=False)

def providers():
    return dict(inherited=previous.providers(),new_providers=[],new_import_bindings=[],allocator='inherited original matching Bionic malloc',
        component_services='fresh independent ELF fixtures; synthetic allocation and explicit thread id with matching Bionic mutex bodies',
        returned_X0='incidental reference/factory register value; not interpreted as the object or counter result',
        exported_output='lengths, hashes, initialized pointers/counters and write locations only; no raw identifier or seed bytes',
        maximum_instruction_observations=MAX_OBSERVATIONS)

def claims_for():
    return dict(evidence_label='Sample verified',string_constructor_prefix_revalidated=True,original_reference_constructor_returned=True,
        original_identifier_factory_returned=True,temporary_reference_and_count_one_verified=True,diagnostic_entry_and_exit_verified=True,
        factory_SP_and_callee_saved_restored=True,prior_objects_string_payload_descriptor_cache_output_and_errno_write_protected=True,
        next_output_assignment_executed=False,current_identifier_getter_returned=False,current_identifier_published=False,
        new_providers_added=False,native_snapshot_used_as_python_model_input=False,complete_VM_suffix_return_verified=False,
        complete_standalone_signer_verified=False,real_ART_JVM_execution=False,Android_execution=False,physical_PAC_authentication_verified=False,online_acceptance_verified=False)

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
BASES=(0x122C0000,0x775C205000)

def compare(path,libc,base,warm,null_object):
    p,blocks,destination,pointer=controls.fixture(path,base,'construct',warm=warm,null_object=null_object)
    expected=controls.Services(blocks);actual=controls.Services(blocks)
    observed={(page<<12,4096):None for page in p if base<=page<<12<base+0x400000};observed[controls.SP-0x50,24]=None
    saved={getattr(arm,f'UC_ARM64_REG_X{n}'):0x810000+n for n in range(19,30)};returned=[]
    def watch(cpu,pc):
        off=pc-base
        if off in (0x347F00,0x347F10):expected.diagnostic('pthread_mutex_lock' if off==0x347F00 else 'pthread_mutex_unlock',cpu.reg_read(arm.UC_ARM64_REG_X0))
        if off==0x348310:expected.diagnostic('gettid',137)
        if off==0x162618:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==controls.SP and all(cpu.reg_read(r)==v for r,v in saved.items());returned.append(True)
    _,memory,_,_=oracle.native(path,base,0x1625A4,[controls.OUT,pointer],p,libc=libc,
        real_diagnostics=True,real_singletons=True,real_mutexes=True,real_recursive_mutexes=True,
        extra_registers={**saved,arm.UC_ARM64_REG_TPIDR_EL0:controls.TP},thread_id=137,
        malloc_handler=expected.native_malloc,observed_memory=observed,instruction_observer=watch,instruction_limit=100000)
    counter=model.construct_scoped_string_reference(p,reference_address=controls.OUT,string_address=pointer,
        entry_stack_address=controls.SP,image_base=base,thread_pointer=controls.TP,thread_id=137,
        allocate=actual.malloc,diagnostic_observer=actual.diagnostic)
    assert _read_span(p,controls.G,0xA000)==memory and all(_read_span(p,a,n)==data for (a,n),data in observed.items())
    assert actual.events==expected.events and actual.effects.calls==expected.effects.calls and actual.effects.blocks==expected.effects.blocks
    assert actual.freed==expected.freed==[] and returned==[True]
    assert controls.u(p,controls.OUT)==pointer and controls.u(p,controls.OUT+8)==counter and controls.u(p,counter,4)==1
    return dict(image_base=hex(base),case='NULL_string' if null_object else 'string',warm_locks=warm,
        original_reference_constructor_returned=True,declared_guest_payload_image_and_scope_equal=True,
        ordered_allocations_and_lock_effects_equal=True,counter_initial_value=1,SP_and_callee_saved_restored=True,
        explicit_synthetic_allocator=True,native_snapshot_input=False,physical_PAC_compared=False)

def guards(path):
    rows=[];base=BASES[0]
    for failure in ('unaligned_stack','unmapped_scope','guard_wait','missing_allocator'):
        p,blocks,destination,pointer=controls.fixture(path,base,'construct');service=controls.Services(blocks)
        kw=dict(entry_stack_address=controls.SP,image_base=base,thread_pointer=controls.TP,thread_id=137,allocate=service.malloc,diagnostic_observer=service.diagnostic)
        if failure=='unaligned_stack':kw['entry_stack_address']=controls.SP-1
        elif failure=='unmapped_scope':kw['entry_stack_address']=0x66001000
        elif failure=='guard_wait':controls.w(p,base+diagnostics.GUARD+1,2,1)
        else:kw['allocate']=None
        before={k:bytes(v) for k,v in p.items()}
        try:model.construct_scoped_string_reference(p,reference_address=controls.OUT,string_address=pointer,**kw)
        except (RefillUnsupported,ValueError,TypeError):pass
        else:raise AssertionError(failure)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(case=failure,rejected=True,all_pages_unchanged=True,external_provider_effects_rolled_back=False))
    return rows

def independent_controls(path,libc):
    cases=[]
    for base in BASES:
        for warm in (False,True):
            for null_object in (False,True):
                cases.append(compare(path,libc,base,warm,null_object));print('PASS reference constructor',hex(base),warm,null_object,flush=True)
    negative=guards(path)
    assert cases==CONTROL_SPECS and negative==ROLLBACK_SPECS
    return cases,negative

class IdentifierReferenceFactoryScenario(previous.IdentifierStringConstructorScenario):
    def __init__(self,control):
        super().__init__(control)
        self._idref_active=False;self._idref_done=False;self._idref_reference_returned=False;self._idref_factory_returned=False
        self._idref_count=0;self._idref_trace=[];self._idref_code={};self._idref_rows=[];self._idref_writes=[];self._idref_services=[]
        self._idref_counter=0

    def _idref_track(self,cpu,pc):
        self._idref_count+=1;assert self._idref_count<MAX_OBSERVATIONS
        domain,off=('libc',pc-LIBC_BASE) if LIBC_BASE<=pc<LIBC_BASE+0x200000 else ('main',pc-self.image)
        assert domain=='libc' or 0<=off<0x400000
        key=domain+':'+hex(off);self._idref_trace.append(key);self._idref_code[key]=bytes(cpu.mem_read(pc,4)).hex()

    def _idref_protected_hash(self,cpu):
        h=hashlib.sha256()
        for a,n in self._idref_protected:h.update(a.to_bytes(8,'little')+n.to_bytes(8,'little')+bytes(cpu.mem_read(a,n)))
        return h.hexdigest()

    def _idref_diagnostic(self,cpu):
        global_lock=self._u(cpu,self.image+0x3DED98);table=self._u(cpu,self.image+0x3DEDA8)
        index=(self._idref_string>>4)&255;slot=table+index*8 if table else 0;entry=self._u(cpu,slot) if slot else 0
        row=dict(global_lock=hex(global_lock),guard=hex(self._u(cpu,self.image+0x3DEDA0)),table=hex(table),index=index,slot=hex(slot),entry=hex(entry))
        if table:row['table_sha256']=raw_hash(bytes(cpu.mem_read(table,0x800)))
        if global_lock:row['global_lock_sha256']=raw_hash(bytes(cpu.mem_read(global_lock,48)))
        if entry:row.update(entry_sha256=raw_hash(bytes(cpu.mem_read(entry,48))),mutex_state_u16=self._u(cpu,entry+8,2),owner_u32=self._u(cpu,entry+12,4))
        return row

    def _idref_snapshot(self,cpu,pc,kind):
        assert self._idref_protected_hash(cpu)==self._idref_initial_protected
        pair=bytes(cpu.mem_read(self._idref_reference,16));scope=bytes(cpu.mem_read(self._idref_scope,24))
        row=dict(kind=kind,index=self._idref_count,pc=hex(pc-self.image),SP=hex(cpu.reg_read(arm.UC_ARM64_REG_SP)),
            registers={f'x{n}':hex(self._reg(cpu,n)) for n in (0,30)},callee_saved_sha256=self._idctor_saved_hash(cpu),
            protected_regions_sha256=self._idref_protected_hash(cpu),reference_address=hex(self._idref_reference),
            reference_pointer=hex(int.from_bytes(pair[:8],'little')),reference_counter=hex(int.from_bytes(pair[8:],'little')),reference_pair_sha256=raw_hash(pair),
            string_address=hex(self._idref_string),payload_length=36,payload_including_NUL_sha256=raw_hash(bytes(cpu.mem_read(self._idctor_payload,37))),
            scope_address=hex(self._idref_scope),scope_sha256=raw_hash(scope),diagnostic=self._idref_diagnostic(cpu),errno=self._u(cpu,self._seedfail_errno,4))
        if self._idref_counter:row.update(counter_address=hex(self._idref_counter),counter_u32=self._u(cpu,self._idref_counter,4))
        if kind in ('scope_entered','counter_published','scope_left','reference_return','factory_return','before_output_assign_BL'):
            row.update(scope_vtable=hex(self._u(cpu,self._idref_scope)),scope_lock_result=self._u(cpu,self._idref_scope+8,4),scope_input=hex(self._u(cpu,self._idref_scope+16)))
        self._idref_rows.append(project_snapshot(row))

    def _idref_start(self,cpu,pc,state):
        self._idctor_track(cpu,pc);self._idctor_snapshot(cpu,pc,'before_reference_BL')
        data=json.loads(previous.EVIDENCE.read_text());previous.validate(data);old=data['case_result']
        h=hashlib.sha256()
        for key in self._idctor_trace:h.update(key.encode()+bytes.fromhex(self._idctor_code[key]))
        for value,key in ((self._idctor_count,'instruction_observations'),(h.hexdigest(),'instruction_trace_sha256'),
            (digest(self._idctor_code),'observed_code_sha256'),(self._idctor_trace,'observation_sites'),(self._idctor_code,'observed_code'),
            (self._idctor_rows,'snapshots'),(self._idctor_writes,'native_writes'),(self._idctor_services,'services'),(self._idctor_copies,'copy_provider_effects')):assert value==old[key],key
        events=state['allocator_events_ref'];assert events[:len(self._idctor_events)]==self._idctor_events
        assert events[len(self._idctor_events):]==old['new_allocator_events']
        self._idref_old=old;self._idref_events=deepcopy(events);self._idref_live_events=events
        self._idref_reference=self._reg(cpu,0);self._idref_string=self._reg(cpu,1);self._idref_sp=cpu.reg_read(arm.UC_ARM64_REG_SP)
        assert self._idref_string==self._idctor_object
        self._idref_scope=self._idref_sp-0x50;self._idref_saved=self._idctor_saved_hash(cpu)
        values=[self._u(cpu,self._idref_sp+0x58),self._u(cpu,self._idref_sp+0x50),self._u(cpu,self._idref_sp+0x40)]+[self._reg(cpu,n) for n in range(22,29)]+[self._u(cpu,self._idref_sp+0x30)]
        self._idref_factory_saved=raw_hash(b''.join(n.to_bytes(8,'little') for n in values))
        self._idref_factory_lr=self._u(cpu,self._idref_sp+0x38);assert self._idref_factory_lr==self.image+FACTORY_RETURN
        self._idref_protected=self._idctor_protected+[(self._idctor_object,24),(self._idctor_payload,37)]
        self._idref_initial_protected=self._idref_protected_hash(cpu)
        self._idctor_active=False;self._idctor_done=False;self._idref_active=True
        self._idref_track(cpu,pc);self._idref_snapshot(cpu,pc,'reference_BL')

    def native_runner(self,*args,**kwargs):
        assert kwargs.get('real_malloc') is True and not kwargs.get('malloc_handler')
        old_write=kwargs['memory_write_observer']
        def write(cpu,address,size):
            if self._idref_active:
                if any(address<a+n and a<address+size for a,n in self._idref_protected):raise AssertionError('identifier reference wrote protected state')
                diag=self._idref_diagnostic(cpu);table=int(diag['table'],16);slot=int(diag['slot'],16)
                if table and address<table+0x800 and table<address+size:assert slot<=address and address+size<=slot+8
                spans=[(self._idref_reference,16),(self._idref_scope,24),(self.image+0x3DED98,24),(slot,8)]
                spans.extend((int(diag[k],16),48) for k in ('global_lock','entry') if int(diag[k],16))
                spans.extend((e[2],e[1]) for e in self._idref_live_events[len(self._idref_events):] if e[0]=='alloc')
                if any(a and address<a+n and a<address+size for a,n in spans):
                    pc=cpu.reg_read(arm.UC_ARM64_REG_PC);domain='libc' if LIBC_BASE<=pc<LIBC_BASE+0x200000 else 'main'
                    self._idref_writes.append(dict(index=self._idref_count,PC=domain+':'+hex(pc-LIBC_BASE if domain=='libc' else pc-self.image),address=hex(address),size=size))
            if old_write:old_write(cpu,address,size)
        kwargs['memory_write_observer']=write;return super().native_runner(*args,**kwargs)

    def observe(self,cpu,pc,state):
        if not self._idref_active:
            if self._idctor_active and pc==self.image+START:
                self._idref_start(cpu,pc,state);self._base_observe(cpu,pc,state);return
            return super().observe(cpu,pc,state)
        self._idref_track(cpu,pc);off=pc-self.image
        if off in (TARGET,0x26C858,0x1625D8,0x1625F0,0x26C9D0,0x1625F8):
            self._idref_snapshot(cpu,pc,{TARGET:'reference_entry',0x26C858:'scope_enter',0x1625D8:'scope_entered',0x1625F0:'counter_published',0x26C9D0:'scope_leave',0x1625F8:'scope_left'}[off])
        if off==0x1625E4:
            self._idref_counter=self._reg(cpu,0);assert self._idref_counter
            self._idref_snapshot(cpu,pc,'counter_allocation_return')
        if off in (0x347F00,0x347F10,0x347FD0):
            self._idref_services.append(dict(index=self._idref_count,PC=hex(off),kind={0x347F00:'pthread_mutex_lock',0x347F10:'pthread_mutex_unlock',0x347FD0:'actual_Bionic_malloc_route'}[off],argument=hex(self._reg(cpu,0))))
        if pc==LIBC_BASE+MALLOC:self._idref_services.append(dict(index=self._idref_count,PC='libc:'+hex(MALLOC),kind='actual_Bionic_malloc_entry',request=self._reg(cpu,0)))
        if off==REFERENCE_RETURN:
            assert cpu.reg_read(arm.UC_ARM64_REG_SP)==self._idref_sp and self._idctor_saved_hash(cpu)==self._idref_saved
            assert self._u(cpu,self._idref_reference)==self._idref_string and self._u(cpu,self._idref_reference+8)==self._idref_counter and self._u(cpu,self._idref_counter,4)==1
            self._idref_snapshot(cpu,pc,'reference_return');self._idref_reference_returned=True
        if off==FACTORY_RETURN:
            assert self._idref_reference_returned and cpu.reg_read(arm.UC_ARM64_REG_SP)==self._idref_sp+0x60
            assert self._idctor_saved_hash(cpu)==self._idref_factory_saved
            self._idref_snapshot(cpu,pc,'factory_return');self._idref_factory_returned=True
        if off==NEXT:
            assert self._idref_factory_returned and [self._reg(cpu,n) for n in (0,1)]==[self._idopen_output,self._idref_reference]
            self._idref_snapshot(cpu,pc,'before_output_assign_BL');self._idref_done=True
            cpu.emu_stop();cpu.reg_write(arm.UC_ARM64_REG_PC,previous.oracle.STOP);return
        self._base_observe(cpu,pc,state)

    def finish(self,result,state,proof):
        assert self._idref_done and self._idref_reference_returned and self._idref_factory_returned
        h=hashlib.sha256()
        for key in self._idref_trace:h.update(key.encode()+bytes.fromhex(self._idref_code[key]))
        ledgers=dict(allocator_counts=result['actual_allocator_counts'],inherited_service_counts=result['explicit_service_counts'],inherited_JNI_calls=proof['JNI_calls'],inherited_libc_SVC=proof['libc_SVC_boundaries'],inherited_main_SVC=proof['main_image_SVC_boundaries'],inherited_syscall_172=self._pid_syscalls,inherited_syscall_173=self._pp_syscalls,late_jni=self.late_jni_calls,java_dispatch=self.java_dispatch_calls)
        assert result['allocator_events'][:len(self._idref_events)]==self._idref_events
        return dict(control=self._idref_old['control'],retained_string_constructor=dict(case_result_sha256=digest(self._idref_old),verified_fields=list(PARENT_FIELDS)),
            instruction_observations=self._idref_count,instruction_trace_sha256=h.hexdigest(),observed_code_sha256=digest(self._idref_code),
            snapshots=self._idref_rows,native_writes=self._idref_writes,services=self._idref_services,observation_sites=self._idref_trace,observed_code=self._idref_code,
            new_allocator_events=result['allocator_events'][len(self._idref_events):],**ledgers,protected_write_events=[],
            protected_ranges=[dict(address=hex(a),size=n) for a,n in self._idref_protected],factory_saved_sha256=self._idref_factory_saved,
            stop_boundary=dict(kind='before_identifier_output_assignment_BL',stop_before=hex(NEXT),target=hex(NEXT_TARGET),call_executed=False,target_executed=False))


def run(path,libc):
    parent=prior_evidence();p=previous.previous.previous.previous.previous.bootstrap.module_prefix();p.digest.verify_images(path,libc)
    code=read_static(path,libc);assert {k:v['sha256'] for k,v in code.items()}==CODE_SHA256
    def create(control):
        s=IdentifierReferenceFactoryScenario(control);s.path=path;s.continue_to_svc=True;return s
    rows=p.digest.context.replay(path,libc,case_controls=[p.CONTROL],_extension_factory=create,
        _request_profile=p.digest.previous.previous.name.previous.previous.PROFILE['name'],_handler_read_profile=p.digest.context.NULL_PAYLOAD_READ_PROFILE['name'])
    assert len(rows)==1
    components,negative=independent_controls(path,libc)
    return dict(schema=SCHEMA,claims=claims_for(),providers=providers(),source_fingerprints=source_fingerprints(),input_provenance=provenance(parent),
        static_code=code,native_controls=components,component_rollback_checks=negative,case_result=rows[0],case_result_sha256=digest(rows[0]))

def validate(data):
    parent=prior_evidence();old=parent['case_result']
    assert set(data)=={'schema','claims','providers','source_fingerprints','input_provenance','static_code','native_controls','component_rollback_checks','case_result','case_result_sha256'}
    assert data['schema']==SCHEMA and data['claims']==claims_for() and data['providers']==providers()
    assert data['source_fingerprints']==source_fingerprints() and data['input_provenance']==provenance(parent)
    assert data['native_controls']==CONTROL_SPECS and len(CONTROL_SPECS)==8
    assert data['component_rollback_checks']==ROLLBACK_SPECS and len(ROLLBACK_SPECS)==4
    assert set(data['static_code'])==set(CODE_SHA256)
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            entry=data['static_code'][domain+':'+hex(off)];raw=bytes.fromhex(entry['hex'])
            assert set(entry)=={'size','hex','sha256'} and len(raw)==entry['size']==size and raw_hash(raw)==entry['sha256']==CODE_SHA256[domain+':'+hex(off)]
    row=data['case_result'];assert data['case_result_sha256']==digest(row) and row['control']==old['control']
    assert set(row)=={'control','retained_string_constructor','instruction_observations','instruction_trace_sha256','observed_code_sha256','snapshots','native_writes','services','observation_sites','observed_code','new_allocator_events','protected_ranges','factory_saved_sha256','protected_write_events','stop_boundary'}|set(EXPECTED['ledgers'])
    assert row['retained_string_constructor']==dict(case_result_sha256=digest(old),verified_fields=list(PARENT_FIELDS))
    sites=row['observation_sites'];code=row['observed_code'];h=hashlib.sha256()
    assert len(sites)==row['instruction_observations']==EXPECTED['instruction_observations']<MAX_OBSERVATIONS and set(sites)==set(code)
    assert sites[0]=='main:'+hex(START) and sites[-1]=='main:'+hex(NEXT) and 'main:'+hex(NEXT_TARGET) not in sites
    for off in (TARGET,0x26C858,0x26C9D0,REFERENCE_RETURN,FACTORY_RETURN):assert sites.count('main:'+hex(off))==1,hex(off)
    for key in sites:
        raw=bytes.fromhex(code[key]);assert len(raw)==4;h.update(key.encode()+raw)
    assert h.hexdigest()==row['instruction_trace_sha256']==EXPECTED['instruction_trace_sha256'] and digest(code)==row['observed_code_sha256']==EXPECTED['observed_code_sha256']
    for domain,ranges in CODE_RANGES.items():
        for off,size in ranges:
            raw=data['static_code'][domain+':'+hex(off)]['hex']
            for pc in range(off,off+size,4):
                if domain+':'+hex(pc) in code:assert code[domain+':'+hex(pc)]==raw[(pc-off)*2:(pc-off+4)*2]
    for key in ('snapshots','native_writes','services','new_allocator_events','protected_ranges','factory_saved_sha256'):assert row[key]==EXPECTED[key],key
    first=row['snapshots'][0];by_kind={x['kind']:x for x in row['snapshots']}
    entered,left,returned,factory,stop=[by_kind[k] for k in ('scope_entered','scope_left','reference_return','factory_return','before_output_assign_BL')]
    assert first['kind']=='reference_BL' and stop['pc']==hex(NEXT)
    assert first['SP']==returned['SP'] and first['callee_saved_sha256']==returned['callee_saved_sha256']
    assert int(factory['SP'],16)==int(first['SP'],16)+0x60 and factory['SP']==stop['SP']
    assert factory['callee_saved_sha256']==stop['callee_saved_sha256']==row['factory_saved_sha256']
    prior=old['snapshots'][-1];ref=int(first['reference_address'],16)
    assert first['reference_address']==first['registers']['x0']
    assert 'reference_pointer' not in first and 'reference_counter' not in first
    assert 'counter_u32' not in by_kind['counter_allocation_return']
    for x in row['snapshots']:
        assert x['protected_regions_sha256']==first['protected_regions_sha256'] and x['errno']==prior['errno']==2
        assert x['string_address']==prior['object_address'] and x['payload_length']==36 and x['payload_including_NUL_sha256']==prior['payload_including_NUL_sha256']
        assert set(x['registers'])=={'x0','x30'}
    for x in (by_kind['counter_published'],left,returned,factory,stop):
        assert x['reference_pointer']==first['string_address'] and x['reference_counter']==x['counter_address'] and x['counter_u32']==1
        pair=int(x['reference_pointer'],16).to_bytes(8,'little')+int(x['reference_counter'],16).to_bytes(8,'little')
        assert raw_hash(pair)==x['reference_pair_sha256']
    for x in (entered,left):
        assert x['scope_vtable']==hex(row['control']['base']+0x35D410) and x['scope_lock_result']==0 and x['scope_input']==first['string_address']
    assert entered['scope_sha256']==left['scope_sha256']
    before=first['diagnostic'];after=stop['diagnostic']
    assert int(before['global_lock'],16) and int(before['table'],16) and int(before['guard'],16)&1
    assert before['global_lock']==after['global_lock'] and before['global_lock_sha256']==after['global_lock_sha256']
    assert before['guard']==after['guard'] and before['table']==after['table'] and before['index']==after['index']
    if int(before['entry'],16):
        assert before['entry']==after['entry'] and before['entry_sha256']==after['entry_sha256']
        assert [e[1] for e in row['new_allocator_events']]==[4]
    else:
        assert int(after['entry'],16) and after['mutex_state_u16']==0x4000 and after['owner_u32']==0
        assert [e[1] for e in row['new_allocator_events']]==[48,4]
    assert all(e[0]=='alloc' for e in row['new_allocator_events'])
    counter=int(stop['counter_address'],16)
    assert [(w['PC'],int(w['address'],16)-ref,w['size']) for w in row['native_writes'] if ref<=int(w['address'],16)<ref+16]==[
        ('main:0x1625cc',0,8),('main:0x1625cc',8,8),('main:0x1625dc',0,8),('main:0x1625e8',8,8)]
    assert [(w['PC'],w['size']) for w in row['native_writes'] if int(w['address'],16)==counter]==[('main:0x1625ec',4)]
    assert all(set(w)=={'index','PC','address','size'} for w in row['native_writes'])
    counts=deepcopy(old['allocator_counts']);counts['malloc']+=len(row['new_allocator_events'])
    assert row['allocator_counts']==counts
    for key,value in EXPECTED['ledgers'].items():
        assert row[key]==value,key
        if key!='allocator_counts':assert row[key]==old[key],key
    assert row['protected_write_events']==[]
    assert row['stop_boundary']==dict(kind='before_identifier_output_assignment_BL',stop_before=hex(NEXT),target=hex(NEXT_TARGET),call_executed=False,target_executed=False)

def damaged_evidence_rejected(data):
    changes=[(('claims','next_output_assignment_executed'),True),(('claims','current_identifier_getter_returned'),True),
        (('claims','current_identifier_published'),True),(('claims','complete_standalone_signer_verified'),True),
        (('providers','new_providers'),['hidden']),(('source_fingerprints','owners','reference_model'),'0'*64),
        (('case_result','retained_string_constructor','case_result_sha256'),'0'*64),(('case_result','instruction_observations'),0),
        (('case_result','instruction_trace_sha256'),'0'*64),(('case_result','observed_code_sha256'),'0'*64),
        (('case_result','snapshots',-1,'reference_pointer'),'0x0'),(('case_result','snapshots',-1,'reference_counter'),'0x0'),
        (('case_result','snapshots',-1,'counter_u32'),2),(('case_result','snapshots',-1,'payload_including_NUL_sha256'),'0'*64),
        (('case_result','snapshots',-1,'protected_regions_sha256'),'0'*64),(('case_result','snapshots',-1,'SP'),'0x0'),
        (('case_result','snapshots',-1,'callee_saved_sha256'),'0'*64),(('case_result','snapshots',-1,'diagnostic','entry'),'0x0'),
        (('case_result','snapshots',-1,'diagnostic','mutex_state_u16'),0),(('case_result','native_writes',0,'size'),1),
        (('case_result','new_allocator_events'),[]),(('case_result','factory_saved_sha256'),'0'*64),
        (('case_result','protected_write_events'),['hidden']),(('case_result','stop_boundary','call_executed'),True),
        (('case_result','raw_identifier'),'omitted'),(('raw_identifier',),'omitted'),
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
        raise AssertionError(f'damaged reference evidence accepted: {path}')
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
        if args.replay:assert run(args.elf,args.libc)==data,'fresh identifier reference/factory replay differs'
    print(json.dumps(dict(schema=SCHEMA,native_controls=len(data['native_controls']),component_rollback_checks=len(data['component_rollback_checks']),
        damaged_evidence_rejected=rejected,instruction_observations=data['case_result']['instruction_observations'],
        original_reference_constructor_returned=True,original_identifier_factory_returned=True,next_output_assignment_executed=False,complete_standalone_signer_verified=False)))
if __name__=='__main__':main()
