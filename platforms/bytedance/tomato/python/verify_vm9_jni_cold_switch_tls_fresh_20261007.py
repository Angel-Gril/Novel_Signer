"""Original JNI_OnLoad -> cold switch once -> fresh per-thread TLS -> Java getter.

Two native observations only, not Python bootstrap comparisons. Emulated TLS
subsystem globals/OS keys and 136/320 references are explicit warm inputs;
thread storage starts empty. Allocator/OS/JavaVM/JNI services are explicit.
Stop before +0x26e70c, so its legacy oracle stub never runs.
"""
from pathlib import Path
import argparse,json,collections,hashlib
import verify_vm9_jni_environment_fresh_20261007 as acquisition
import verify_vm9_jni_initialization_fresh_20261007 as initialization
from verify_vm9_signer_objects import GUEST,native,LIBRARY_SHA256
from verify_vm9_strings import Effects
from vm9_allocator import _read_span,_write_span
from unicorn import arm64_const as arm
from elftools.elf.elffile import ELFFile
parser=argparse.ArgumentParser()
parser.add_argument('--library',type=Path,required=True)
parser.add_argument('--libc',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args();lib,libc=args.library,args.libc
assert hashlib.sha256(lib.read_bytes()).hexdigest()==LIBRARY_SHA256
assert hashlib.sha256(libc.read_bytes()).hexdigest()==initialization.LIBC_SHA256
with lib.open('rb') as stream:
 elf=ELFFile(stream);defined=None
 for section in elf.iter_sections():
  if section['sh_type']=='SHT_RELA':
   symbols=elf.get_section(section['sh_link'])
   for reloc in section.iter_relocations():
    if reloc['r_offset']==0x375010:
     symbol=symbols.get_symbol(reloc['r_info_sym']);assert symbol.name=='JNI_OnLoad' and reloc['r_info_type']==1025 and symbol['st_shndx']!='SHN_UNDEF'
     defined=symbol['st_value']+reloc['r_addend']
assert defined==0x27B41C
ENV,TABLE=initialization.ENV,initialization.TABLE
cases=[]
for base in (0x122C0000,0x775C205000):
 p,blocks=acquisition.fixture(lib,base,tls_cold=True,vm_present=False)
 def w(a,v,n=8):_write_span(p,a,v.to_bytes(n,'little'))
 w(ENV,TABLE)
 for i,slot in enumerate(initialization.SLOTS):w(TABLE+slot,GUEST+0xF210+i*0x10)
 wrapper,payload,counter=(GUEST+x for x in (0x5000,0x5100,0x5200))
 _write_span(p,payload,bytes(136));w(wrapper,payload);w(wrapper+8,counter);w(counter,1)
 w(base+0x3D1678,wrapper);w(base+0x3D1680,1)
 reg,regpayload,timer=(GUEST+x for x in (0x5300,0x5400,0x5600))
 _write_span(p,regpayload,bytes(320));w(reg,regpayload);w(reg+8,GUEST+0x53E0)
 w(regpayload+0x130,timer);w(timer,3);w(timer+8,5)
 w(base+0x3D1550,reg);w(base+0x3D1558,1);w(base+0x375010,base+defined)
 effects=Effects(blocks=blocks)
 vm=acquisition.Providers(base,effects,((0,ENV),)*3)
 jni=initialization.Providers(base,{})
 imports=vm.imports();imports.update(jni.imports());decimals=[];entries=[];calls=[];trace=collections.deque(maxlen=24)
 def decimal(cpu):
  assert cpu.reg_read(arm.UC_ARM64_REG_X1)==0 and cpu.reg_read(arm.UC_ARM64_REG_X2)==10
  raw=initialization.cstring(lambda a,n:bytes(cpu.mem_read(a,n)),cpu.reg_read(arm.UC_ARM64_REG_X0))
  value=int(raw.decode(),10);decimals.append(value);return value
 def clock(cpu):
  cpu.mem_write(cpu.reg_read(arm.UC_ARM64_REG_X1),(1791023800).to_bytes(8,'little')+(500000000).to_bytes(8,'little'));return 0
 imports.update({0x3484B0:decimal,0x348450:clock})
 def observe(cpu,address):
  off=address-base;trace.append(hex(off))
  if off in (0x27B41C,0x27BE88,0x26E19C,0x32A0A0,0x165648,0x165658,0x26EDC4,0x34377C,0x34265C,0x26EEEC,0x17CAAC):entries.append(hex(off))
  if off==0x1656A0:
   calls.append([cpu.reg_read(getattr(arm,'UC_ARM64_REG_X'+str(i))) for i in range(7)])
 observed={(base+0x3D1570,8):None,(base+0x3D1578,8):None,(base+0x3DEED8,8):None,
  (base+0x3DEEB8,16):None,(acquisition.OS_SLOT,8):None}
 try:
  result,memory,allocations,ledger=native(lib,base,0x27B41C,[acquisition.VM,0],p,libc=libc,
   real_singletons=True,real_mutexes=True,thread_id=137,real_jni_acquisition=True,host_imports=imports,
   malloc_handler=lambda cpu,n:effects.native(cpu,'malloc',n),instruction_observer=observe,
   observed_memory=observed,stop_offset=0x26E70C,instruction_limit=300000)
 except Exception:
  print('last native PCs',list(trace));print('VM services',vm.events);print('JNI services',jni.events);raise
 case=dict(image_base=hex(base),stopped_before_offset='0x26e70c',native_entry_order=entries,
  vm_services=vm.events,JNI_services=[e[0] for e in jni.events],allocator_effects=effects.calls,
  switch_getter_call_arguments=[c[:5] for c in calls],once_state=int.from_bytes(observed[base+0x3D1570,8],'little'),
  switch_word=int.from_bytes(observed[base+0x3D1578,8],'little'),
  TLS_OS_slot=int.from_bytes(observed[acquisition.OS_SLOT,8],'little'),actual_ELF_decimal_selectors=decimals,
  explicit_warm_references_JNI_pthread_allocator_services_used=True,
  fresh_thread_TLS_slot_used=True,explicit_preinitialized_emulated_TLS_global_and_OS_keys_used=True,
  matching_libc_mutex_bodies_executed=True,original_vm_publication_executed=True,
  original_JNI_initialization_returned=True,native_input_snapshot_used=False,
  same_original_JNI_OnLoad_invocation_used=True,
  explicit_host_continuation_used=False,actual_android_jvm_executed=False,
  original_TLS_body_executed=True,original_emulated_TLS_body_executed=True,
  original_switch_getter_Java_dispatch_body_executed=False,legacy_26e70c_stub_executed=False,
  full_Python_bootstrap_compared=False,full_JNI_OnLoad_return_verified=False,fresh_signer_output_verified=False)
 assert case['once_state']==1 and len(calls)==1 and calls[0][:5]==[0x1000000E,0,0,0,0]
 assert case['TLS_OS_slot'] and decimals==[5256,5256] and not vm.responses
 assert len(effects.calls)==6 and all(c[0]=='malloc' for c in effects.calls)
 assert [c[1] for c in effects.calls]==[128,16,39,16,24,23]
 assert [e[0] for e in vm.events].count('GetEnv')==3
 cases.append(case)
 print('cold once through real TLS:',hex(base),'entries',entries,'VM GetEnv',sum(x[0]=='GetEnv' for x in vm.events),'query',list(map(hex,calls[0][:5])))
evidence=dict(schema='vm9-jni-cold-switch-tls-original-prefix-v1',evidence_date='2026-10-07',
 sample_sha256=LIBRARY_SHA256,matching_libc_sha256=initialization.LIBC_SHA256,
 original_bootstrap_probes=len(cases),Python_bootstrap_comparison_controls=0,probe_cases=cases,
 native_input_snapshot_used=False,explicit_OS_JNI_allocator_services_used=True,
 full_cold_TLS_subsystem_boot_verified=False,original_switch_getter_Java_dispatch_body_executed=False,
 legacy_26e70c_stub_executed=False,full_JNI_OnLoad_recovered=False,
 actual_android_jvm_executed=False,complete_python_medusa=False,fresh_signer_output_verified=False,
 live_server_matrix_verified=False)
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
print('cold switch TLS: two original bootstrap probes passed; no Python bootstrap comparisons')
