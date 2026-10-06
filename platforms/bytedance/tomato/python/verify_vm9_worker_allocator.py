"""Fresh main malloc -> independent TLS workers through actual matching libc.

Virtual OS, thread descriptors and serial scheduling are explicit inputs.
No native snapshot, ready flag, allocator return provider or host thread is used.
This verifies bounded worker allocations, not startup/root/signature completion.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_TPIDR_EL0
import vm9_allocator as allocator
import vm9_libc_cold as model
import verify_vm9_libc_stdio as fixture
import verify_vm9_signer_objects as oracle
from verify_vm9_libc_mapping import LIBC_SHA256

LIBC = fixture.LIBC
MAIN_TLS = fixture.WORKER_TLS
WORKERS = (fixture.GUEST + 0x50000, fixture.GUEST + 0x52000)
STACK = fixture.GUEST + 0x40000
STACK_BYTES = 0x10000
TOP = STACK + 0xF000
SCRATCH = fixture.GUEST + 0xF800
LABELS = ('small', 'large', 'mixed', 'two_workers', 'one_cpu', 'large_regions', 'foreign_fallback')
ENTRIES = (0x8E250, 0x8E41C, 0x8E51C, 0x99C78, 0x99610, 0x99600,
    0x8E0EC, 0x996D4, 0x8DDA0, 0x8E0F8, 0x98490, 0x8ED90)


def requests(label):
    first, second = WORKERS
    worker = {
        'small': [(first,128)], 'large': [(first,16384)],
        'mixed': [(first,n) for n in (0,128,16384,65536,128)],
        'two_workers': [(first,128),(second,128),(first,16384),(second,16384)],
        'one_cpu': [(first,128),(first,16384)],
        'large_regions': [(first,65536)]*40, 'foreign_fallback': [(first,128)],
    }[label]
    return [(MAIN_TLS,48), *worker]


def fresh(library, libc, image):
    pages = fixture.cpu_fresh(library,libc,image)
    for start,length in ((STACK,STACK_BYTES), *((address,0x2000) for address in WORKERS)):
        for address in range(start,start+length,4096):
            pages[address>>12] = bytearray(4096)
    for index,pointer in enumerate(WORKERS):
        fixture.put(pages,pointer+8,pointer+0x200)
        fixture.put(pages,pointer+0x210,271+index,4)
        fixture.put(pages,pointer+0x10,37,4)
    return pages


class Environment:
    def __init__(self,pages,cpus):
        self.os = allocator.GuestOS(pages)
        self.calls = []
        self.cursor = 0
        self.contents = b'cpu 0 0\n'+b''.join(('cpu%d 0\n'%i).encode() for i in range(cpus))
        self.fail_worker_mapping = False
    def stat(self):
        result = bytearray(128)
        result[16:20] = (0x8124).to_bytes(4,'little')
        result[56:60] = (4096).to_bytes(4,'little')
        return bytes(result)
    def brk(self,pages,value):
        assert value == 0
        self.calls.append(['brk',value])
        return 0x13600000
    def service(self,tx,operation,*fields):
        self.calls.append([operation,*fields])
        if operation == 'mmap':
            if self.fail_worker_mapping:
                raise allocator.RefillUnsupported('explicit worker mapping provider failure')
            return tx.next_address
        if operation == 'openat': return 53
        if operation == 'read':
            data = self.contents[self.cursor:self.cursor+fields[1]]
            self.cursor += len(data)
            return len(data),data
        if operation == 'fstat': return 0,self.stat()
        assert operation in ('close','prctl','mprotect','munmap'),operation
        return 0
    def syscall(self,cpu,number,observed):
        fields = [cpu.reg_read(register) for register in fixture.REGS]
        if number == 214: return self.brk(None,fields[0])
        if number == 222:
            assert fields[0] == 0 and fields[2:] == [3,0x22,0xFFFFFFFF,0]
            self.calls.append(['mmap',*fields])
            record = self.os.map_anonymous(fields[1],prot=3,flags=0x22,fd=0xFFFFFFFF,anonymous_name=b'')
            cpu.mem_map(record.base,record.length)
            observed.update({(page<<12,4096):None for page in range(record.base>>12,record.end>>12)})
            return record.base
        if number == 167:
            name = fixture.cstring(cpu,fields[4])
            assert name == b'libc_malloc'
            self.calls.append(['prctl',*fields[:4],name])
            self.os.name_exact(fields[2],fields[3],name)
            return 0
        if number == 56:
            self.calls.append(['openat',fields[0],fixture.cstring(cpu,fields[1]),fields[2],fields[3]])
            return 53
        if number == 63:
            self.calls.append(['read',fields[0],fields[2]])
            data = self.contents[self.cursor:self.cursor+fields[2]]
            self.cursor += len(data)
            cpu.mem_write(fields[1],data)
            return len(data)
        if number == 80:
            self.calls.append(['fstat',fields[0]])
            cpu.mem_write(fields[1],self.stat())
            return 0
        if number == 57:
            self.calls.append(['close',fields[0]])
            return 0
        if number == 226:
            self.calls.append(['mprotect',*fields[:3]])
            self.os.protect_exact(*fields[:3]);cpu.mem_protect(*fields[:3])
            return 0
        assert number == 215,number
        self.calls.append(['munmap',*fields[:2]])
        self.os.unmap_range(*fields[:2]);cpu.mem_unmap(*fields[:2])
        for page in range(fields[0]>>12,(fields[0]+fields[1])>>12):
            observed.pop((page<<12,4096),None)
        return 0


def allocate(environment,pointer,size,scratch=SCRATCH):
    body = model.allocate_default_small if size <= 0x3800 else model.allocate_default_large
    return body(environment.os,request_size=size,scratch_address=scratch,libc_base=LIBC,
        thread_pointer=pointer,brk=environment.brk,os_call=environment.service)


def install_foreign_fallback(write):
    """Explicit live-node control input from another pthread, never a snapshot."""
    node=fixture.GUEST+0x3000
    for address,value in ((LIBC+0xE6AB8,node),(node,node),(node+8,node),
            (node+0x10,WORKERS[1]+0x200),(node+0x18,fixture.GUEST+0x3200)):
        write(address,value.to_bytes(8,'little'))


def case(library,libc,image,label):
    pages,seed = fresh(library,libc,image),fresh(library,libc,image)
    cpus = 1 if label == 'one_cpu' else 2
    actual_env,expected_env = Environment(pages,cpus),Environment(seed,cpus)
    operations = requests(label)
    observed = fixture.observed_spans()
    observed.update({(pointer,0xB00):None for pointer in WORKERS})
    observed.update({(LIBC+0xD8DC8,8):None,(LIBC+0xDE888,8):None,
        (LIBC+0xDB380,40):None,(LIBC+0xE01C0,16):None})
    snapshots=[];native_results=[];counts=Counter();mapped=[False];booted=[False];plt_calls=[0]
    def observe(cpu,pc):
        offset = pc-LIBC
        if offset in ENTRIES: counts[offset]+=1
        if pc == image+0x347FD0:
            plt_calls[0]+=1
            if not mapped[0]:
                mapped[0]=True
                for start,length in ((STACK,STACK_BYTES), *((p,0x2000) for p in WORKERS)):
                    cpu.mem_map(start,length)
                    for address in range(start,start+length,4096):
                        cpu.mem_write(address,bytes(seed[address>>12]))
        if offset == 0x8E250 and not booted[0]:
            booted[0]=True
            cpu.mem_write(fixture.TABLE,allocator._read_span(seed,fixture.TABLE,141*16))
    def continuation(cpu):
        native_results.append(cpu.reg_read(UC_ARM64_REG_X0))
        snapshots.append({span:bytes(cpu.mem_read(*span)) for span in observed})
        if len(native_results) == len(operations):
            cpu.reg_write(UC_ARM64_REG_PC,fixture.STOP)
            return
        if label=='foreign_fallback' and len(native_results)==1:
            install_foreign_fallback(cpu.mem_write)
        pointer,size = operations[len(native_results)]
        cpu.reg_write(UC_ARM64_REG_TPIDR_EL0,pointer)
        cpu.reg_write(UC_ARM64_REG_SP,TOP)
        cpu.reg_write(UC_ARM64_REG_X0,size)
        cpu.reg_write(UC_ARM64_REG_X30,fixture.CONTINUE)
        cpu.reg_write(UC_ARM64_REG_PC,image+0x347FD0)
    native_inputs = {key:data for key,data in fixture.inputs(seed).items()
        if not STACK<=key<<12<STACK+STACK_BYTES and not WORKERS[0]<=key<<12<WORKERS[-1]+0x2000}
    result,memory,allocations,_ = oracle.native(library,image,0x347FD0,[operations[0][1]],native_inputs,
        libc=libc,real_malloc=True,real_mutexes=True,
        syscall_handler=lambda cpu,number:expected_env.syscall(cpu,number,observed),
        host_imports={fixture.CONTINUE-image:continuation},instruction_observer=observe,observed_memory=observed,
        extra_registers={UC_ARM64_REG_TPIDR_EL0:MAIN_TLS,UC_ARM64_REG_SP:TOP,UC_ARM64_REG_X30:fixture.CONTINUE},
        instruction_limit=2000000)
    assert len(snapshots)==len(operations) and not allocations and plt_calls[0]==len(operations)
    model_results=[]
    for index,(pointer,size) in enumerate(operations):
        if label=='foreign_fallback' and index==1:
            install_foreign_fallback(lambda address,data:allocator._write_span(pages,address,data))
        model_results.append(allocate(actual_env,pointer,size))
        assert model_results[-1] == native_results[index],('malloc pointer',label,index)
        differences=[]
        for (address,width),expected in snapshots[index].items():
            actual=allocator._read_span(pages,address,width)
            if actual!=expected:
                differences.append((hex(address),width,[i for i,(a,b) in enumerate(zip(actual,expected)) if a!=b][:8]))
        assert not differences,('observed bytes',label,index,differences)
    assert allocator._read_span(pages,fixture.GUEST,0xA000)==memory
    assert actual_env.calls==expected_env.calls and actual_env.os.mappings==expected_env.os.mappings
    assert actual_env.os.next_address==expected_env.os.next_address
    assert all(counts[offset]==1 for offset in (0x8E250,0x8E41C,0x8E51C,0x99C78))
    workers={pointer for pointer,size in operations if pointer!=MAIN_TLS}
    assert counts[0x99610]==counts[0x99600]==counts[0x996D4]==len(workers)
    assert fixture.get(pages,LIBC+0xDB6A0,4)==0
    assert fixture.get(pages,LIBC+0xE6AB8)==(fixture.GUEST+0x3000 if label=='foreign_fallback' else 0)
    table=fixture.get(pages,LIBC+0xE69D0)
    arenas=[fixture.get(pages,table+i*8) for i in range(cpus)]
    assert all(arenas) and counts[0x8E0F8]==cpus
    row=dict(case=label,image_base=hex(image),public_malloc_returns=len(model_results),
        independent_worker_tls_count=len(workers),cpu_count=cpus,constructed_arenas=cpus,
        foreign_fallback_node_input_preserved=label=='foreign_fallback',
        native_libc_entry_counts={hex(key):value for key,value in sorted(counts.items())},
        all_observed_globals_tls_and_owned_mapping_bytes_match_at_every_return=True,
        mapping_records_protection_cursor_and_os_order_match=True,
        actual_native_malloc=True,substituted_allocations=0,native_input_snapshot_used=False,
        explicit_virtual_os=True,physical_stack_compared=False)
    print(json.dumps(row),flush=True)
    return row


def rejection_cases(library,libc):
    rows=[]
    for label in ('unmapped_scratch','misaligned_scratch','missing_identity','busy_fallback_mutex',
            'busy_arena_mutex','unsupported_arena_limit','short_arena_table','worker_mapping_failure'):
        pages=fresh(library,libc,0x122C0000);environment=Environment(pages,2)
        allocate(environment,MAIN_TLS,48)
        scratch=SCRATCH
        if label=='unmapped_scratch': scratch=0x7F100000
        if label=='misaligned_scratch': scratch+=1
        if label=='missing_identity': fixture.put(pages,WORKERS[0]+8,0)
        if label=='busy_fallback_mutex': fixture.put(pages,LIBC+0xE6AC0,1,2)
        if label=='busy_arena_mutex': fixture.put(pages,LIBC+0xE6980,1,2)
        if label=='unsupported_arena_limit': fixture.put(pages,LIBC+0xE6970,3,4)
        if label=='short_arena_table': fixture.put(pages,LIBC+0xE6960,1,4)
        if label=='worker_mapping_failure': environment.fail_worker_mapping=True
        before={key:bytes(value) for key,value in pages.items()}
        mappings=list(environment.os.mappings);cursor=environment.os.next_address;calls=len(environment.calls)
        try: allocate(environment,WORKERS[0],128,scratch)
        except (allocator.RefillUnsupported,ValueError): pass
        else: raise AssertionError(('unsupported worker case accepted',label))
        assert {key:bytes(value) for key,value in pages.items()}==before
        assert environment.os.mappings==mappings and environment.os.next_address==cursor
        rows.append(dict(case=label,rejected=True,all_guest_pages_mapping_records_protection_and_cursor_unchanged=True,
            external_os_provider_effects_not_rolled_back=len(environment.calls)>calls))
    return rows


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--library',type=Path,required=True);ap.add_argument('--libc',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);ap.add_argument('--case',choices=LABELS)
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==LIBC_SHA256
    labels=(args.case,) if args.case else LABELS
    rows=[case(args.library,args.libc,image,label) for image in (0x122C0000,0x775C205000) for label in labels]
    rejected=rejection_cases(args.library,args.libc)
    report=dict(schema='vm9-independent-worker-allocator-v1',sample_sha256=oracle.LIBRARY_SHA256,
        libc_sha256=LIBC_SHA256,cases=rows,rejection_cases=rejected,
        full_bounded_worker_allocation_matrix_verified=args.case is None,
        independent_worker_tsd_and_actual_allocator_verified=True,
        same_startup_worker_actual_allocator_composed=False,complete_python_medusa=False,
        current_online_header_matrix_verified=False)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('worker allocator',len(rows),'native /',len(rejected),'rollback PASS',flush=True)


if __name__=='__main__':main()
