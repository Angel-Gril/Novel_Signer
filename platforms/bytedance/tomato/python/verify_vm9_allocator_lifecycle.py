"""Requires Unicorn and the private primary checkpoint; publishes no page bytes."""
from pathlib import Path
import json, pickle, hashlib, sys
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE, UC_HOOK_INTR
from unicorn.arm64_const import *
import argparse
parser = argparse.ArgumentParser(description="Native differential verification of VM9 allocator lifecycle branches.")
parser.add_argument("--checkpoint", type=Path, required=True, help="Trusted local primary initialized VM9 checkpoint (pickle); never accept untrusted files.")
parser.add_argument("--output", type=Path, required=True, help="Sanitized JSON result path.")
options = parser.parse_args()
import vm9_allocator as model
source = options.checkpoint.resolve()
baseline=pickle.load(source.open('rb'))
regions=((0x11ec0000,0x890000),(0x12800000,0x800000),(0xe4ff0000,0x10000));stop=0x70000000
def native(pages,fn,args, madvise_result=None):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for b,n in regions:uc.mem_map(b,n)
    uc.mem_map(stop,0x100000)
    for k,v in pages.items():
        if any(b<=k<<12<b+n for b,n in regions):uc.mem_write(k<<12,bytes(v))
    for reg,val in {UC_ARM64_REG_SP:stop+0xff000,UC_ARM64_REG_X30:stop,UC_ARM64_REG_TPIDR_EL0:0xe4fff718}.items():uc.reg_write(reg,val)
    for i,v in enumerate(args):uc.reg_write(globals()[f'UC_ARM64_REG_X{i}'],v)
    writes=[]
    def wh(cpu,access,a,n,v,d):
        if not stop<=a<stop+0x100000:writes.append([cpu.reg_read(UC_ARM64_REG_PC),a,n,v&((1<<(n*8))-1)])
    def ih(cpu,n,d):
        nr=cpu.reg_read(UC_ARM64_REG_X8)
        if nr==233 and madvise_result is not None:cpu.reg_write(UC_ARM64_REG_X0,madvise_result & ((1<<64)-1))
        else:raise AssertionError(f'unmodeled syscall {nr}')
    uc.hook_add(UC_HOOK_MEM_WRITE,wh);uc.hook_add(UC_HOOK_INTR,ih)
    uc.emu_start(fn,stop,count=500000)
    assert uc.reg_read(UC_ARM64_REG_PC)==stop
    expected={k:bytearray(v) for k,v in pages.items()}
    for _,a,n,v in writes:
        payload=v.to_bytes(n,'little')
        for off,byte in enumerate(payload):expected[(a+off)>>12][(a+off)&4095]=byte
    return uc.reg_read(UC_ARM64_REG_X0),expected,writes
bins=0x12282000;thread=0x12296000;arena=0x12240180;caller=bins+3*0x20;control=arena+3*0xe0+0x508
results=[]
cases=[
 ('empty_current','malloc',0x2c,[(caller+0x30,0,4)]),
 ('empty_available','malloc',0x2c,[(caller+0x30,0,4),(control+0x28,0,8)]),
 ('empty_real_new_slab','malloc',0x2c,[(caller+0x30,0,4),(control+0x28,0,8),(control+0x30,control+0x38,8)]),
 ('cleanup_zero','cleanup',0,[(bins+0x1c,3,4),(caller+0x28,0,4)]),
 ('cleanup_negative','cleanup',0,[(bins+0x1c,3,4),(caller+0x28,0xffffffff,4),(caller+0x2c,3,4)]),
 ('cleanup_positive','cleanup',0,[(bins+0x1c,3,4),(caller+0x28,2,4)]),
 ('malloc_cleanup','malloc',0x2c,[(bins+0x18,0xe3,4),(bins+0x1c,3,4),(caller+0x28,2,4)]),
 ('free_cleanup','free',0x1296ba60,[(bins+0x18,0xe3,4),(bins+0x1c,3,4),(caller+0x28,2,4)]),
 ('cleanup_cursor_wrap','cleanup',0,[(bins+0x1c,model.read_u64(baseline,0x121d9f48)-1,4)]),
]
for class_id in range(36):
    width=model.read_u64(baseline,0x12196c80+class_id*8)
    class_control=arena+class_id*0xe0+0x508
    class_bin=bins+class_id*0x20
    cases.append((f'new_slab_class_{class_id}','malloc',width,
                  [(class_bin+0x30,0,4),(class_control+0x28,0,8),(class_control+0x30,class_control+0x38,8)]))
for label,kind,value,patches in cases:
    pages={k:bytearray(v) for k,v in baseline.items()}
    for a,v,n in patches:pages[a>>12][a&4095:(a&4095)+n]=v.to_bytes(n,'little')
    fn={'malloc':0x1210bb08,'free':0x1210bac0,'cleanup':0x1218833c}[kind]
    args=[thread+8,bins] if kind=='cleanup' else [value]
    out,expected,writes=native(pages,fn,args)
    try:
        if kind=='malloc':res=model.allocate_small_object(pages,thread_state_address=thread,request_size=value);assert res.free_list.object_address==out,(label,hex(out),res)
        elif kind=='free':model.free_small_object(pages,thread_state_address=thread,object_address=value)
        else:model.cleanup_small_object_bins(pages,thread_state_address=thread)
    except Exception:
        print('FAILED',label,flush=True);raise
    different=[k for k in pages if pages[k]!=expected[k]]
    if different:
        print('DIFFERENT',label,[hex(k<<12) for k in different])
        for k in different:
            for i in range(0,4096,8):
                if pages[k][i:i+8]!=expected[k][i:i+8]:print(hex((k<<12)+i),'py',pages[k][i:i+8].hex(),'native',expected[k][i:i+8].hex())
        raise AssertionError(label)
    print('PASS',label,'return',hex(out),'writes',len(writes),'pages',len(pages),flush=True)
    results.append({'case':label,'return':hex(out) if kind=='malloc' else None,'native_nonstack_writes':len(writes),'checkpoint_pages_compared':len(pages),'final_memory_match':True})
# Fresh bitmap bytes are generated from the descriptor for every native small
# class, rather than copied from a captured post-initialization page.
for class_id in range(36):
    pages={k:bytearray(v) for k,v in baseline.items()}
    target=0x12f00000;descriptor=0x121d9120+class_id*0x60+0x28
    out,expected,writes=native(pages,0x1216dd70,[target,descriptor])
    model.initialize_slab_bitmap(pages,bitmap_address=target,descriptor_address=descriptor)
    assert pages==expected,('bitmap',class_id)
    results.append({'case':f'bitmap_class_{class_id}','final_memory_match':True,'checkpoint_pages_compared':len(pages)})
print('PASS bitmap classes 0..35',flush=True)
for succeeded in (True,False):
    pages={k:bytearray(v) for k,v in baseline.items()}
    slab=0x12941108;pointer=0x1296ba60
    # 0x1216b024 is called under the class lock; it temporarily drops and
    # reacquires it around arena release, then its caller unlocks afterwards.
    pages[control>>12][control&4095:(control&4095)+2]=(1).to_bytes(2,'little')
    model.initialize_slab_bitmap(pages,bitmap_address=slab+8,descriptor_address=0x121d9120+3*0x60+0x28)
    model.write_u32(pages,slab+4,255)
    index=(pointer-0x12969000)//0x30
    address=slab+8+(index>>6)*8
    model.write_u64(pages,address,model.read_u64(pages,address) ^ (1<<(index&63)))
    out,expected,writes=native(pages,0x1216b024,[arena,0x12940000,pointer],0 if succeeded else -22)
    transaction=model._PageTransaction(pages)
    model._return_slab_slot(transaction,arena,pointer,3,model.AllocatorConstants(purge_madvise_result=0 if succeeded else -22,guest_errno_address=0xe4fff728))
    transaction.commit()
    different=[k for k in pages if pages[k]!=expected[k]]
    if different:
        for k in different:
            for i in range(0,4096,8):
                if pages[k][i:i+8]!=expected[k][i:i+8]:print('RELEASE_DIFF',succeeded,hex((k<<12)+i),'py',pages[k][i:i+8].hex(),'native',expected[k][i:i+8].hex())
        raise AssertionError(('release',succeeded))
    print('PASS release_purge',succeeded,'writes',len(writes),flush=True)
    results.append({'case':f'release_purge_success_{succeeded}','native_nonstack_writes':len(writes),'checkpoint_pages_compared':len(pages),'final_memory_match':True})
negative_cases=[]
for label,patches,kind,arg in (
    ('pending_tls',[(thread+8,0,4)],'malloc',0x2c),
    ('missing_arena',[(thread+0x30,0,8)],'malloc',0x2c),
    ('fresh_region_required',[(caller+0x30,0,4),(control+0x28,0,8),(control+0x30,control+0x38,8),(arena+0xe8,arena+0xf0,8)],'malloc',0x2c),
    ('dirty_region_required',[(caller+0x30,0,4),(control+0x28,0,8),(control+0x30,control+0x38,8),(0x12bc0230,0x5ff8,8)],'malloc',0x2c),
    ('entire_slab_release',[(bins+0x1c,3,4),(caller+0x28,1,4),(0x1294110c,0xff,4)],'cleanup',0),
    ('large_allocation',[],'malloc',0x3801),
    ('fill_flag',[(0x121d69c9,1,1)],'malloc',0x2c),
    ('bad_cursor',[(bins+0x1c,0xffffffff,4)],'cleanup',0),
):
    pages={k:bytearray(v) for k,v in baseline.items()}
    for a,v,n in patches:pages[a>>12][a&4095:(a&4095)+n]=v.to_bytes(n,'little')
    before={k:bytes(v) for k,v in pages.items()}
    try:
        if kind=='malloc':model.allocate_small_object(pages,thread_state_address=thread,request_size=arg)
        else:model.cleanup_small_object_bins(pages,thread_state_address=thread)
    except model.RefillUnsupported as error:reason=str(error)
    else:raise AssertionError(('not rejected',label))
    assert pages==before,('mutation on failure',label)
    negative_cases.append({'case':label,'rejected':True,'unchanged':True,'reason':reason})
    print('PASS reject',label,'without writes',flush=True)
pages={k:bytearray(v) for k,v in baseline.items()};before={k:bytes(v) for k,v in pages.items()}
assert model.free_small_object(pages,thread_state_address=thread,object_address=0) is None
assert pages==before
payload={'checkpoint_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'model_sha256':hashlib.sha256(Path(model.__file__).read_bytes()).hexdigest(),'cases':results}
payload['negative_cases']=negative_cases;payload['null_free_unchanged']=True
options.output.write_text(json.dumps(payload,indent=2)+'\n',encoding='utf-8')
