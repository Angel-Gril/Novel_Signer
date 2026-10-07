"""Recovered +0x26edc4 TLS environment acquisition with explicit VM services.

No environment is invented. TLS and destructor providers own their existing
components; invoke_javavm executes an explicit JavaVM service and writes its
output slot. Attach failure diagnostics and complete JNI are unrecovered.
Guest-page transactions cannot reverse external JavaVM/provider effects.
"""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64 = (1 << 64) - 1


def _u(pages, address, width=8):
    return int.from_bytes(_read_span(pages,address,width),'little')


def _w(pages, address, value, width=8):
    _write_span(pages,address,value.to_bytes(width,'little'))


def _address(value, label, width=8):
    if not isinstance(value,int) or not 0 < value <= MASK64-width:
        raise RefillUnsupported(label+' must be a nonzero uint64 address')


def _java_vm(pages, image_base, *, indirect=True):
    storage = _u(pages,image_base+0x374F90) if indirect else image_base+0x3DEED8
    _address(storage,'JavaVM storage')
    return _u(pages,storage)


def _invoke(pages, image_base, slot, arguments, invoke_javavm, *, indirect=True):
    vm = _java_vm(pages,image_base,indirect=indirect)
    if not vm:
        method = {0x20:'AttachCurrentThread +0x26ef7c',0x28:'DetachCurrentThread',0x30:'GetEnv'}[slot]
        raise RefillUnsupported('JavaVM unavailable for '+method)
    _address(vm,'JavaVM object')
    table = _u(pages,vm)
    _address(table,'JavaVM table')
    function = _u(pages,table+slot)
    _address(function,'JavaVM function')
    if invoke_javavm is None:
        raise RefillUnsupported('JavaVM service provider is required')
    status = invoke_javavm(pages,function,(vm,*arguments))
    if not isinstance(status,int) or not -(1<<31) <= status <= 0xFFFFFFFF:
        raise RefillUnsupported('JavaVM status must fit signed/unsigned uint32')
    return status & 0xFFFFFFFF


def get_java_environment(pages, *, image_base, entry_stack_address, invoke_javavm):
    """+0x17caac; GetEnv status is ignored, output initialized to NULL."""
    if not isinstance(entry_stack_address,int) or entry_stack_address<0x30 or entry_stack_address&15:
        raise RefillUnsupported('GetEnv stack must be aligned with scratch space')
    p = _PageTransaction(pages)
    slot = entry_stack_address-0x30
    _w(p,slot,0)
    if _java_vm(p,image_base):
        _invoke(p,image_base,0x30,(slot,0x10006),invoke_javavm)
    result = _u(p,slot)
    p.commit()
    return result


def _attach(pages, *, image_base, object_address, invoke_javavm):
    for flag,destination,source,mask in ((0x3DEEF0,0x3DEEE8,0xA5730,0xA5798),
            (0x3DEF28,0x3DEF00,0xA5740,0xA5770)):
        if not _u(pages,image_base+flag,4):
            objects.decode_masked_bytes(pages,source_address=image_base+source,
                destination_address=image_base+destination,mask_address=image_base+mask)
            _w(pages,image_base+flag,1,4)
    status = _invoke(pages,image_base,0x20,(object_address+16,0),invoke_javavm)
    # Native checks status == JNI_ERR (-1), rather than status != JNI_OK.
    if status == 0xFFFFFFFF or not _u(pages,object_address+16):
        raise RefillUnsupported('JavaVM attach failure +0x26f054 diagnostics is not recovered')
    _w(pages,object_address+8,1,1)


def construct_thread_environment(pages, *, image_base, entry_stack_address,
        object_address, invoke_javavm):
    """+0x26eeec; initialize only vtable, ownership byte, and env word."""
    _address(object_address,'thread environment',24)
    p = _PageTransaction(pages)
    _w(p,object_address,image_base+0x35D478)
    _w(p,object_address+8,0,1)
    env = get_java_environment(p,image_base=image_base,
        entry_stack_address=entry_stack_address-0x20,invoke_javavm=invoke_javavm)
    _w(p,object_address+16,env)
    if not env:
        _attach(p,image_base=image_base,object_address=object_address,invoke_javavm=invoke_javavm)
    env = _u(p,object_address+16)
    p.commit()
    return env


def destroy_thread_environment(pages, *, image_base, object_address, invoke_javavm):
    """+0x26ef2c; detach only when the entire ownership byte is nonzero."""
    _address(object_address,'thread environment',24)
    p = _PageTransaction(pages)
    owned = bool(_u(p,object_address+8,1))
    _w(p,object_address,image_base+0x35D478)
    if owned:
        _invoke(p,image_base,0x28,(),invoke_javavm)
        _w(p,object_address+16,0)
        _w(p,object_address+8,0,1)
    p.commit()
    return owned


@dataclass(frozen=True)
class EnvironmentAcquisitionResult:
    environment: int
    owner_address: int
    cold_tls_constructed: bool
    temporary_constructed: bool
    temporary_detached: bool


def acquire_thread_environment(pages, *, image_base, entry_stack_address,
        output_pair_address, get_tls, register_destructor, invoke_javavm, observer=None):
    """+0x26edc4; cold TLS construction, refresh and temporary fallback.

    Successful original return is represented by the output pair, not native
    X0 (which is incidental on this void path). Registration status is ignored
    as in native. Physical stack/canary and concurrent TLS are not modeled.
    """
    if not isinstance(entry_stack_address,int) or entry_stack_address<0xE0 or entry_stack_address&15:
        raise RefillUnsupported('environment acquisition stack must be aligned')
    _address(output_pair_address,'environment output pair',16)
    if get_tls is None or register_destructor is None:
        raise RefillUnsupported('environment acquisition requires TLS/destructor providers')
    p = _PageTransaction(pages)
    local = entry_stack_address-0x50
    if max(output_pair_address,local)<min(output_pair_address+16,local+24):
        raise RefillUnsupported('environment output pair aliases temporary storage')
    _write_span(p,output_pair_address,bytes(16))
    guard = get_tls(p,image_base+0x3825E0)
    _address(guard,'environment TLS guard',1)
    cold = not _u(p,guard,1)&1
    if cold:
        owner = get_tls(p,image_base+0x3825C0)
        _address(owner,'environment TLS object',24)
        construct_thread_environment(p,image_base=image_base,entry_stack_address=local,
            object_address=owner,invoke_javavm=invoke_javavm)
        register_destructor(p,image_base+0x26EF2C,owner,image_base+0x34C700)
        guard = get_tls(p,image_base+0x3825E0)
        _w(p,guard,1,1)
    owner = get_tls(p,image_base+0x3825C0)
    _address(owner,'environment TLS object',24)
    if max(owner,output_pair_address)<min(owner+24,output_pair_address+16):
        raise RefillUnsupported('environment output pair aliases TLS owner')
    _w(p,output_pair_address+8,owner)
    env = get_java_environment(p,image_base=image_base,
        entry_stack_address=local,invoke_javavm=invoke_javavm)
    _w(p,owner+16,env)
    _w(p,output_pair_address,env)
    temporary = not bool(env)
    detached = False
    if temporary:
        construct_thread_environment(p,image_base=image_base,entry_stack_address=local,
            object_address=local,invoke_javavm=invoke_javavm)
        owner = get_tls(p,image_base+0x3825C0)
        _write_span(p,owner+8,_read_span(p,local+8,16))
        owned = bool(_u(p,local+8,1))
        _w(p,local,image_base+0x35D478)
        if owned:
            _invoke(p,image_base,0x28,(),invoke_javavm,indirect=False)
            detached = True
        owner = get_tls(p,image_base+0x3825C0)
        env = _u(p,owner+16)
        _w(p,output_pair_address,env)
    result = EnvironmentAcquisitionResult(env,owner,cold,temporary,detached)
    if observer:
        observer(p,phase='jni_environment_acquired',environment=env,owner_address=owner,
            cold_tls_constructed=cold,temporary_constructed=temporary,
            temporary_detached=detached,explicit_javavm_service_used=True,
            complete_jni_verified=False)
    p.commit()
    return result


@dataclass(frozen=True)
class JavaVmPublicationResult:
    storage_address: int
    java_vm_pointer: int
    frame_address: int
    frame_rewritten: bool
    restored_frame_pointer: int
    continuation_address: int
    native_return_x0: int


def publish_java_vm_wrapper(pages, *, image_base, entry_stack_address,
        argument_block_address, first_word, second_word, saved_frame_pointer,
        return_address, saved_x20=0, saved_x19=0, saved_x6=0):
    """+0x27be88: publish parameter word, optionally replace saved FP/LR.

    JVM pointer may be NULL, as in the original store. The wrapper does not
    initialize or validate a JavaVM table. A retained 32-byte frame is modeled;
    the live X6 spill from +0x26ecb4 is retained too; its other deeper spill
    words/ABI are not modeled. X0 is incidental but
    measured for this component, not treated as a JNI return status.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x100
            or entry_stack_address&15):
        raise RefillUnsupported('JavaVM publication stack must be aligned')
    values=(first_word,second_word,saved_frame_pointer,return_address,saved_x20,saved_x19,saved_x6)
    if any(not isinstance(v,int) or not 0<=v<1<<64 for v in values):
        raise RefillUnsupported('JavaVM publication ABI inputs must fit uint64')
    _address(argument_block_address,'JavaVM publication argument block')
    p=_PageTransaction(pages);frame=entry_stack_address-0x20
    _read_span(p,frame,32)
    for offset,value in ((0,saved_frame_pointer),(8,return_address),(16,saved_x20),(24,saved_x19)):
        _w(p,frame+offset,value)
    # Load the parameter only after writing the prologue, matching native
    # aliases involving that retained frame. Global storage aliases stay real.
    storage=_u(p,image_base+0x374F90);_address(storage,'JavaVM publication storage')
    vm=_u(p,argument_block_address)
    _w(p,storage,vm)
    rewritten=first_word>4096 and second_word>4096
    if rewritten:
        # The later +0x26ed3c STP X7,X6 overwrites the earlier X7 spill.
        # Its final X6 word at getter entry SP -0x28 supplies temporary padding.
        _w(p,frame-0x28,saved_x6)
        _w(p,frame,first_word-0xE9);_w(p,frame+8,second_word-0xD5)
    result=JavaVmPublicationResult(storage,vm,frame,rewritten,_u(p,frame),_u(p,frame+8),
        frame if rewritten else argument_block_address)
    p.commit();return result


def publish_java_vm_callback(pages, *, image_base, entry_stack_address,
        argument_block_address, saved_frame_pointer, return_address, saved_x20=0,saved_x19=0,saved_x6=0):
    """Compose original +0x271998 -> +0x27be88 with a valid retained caller.

    This is the measured publication callback, not all JNI_OnLoad. The caller
    supplies a JavaVM pointer in the parameter block, never a native snapshot.
    """
    from vm9_callbacks import prepare_encoded_callback_frame
    p=_PageTransaction(pages)
    adapter=prepare_encoded_callback_frame(p,entry_stack_address=entry_stack_address,
        callback_address=image_base+0x27BE88,argument_block_address=argument_block_address,
        saved_frame_pointer=saved_frame_pointer,return_address=return_address,saved_x6=saved_x6)
    _,first,second=adapter.argument_words
    if first<=4096 or second<=4096:
        raise RefillUnsupported('JavaVM publication callback requires encodable caller FP/LR')
    result=publish_java_vm_wrapper(p,image_base=image_base,entry_stack_address=entry_stack_address,
        argument_block_address=argument_block_address,first_word=first,second_word=second,
        saved_frame_pointer=adapter.callback_frame_pointer,return_address=adapter.callback_address,
        saved_x20=saved_x20,saved_x19=saved_x19,saved_x6=saved_x6)
    p.commit();return result
