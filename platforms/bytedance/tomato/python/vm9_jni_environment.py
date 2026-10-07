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


def _invoke_jni(pages, environment_pointer, slot, arguments, invoke_jni):
    """Read the live environment table for each actual JNI call."""
    _address(environment_pointer,'JNI environment')
    table=_u(pages,environment_pointer);_address(table,'JNI environment table')
    function=_u(pages,table+slot);_address(function,'JNI function')
    if not callable(invoke_jni):
        raise RefillUnsupported('explicit JNI service provider is required')
    result=invoke_jni(pages,function,(environment_pointer,*arguments))
    if not isinstance(result,int) or not -(1<<31)<=result<=MASK64:
        raise RefillUnsupported('JNI service result must fit signed int32 or uint64')
    return result&MASK64


def retain_global_jni_reference(pages, *, environment_pointer, reference, invoke_jni):
    """+0x26f154: preserve type 2; otherwise NewGlobalRef then DeleteLocalRef.

    The original calls GetObjectRefType even for a NULL reference. Every other
    type follows the same promotion branch, including 0/3/unknown values.
    No Java object is invented, and the local is deleted even when promotion
    returns NULL. A NULL environment returns NULL without a JNI call.
    """
    for value in (environment_pointer,reference):
        if not isinstance(value,int) or not 0<=value<=MASK64:
            raise RefillUnsupported('JNI retention pointers must fit uint64')
    p=_PageTransaction(pages)
    if not environment_pointer:return 0
    kind=_invoke_jni(p,environment_pointer,0x740,(reference,),invoke_jni)&0xFFFFFFFF
    if kind==2:result=reference
    else:
        result=_invoke_jni(p,environment_pointer,0xA8,(reference,),invoke_jni)
        _invoke_jni(p,environment_pointer,0xB8,(reference,),invoke_jni)
    p.commit();return result


def _dispatch_delta(image_base,entry_offset=0x26E19C):
    entry=image_base+entry_offset
    folded=(((0x00A060400A021040 | (~entry&MASK64)) & 0x00A061440A061440)
        +(entry&0x0000010400040400))&MASK64
    return ((folded|0x01010104)^0xFF5F9EBBF4C6A63C)&MASK64


@dataclass(frozen=True)
class JavaDispatchInitializationResult:
    methods_address: int
    decoded_lengths: tuple[int|None, ...]
    class_reference: int
    superclass_reference: int
    ancestor_reference: int
    native_registration_attempted: bool
    method_lookup_attempted: bool
    static_method_id: int|None
    retained_class_reference: int|None


def initialize_java_dispatch(pages, *, image_base, entry_stack_address,
        environment_pointer, class_name_address, invoke_jni):
    """+0x26e19c initialization after JavaVM publication.

    Decode guest constants from the encoded ELF table, then FindClass and
    two GetSuperclass calls. Register one native callback on the ancestor if
    present, delete that local, and publish a static method ID plus a retained
    reference to the ORIGINAL FindClass class. RegisterNatives status is
    ignored. Missing class/first superclass leave prior outputs untouched.

    JNI services are explicit inputs. The registered +0x26e684 callback body,
    Java class loading, VM exceptions, full stack spills and JNI_OnLoad remain
    outside this component. Pages roll back on refusal; external JNI effects
    do not. Only the consumed 24-byte JNINativeMethod table is modeled on stack.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0xA0
            or entry_stack_address&15):
        raise RefillUnsupported('JNI initialization stack must be aligned with scratch space')
    for value in (image_base,environment_pointer,class_name_address):
        if not isinstance(value,int) or not 0<=value<=MASK64:
            raise RefillUnsupported('JNI initialization inputs must fit uint64')
    p=_PageTransaction(pages);delta=_dispatch_delta(image_base)
    def resolve(off):return (_u(p,image_base+off)+delta)&MASK64
    # These three words are retained before any decode or JNI provider call.
    native_name,signature,static_name=(resolve(off) for off in (0x382550,0x382558,0x382560))
    lengths=[]
    for flag_off,source_off,destination_off,mask_off in (
            (0x382568,0x382570,0x382550,0x382578),
            (0x382580,0x382588,0x382558,0x382590),
            (0x382598,0x3825A0,0x382560,0x3825A8)):
        length=None
        if not _u(p,resolve(flag_off),4):
            length=objects.decode_masked_bytes(p,source_address=resolve(source_off),
                destination_address=resolve(destination_off),mask_address=resolve(mask_off))
            # Reload the encoded flag word after decode, like native.
            _w(p,resolve(flag_off),1,4)
        lengths.append(length)
    methods=entry_stack_address-0xA0
    cls=parent=ancestor=0;registered=looked_up=False;method_id=retained=None
    if class_name_address:
        cls=_invoke_jni(p,environment_pointer,0x30,(class_name_address,),invoke_jni)
        if cls:
            parent=_invoke_jni(p,environment_pointer,0x50,(cls,),invoke_jni)
            if parent:
                ancestor=_invoke_jni(p,environment_pointer,0x50,(parent,),invoke_jni)
                if ancestor:
                    _write_span(p,methods,b''.join(value.to_bytes(8,'little')
                        for value in (native_name,signature,image_base+0x26E684)))
                    _invoke_jni(p,environment_pointer,0x6B8,(ancestor,methods,1),invoke_jni)
                    registered=True
                    _invoke_jni(p,environment_pointer,0xB8,(ancestor,),invoke_jni)
                method_id=_invoke_jni(p,environment_pointer,0x388,(cls,static_name,signature),invoke_jni)
                looked_up=True;_w(p,resolve(0x3825B0),method_id)
                retained=retain_global_jni_reference(p,environment_pointer=environment_pointer,
                    reference=cls,invoke_jni=invoke_jni)
                _w(p,resolve(0x3825B8),retained)
    result=JavaDispatchInitializationResult(methods,tuple(lengths),cls,parent,ancestor,
        registered,looked_up,method_id,retained)
    p.commit();return result


def check_and_clear_java_exception(pages, *, environment_pointer, invoke_jni):
    """+0x27184c: low-byte check, occurred/clear/delete, boolean result.

    A NULL environment returns false. DeleteLocalRef is executed even if
    ExceptionOccurred returns NULL. JNI side effects are explicit services.
    """
    if not isinstance(environment_pointer,int) or not 0<=environment_pointer<=MASK64:
        raise RefillUnsupported('exception environment must fit uint64')
    if not environment_pointer:return False
    p=_PageTransaction(pages)
    found=bool(_invoke_jni(p,environment_pointer,0x720,(),invoke_jni)&0xFF)
    if found:
        exception=_invoke_jni(p,environment_pointer,0x78,(),invoke_jni)
        _invoke_jni(p,environment_pointer,0x88,(),invoke_jni)
        _invoke_jni(p,environment_pointer,0xB8,(exception,),invoke_jni)
    p.commit();return found


def clear_java_exception(pages, *, environment_pointer, invoke_jni):
    """+0x26f258: independent low-byte check and conditional ExceptionClear."""
    if not isinstance(environment_pointer,int) or not 0<=environment_pointer<=MASK64:
        raise RefillUnsupported('exception environment must fit uint64')
    if not environment_pointer:return
    p=_PageTransaction(pages)
    if _invoke_jni(p,environment_pointer,0x720,(),invoke_jni)&0xFF:
        _invoke_jni(p,environment_pointer,0x88,(),invoke_jni)
    p.commit()


@dataclass(frozen=True)
class IntegerJavaVariadicFrame:
    copied_va_list_address: int
    original_va_list_address: int
    general_registers_address: int
    integer_words: tuple[int, ...]


def prepare_integer_java_variadic_frame(pages, *, entry_stack_address, argument_words):
    """+0x26e944 integer-only ABI consumed by this (IIJ...Object) signature.

    Preserve the two actual va_list structures, five GP save slots and offsets.
    The 128-byte SIMD save area, stack canary, FP/LR and full physical spill ABI
    are outside this helper. The recovered signature consumes no FP arguments.
    Callers must not use it for a different/floating-point JNI signature.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x120
            or entry_stack_address&15):
        raise RefillUnsupported('JNI variadic stack must be aligned with scratch space')
    words=tuple(argument_words)
    if len(words)!=5 or any(not isinstance(v,int) or not 0<=v<=MASK64 for v in words):
        raise RefillUnsupported('JNI variadic call requires five uint64 raw words')
    p=_PageTransaction(pages);gp=entry_stack_address-0x98
    original=entry_stack_address-0x48;copied=entry_stack_address-0x70
    _write_span(p,gp,b''.join(v.to_bytes(8,'little') for v in words))
    # va_list: stack, gr_top, vr_top, int32 gr_offs, int32 vr_offs.
    raw=b''.join(v.to_bytes(8,'little') for v in
        (entry_stack_address,copied,entry_stack_address-0xA0))
    raw+=(-40).to_bytes(4,'little',signed=True)+(-128).to_bytes(4,'little',signed=True)
    _write_span(p,original,raw);_write_span(p,copied,_read_span(p,original,32))
    result=IntegerJavaVariadicFrame(copied,original,gp,words)
    p.commit();return result


@dataclass(frozen=True)
class JavaDispatchResult:
    environment_pointer: int
    returned_reference: int
    static_call_attempted: bool
    exception_seen: bool
    variadic_frame: IntegerJavaVariadicFrame|None


def invoke_java_dispatch(pages, *, image_base, entry_stack_address, argument_words,
        acquire_environment, invoke_jni):
    """+0x26e70c -> +0x26e944, preserving original lookup/call/cleanup order.

    Acquisition writes the real output pair at query SP+8. The caller may use
    the recovered TLS owner or an explicit component provider. JNI still comes
    from explicit services, never an invented Android VM. Exceptions clear the
    returned reference without inventing deletion of that result. The second
    exception check is independent and does not change the chosen result.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x190
            or entry_stack_address&15):
        raise RefillUnsupported('JNI dispatcher stack must be aligned with scratch space')
    if not isinstance(image_base,int) or not 0<=image_base<=MASK64:
        raise RefillUnsupported('JNI dispatcher image base must fit uint64')
    words=tuple(argument_words)
    if len(words)!=5 or any(not isinstance(v,int) or not 0<=v<=MASK64 for v in words):
        raise RefillUnsupported('JNI dispatcher requires five uint64 raw argument words')
    if not callable(acquire_environment):
        raise RefillUnsupported('JNI dispatcher requires an explicit environment acquisition provider')
    # W24/W23 are latched before acquisition; X2/X3/X4 remain full raw words.
    arguments=(words[0]&0xFFFFFFFF,words[1]&0xFFFFFFFF,*words[2:])
    p=_PageTransaction(pages);stack=entry_stack_address-0x70;pair=stack+8
    acquire_environment(p,entry_stack_address=stack,output_pair_address=pair)
    env=_u(p,pair);reference=0;called=False;exception=False;frame=None
    if env:
        delta=_dispatch_delta(image_base,0x26E70C)
        def resolve(off):return (_u(p,image_base+off)+delta)&MASK64
        if _u(p,resolve(0x3825B8)) and _u(p,resolve(0x3825B0)):
            # Re-read the slots at the actual call, after the ordered checks.
            cls=_u(p,resolve(0x3825B8));method=_u(p,resolve(0x3825B0))
            frame=prepare_integer_java_variadic_frame(p,entry_stack_address=stack,argument_words=arguments)
            reference=_invoke_jni(p,env,0x398,(cls,method,frame.copied_va_list_address),invoke_jni)
            called=True
        exception=check_and_clear_java_exception(p,environment_pointer=env,invoke_jni=invoke_jni)
        if exception:reference=0
        clear_java_exception(p,environment_pointer=env,invoke_jni=invoke_jni)
    result=JavaDispatchResult(env,reference,called,exception,frame)
    p.commit();return result


@dataclass(frozen=True)
class NoArgumentJavaVariadicFrame:
    copied_va_list_address: int
    original_va_list_address: int
    redundant_object_spill_address: int


def prepare_no_argument_java_variadic_frame(pages, *, entry_stack_address, object_reference):
    """+0x224ff8 structures for the known ()J signature only.

    The caller places its object reference in X3 as well as X1; preserve that
    redundant GP spill. The other four saved GP words are unconsumed registers,
    so do not invent their values. SIMD saves/canary/FP/LR remain outside this
    semantic frame. This helper is not an arbitrary JNI variadic ABI.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x120
            or entry_stack_address&15):
        raise RefillUnsupported('no-argument JNI variadic stack must be aligned')
    if not isinstance(object_reference,int) or not 0<=object_reference<=MASK64:
        raise RefillUnsupported('JNI object reference must fit uint64')
    p=_PageTransaction(pages);original=entry_stack_address-0x48;copied=entry_stack_address-0x70
    spill=entry_stack_address-0x98;_w(p,spill,object_reference)
    raw=b''.join(v.to_bytes(8,'little') for v in
        (entry_stack_address,copied,entry_stack_address-0xA0))
    raw+=(-40).to_bytes(4,'little',signed=True)+(-128).to_bytes(4,'little',signed=True)
    _write_span(p,original,raw);_write_span(p,copied,_read_span(p,original,32))
    result=NoArgumentJavaVariadicFrame(copied,original,spill)
    p.commit();return result


@dataclass(frozen=True)
class JavaLongConversionResult:
    returned_word: int
    decoded_lengths: tuple[int|None, ...]
    class_reference: int
    method_id: int
    cache_lock_taken: bool
    long_call_attempted: bool
    variadic_frame: NoArgumentJavaVariadicFrame|None


def convert_java_long(pages, *, image_base, entry_stack_address,
        environment_pointer, object_reference, invoke_jni,
        lock_mutex=objects.lock_uncontended_mutex,unlock_mutex=objects.unlock_uncontended_mutex):
    """+0x270854 -> cached java/lang/Long.longValue()J -> +0x224ff8.

    Decode three strings before the NULL-env branch. A warm class/method pair
    bypasses the cache mutex; otherwise use the already constructed mutex at
    +0x3df0a8, recheck under its serialized lock, retain the FindClass result,
    and cache GetMethodID. The cache constructor is not supplied here.

    NULL object references are passed to CallLongMethodV when the cache/env
    allow a call, as in the original body. No exception check is added: this
    component does not contain one. Only uncontended successful mutex status
    is supported. Page rollback does not reverse external JNI/lock effects.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x190
            or entry_stack_address&15):
        raise RefillUnsupported('JNI Long stack must be aligned with scratch space')
    for value in (image_base,environment_pointer,object_reference):
        if not isinstance(value,int) or not 0<=value<=MASK64:
            raise RefillUnsupported('JNI Long inputs must fit uint64')
    p=_PageTransaction(pages);lengths=[]
    for flag,source,dest,mask in (
            (0x3DEF7C,0xA5828,0x3DEF6C,0xA5A1C),
            (0x3DEFB4,0xA5854,0x3DEFA8,0xA59E8),
            (0x3DEFBC,0xA5860,0x3DEFB8,0xA59E4)):
        length=None
        if not _u(p,image_base+flag,4):
            length=objects.decode_masked_bytes(p,source_address=image_base+source,
                destination_address=image_base+dest,mask_address=image_base+mask)
            _w(p,image_base+flag,1,4)
        lengths.append(length)
    scope=entry_stack_address-0x70;cls=method=word=0;locked=called=False;frame=None
    if environment_pointer:
        method=_u(p,image_base+0x3DF0C8)
        cls=_u(p,image_base+0x3DF0C0) if method else 0
        if not cls or not method:
            mutex=_u(p,image_base+0x3DF0A8)
            _address(mutex,'JNI Long cache mutex object',48)
            _w(p,scope,image_base+0x34C778);_w(p,scope+8,mutex)
            if not callable(lock_mutex) or not callable(unlock_mutex):
                raise RefillUnsupported('JNI Long requires explicit lock services')
            status=lock_mutex(p,mutex_address=mutex+8)
            if status!=0:raise RefillUnsupported('JNI Long only supports successful uncontended cache locks')
            _w(p,scope+16,status,4);locked=True
            method=_u(p,image_base+0x3DF0C8)
            cls=_u(p,image_base+0x3DF0C0) if method else 0
            if not cls or not method:
                local=_invoke_jni(p,environment_pointer,0x30,(image_base+0x3DEF6C,),invoke_jni)
                cls=retain_global_jni_reference(p,environment_pointer=environment_pointer,
                    reference=local,invoke_jni=invoke_jni)
                _w(p,image_base+0x3DF0C0,cls)
                if cls:
                    method=_invoke_jni(p,environment_pointer,0x108,
                        (cls,image_base+0x3DEFA8,image_base+0x3DEFB8),invoke_jni)
                    _w(p,image_base+0x3DF0C8,method)
            # +0x15f778 overwrites the scope vtable, then uses its saved mutex.
            _w(p,scope,image_base+0x34C778)
            if unlock_mutex(p,mutex_address=_u(p,scope+8)+8)!=0:
                raise RefillUnsupported('JNI Long cache unlock failure is unrecovered')
            cls=_u(p,image_base+0x3DF0C0);method=_u(p,image_base+0x3DF0C8)
        if cls and method:
            frame=prepare_no_argument_java_variadic_frame(p,entry_stack_address=scope,
                object_reference=object_reference)
            word=_invoke_jni(p,environment_pointer,0x1A8,
                (object_reference,method,frame.copied_va_list_address),invoke_jni)
            called=True
    result=JavaLongConversionResult(word,tuple(lengths),cls,method,locked,called,frame)
    p.commit();return result


@dataclass(frozen=True)
class JavaCacheMutexInitializationResult:
    allocated_mutex_object: int
    inline_mutex_object: int
    registration_status: int


def initialize_java_cache_mutexes(pages, *, image_base, allocate, register_exit):
    """.init_array +0x271940: new48, publish +3df0a8, inline +3df118.

    Both +0x15dea8 constructors use flag0/normal mutex attributes. Preserve
    preexisting class/method cache fields; this is not a cache reset routine.
    Finally request __cxa_atexit(+165388, inline, +34c700). Nonzero registration
    status is not rejected by the original body. Actual destructor execution,
    all ELF constructors, allocator boot and whole JNI_OnLoad remain separate.
    Page rollback cannot reverse allocator/exit-provider effects.
    """
    if not isinstance(image_base,int) or not 0<=image_base<=MASK64-0x3DF148:
        raise RefillUnsupported('JNI cache mutex image base must fit guest addresses')
    if not callable(allocate):raise RefillUnsupported('JNI cache mutex requires an allocator')
    p=_PageTransaction(pages);allocated=allocate(p,48)
    _address(allocated,'JNI cache allocated mutex',48)
    objects.construct_normal_mutex_object(p,object_address=allocated,image_base=image_base)
    _w(p,image_base+0x3DF0A8,allocated)
    inline=image_base+0x3DF118
    objects.construct_normal_mutex_object(p,object_address=inline,image_base=image_base)
    if not callable(register_exit):raise RefillUnsupported('JNI cache mutex requires an exit registration service')
    status=register_exit(p,image_base+0x165388,inline,image_base+0x34C700)
    if not isinstance(status,int) or not -(1<<31)<=status<=0xFFFFFFFF:
        raise RefillUnsupported('exit registration status must fit signed/unsigned uint32')
    result=JavaCacheMutexInitializationResult(allocated,inline,status&0xFFFFFFFF)
    p.commit();return result


@dataclass(frozen=True)
class ColdJavaSwitchInitializationResult:
    environment_pointer: int
    object_reference: int
    written_switch_word: int|None
    object_deleted: bool


def initialize_cold_java_switch(pages, *, image_base, entry_stack_address,
        acquire_environment, invoke_jni):
    """+0x165658: acquire -> actual getter -> Long -> store -> DeleteLocalRef.

    This is the cold once initializer's caller body, not the +0x32a0a0 once
    wrapper or whole JNI_OnLoad. It acquires the outer env at caller SP+8,
    then the dispatcher independently acquires its own env. A NULL outer env
    or returned object leaves the switch word untouched. Only a non-NULL
    returned object is converted, stored to +0x3d1578 and locally deleted.
    The acquired outer env is retained for conversion/cleanup, independently
    of the dispatcher's env. Page rollback does not reverse provider effects.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x1E0
            or entry_stack_address&15):
        raise RefillUnsupported('cold JNI switch caller stack must be aligned with scratch space')
    if not isinstance(image_base,int) or not 0<=image_base<=MASK64:
        raise RefillUnsupported('cold JNI switch image base must fit uint64')
    if not callable(acquire_environment):
        raise RefillUnsupported('cold JNI switch requires environment acquisition')
    p=_PageTransaction(pages);stack=entry_stack_address-0x50;pair=stack+8
    acquire_environment(p,entry_stack_address=stack,output_pair_address=pair)
    env=_u(p,pair);reference=0;word=None;deleted=False
    if env:
        dispatch=invoke_java_dispatch(p,image_base=image_base,entry_stack_address=stack,
            argument_words=(0x1000000E,0,0,0,0),acquire_environment=acquire_environment,invoke_jni=invoke_jni)
        reference=dispatch.returned_reference
        if reference:
            conversion=convert_java_long(p,image_base=image_base,entry_stack_address=stack,
                environment_pointer=env,object_reference=reference,invoke_jni=invoke_jni)
            word=conversion.returned_word;_w(p,image_base+0x3D1578,word)
            _invoke_jni(p,env,0xB8,(reference,),invoke_jni);deleted=True
    result=ColdJavaSwitchInitializationResult(env,reference,word,deleted)
    p.commit();return result
