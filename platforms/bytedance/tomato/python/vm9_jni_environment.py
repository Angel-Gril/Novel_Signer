"""Recovered +0x26edc4 TLS environment acquisition with explicit VM services.

No environment is invented. TLS and destructor providers own their existing
components; invoke_javavm executes an explicit JavaVM service and writes its
output slot. Attach failure diagnostics and complete JNI are unrecovered.
Guest-page transactions cannot reverse external JavaVM/provider effects.
"""
from __future__ import annotations
from dataclasses import dataclass
import vm9_objects as objects
import vm9_cpp_strings as cpp_strings
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


@dataclass(frozen=True)
class StaticMethodAvailabilityResult:
    availability: int
    environment: int | None
    acquisition: EnvironmentAcquisitionResult | None


def check_cached_static_method_availability(pages, *, image_base,
        entry_stack_address, acquire_environment, invoke_jni):
    """Shared +204b80 semantics; stack address is its acquisition/output pair.

    Decode guards precede the raw cached byte. The method ID is ignored;
    only ExceptionCheck's low byte decides availability. A missing acquired
    environment returns the live cache byte. Physical prologue, canary and
    epilogue belong to the caller. Providers own external effects.
    """
    if type(entry_stack_address) is not int or entry_stack_address<0xE0 or entry_stack_address&15:
        raise RefillUnsupported('static method availability stack must be aligned')
    p=_PageTransaction(pages);base=image_base
    for source,dest,mask,flag in ((0x89F20,0x3DA014,0x8A03C,0x3DA018),
                                (0x89F24,0x3DA01C,0x8A038,0x3DA020)):
        if not _u(p,base+flag,4):
            objects.decode_masked_bytes(p,source_address=base+source,
                destination_address=base+dest,mask_address=base+mask,max_bytes=64)
            _w(p,base+flag,1,4)
    cached=_u(p,base+0x3DA010,1);acquired=None;env=None
    if not cached:
        if not callable(acquire_environment):
            raise RefillUnsupported('static method availability requires environment acquisition')
        acquired=acquire_environment(p,entry_stack_address=entry_stack_address,
            output_pair_address=entry_stack_address)
        env=acquired.environment;cls=_u(p,base+0x3DEEB8)
        if type(env) is not int or not 0<=env<=MASK64:
            raise RefillUnsupported('invalid acquired JNI environment')
        if env:
            _invoke_jni(p,env,0x388,(cls,base+0x3DA014,base+0x3DA01C),invoke_jni)
            if _invoke_jni(p,env,0x720,(),invoke_jni)&255:
                _invoke_jni(p,env,0x88,(),invoke_jni);_w(p,base+0x3DA010,0,1)
            else:_w(p,base+0x3DA010,1,1)
        cached=_u(p,base+0x3DA010,1)
    result=StaticMethodAvailabilityResult(cached,env,acquired)
    p.commit();return result


@dataclass(frozen=True)
class JavaByteArrayReferenceResult:
    string_address: int
    counter_address: int
    array_length_word: int | None
    temporary_buffer_address: int
    byte_region_called: bool


def construct_java_byte_array_reference(pages, *, image_base, entry_stack_address,
        output_reference_address, environment_pointer, array_reference,
        thread_pointer, thread_id, invoke_jni, calloc, allocate, free,
        max_payload_bytes=0x100000, diagnostic_observer=None):
    """+0x2700a8: sized binary array -> string -> actual scoped reference.

    NULL environment/array, nonpositive signed W32 length and calloc NULL
    produce a NULL string with a count of one. A string-buffer malloc NULL
    still retains its empty string object. GetByteArrayRegion is a void call;
    its result is ignored and no Java exception check is inserted. JNI and
    allocation services are supplied explicitly. Page rollback cannot undo
    their external effects. Physical frame spills and C++ unwind are excluded.
    """
    import vm9_diagnostics as diagnostics
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0x50
            or entry_stack_address>MASK64 or entry_stack_address&15):
        raise RefillUnsupported('byte array helper requires an aligned guest stack')
    _address(output_reference_address,'byte array output reference',16)
    for value in (environment_pointer,array_reference):
        if not isinstance(value,int) or not 0<=value<=MASK64:
            raise RefillUnsupported('byte array JNI pointers must fit uint64')
    if not isinstance(max_payload_bytes,int) or not 0<=max_payload_bytes<=0x100000:
        raise ValueError('invalid byte array payload bound')
    if not callable(allocate):raise RefillUnsupported('byte array reference requires an allocator')
    p=_PageTransaction(pages);string=buffer=0;length=None;called=False
    if environment_pointer and array_reference:
        length=_invoke_jni(p,environment_pointer,0x558,(array_reference,),invoke_jni)&0xFFFFFFFF
        if 0<length<0x80000000:
            if length>max_payload_bytes:raise RefillUnsupported('Java byte array exceeds the explicit payload bound')
            if not callable(calloc):raise RefillUnsupported('byte array helper requires a calloc service')
            buffer=calloc(p,1,length)
            if not isinstance(buffer,int) or not 0<=buffer<=MASK64:
                raise RefillUnsupported('byte array calloc result must fit uint64')
            if buffer:
                _address(buffer,'byte array temporary buffer',length)
                _read_span(p,buffer,length)
                _invoke_jni(p,environment_pointer,0x640,(array_reference,0,length,buffer),invoke_jni)
                called=True
                string=objects._allocate(p,allocate,24)
                # +248208 saves the caller's X19 (the output pair) below its
                # frame. The later reference scope keeps the upper four
                # bytes of this word as its otherwise unwritten padding.
                _w(p,entry_stack_address-0x48,output_reference_address)
                objects.construct_sized_string_object(p,object_address=string,
                    source_address=buffer,length=length,image_base=image_base,
                    allocate=allocate,max_payload_bytes=max_payload_bytes)
                if not callable(free):raise RefillUnsupported('byte array helper requires a free service')
                free(p,buffer)
    # The tail-call +1625a4 uses the original helper entry SP again. It clears
    # the output pair before entering the scope, then publishes the string.
    _write_span(p,output_reference_address,bytes(16));scope=entry_stack_address-0x50
    diagnostics.enter_diagnostic_scope(p,object_address=scope,input_word=string,
        image_base=image_base,thread_pointer=thread_pointer,thread_id=thread_id,
        allocate=allocate,observer=diagnostic_observer)
    counter=objects.construct_reference_wrapper(p,object_address=output_reference_address,
        referenced_address=string,allocate=allocate)
    diagnostics.leave_diagnostic_scope(p,object_address=scope,image_base=image_base,
        thread_pointer=thread_pointer,observer=diagnostic_observer)
    result=JavaByteArrayReferenceResult(string,counter,length,buffer,called)
    p.commit();return result


def convert_java_object_to_byte_reference(pages, *, image_base, entry_stack_address,
        output_reference_address, environment_pointer, object_reference,
        thread_pointer, thread_id, invoke_jni, allocate, calloc, free,
        max_payload_bytes=0x100000, diagnostic_observer=None):
    """+0x26fe2c: decoded UTF argument, instance method and owned byte reference.

    Reuse integer/reference JNI dispatch, binary conversion and scoped reference
    owners. Every JNI lookup reads the current environment table. Temporary
    locals are deleted in native order, including a non-NULL result accompanied
    by an exception. Physical stack spills/padding and unwind stay outside this
    composition; page rollback cannot undo external provider effects.
    """
    import vm9_reference_scopes as references
    if (type(entry_stack_address) is not int or not 0x240<=entry_stack_address<=MASK64
            or entry_stack_address&15):
        raise RefillUnsupported('Java object bytes helper requires an aligned guest stack')
    _address(output_reference_address,'Java object bytes output reference',16)
    for value in (environment_pointer,object_reference):
        if type(value) is not int or not 0<=value<=MASK64:
            raise RefillUnsupported('Java object bytes JNI pointers must fit uint64')
    if type(max_payload_bytes) is not int or not 0<=max_payload_bytes<=0x100000:
        raise ValueError('invalid Java object byte payload bound')
    p=_PageTransaction(pages)
    for source,dest,mask,flag in ((0xA57F8,0x3DEF2C,0xA5A54,0x3DEF34),
            (0xA5800,0x3DEF38,0xA5A48,0x3DEF44),
            (0xA5810,0x3DEF50,0xA5A30,0x3DEF68)):
        if not _u(p,image_base+flag,4):
            objects.decode_masked_bytes(p,source_address=image_base+source,
                destination_address=image_base+dest,mask_address=image_base+mask)
            _w(p,image_base+flag,1,4)
    call_sp=entry_stack_address-0x90
    temporary,status,binary=entry_stack_address-0x70,entry_stack_address-0x80,call_sp
    kw=dict(entry_stack_address=call_sp,image_base=image_base,thread_pointer=thread_pointer,
        thread_id=thread_id,allocate=allocate,diagnostic_observer=diagnostic_observer)
    if environment_pointer and object_reference:
        references.construct_scoped_string_reference(p,reference_address=temporary,string_address=0,**kw)
        utf=_invoke_jni(p,environment_pointer,0x538,(image_base+0x3DEF2C,),invoke_jni)
        if utf:
            result=invoke_integer_argument_java_method(p,entry_stack_address=call_sp,
                environment_pointer=environment_pointer,status_address=status,
                object_reference=object_reference,name_address=image_base+0x3DEF38,
                signature_address=image_base+0x3DEF50,argument_words=(utf,),invoke_jni=invoke_jni)
            array=result.word
            if array and not _u(p,status,1):
                construct_java_byte_array_reference(p,output_reference_address=binary,
                    environment_pointer=environment_pointer,array_reference=array,invoke_jni=invoke_jni,
                    calloc=calloc,free=free,max_payload_bytes=max_payload_bytes,**kw)
                references.assign_scoped_string_reference(p,destination_address=temporary,
                    source_address=binary,free=free,**kw)
                references.release_scoped_string_reference(p,reference_address=binary,free=free,**kw)
            if array:_invoke_jni(p,environment_pointer,0xB8,(array,),invoke_jni)
            _invoke_jni(p,environment_pointer,0xB8,(utf,),invoke_jni)
        references.copy_scoped_string_reference(p,destination_address=output_reference_address,
            source_address=temporary,**kw)
        references.release_scoped_string_reference(p,reference_address=temporary,free=free,**kw)
    else:
        references.construct_scoped_string_reference(p,reference_address=output_reference_address,
            string_address=0,**kw)
    p.commit()


def construct_cached_dispatch_byte_reference(pages, *, image_base, entry_stack_address,
        output_reference_address, thread_pointer, thread_id, acquire_environment,
        invoke_jni, allocate, calloc, free, max_payload_bytes=0x100000,
        diagnostic_observer=None):
    """+0x1cf688: dispatch 0x01000011, convert bytes or construct an empty string.

    Preserve the first acquired environment for the final local deletion while
    the dispatcher performs its own acquisition. Conversion re-reads the first
    pair after dispatch. Reference ownership and empty StringObject construction
    remain in their existing owners. External service effects are not rolled back.
    """
    import vm9_reference_scopes as references
    if (type(entry_stack_address) is not int or not 0x2B0<=entry_stack_address<=MASK64
            or entry_stack_address&15):
        raise RefillUnsupported('cached dispatch producer requires an aligned guest stack')
    _address(output_reference_address,'cached dispatch output reference',16)
    if not callable(acquire_environment):
        raise RefillUnsupported('cached dispatch producer requires environment acquisition')
    p=_PageTransaction(pages);call_sp=entry_stack_address-0x70
    pair,temporary=entry_stack_address-0x58,entry_stack_address-0x68
    acquire_environment(p,entry_stack_address=call_sp,output_pair_address=pair)
    retained_environment=_u(p,pair)
    dispatched=invoke_java_dispatch(p,image_base=image_base,entry_stack_address=call_sp,
        argument_words=(0x01000011,0,0,0,0),acquire_environment=acquire_environment,invoke_jni=invoke_jni)
    reference=dispatched.returned_reference
    kw=dict(entry_stack_address=call_sp,image_base=image_base,thread_pointer=thread_pointer,
        thread_id=thread_id,allocate=allocate,diagnostic_observer=diagnostic_observer)
    convert_java_object_to_byte_reference(p,output_reference_address=temporary,
        environment_pointer=_u(p,pair),object_reference=reference,invoke_jni=invoke_jni,
        calloc=calloc,free=free,max_payload_bytes=max_payload_bytes,**kw)
    if _u(p,temporary):
        references.copy_scoped_string_reference(p,destination_address=output_reference_address,
            source_address=temporary,**kw)
    else:
        string=objects._allocate(p,allocate,24)
        objects.construct_string_object(p,object_address=string,source_address=0,
            allocate=allocate,vtable_address=image_base+0x34F5F8,
            empty_descriptor_address=image_base+0x6E168)
        references.construct_scoped_string_reference(p,reference_address=output_reference_address,
            string_address=string,**kw)
    references.release_scoped_string_reference(p,reference_address=temporary,free=free,**kw)
    if reference:_invoke_jni(p,retained_environment,0xB8,(reference,),invoke_jni)
    p.commit()


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


def release_java_reference(pages, *, environment_pointer, reference, invoke_jni):
    """+0x26f1d0: delete only recognized local/global/weak reference types."""
    for value in (environment_pointer,reference):
        if not isinstance(value,int) or not 0<=value<=MASK64:
            raise RefillUnsupported('JNI release pointers must fit uint64')
    if not environment_pointer or not reference:return
    p=_PageTransaction(pages)
    kind=_invoke_jni(p,environment_pointer,0x740,(reference,),invoke_jni)&0xFFFFFFFF
    slot={1:0xB8,2:0xB0,3:0x718}.get(kind)
    if slot is not None:_invoke_jni(p,environment_pointer,slot,(reference,),invoke_jni)
    p.commit()


@dataclass(frozen=True)
class JavaReferenceMemberResult:
    reference: int
    status_byte: int | None
    status_written: bool
    copied_va_list_address: int | None


def _reference_member(pages, *, kind, entry_stack_address, environment_pointer,
        status_address, object_reference, name_address, signature_address, invoke_jni,
        argument_words=None):
    is_method=kind in ('method','static_method')
    is_static=kind in ('static_method','static_field')
    minimum=0x1B0 if is_method else 0x60
    if (not isinstance(entry_stack_address,int) or entry_stack_address<minimum
            or entry_stack_address>MASK64 or entry_stack_address&15):
        raise RefillUnsupported('JNI member helper requires an aligned guest stack')
    for value in (environment_pointer,status_address,object_reference,name_address,signature_address):
        if not isinstance(value,int) or not 0<=value<=MASK64:
            raise RefillUnsupported('JNI member pointers must fit uint64')
    p=_PageTransaction(pages);result=0;status=None;copied=None
    temporary=entry_stack_address-(0x1A8 if is_method else 0x60)
    _write_span(p,temporary,bytes(8))
    if is_method:
        # +26f728 scans the signature before it tests the environment.
        _address(signature_address,'JNI method signature',1)
        signature=objects._cstring(p,signature_address,0x1000)[:-1]
        if argument_words is None:
            if not signature.startswith((b'()[',b'()L')):
                raise RefillUnsupported('JNI reference method requires no arguments and an object/array return')
            result_kind=signature[2:3]
        else:
            parameters,result_kind=_integer_method_signature(signature)
            words=tuple(argument_words)
            if len(words)!=len(parameters) or any(type(v) is not int or not 0<=v<=MASK64 for v in words):
                raise RefillUnsupported('JNI integer arguments must match the signature as uint64 words')
            for i,word in enumerate(words):
                _w(p,entry_stack_address-0x88+i*8 if i<3 else entry_stack_address+(i-3)*8,word)
        original=entry_stack_address-0x48;copied=entry_stack_address-0x70
        raw=b''.join(v.to_bytes(8,'little') for v in (entry_stack_address,copied,entry_stack_address-0x90))
        raw+=(-24).to_bytes(4,'little',signed=True)+(-128).to_bytes(4,'little',signed=True)
        _write_span(p,original,raw);_write_span(p,copied,_read_span(p,original,32))
    if environment_pointer:
        def call(slot,*args):return _invoke_jni(p,environment_pointer,slot,args,invoke_jni)
        pushed=objects._s32(call(0xD0,3)&0xFFFFFFFF)
        if pushed>=0 and not call(0x720)&0xFF:
            if (object_reference or kind=='static_method') and name_address and signature_address:
                cls=call(0x30 if is_static else 0xF8,object_reference)
                if cls and not call(0x720)&0xFF:
                    member=call((0x388 if is_static else 0x108) if is_method else (0x480 if is_static else 0x2F0),cls,name_address,signature_address)
                    if member:
                        signature=objects._cstring(p,signature_address,0x1000)[:-1]
                        if not is_method:
                            if kind=='static_field':
                                result_kind=_integer_field_signature(signature)
                                slot,width=_STATIC_FIELD_SLOTS[result_kind]
                                result=call(slot,cls,member)&((1<<(width*8))-1)
                            else:
                                if not signature.startswith((b'[',b'L')):
                                    raise RefillUnsupported('JNI reference field requires an object/array signature')
                                result=call(0x2F8,object_reference,member)
                            _w(p,temporary,result)
                        else:
                            if argument_words is None and not signature.startswith((b'()[',b'()L')):
                                raise RefillUnsupported('JNI reference method requires no arguments and an object/array return')
                            consumed=entry_stack_address-0x1A0
                            _write_span(p,consumed,_read_span(p,copied,32))
                            slot,width=(_STATIC_METHOD_SLOTS if is_static else _INSTANCE_METHOD_SLOTS)[result_kind]
                            word=call(slot,cls if is_static else object_reference,member,consumed)
                            result=word&((1<<(width*8))-1) if width else 0
                            _w(p,temporary,result)
                    call(0xB8,cls)
        exception=call(0x720)&0xFFFFFFFF
        if exception&0xFF:call(0x88)
        status=exception&0xFF
        if status_address:_w(p,status_address,status,1)
    output=JavaReferenceMemberResult(result,status,bool(environment_pointer and status_address),copied)
    p.commit();return output


_INSTANCE_METHOD_SLOTS={b'L':(0x118,8),b'[':(0x118,8),b'Z':(0x130,1),b'B':(0x148,1),
    b'C':(0x160,2),b'S':(0x178,2),b'I':(0x190,4),b'J':(0x1A8,8),b'V':(0x1F0,0)}
_STATIC_METHOD_SLOTS={kind:(slot+0x280,width) for kind,(slot,width) in _INSTANCE_METHOD_SLOTS.items()}
_STATIC_FIELD_SLOTS={b'L':(0x488,8),b'[':(0x488,8),b'Z':(0x490,1),b'B':(0x498,1),
    b'C':(0x4A0,2),b'S':(0x4A8,2),b'I':(0x4B0,4),b'J':(0x4B8,8)}


def _integer_java_type(signature,index,*,allow_void=False):
    if index>=len(signature):raise RefillUnsupported('incomplete JNI signature')
    start=index;kind=signature[index:index+1];index+=1
    if kind==b'[':
        while signature[index:index+1]==b'[':index+=1
        _,index=_integer_java_type(signature,index)
    elif kind==b'L':
        end=signature.find(b';',index)
        if end<=index:raise RefillUnsupported('incomplete JNI reference type')
        index=end+1
    elif kind not in (b'B',b'C',b'S',b'I',b'J',b'Z') and not (allow_void and kind==b'V'):
        raise RefillUnsupported('JNI floating-point or unknown types are unsupported')
    return signature[start:start+1],index


def _integer_method_signature(signature):
    if not signature.startswith(b'('):raise RefillUnsupported('JNI method signature requires parameters')
    parameters=[];index=1
    while signature[index:index+1]!=b')':
        kind,index=_integer_java_type(signature,index);parameters.append(kind)
        if len(parameters)>64:raise RefillUnsupported('JNI method argument bound exceeded')
    result,index=_integer_java_type(signature,index+1,allow_void=True)
    if index!=len(signature):raise RefillUnsupported('JNI signature has trailing bytes')
    return tuple(parameters),result


def _integer_field_signature(signature):
    kind,index=_integer_java_type(signature,0)
    if index!=len(signature):raise RefillUnsupported('JNI field signature has trailing bytes')
    return kind


@dataclass(frozen=True)
class IntegerJavaMemberResult:
    word: int
    status_byte: int | None
    status_written: bool
    copied_va_list_address: int | None


def invoke_integer_argument_java_method(pages, *, entry_stack_address,
        environment_pointer,status_address,object_reference,name_address,
        signature_address,argument_words,invoke_jni):
    """+26f650: instance method with integer/reference arguments and non-FP return.

    The first three raw words use X5-X7 saves; subsequent words use the guest
    entry stack. JNI consumes its own va_list copy. Return widths and void
    preserve the native zero-filled eight-byte result, including exceptions.
    SIMD and physical saved registers remain outside this logical helper.
    """
    result=_reference_member(pages,kind='method',entry_stack_address=entry_stack_address,
        environment_pointer=environment_pointer,status_address=status_address,
        object_reference=object_reference,name_address=name_address,
        signature_address=signature_address,argument_words=argument_words,invoke_jni=invoke_jni)
    return IntegerJavaMemberResult(result.reference,result.status_byte,result.status_written,result.copied_va_list_address)


def invoke_integer_argument_static_java_method(pages, *, entry_stack_address,
        environment_pointer,status_address,class_name_address,name_address,
        signature_address,argument_words,invoke_jni):
    """+26f2a4: FindClass/GetStaticMethodID and the native non-FP MethodV slot.

    Preserve PushLocalFrame, exception checks/clear and class local cleanup.
    Page rollback does not undo external JNI effects; C++ unwind is unsupported.
    """
    result=_reference_member(pages,kind='static_method',entry_stack_address=entry_stack_address,
        environment_pointer=environment_pointer,status_address=status_address,
        object_reference=class_name_address,name_address=name_address,
        signature_address=signature_address,argument_words=argument_words,invoke_jni=invoke_jni)
    return IntegerJavaMemberResult(result.reference,result.status_byte,result.status_written,result.copied_va_list_address)


def read_integer_static_java_field(pages, *, entry_stack_address,
        environment_pointer,status_address,class_name_address,name_address,
        signature_address,invoke_jni):
    """+2715b8: non-FP static field with native width and class local cleanup."""
    result=_reference_member(pages,kind='static_field',entry_stack_address=entry_stack_address,
        environment_pointer=environment_pointer,status_address=status_address,
        object_reference=class_name_address,name_address=name_address,
        signature_address=signature_address,invoke_jni=invoke_jni)
    return IntegerJavaMemberResult(result.reference,result.status_byte,result.status_written,result.copied_va_list_address)


def read_java_reference_field(pages, *, entry_stack_address, environment_pointer,
        status_address, object_reference, name_address, signature_address, invoke_jni):
    """+0x26fa00 object/array field subset with original JNI checks and cleanup.

    Preserve the returned reference even if the final check reports an
    exception. The caller receives the low status byte. The class local is
    deleted after member lookup; the original early class-exception path
    skips that deletion. Primitive fields and C++ unwind are outside this
    bounded API. Page rollback cannot undo already performed JNI effects.
    """
    return _reference_member(pages,kind='field',entry_stack_address=entry_stack_address,
        environment_pointer=environment_pointer,status_address=status_address,
        object_reference=object_reference,name_address=name_address,
        signature_address=signature_address,invoke_jni=invoke_jni)


def invoke_no_argument_java_reference_method(pages, *, entry_stack_address,
        environment_pointer,status_address,object_reference,name_address,signature_address,invoke_jni):
    """+0x26f650 -> +0x26f6e0 object/array method with an empty argument list.

    Model both wrapper va_list structures and the 32-byte copy consumed by
    CallObjectMethodV. Unconsumed GP/SIMD saves, physical spills, primitive
    returns and methods with arguments are outside this bounded signature.
    Push/check/class/member/call/delete/check/clear ordering stays native.
    """
    return _reference_member(pages,kind='method',entry_stack_address=entry_stack_address,
        environment_pointer=environment_pointer,status_address=status_address,
        object_reference=object_reference,name_address=name_address,
        signature_address=signature_address,invoke_jni=invoke_jni)


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


def construct_java_utf_string(pages, *, entry_stack_address, environment_pointer,
        source_address, allocate, free, invoke_jni, max_bytes=0x100000):
    """+270204: C string through owned C++ string into NewStringUTF.

    The inner +270168 scope clears preexisting and newly raised exceptions,
    and preserves the JNI reference even if a new exception was cleared.
    Tagged heap storage is released after JNI. NULL environment/source skips
    construction. This models logical objects; saved registers are separate.
    """
    if type(entry_stack_address) is not int or not 0xA0<=entry_stack_address<=MASK64 or entry_stack_address&15:
        raise RefillUnsupported('JNI UTF helper requires an aligned guest stack')
    for value in (environment_pointer,source_address):
        if type(value) is not int or not 0<=value<=MASK64:
            raise RefillUnsupported('JNI UTF pointers must fit uint64')
    if not environment_pointer or not source_address:return 0
    p=_PageTransaction(pages);temporary=entry_stack_address-0x50
    cpp_strings.construct_cpp_string(p,object_address=temporary,source_address=source_address,
        allocate=allocate,max_bytes=max_bytes)
    scope=entry_stack_address-0x98;_w(p,scope,environment_pointer);_w(p,scope+8,0,1)
    clear_java_exception(p,environment_pointer=environment_pointer,invoke_jni=invoke_jni)
    source=_u(p,temporary+16) if _u(p,temporary,1)&1 else temporary+1
    result=_invoke_jni(p,environment_pointer,0x538,(source,),invoke_jni)
    clear_java_exception(p,environment_pointer=environment_pointer,invoke_jni=invoke_jni)
    cpp_strings.destroy_cpp_string(p,object_address=temporary,free=free)
    p.commit();return result


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


@dataclass(frozen=True)
class ColdJavaSwitchReadResult:
    switch_word: int
    once_state_before: int
    initialized: bool
    initializer: ColdJavaSwitchInitializationResult | None


@dataclass(frozen=True)
class ColdJavaSwitchMaskResult:
    switch: ColdJavaSwitchReadResult
    requested_mask: int
    matched: bool


def read_cold_java_switch(pages, *, image_base, entry_stack_address,
        acquire_environment, invoke_jni, wake_condition):
    """+0x165588 -> +0x1655e0 -> normal +0x32a0a0 -> +0x165644.

    The all-ones once value skips the once mutex; other nonzero values except
    the waiting value 1 enter then leave the mutex without initialization.
    Cold state 0 publishes 1, runs the actual JNI caller outside the lock,
    publishes all-ones under the lock, and executes no-waiter broadcast.
    Explicit wake_condition(pages, address, operation, count) supplies the OS
    result. Waiting, C++ unwind and host concurrency are not implemented.
    Page rollback cannot undo JNI/OS/allocator effects already performed.
    """
    if (not isinstance(entry_stack_address, int) or entry_stack_address < 0x210
            or entry_stack_address & 15 or entry_stack_address > MASK64):
        raise RefillUnsupported('cold JNI switch getter stack must be aligned with scratch space')
    if not isinstance(image_base, int) or not 0 <= image_base <= MASK64 - 0x3E2EE4:
        raise RefillUnsupported('cold JNI switch getter image range must fit uint64')
    p = _PageTransaction(pages)
    once = image_base + 0x3D1570
    mutex = image_base + 0x3E2EB8
    before = _u(p, once)
    initializer = None
    if before != MASK64:
        # +0x165588's frame becomes x1 for +0x1655e0; preserve both live links.
        frame = entry_stack_address - 0x30
        wrapper = frame - 0x40
        _w(p, wrapper + 8, wrapper + 0x10)
        _w(p, wrapper + 0x10, frame)
        objects.lock_uncontended_mutex(p, mutex_address=mutex)
        state = _u(p, once)
        if state == 1:
            raise RefillUnsupported('cold JNI switch once requires pthread_cond_wait')
        if state == 0:
            _w(p, once, 1)
            objects.unlock_uncontended_mutex(p, mutex_address=mutex)
            # The two thin wrappers tail-call +0x165658 with this dereferenced
            # value; that body replaces x0 before acquiring the outer env.
            _u(p, _u(p, wrapper + 8))
            initializer = initialize_cold_java_switch(p, image_base=image_base,
                entry_stack_address=wrapper - 0x40,
                acquire_environment=acquire_environment, invoke_jni=invoke_jni)
            objects.lock_uncontended_mutex(p, mutex_address=mutex)
            _w(p, once, MASK64)
            objects.unlock_uncontended_mutex(p, mutex_address=mutex)
            if not callable(wake_condition):
                raise RefillUnsupported('cold JNI switch once requires a condition wake service')
            objects.broadcast_condition_no_waiters(p,
                condition_address=image_base + 0x3E2EE0, wake=wake_condition)
        else:
            objects.unlock_uncontended_mutex(p, mutex_address=mutex)
    result = ColdJavaSwitchReadResult(_u(p, image_base + 0x3D1578), before,
                                     initializer is not None, initializer)
    p.commit()
    return result


def check_cold_java_switch_mask(pages, *, image_base, entry_stack_address,
        mask, acquire_environment, invoke_jni, wake_condition):
    """+0x165560: initialize/read the word, then test (mask & ~word) == 0.

    A zero mask still runs the getter. Both operands are full uint64. The
    startup predicate +0x1658dc tail-calls this body with the fixed mask 0x200.
    The diagnostic dataclass exposes the observed W0 bool and getter outcome;
    it does not represent the complete physical return ABI.
    """
    if not isinstance(mask, int) or not 0 <= mask <= MASK64:
        raise RefillUnsupported('cold JNI switch mask must fit uint64')
    if (not isinstance(entry_stack_address, int) or entry_stack_address < 0x230
            or entry_stack_address & 15 or entry_stack_address > MASK64):
        raise RefillUnsupported('cold JNI switch mask stack must be aligned with scratch space')
    p = _PageTransaction(pages)
    switch = read_cold_java_switch(p, image_base=image_base,
        entry_stack_address=entry_stack_address - 0x20,
        acquire_environment=acquire_environment, invoke_jni=invoke_jni,
        wake_condition=wake_condition)
    result = ColdJavaSwitchMaskResult(switch, mask, (mask & (MASK64 ^ switch.switch_word)) == 0)
    p.commit()
    return result
