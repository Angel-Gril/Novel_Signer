"""Bounded +287474 second request VM with an independently generated caller."""
from dataclasses import dataclass
from vm9_allocator import _PageTransaction,RefillUnsupported,_read_span,_write_span
from vm9_request_caller import prepare_request_287474_vm_caller,RequestVmCallerFrame
from vm9_objects import decode_masked_bytes


@dataclass(frozen=True)
class RequestVm287474Prefix:
    staged: object
    frame: RequestVmCallerFrame
    registers: tuple[int,...]
    callbacks: tuple
    decoded: tuple
    pc: int
    steps: int


@dataclass(frozen=True)
class RequestVm287474ChildPrefix(RequestVm287474Prefix):
    child_prefix: object


@dataclass(frozen=True)
class RequestVm287474StringsPrefix(RequestVm287474ChildPrefix):
    strings: tuple


@dataclass(frozen=True)
class RequestVm287474ReaderPrefix(RequestVm287474StringsPrefix):
    reader_acquisitions: tuple


@dataclass(frozen=True)
class RequestVm287474DiagnosticPrefix(RequestVm287474ReaderPrefix):
    diagnostics: tuple


@dataclass(frozen=True)
class RequestVm287474DiagnosticCleanupPrefix(RequestVm287474DiagnosticPrefix):
    diagnostic_leaves: tuple


@dataclass(frozen=True)
class RequestVm287474ReaderReleasePrefix(RequestVm287474DiagnosticCleanupPrefix):
    reader_releases: tuple


@dataclass(frozen=True)
class RequestVm287474EqualityPrefix(RequestVm287474ReaderReleasePrefix):
    string_comparisons: tuple


@dataclass(frozen=True)
class RequestVm287474AssignmentPrefix(RequestVm287474EqualityPrefix):
    string_assignments: tuple


@dataclass(frozen=True)
class RequestVm287474RandomPrefix(RequestVm287474AssignmentPrefix):
    random_values: tuple


@dataclass(frozen=True)
class RequestVm287474ReferenceGetterPrefix(RequestVm287474RandomPrefix):
    reference_getters: tuple


@dataclass(frozen=True)
class RequestVm287474CachedU32Prefix(RequestVm287474ReferenceGetterPrefix):
    cached_u32_getters: tuple


@dataclass(frozen=True)
class RequestVm287474PairGetterPrefix(RequestVm287474CachedU32Prefix):
    pair_getters: tuple


@dataclass(frozen=True)
class RequestVm287474CachedReferencePrefix(RequestVm287474PairGetterPrefix):
    cached_references: tuple


@dataclass(frozen=True)
class RequestVm287474GuardAcquirePrefix(RequestVm287474CachedReferencePrefix):
    guard_acquisitions: tuple


@dataclass(frozen=True)
class RequestVm287474EnvironmentConstantPrefix(RequestVm287474GuardAcquirePrefix):
    environment_constants: tuple


@dataclass(frozen=True)
class RequestVm287474CStringFormatPrefix(RequestVm287474EnvironmentConstantPrefix):
    cstring_formats: tuple


@dataclass(frozen=True)
class RequestVm287474GuardReleasePrefix(RequestVm287474CStringFormatPrefix):
    guard_releases: tuple


@dataclass(frozen=True)
class RequestVm287474RegistryReadPrefix(RequestVm287474GuardReleasePrefix):
    registry_reads: tuple


@dataclass(frozen=True)
class RequestVm287474RealtimeSecondsPrefix(RequestVm287474RegistryReadPrefix):
    realtime_seconds: tuple


@dataclass(frozen=True)
class RequestVm287474ProcessIdPrefix(RequestVm287474RealtimeSecondsPrefix):
    process_ids: tuple


@dataclass(frozen=True)
class RequestVm287474ThreadPointerPrefix(RequestVm287474ProcessIdPrefix):
    thread_pointers: tuple


@dataclass(frozen=True)
class RequestVm287474EnvironmentAcquisitionPrefix(RequestVm287474ThreadPointerPrefix):
    environment_acquisitions: tuple


@dataclass(frozen=True)
class RequestVm287474LockedPointerPrefix(RequestVm287474EnvironmentAcquisitionPrefix):
    locked_pointers: tuple


@dataclass(frozen=True)
class RequestVm287474TreePointerPrefix(RequestVm287474LockedPointerPrefix):
    tree_pointers: tuple


@dataclass(frozen=True)
class RequestVm287474IdentifierPrefix(RequestVm287474TreePointerPrefix):
    identifiers: tuple


@dataclass(frozen=True)
class RequestVm287474AllocationPrefix(RequestVm287474IdentifierPrefix):
    allocations: tuple


@dataclass(frozen=True)
class RequestVm287474StringFormatPrefix(RequestVm287474AllocationPrefix):
    string_formats: tuple


@dataclass(frozen=True)
class RequestVm287474StringPairPrefix(RequestVm287474StringFormatPrefix):
    string_pairs: tuple


@dataclass(frozen=True)
class RequestVm287474DigestPrefix(RequestVm287474StringPairPrefix):
    digests: tuple


@dataclass(frozen=True)
class RequestVm287474CrcPrefix(RequestVm287474DigestPrefix):
    crcs: tuple


@dataclass(frozen=True)
class RequestVm287474FreePrefix(RequestVm287474CrcPrefix):
    frees: tuple


@dataclass(frozen=True)
class RequestVm287474JsonPrefix(RequestVm287474FreePrefix):
    json_references: tuple


@dataclass(frozen=True)
class RequestVm287474GlobalU32Prefix(RequestVm287474JsonPrefix):
    global_u32_getters: tuple


@dataclass(frozen=True)
class RequestVm287474JsonNumberPrefix(RequestVm287474GlobalU32Prefix):
    json_numbers: tuple


@dataclass(frozen=True)
class RequestVm287474EnvironmentHelperPrefix(RequestVm287474JsonNumberPrefix):
    environment_helpers: tuple


@dataclass(frozen=True)
class RequestVm287474TlsU32Prefix(RequestVm287474EnvironmentHelperPrefix):
    tls_u32_getters: tuple


@dataclass(frozen=True)
class RequestVm287474JsonStringPrefix(RequestVm287474TlsU32Prefix):
    json_strings: tuple


@dataclass(frozen=True)
class RequestVm287474NumericStringPrefix(RequestVm287474JsonStringPrefix):
    numeric_strings: tuple


@dataclass(frozen=True)
class RequestVm287474ConfigurationStringPrefix(RequestVm287474NumericStringPrefix):
    configuration_strings: tuple


@dataclass(frozen=True)
class RequestVm287474JsonBoolPrefix(RequestVm287474ConfigurationStringPrefix):
    json_bools: tuple


@dataclass(frozen=True)
class RequestVm287474JsonPrintPrefix(RequestVm287474JsonBoolPrefix):
    json_prints: tuple


@dataclass(frozen=True)
class RequestVm287474MutexLockPrefix(RequestVm287474JsonPrintPrefix):
    mutex_locks: tuple


@dataclass(frozen=True)
class RequestVm287474RealtimeMillisecondsPrefix(RequestVm287474MutexLockPrefix):
    realtime_milliseconds: tuple


@dataclass(frozen=True)
class RequestVm287474ProtobufSizePrefix(RequestVm287474RealtimeMillisecondsPrefix):
    protobuf_sizes: tuple


@dataclass(frozen=True)
class RequestVm287474StringFillPrefix(RequestVm287474ProtobufSizePrefix):
    string_fills: tuple


@dataclass(frozen=True)
class RequestVm287474ProtobufPackPrefix(RequestVm287474StringFillPrefix):
    protobuf_packs: tuple


@dataclass(frozen=True)
class RequestVm287474MutexUnlockPrefix(RequestVm287474ProtobufPackPrefix):
    mutex_unlocks: tuple


@dataclass(frozen=True)
class RequestVm287474JsonDeletePrefix(RequestVm287474MutexUnlockPrefix):
    json_deletions: tuple


@dataclass(frozen=True)
class RequestVm287474ConfigurationLookupPrefix(RequestVm287474JsonDeletePrefix):
    configuration_lookups: tuple


@dataclass(frozen=True)
class RequestVm287474DecodedReferencePrefix(RequestVm287474ConfigurationLookupPrefix):
    decoded_references: tuple


@dataclass(frozen=True)
class RequestVm287474StringClonePrefix(RequestVm287474DecodedReferencePrefix):
    string_clones: tuple


@dataclass(frozen=True)
class RequestVm287474SizedStringPrefix(RequestVm287474StringClonePrefix):
    sized_strings: tuple


@dataclass(frozen=True)
class RequestVm287474MemoryFillPrefix(RequestVm287474SizedStringPrefix):
    memory_fills: tuple


@dataclass(frozen=True)
class RequestVm287474FlaggedCleanupPrefix(RequestVm287474MemoryFillPrefix):
    flagged_cleanups: tuple


def execute_request_287474_vm_prefix(pages, *, vm_module, maxsteps=4000,
        consumer_services=None, **inputs):
    """Execute known decoder callbacks and retain the first unknown boundary.

    Undefined virtual words retain the independently supplied caller memory.
    A bounded result never publishes pages or claims a complete nested return.
    """
    if type(maxsteps) is not int or maxsteps<1:
        raise RefillUnsupported('second request VM budget must be positive')
    if consumer_services is not None and (not isinstance(consumer_services,dict) or
            any(not callable(consumer_services.get(n)) for n in ('allocate','free'))):
        raise RefillUnsupported('second request consumers require allocation and free services')
    staged=_PageTransaction(pages);frame=prepare_request_287474_vm_caller(staged,**inputs)
    image=inputs['image_base']
    class StrictMem(vm_module.Mem):
        def __init__(self):self.pages=staged
        def _pg(self,address):
            if address>>12 not in self.pages:
                raise RefillUnsupported(f'unmapped second request VM page {address:#x}')
            return self.pages[address>>12]
    class Boundary(Exception):pass
    callbacks,decoded=[],[];previous=vm_module.B
    children=[]
    strings=[]
    reader_acquisitions=[]
    diagnostics=[]
    diagnostic_leaves=[]
    reader_releases=[]
    string_comparisons=[]
    string_assignments=[]
    random_values=[]
    reference_getters=[]
    cached_u32_getters=[]
    pair_getters=[]
    cached_references=[]
    guard_acquisitions=[]
    environment_constants=[]
    cstring_formats=[]
    guard_releases=[]
    registry_reads=[]
    realtime_seconds=[]
    process_ids=[]
    thread_pointers=[]
    environment_acquisitions=[]
    locked_pointers=[]
    tree_pointers=[]
    identifiers=[]
    allocations=[]
    string_formats=[]
    string_pairs=[]
    digests=[]
    crcs=[]
    frees=[]
    json_references=[]
    global_u32_getters=[]
    json_numbers=[]
    environment_helpers=[]
    tls_u32_getters=[]
    json_strings=[]
    numeric_strings=[]
    configuration_strings=[]
    json_bools=[]
    json_prints=[]
    mutex_locks=[]
    realtime_milliseconds=[]
    protobuf_sizes=[]
    string_fills=[]
    protobuf_packs=[]
    mutex_unlocks=[]
    json_deletions=[]
    configuration_lookups=[]
    decoded_references=[]
    string_clones=[]
    sized_strings=[]
    memory_fills=[]
    flagged_cleanups=[]
    try:
        vm_module.B=image
        vm=vm_module.VM(StrictMem(),frame.bytecode_offset,frame.packed_arguments_address,
            image+0x35EDF0,image+0x35F3D0,image+0x2884AC,inputs['return_address'],maxsteps=maxsteps)
        vm.R=list(frame.registers);vm.register_backing_base=frame.register_backing_address
        def callback(vm,function,argument):
            words=tuple(vm.m.u64(argument+i*8) for i in range(4))
            wrapper,target=function-image,words[0]-image
            callbacks.append((wrapper,target,argument,words))
            if (wrapper,target) in ((0x288AF4,0x167E54),(0x2884B8,0x167E54)):
                length=decode_masked_bytes(staged,source_address=words[1],destination_address=words[2],mask_address=words[3])
                decoded.append((words[2],length))
            elif consumer_services is not None and (wrapper,target) in (
                    (0x2884CC,0x2481AC),(0x2884CC,0x2484B8),(0x2884CC,0x2484FC),
                    (0x288578,0x248274),(0x2884D8,0x347F60),(0x28858C,0x2A9280)):
                apply_request_287474_consumer(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
            elif consumer_services is not None and (wrapper,target)==(0x288530,0x26C858):
                from vm9_request_token_vm import apply_token_diagnostic_callback
                scope=apply_token_diagnostic_callback(staged,argument_block_address=argument,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],thread_id=consumer_services.get('thread_id'),
                    observer=consumer_services.get('diagnostic_observer'))
                diagnostics.append((argument,scope))
            elif consumer_services is not None and (wrapper,target)==(0x288540,0x26C9D0):
                from vm9_request_token_vm import apply_token_diagnostic_callback
                result=apply_token_diagnostic_callback(staged,argument_block_address=argument,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],thread_id=consumer_services.get('thread_id'),
                    observer=consumer_services.get('diagnostic_observer'))
                diagnostic_leaves.append((argument,result))
            elif consumer_services is not None and (wrapper,target)==(0x2885E0,0x32A4FC):
                readers=apply_request_287474_reader_release_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image)
                reader_releases.append((argument,readers))
            elif consumer_services is not None and (wrapper,target)==(0x2885EC,0x24880C):
                equal=apply_request_287474_string_equality_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image)
                string_comparisons.append((argument,equal))
            elif consumer_services is not None and (wrapper,target)==(0x28861C,0x2485A4):
                if not callable(consumer_services.get('reallocate')):raise Boundary()
                assigned=apply_request_287474_string_assignment_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],reallocate=consumer_services['reallocate'],
                    free=consumer_services['free'])
                string_assignments.append((argument,assigned))
            elif consumer_services is not None and (wrapper,target)==(0x28863C,0x26CC8C):
                services=consumer_services.get('random_services')
                if services is None:raise Boundary()
                from vm9_request_random import store_request_random_callback
                result=store_request_random_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    libc_base=services['libc_base'],syscall=services['syscall'],
                    errno_address=services['errno_address'],thread_id=services.get('thread_id'))
                random_values.append((argument,result))
            elif consumer_services is not None and (wrapper,target)==(0x288854,0x261350):
                value=apply_request_287474_json_number_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'],free=consumer_services['free'])
                json_numbers.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288AC8,0x1B55F8):
                output=apply_request_287474_flagged_cleanup_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,free=consumer_services['free'])
                flagged_cleanups.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288AB4,0x347F20):
                output=apply_request_287474_memory_fill_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                memory_fills.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288A74,0x2481FC):
                output=apply_request_287474_sized_string_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'])
                sized_strings.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288A64,0x2483E0):
                output=apply_request_287474_string_clone_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'])
                string_clones.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288A4C,0x258E7C):
                output=apply_request_287474_decoded_reference_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],free=consumer_services['free'],
                    thread_id=consumer_services.get('thread_id'),diagnostic_observer=consumer_services.get('diagnostic_observer'))
                decoded_references.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288A30,0x263174):
                if not callable(consumer_services.get('get_singleton')):raise Boundary()
                output=apply_request_287474_configuration_lookup_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    thread_pointer=inputs['thread_pointer'],vm_module=vm_module,
                    allocate=consumer_services['allocate'],reallocate=consumer_services.get('reallocate'),
                    free=consumer_services['free'],
                    get_singleton=consumer_services['get_singleton'],
                    thread_id=consumer_services.get('thread_id'),diagnostic_observer=consumer_services.get('diagnostic_observer'))
                configuration_lookups.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288A24,0x2614EC):
                apply_request_287474_json_delete_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    free=consumer_services['free'])
                json_deletions.append((argument,words[1]))
            elif (consumer_services is not None and wrapper==0x2889A8 and
                    isinstance(consumer_services.get('mutex_import_bindings'),dict) and
                    type(consumer_services['mutex_import_bindings'].get('pthread_mutex_unlock')) is int and
                    consumer_services['mutex_import_bindings']['pthread_mutex_unlock']>0 and
                    words[0]==consumer_services['mutex_import_bindings']['pthread_mutex_unlock']):
                value=apply_request_287474_mutex_unlock_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    import_bindings=consumer_services['mutex_import_bindings'])
                mutex_unlocks.append((argument,value))
            elif (consumer_services is not None and wrapper==0x2889A8 and
                    isinstance(consumer_services.get('mutex_import_bindings'),dict) and
                    type(consumer_services['mutex_import_bindings'].get('pthread_mutex_lock')) is int and
                    consumer_services['mutex_import_bindings']['pthread_mutex_lock']>0 and
                    words[0]==consumer_services['mutex_import_bindings']['pthread_mutex_lock']):
                value=apply_request_287474_mutex_lock_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    import_bindings=consumer_services['mutex_import_bindings'])
                mutex_locks.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288990,0x2616B4):
                value=apply_request_287474_json_print_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],free=consumer_services['free'],
                    thread_id=consumer_services.get('thread_id'),diagnostic_observer=consumer_services.get('diagnostic_observer'),
                    prepare_format=consumer_services.get('prepare_format'))
                json_prints.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288968,0x261580):
                value=apply_request_287474_json_bool_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'],free=consumer_services['free'])
                json_bools.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28890C,0x256CE0):
                value=apply_request_287474_configuration_string_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'])
                configuration_strings.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2888F4,0x28794C):
                if not callable(consumer_services.get('get_tls')):raise Boundary()
                value=apply_request_287474_numeric_string_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'],free=consumer_services['free'],
                    get_tls=consumer_services['get_tls'])
                numeric_strings.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2888D0,0x2613E4):
                value=apply_request_287474_json_string_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'],free=consumer_services['free'])
                json_strings.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288898,0x2850A8):
                if not callable(consumer_services.get('get_tls')):raise Boundary()
                value=apply_request_287474_tls_u32_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,get_tls=consumer_services['get_tls'])
                tls_u32_getters.append((argument,value))
            elif consumer_services is not None and (wrapper,target) in ((0x28863C,0x1C3018),(0x28863C,0x1C3024),(0x28863C,0x1E53D0)):
                value=apply_request_287474_global_u32_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                global_u32_getters.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28863C,0x204E50):
                if not callable(consumer_services.get('acquire_environment')) or consumer_services.get('logger_services') is None:
                    raise Boundary()
                from vm9_request_environment_vm import execute_request_environment_vm_prefix
                helper=execute_request_environment_vm_prefix(staged,vm_module=vm_module,
                    helper_offset=target,wrapper_offset=wrapper,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,
                    return_address=image+0x16AA4C,thread_pointer=inputs['thread_pointer'],image_base=image,
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,saved_x19=frame.register_backing_address-8,
                    acquire_environment=consumer_services['acquire_environment'],
                    consumer_services=consumer_services,continue_caller_return=True)
                environment_helpers.append((argument,helper))
                if getattr(helper,'caller_return',None) is None:raise Boundary()
            elif consumer_services is not None and wrapper==0x28863C and consumer_services.get('process_services') is not None:
                services=consumer_services['process_services']
                if not isinstance(services,dict):raise Boundary()
                bindings=services.get('import_bindings')
                if not isinstance(bindings,dict) or words[0] not in bindings.values():raise Boundary()
                value=apply_request_287474_process_id_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    thread_pointer=inputs['thread_pointer'],import_bindings=bindings,
                    syscall=services.get('syscall'))
                process_ids.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288658,0x257804):
                output=apply_request_287474_reference_getter_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],thread_id=consumer_services.get('thread_id'))
                reference_getters.append((argument,output))
            elif consumer_services is not None and (wrapper,target) in ((0x288670,0x257880),(0x28887C,0x256F58)):
                value=apply_request_287474_cached_u32_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                cached_u32_getters.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28868C,0x2633A4):
                output=apply_request_287474_pair_getter_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    allocate=consumer_services['allocate'],thread_id=consumer_services.get('thread_id'))
                pair_getters.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x2886B0,0x1CF55C):
                if any(not callable(consumer_services.get(n)) for n in
                        ('acquire_environment','invoke_jni','register_exit','calloc')):raise Boundary()
                output=apply_request_287474_cached_reference_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'],
                    acquire_environment=consumer_services['acquire_environment'],
                    invoke_jni=consumer_services['invoke_jni'],register_exit=consumer_services['register_exit'],
                    allocate=consumer_services['allocate'],calloc=consumer_services['calloc'],free=consumer_services['free'],
                    thread_id=consumer_services.get('thread_id'),
                    diagnostic_observer=consumer_services.get('diagnostic_observer'))
                cached_references.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x2884EC,0x32D3A0):
                value=apply_request_287474_guard_acquire_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_id=consumer_services.get('thread_id'),
                    observer=consumer_services.get('diagnostic_observer'))
                guard_acquisitions.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2886FC,0x256330):
                value=apply_request_287474_environment_constant_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                environment_constants.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288718,0x2781F4):
                value=apply_request_287474_cstring_format_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                cstring_formats.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28854C,0x32D4F8):
                value=apply_request_287474_guard_release_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,observer=consumer_services.get('diagnostic_observer'))
                guard_releases.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28874C,0x256A18):
                from vm9_request_28048c_vm import apply_request_28048c_registry_read_callback
                value=apply_request_28048c_registry_read_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                registry_reads.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2889F4,0x2A337C):
                value=apply_request_287474_protobuf_pack_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                protobuf_packs.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2889E0,0x248DD8):
                if not callable(consumer_services.get('reallocate')):raise Boundary()
                value=apply_request_287474_string_fill_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'],
                    reallocate=consumer_services['reallocate'],free=consumer_services['free'])
                string_fills.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2889C4,0x2A3378):
                value=apply_request_287474_protobuf_size_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                protobuf_sizes.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28876C,0x26CC60):
                if not callable(consumer_services.get('read_clock')):raise Boundary()
                value=apply_request_287474_realtime_milliseconds_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,read_clock=consumer_services['read_clock'])
                realtime_milliseconds.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x28876C,0x26CC64):
                if not callable(consumer_services.get('read_clock')):raise Boundary()
                value=apply_request_287474_realtime_seconds_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,read_clock=consumer_services['read_clock'])
                realtime_seconds.append((argument,value))
            elif (wrapper,target)==(0x28876C,0x204F58):
                value=apply_request_287474_thread_pointer_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,thread_pointer=inputs['thread_pointer'])
                thread_pointers.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288788,0x26EDC4):
                if not callable(consumer_services.get('acquire_environment')):raise Boundary()
                from vm9_request_environment_vm import apply_request_environment_acquisition_callback
                acquired=apply_request_environment_acquisition_callback(staged,
                    argument_block_address=argument,image_base=image,
                    entry_stack_address=frame.native_stack_address-0x180,
                    acquire_environment=consumer_services['acquire_environment'])
                environment_acquisitions.append((argument,acquired))
            elif (wrapper,target)==(0x288794,0x282B84):
                value=apply_request_287474_locked_pointer_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                locked_pointers.append((argument,value))
            elif (wrapper,target)==(0x2887B0,0x256B84):
                value=apply_request_287474_tree_pointer_callback(staged,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image)
                tree_pointers.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x2886B0,0x25BD8C):
                if consumer_services.get('identifier_file_services') is None:raise Boundary()
                from vm9_request_identifier import apply_request_identifier_callback
                output=apply_request_identifier_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    thread_pointer=inputs['thread_pointer'],allocate=consumer_services['allocate'],
                    free=consumer_services['free'],file_services=consumer_services['identifier_file_services'],
                    thread_id=consumer_services.get('thread_id'),
                    diagnostic_observer=consumer_services.get('diagnostic_observer'))
                identifiers.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288508,0x32A1F0):
                pointer=apply_request_287474_allocation_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    allocate=consumer_services['allocate'])
                allocations.append((argument,pointer))
            elif consumer_services is not None and (wrapper,target) in ((0x28880C,0x248908),(0x2888B4,0x248908)):
                output=apply_request_287474_string_format_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    allocate=consumer_services['allocate'],reallocate=consumer_services.get('reallocate'),
                    free=consumer_services['free'],prepare_format=consumer_services.get('prepare_format'),wrapper_offset=wrapper)
                string_formats.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x2887F0,0x248780):
                from vm9_request_token_vm import apply_token_string_transform_callback
                status=apply_token_string_transform_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    image_base=image,allocate=consumer_services['allocate'],
                    reallocate=consumer_services.get('reallocate'),free=consumer_services['free'])
                string_pairs.append((argument,status))
            elif consumer_services is not None and (wrapper,target)==(0x2887D0,0x25874C):
                from vm9_request_token_vm import apply_token_digest_callback
                output=apply_token_digest_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    thread_pointer=inputs['thread_pointer'],allocate=consumer_services['allocate'],
                    reallocate=consumer_services.get('reallocate'),free=consumer_services['free'],
                    thread_id=consumer_services.get('thread_id'),observer=consumer_services.get('diagnostic_observer'))
                digests.append((argument,output))
            elif consumer_services is not None and (wrapper,target)==(0x288820,0x258BAC):
                value=apply_request_287474_crc_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image)
                crcs.append((argument,value))
            elif consumer_services is not None and (wrapper,target)==(0x288610,0x32A264):
                apply_request_287474_consumer(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
                frees.append((argument,words[1]))
            elif consumer_services is not None and (wrapper,target)==(0x28883C,0x261404):
                result=apply_request_287474_json_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    thread_pointer=inputs['thread_pointer'],allocate=consumer_services['allocate'],
                    free=consumer_services['free'],thread_id=consumer_services.get('thread_id'),
                    diagnostic_observer=consumer_services.get('diagnostic_observer'))
                json_references.append((argument,result))
            elif consumer_services is not None and (wrapper,target)==(0x2885E0,0x32A444):
                readers=apply_request_287474_reader_acquisition_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image)
                reader_acquisitions.append((argument,readers))
            elif consumer_services is not None and (wrapper,target)==(0x2885D0,0x248344):
                from vm9_request_environment_vm import apply_request_environment_string_callback
                constructed=apply_request_environment_string_callback(staged,wrapper_offset=wrapper,
                    argument_block_address=argument,image_base=image,
                    allocate=consumer_services['allocate'],free=consumer_services['free'])
                strings.append((wrapper,target,argument,constructed))
            elif consumer_services is not None and (wrapper,target)==(0x2885AC,0x28048C):
                from vm9_request_28048c_vm import execute_request_28048c_vm_prefix
                child=execute_request_28048c_vm_prefix(staged,vm_module=vm_module,
                    maxsteps=20000,consumer_services=consumer_services,continue_caller_return=True,
                    argument_block_address=argument,entry_stack_address=frame.native_stack_address-0x180,
                    return_address=image+0x16AA4C,thread_pointer=inputs['thread_pointer'],image_base=image,
                    saved_frame_pointer=frame.native_stack_address-0x60,
                    saved_x28=frame.register_backing_address,saved_x19=frame.register_backing_address-8)
                children.append(child)
                if getattr(child,'caller_return',None) is None:raise Boundary()
            else:raise Boundary()
        vm.native_hook=callback
        try:vm.run()
        except Boundary:
            if flagged_cleanups:
                return RequestVm287474FlaggedCleanupPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions),tuple(configuration_lookups),tuple(decoded_references),tuple(string_clones),tuple(sized_strings),tuple(memory_fills),tuple(flagged_cleanups))
            if memory_fills:
                return RequestVm287474MemoryFillPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions),tuple(configuration_lookups),tuple(decoded_references),tuple(string_clones),tuple(sized_strings),tuple(memory_fills))
            if sized_strings:
                return RequestVm287474SizedStringPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions),tuple(configuration_lookups),tuple(decoded_references),tuple(string_clones),tuple(sized_strings))
            if string_clones:
                return RequestVm287474StringClonePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions),tuple(configuration_lookups),tuple(decoded_references),tuple(string_clones))
            if decoded_references:
                return RequestVm287474DecodedReferencePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions),tuple(configuration_lookups),tuple(decoded_references))
            if configuration_lookups:
                return RequestVm287474ConfigurationLookupPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions),tuple(configuration_lookups))
            if json_deletions:
                return RequestVm287474JsonDeletePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks),tuple(json_deletions))
            if mutex_unlocks:
                return RequestVm287474MutexUnlockPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs),tuple(mutex_unlocks))
            if protobuf_packs:
                return RequestVm287474ProtobufPackPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills),tuple(protobuf_packs))
            if string_fills:
                return RequestVm287474StringFillPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes),tuple(string_fills))
            if protobuf_sizes:
                return RequestVm287474ProtobufSizePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds),tuple(protobuf_sizes))
            if realtime_milliseconds:
                return RequestVm287474RealtimeMillisecondsPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks),tuple(realtime_milliseconds))
            if mutex_locks:
                return RequestVm287474MutexLockPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints),tuple(mutex_locks))
            if json_prints:
                return RequestVm287474JsonPrintPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools),tuple(json_prints))
            if json_bools:
                return RequestVm287474JsonBoolPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings),tuple(json_bools))
            if configuration_strings:
                return RequestVm287474ConfigurationStringPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings),tuple(configuration_strings))
            if numeric_strings:
                return RequestVm287474NumericStringPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings),tuple(numeric_strings))
            if json_strings:
                return RequestVm287474JsonStringPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters),tuple(json_strings))
            if tls_u32_getters:
                return RequestVm287474TlsU32Prefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers),tuple(tls_u32_getters))
            if environment_helpers:
                return RequestVm287474EnvironmentHelperPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers),tuple(environment_helpers))
            if json_numbers:
                return RequestVm287474JsonNumberPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters),tuple(json_numbers))
            if global_u32_getters:
                return RequestVm287474GlobalU32Prefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references),tuple(global_u32_getters))
            if json_references:
                return RequestVm287474JsonPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees),tuple(json_references))
            if frees:
                return RequestVm287474FreePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs),tuple(frees))
            if crcs:
                return RequestVm287474CrcPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests),tuple(crcs))
            if digests:
                return RequestVm287474DigestPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs),tuple(digests))
            if string_pairs:
                return RequestVm287474StringPairPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats),tuple(string_pairs))
            if string_formats:
                return RequestVm287474StringFormatPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations),tuple(string_formats))
            if allocations:
                return RequestVm287474AllocationPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers),tuple(allocations))
            if identifiers:
                return RequestVm287474IdentifierPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers),tuple(identifiers))
            if tree_pointers:
                return RequestVm287474TreePointerPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers),tuple(tree_pointers))
            if locked_pointers:
                return RequestVm287474LockedPointerPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions),tuple(locked_pointers))
            if environment_acquisitions:
                return RequestVm287474EnvironmentAcquisitionPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers),tuple(environment_acquisitions))
            if thread_pointers:
                return RequestVm287474ThreadPointerPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids),tuple(thread_pointers))
            if process_ids:
                return RequestVm287474ProcessIdPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds),tuple(process_ids))
            if realtime_seconds:
                return RequestVm287474RealtimeSecondsPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads),tuple(realtime_seconds))
            if registry_reads:
                return RequestVm287474RegistryReadPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases),tuple(registry_reads))
            if guard_releases:
                return RequestVm287474GuardReleasePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats),tuple(guard_releases))
            if cstring_formats:
                return RequestVm287474CStringFormatPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants),tuple(cstring_formats))
            if environment_constants:
                return RequestVm287474EnvironmentConstantPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions),tuple(environment_constants))
            if guard_acquisitions:
                return RequestVm287474GuardAcquirePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references),tuple(guard_acquisitions))
            if cached_references:
                return RequestVm287474CachedReferencePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters),tuple(cached_references))
            if pair_getters:
                return RequestVm287474PairGetterPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters),tuple(pair_getters))
            if cached_u32_getters:
                return RequestVm287474CachedU32Prefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters),tuple(cached_u32_getters))
            if reference_getters:
                return RequestVm287474ReferenceGetterPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values),tuple(reference_getters))
            if random_values:
                return RequestVm287474RandomPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments),tuple(random_values))
            if string_assignments:
                return RequestVm287474AssignmentPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons),tuple(string_assignments))
            if string_comparisons:
                return RequestVm287474EqualityPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases),tuple(string_comparisons))
            if reader_releases:
                return RequestVm287474ReaderReleasePrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves),tuple(reader_releases))
            if diagnostic_leaves:
                return RequestVm287474DiagnosticCleanupPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics),tuple(diagnostic_leaves))
            if diagnostics:
                return RequestVm287474DiagnosticPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions),tuple(diagnostics))
            if reader_acquisitions:
                return RequestVm287474ReaderPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings),tuple(reader_acquisitions))
            if strings:
                return RequestVm287474StringsPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,
                    children[-1] if children else None,tuple(strings))
            if children:
                return RequestVm287474ChildPrefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps,children[-1])
            return RequestVm287474Prefix(staged,frame,tuple(vm.R),tuple(callbacks),tuple(decoded),vm.pc,vm.steps)
        except vm_module.VMExit as exc:
            raise RefillUnsupported('second request VM return is not recovered') from exc
        raise RefillUnsupported('second request VM budget exhausted before a boundary')
    finally:vm_module.B=previous


def apply_request_287474_reader_acquisition_callback(pages, *, wrapper_offset,
        argument_block_address,image_base):
    """+2885e0 tail-calls the existing +32a444 shared-reader owner.

    Declare receiver/packed bytes and reuse normal mutex transitions. Native
    physical guard/canary/PAC and concurrent/writer/wait paths stay outside
    this semantic callback. The returned reader count is internal metadata.
    """
    from vm9_objects import acquire_uncontended_shared_reader
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    if (wrapper_offset,word(0)-image_base)!=(0x2885E0,0x32A444):
        raise RefillUnsupported('unrecovered second shared-reader callback')
    readers=acquire_uncontended_shared_reader(p,mutex_address=word(8))
    p.commit();return readers


def apply_request_287474_reader_release_callback(pages, *, wrapper_offset,
        argument_block_address,image_base):
    """+2885e0 tail-calls the shared +32a4fc release owner.

    Reader count is internal metadata. Writer/signal/wait paths and the
    physical return/stack/canary/PAC remain outside this semantic callback.
    """
    from vm9_objects import release_uncontended_shared_reader
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    if (wrapper_offset,word(0)-image_base)!=(0x2885E0,0x32A4FC):
        raise RefillUnsupported('unrecovered second shared-reader release callback')
    readers=release_uncontended_shared_reader(p,mutex_address=word(8))
    p.commit();return readers


def apply_request_287474_string_equality_callback(pages, *, wrapper_offset,
        argument_block_address,image_base,max_bytes=0x100000):
    """+2885ec compares a StringObject and C string, then stores one byte.

    Preserve packed+25 padding and complete all comparison reads before the
    result store, including when the result aliases an input. Physical stack
    and return X0 remain outside this packed callback contract.
    """
    from vm9_configuration_init import string_equals_cstring
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    if (wrapper_offset,word(0)-image_base)!=(0x2885EC,0x24880C):
        raise RefillUnsupported('unrecovered second string equality callback')
    obj=word(8)
    if not obj:
        raise RefillUnsupported('second string equality requires a non-NULL receiver')
    equal=string_equals_cstring(p,object_address=obj,cstring_address=word(16),max_bytes=max_bytes)
    _write_span(p,argument_block_address+24,bytes([int(equal)]))
    p.commit();return equal


def apply_request_287474_string_assignment_callback(pages, *, wrapper_offset,
        argument_block_address,image_base,allocate,reallocate,free,max_bytes=0x100000):
    """+28861c writes the +2485a4 assignment result at packed+24 as X0."""
    from vm9_objects import assign_string_object
    if not all(callable(f) for f in (allocate,reallocate,free)):
        raise RefillUnsupported('StringObject assignment requires allocator services')
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    if (wrapper_offset,word(0)-image_base)!=(0x28861C,0x2485A4):
        raise RefillUnsupported('unrecovered second string assignment callback')
    assigned=assign_string_object(p,object_address=word(8),source_object_address=word(16),
        allocate=allocate,reallocate=reallocate,free=free,max_bytes=max_bytes)
    _write_span(p,argument_block_address+24,assigned.to_bytes(8,'little'))
    p.commit();return assigned


def apply_request_287474_consumer(pages, *, wrapper_offset,
        argument_block_address, image_base, allocate, free, max_bytes=0x100000):
    """Actual second-VM lifecycle, imported memcpy and local copy wrappers.

    +288578 loads a byte fill and W length. Only +28858c publishes X0 at
    packed+32; the tail wrappers leave their packed bytes alone. Imported
    memcpy accepts disjoint ranges or identical pointers. The local +2a9280
    owner preserves its own ordered loads/stores, including overlapping ranges.
    +288610 tail-calls explicit free without a packed or physical return value.
    +2884cc/+2484fc also deletes the object through the same destructor owner.
    """
    import vm9_objects as objects
    if type(max_bytes) is not int or not 0<=max_bytes<=0x100000:
        raise RefillUnsupported('invalid second request consumer size bound')
    p=_PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(p,argument_block_address+offset,8),'little')
    pair=wrapper_offset,word(0)-image_base
    destination=word(8)
    if pair==(0x2884CC,0x2481AC):
        result=objects.construct_string_object(p,object_address=destination,source_address=0,
            allocate=allocate,vtable_address=image_base+0x34F5F8,
            empty_descriptor_address=image_base+0x6E168)
    elif pair in ((0x2884CC,0x2484B8),(0x2884CC,0x2484FC)):
        result=objects.destroy_string_object(p,object_address=destination,
            image_base=image_base,free=free,delete_object=pair[1]==0x2484FC)
    elif pair==(0x288610,0x32A264):
        free(p,destination)
        result=None
    elif pair==(0x288578,0x248274):
        fill=_read_span(p,argument_block_address+16,1)[0]
        length=int.from_bytes(_read_span(p,argument_block_address+20,4),'little')
        result=objects.construct_filled_string_object(p,object_address=destination,
            fill=fill,length=length,image_base=image_base,allocate=allocate,
            max_payload_bytes=max_bytes)
    elif pair in ((0x2884D8,0x347F60),(0x28858C,0x2A9280)):
        source,length=word(16),word(24)
        if length>max_bytes:
            raise RefillUnsupported('second request copy exceeds the explicit bound')
        if pair[0]==0x2884D8:
            if source!=destination and length and abs(destination-source)<length:
                raise RefillUnsupported('overlapping imported memcpy is not recovered')
            if length:_write_span(p,destination,_read_span(p,source,length))
        else:
            _copy_request_287474_bytes(p,destination,source,length)
            _write_span(p,argument_block_address+32,destination.to_bytes(8,'little'))
        result=destination
    else:raise RefillUnsupported('unrecovered second request consumer')
    p.commit()
    return result


def apply_request_287474_reference_getter_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, thread_pointer, allocate, thread_id=None,
        diagnostic_observer=None):
    """+288658 -> +257804: packed X8 output and X0 receiver; no result store."""
    from vm9_registry import read_configuration_string_reference
    transaction = _PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(transaction,argument_block_address+offset,8),'little')
    target,output,receiver=word(0),word(8),word(16)
    if target!=image_base+0x257804:
        raise RefillUnsupported('unexpected second configuration reference target')
    read_configuration_string_reference(transaction,registry_address=receiver,
        output_reference_address=output,entry_stack_address=entry_stack_address-16,
        image_base=image_base,thread_pointer=thread_pointer,allocate=allocate,
        thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    transaction.commit()
    return output


def apply_request_287474_cached_u32_callback(pages, *, argument_block_address,
        entry_stack_address, image_base):
    """Known cached W getters store at packed+16, retaining +20 padding.

    +257880 retains its shared-reader scope; +256f58 loads receiver+138
    under an explicit serial-memory contract, without a mutex or provider.
    """
    from vm9_registry import read_configuration_cached_u32
    transaction = _PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(transaction,argument_block_address+offset,8),'little')
    target,receiver=word(0),word(8)
    if target not in (image_base+0x257880,image_base+0x256F58):
        raise RefillUnsupported('unexpected second configuration cached value target')
    if target==image_base+0x256F58:
        if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
                or entry_stack_address&15):
            raise RefillUnsupported('atomic u32 callback requires an aligned guest stack')
        if receiver>(1<<64)-0x13C or (receiver+0x138)&3:
            raise RefillUnsupported('atomic u32 field must be aligned and cannot wrap uint64')
        field=receiver+0x138
        if ((argument_block_address<entry_stack_address and argument_block_address+20>entry_stack_address-0x1000)
                or (field<entry_stack_address and field+4>entry_stack_address-0x1000)):
            raise RefillUnsupported('atomic u32 callback aliases unmodeled physical spills')
        value=int.from_bytes(_read_span(transaction,field,4),'little')
    else:
        value=read_configuration_cached_u32(transaction,registry_address=receiver,
            entry_stack_address=entry_stack_address-16,image_base=image_base)
    _write_span(transaction,argument_block_address+16,value.to_bytes(4,'little'))
    transaction.commit()
    return value


def apply_request_287474_pair_getter_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, thread_pointer, allocate, thread_id=None,
        diagnostic_observer=None):
    """+28868c -> +2633a4 tail-calls the scoped copy of receiver+0x18 to X8."""
    from vm9_reference_scopes import copy_scoped_string_reference
    transaction = _PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(transaction,argument_block_address+offset,8),'little')
    target,output,receiver=word(0),word(8),word(16)
    if target!=image_base+0x2633A4:
        raise RefillUnsupported('unexpected second reference pair getter target')
    copy_scoped_string_reference(transaction,destination_address=output,
        source_address=receiver+0x18,entry_stack_address=entry_stack_address-16,
        image_base=image_base,thread_pointer=thread_pointer,allocate=allocate,
        thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    transaction.commit()
    return output


def apply_request_287474_cached_reference_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, thread_pointer, acquire_environment,
        invoke_jni, register_exit, allocate, calloc, free, thread_id=None,
        diagnostic_observer=None):
    """+2886b0 loads target/X8 only; +1cf55c receives SP-16, packed X0 intact.

    The wrapper has no receiver argument and no packed result store. Pages
    commit only after the cache owner returns; external effects stay external.
    """
    from vm9_jni_environment import copy_cached_dispatch_byte_reference
    transaction=_PageTransaction(pages)
    target=int.from_bytes(_read_span(transaction,argument_block_address,8),'little')
    output=int.from_bytes(_read_span(transaction,argument_block_address+8,8),'little')
    if target!=image_base+0x1CF55C:
        raise RefillUnsupported('unexpected second cached byte reference target')
    copy_cached_dispatch_byte_reference(transaction,output_reference_address=output,
        entry_stack_address=entry_stack_address-16,image_base=image_base,thread_pointer=thread_pointer,
        acquire_environment=acquire_environment,invoke_jni=invoke_jni,register_exit=register_exit,
        allocate=allocate,calloc=calloc,free=free,thread_id=thread_id,diagnostic_observer=diagnostic_observer)
    transaction.commit()
    return output


def apply_request_287474_guard_acquire_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, thread_id=None, observer=None):
    """+2884ec -> +32d3a0: load target/guard, then store W0 at packed+16.

    Preserve packed+20 except when the explicit guard overlaps it. Refuse
    aliases with unmodeled physical spills in the wrapper and guard frames.
    """
    from vm9_objects import acquire_static_initialization_guard
    if (type(entry_stack_address) is not int or not 0x50<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('guard callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    guard=int.from_bytes(_read_span(p,argument_block_address+8,8),'little')
    if target!=image_base+0x32D3A0:
        raise RefillUnsupported('unexpected second static guard acquire target')
    for address,width in ((argument_block_address,24),(guard,8)):
        if address<entry_stack_address and address+width>entry_stack_address-0x50:
            raise RefillUnsupported('guard callback aliases unmodeled physical spills')
    result=acquire_static_initialization_guard(p,guard_address=guard,image_base=image_base,
        thread_id=thread_id,observer=observer)
    _write_span(p,argument_block_address+16,result.to_bytes(4,'little'))
    p.commit()
    return result


def apply_request_287474_environment_constant_callback(pages, *, argument_block_address,
        entry_stack_address, image_base):
    """+2886fc -> +256330: ignore receiver and store the full X0 at packed+16.

    Reuse the existing lazy guest constant owner. Refuse packed aliases with
    unmodeled wrapper/getter spills; no host strings or services are supplied.
    """
    from vm9_configuration_init import get_environment_constant
    if (type(entry_stack_address) is not int or not 0x30<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('environment constant callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    packed=_read_span(p,argument_block_address,16)
    if int.from_bytes(packed[:8],'little')!=image_base+0x256330:
        raise RefillUnsupported('unexpected second environment constant target')
    if argument_block_address<entry_stack_address and argument_block_address+24>entry_stack_address-0x30:
        raise RefillUnsupported('environment constant callback aliases unmodeled physical spills')
    result=get_environment_constant(p,image_base=image_base,entry_offset=0x256330)
    _write_span(p,argument_block_address+16,result.to_bytes(8,'little'))
    p.commit()
    return result


def apply_request_287474_cstring_format_callback(pages, *, argument_block_address,
        entry_stack_address, image_base):
    """+288718: six X arguments to +2781f4, then W0 at packed+56.

    Capacity and output are guest inputs. Preserve packed+60 except for an
    explicit output alias. Native spill buffers and other conversions reject.
    """
    from vm9_logger import format_cstring_arguments
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('C-string format callback requires an aligned guest stack')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,56)
    words=tuple(int.from_bytes(packed[i:i+8],'little') for i in range(0,56,8))
    if words[0]!=image_base+0x2781F4:
        raise RefillUnsupported('unexpected second C-string format target')
    if argument_block_address<entry_stack_address and argument_block_address+64>entry_stack_address-0x1000:
        raise RefillUnsupported('C-string format packed block aliases unmodeled native spills')
    result=format_cstring_arguments(p,output_address=words[1],capacity=words[2],format_address=words[3],
        argument_addresses=words[4:],forbidden_span=(entry_stack_address-0x1000,0x1000))
    _write_span(p,argument_block_address+56,result.to_bytes(4,'little'))
    p.commit()
    return result


def apply_request_287474_guard_release_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, observer=None):
    """+28854c -> +32d4f8 tail branch: load target/guard without a packed store.

    The wrapper has no frame. Refuse aliases with the guard body's unmodeled
    0x30-byte physical frame, and require only the two accessed guard bytes.
    """
    from vm9_objects import release_static_initialization_guard
    if (type(entry_stack_address) is not int or not 0x30<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('guard release callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    packed=_read_span(p,argument_block_address,16)
    target=int.from_bytes(packed[:8],'little')
    guard=int.from_bytes(packed[8:],'little')
    if target!=image_base+0x32D4F8:
        raise RefillUnsupported('unexpected second static guard release target')
    for address,width in ((argument_block_address,16),(guard,2)):
        if address<entry_stack_address and address+width>entry_stack_address-0x30:
            raise RefillUnsupported('guard release callback aliases unmodeled physical spills')
    result=release_static_initialization_guard(p,guard_address=guard,image_base=image_base,
        observer=observer)
    p.commit()
    return result


def apply_request_287474_realtime_milliseconds_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,read_clock):
    """+28876c/+26cc60: reuse the signed clock owner and store its X64 bits."""
    from vm9_callbacks import read_realtime_milliseconds
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('realtime milliseconds callback requires an aligned stack')
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-16:
        raise RefillUnsupported('realtime milliseconds packed address wraps uint64')
    if argument_block_address<entry_stack_address and argument_block_address+16>entry_stack_address-0x1000:
        raise RefillUnsupported('realtime milliseconds packed block aliases native spills')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    if target!=image_base+0x26CC60:
        raise RefillUnsupported('unexpected second realtime milliseconds target')
    value=read_realtime_milliseconds(p,read_clock=read_clock)&0xFFFFFFFFFFFFFFFF
    _write_span(p,argument_block_address+8,value.to_bytes(8,'little'))
    p.commit();return value


def apply_request_287474_realtime_seconds_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, read_clock):
    """+28876c -> +26cc64: signed milliseconds, then unsigned UDIV1000.

    Reuse the existing realtime owner, mask its signed result to X64, then
    divide. Only the target is loaded; the full X result replaces packed+8.
    Physical spills/PAC are unmodeled; packed aliases in SP-0x1000..SP refuse.
    External clock-provider effects cannot be reversed by page rollback.
    """
    from vm9_callbacks import read_realtime_milliseconds
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('realtime seconds callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    if target!=image_base+0x26CC64:
        raise RefillUnsupported('unexpected second realtime seconds target')
    if argument_block_address<entry_stack_address and argument_block_address+16>entry_stack_address-0x1000:
        raise RefillUnsupported('realtime seconds packed block aliases unmodeled native spills')
    milliseconds=read_realtime_milliseconds(p,read_clock=read_clock)
    value=(milliseconds&0xFFFFFFFFFFFFFFFF)//1000
    _write_span(p,argument_block_address+8,value.to_bytes(8,'little'))
    p.commit()
    return value


def apply_request_287474_process_id_callback(pages, *, argument_block_address,
        entry_stack_address,thread_pointer,import_bindings,syscall=None):
    """+28863c calls explicit getpid/getppid bindings and stores only W0.

    Matching bionic getpid reads pthread+0x14 through TP+8. A nonzero cached
    W32 bypasses syscall172; the cold path does not populate that cache.
    getppid uses syscall173. Kernel errors write errno at TP+0x10 through the
    existing syscall owner. Import addresses are caller-owned linker results.
    Native spills/PAC and external provider effects are outside page rollback.
    """
    from vm9_configuration_init import _guest_syscall
    if (type(entry_stack_address) is not int or not 0x40<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('process ID callback requires an aligned guest stack')
    if type(thread_pointer) is not int or not 0<thread_pointer<(1<<64)-0x18:
        raise RefillUnsupported('process ID callback requires a guest thread pointer')
    if (not isinstance(import_bindings,dict) or set(import_bindings)!={'getpid','getppid'}
            or any(type(v) is not int or not 0<v<1<<64 for v in import_bindings.values())
            or len(set(import_bindings.values()))!=2):
        raise RefillUnsupported('process ID callback requires distinct resolved libc imports')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    if target not in import_bindings.values():
        raise RefillUnsupported('unexpected second process ID target')
    if argument_block_address<entry_stack_address and argument_block_address+12>entry_stack_address-0x40:
        raise RefillUnsupported('process ID packed block aliases unmodeled native spills')
    value=0
    if target==import_bindings['getpid']:
        thread=int.from_bytes(_read_span(p,thread_pointer+8,8),'little')
        value=int.from_bytes(_read_span(p,thread+0x14,4),'little')
    if not value:
        if not callable(syscall):raise RefillUnsupported('process ID callback requires a syscall provider')
        number=172 if target==import_bindings['getpid'] else 173
        value=_guest_syscall(p,syscall,thread_pointer+0x10,number)&0xFFFFFFFFFFFFFFFF
    _write_span(p,argument_block_address+8,(value&0xFFFFFFFF).to_bytes(4,'little'))
    p.commit()
    return value


def apply_request_287474_thread_pointer_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,thread_pointer):
    """+28876c/+204f58 returns the cached X64 TP, initializing only when zero.

    +20513c advances its link register past opaque instructions. The actual
    cold path reads TPIDR_EL0 and publishes image+3da090 before packed+8.
    No TLS dereference, provider or per-thread cache policy is added here.
    Physical spills/PAC are outside this semantic page transaction.
    """
    if (type(entry_stack_address) is not int or not 0x40<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('thread pointer callback requires an aligned guest stack')
    if type(thread_pointer) is not int or not 0<=thread_pointer<1<<64:
        raise RefillUnsupported('thread pointer callback requires uint64 TPIDR_EL0')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    if target!=image_base+0x204F58:
        raise RefillUnsupported('unexpected second thread pointer target')
    if argument_block_address<entry_stack_address and argument_block_address+16>entry_stack_address-0x40:
        raise RefillUnsupported('thread pointer packed block aliases unmodeled native spills')
    cache=image_base+0x3DA090
    value=int.from_bytes(_read_span(p,cache,8),'little')
    if not value:
        value=thread_pointer
        _write_span(p,cache,value.to_bytes(8,'little'))
    _write_span(p,argument_block_address+8,value.to_bytes(8,'little'))
    p.commit()
    return value


def apply_request_287474_locked_pointer_callback(pages, *, argument_block_address,
        entry_stack_address,image_base):
    """+288794/+282b84 reads receiver+0x40 while holding its normal mutex.

    Retain receiver+0x98 in the +34c778 scope at wrapper SP-0x50 and reuse
    the existing uncontended mutex owner. The +15f778 destructor uses that
    retained mutex before the wrapper writes X64 at packed+16. Scope padding
    remains unchanged. Physical spills/canary/PAC and concurrency are unverified.
    """
    from vm9_objects import lock_uncontended_mutex,unlock_uncontended_mutex
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('locked pointer callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    packed=_read_span(p,argument_block_address,16)
    target,receiver=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    if target!=image_base+0x282B84:
        raise RefillUnsupported('unexpected second locked pointer target')
    def exclude(address,width):
        if address<entry_stack_address and address+width>entry_stack_address-0x1000:
            raise RefillUnsupported('locked pointer callback aliases unmodeled native spills')
    exclude(argument_block_address,24);exclude(receiver,0xA0)
    mutex_owner=int.from_bytes(_read_span(p,receiver+0x98,8),'little')
    exclude(mutex_owner+8,2)
    guard=entry_stack_address-0x50;vtable=(image_base+0x34C778).to_bytes(8,'little')
    _write_span(p,guard,vtable+mutex_owner.to_bytes(8,'little'))
    status=lock_uncontended_mutex(p,mutex_address=mutex_owner+8)
    _write_span(p,guard+16,status.to_bytes(4,'little'))
    value=int.from_bytes(_read_span(p,receiver+0x40,8),'little')
    _write_span(p,guard,vtable)
    if not int.from_bytes(_read_span(p,guard+16,4),'little'):
        retained=int.from_bytes(_read_span(p,guard+8,8),'little')
        unlock_uncontended_mutex(p,mutex_address=retained+8)
    _write_span(p,argument_block_address+16,value.to_bytes(8,'little'))
    p.commit()
    return value


def apply_request_287474_tree_pointer_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,max_nodes=4096,max_bytes=0x100000):
    """+2887b0/+256b84 looks up receiver+0x58 under its shared reader.

    Reuse the tree and reader owners, retain the 24-byte scope at wrapper
    SP-0x60, read the found value as X64 before release, then store packed+24.
    Missing/NULL values return zero. Scope padding and following bytes remain.
    Physical spills/canaries/PAC and concurrent/writer paths are unverified.
    """
    from vm9_registry import lookup_configuration_value
    from vm9_objects import acquire_uncontended_shared_reader,release_uncontended_shared_reader
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('tree pointer callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    packed=_read_span(p,argument_block_address,24)
    target,receiver,key=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x256B84:
        raise RefillUnsupported('unexpected second tree pointer target')
    guard=entry_stack_address-0x60
    def exclude(address,width,allow_scope=False):
        if address<entry_stack_address and address+width>entry_stack_address-0x1000:
            if allow_scope and guard<=address and address+width<=guard+24:return
            raise RefillUnsupported('tree pointer callback aliases unmodeled native spills')
    exclude(argument_block_address,32);exclude(receiver,0x118);exclude(key,24)
    vtable=(image_base+0x34C758).to_bytes(8,'little')
    _write_span(p,guard,vtable+(receiver+0x80).to_bytes(8,'little'))
    acquire_uncontended_shared_reader(p,mutex_address=receiver+0x88)
    _write_span(p,receiver+0x114,b'\x01')
    _write_span(p,guard+16,bytes(4))
    pointer=lookup_configuration_value(p,container_address=receiver+0x58,key_address=key,
        image_base=image_base,max_nodes=max_nodes,max_bytes=max_bytes)
    if pointer:exclude(pointer,8,allow_scope=True)
    value=int.from_bytes(_read_span(p,pointer,8),'little') if pointer else 0
    _write_span(p,guard,vtable)
    if not int.from_bytes(_read_span(p,guard+16,4),'little'):
        mutex=int.from_bytes(_read_span(p,guard+8,8),'little')
        if not _read_span(p,mutex+0x94,1)[0]:
            raise RefillUnsupported('tree pointer writer-mode release is unrecovered')
        release_uncontended_shared_reader(p,mutex_address=mutex+8)
    _write_span(p,argument_block_address+24,value.to_bytes(8,'little'))
    p.commit()
    return value


def apply_request_287474_allocation_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate):
    """+288508/+32a1f0 successful operator-new with explicit allocation owner.

    Load X64 size before the provider, normalize zero to one, then write X64
    pointer at packed+16. A NULL return needs C++ retry/throw and is unsupported.
    Pages roll back on failure; external provider effects do not. Physical
    spills/PAC are unproved, so packed aliases into the native stack are refused.
    """
    from vm9_objects import _word
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('allocation callback requires an aligned guest stack')
    if not callable(allocate):raise RefillUnsupported('allocation callback requires an explicit provider')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,16)
    target=int.from_bytes(packed[:8],'little');size=int.from_bytes(packed[8:],'little')
    if target!=image_base+0x32A1F0:raise RefillUnsupported('unexpected second allocation target')
    if argument_block_address<entry_stack_address and argument_block_address+24>entry_stack_address-0x1000:
        raise RefillUnsupported('allocation packed input aliases unmodeled native spills')
    pointer=allocate(p,max(size,1));_word(pointer)
    if not pointer:raise RefillUnsupported('allocation requires unrecovered C++ new-handler or throw')
    _write_span(p,argument_block_address+16,pointer.to_bytes(8,'little'))
    p.commit();return pointer


def apply_request_287474_string_format_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,reallocate,free,prepare_format=None,max_bytes=0x100000,
        wrapper_offset=0x28880C):
    """Known tail wrappers supply W2 alone or W2 followed by four X words.

    No packed result store. The returned object address is model metadata;
    CPU X0 after cleanup and physical GP/FP/spill/PAC state are not compared.
    Formats requiring additional ambient arguments remain unsupported.
    """
    from vm9_configuration_init import format_string_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('string format callback requires an aligned guest stack')
    if not all(callable(s) for s in (allocate,reallocate,free)):
        raise RefillUnsupported('string format callback requires explicit allocation services')
    if wrapper_offset not in (0x28880C,0x2888B4):
        raise RefillUnsupported('unexpected second string format wrapper')
    width=28 if wrapper_offset==0x28880C else 64
    p=_PageTransaction(pages);raw=_read_span(p,argument_block_address,width)
    target=int.from_bytes(raw[:8],'little');output=int.from_bytes(raw[8:16],'little')
    fmt=int.from_bytes(raw[16:24],'little');value=int.from_bytes(raw[24:28],'little')
    arguments=(value,) if wrapper_offset==0x28880C else (value,*(int.from_bytes(raw[i:i+8],'little') for i in range(32,64,8)))
    if target!=image_base+0x248908:raise RefillUnsupported('unexpected second string format target')
    for address,width in ((argument_block_address,width),(output,24),(fmt,1),*((a,1) for a in arguments)):
        if address<entry_stack_address and address+width>entry_stack_address-0x1000:
            raise RefillUnsupported('string format input aliases unmodeled native spills')
    result=format_string_object(p,object_address=output,format_address=fmt,argument_addresses=arguments,
        image_base=image_base,allocate=allocate,reallocate=reallocate,free=free,
        prepare_format=prepare_format,max_bytes=max_bytes)
    p.commit();return result


def apply_request_287474_crc_callback(pages, *, argument_block_address,
        entry_stack_address,image_base):
    """+288820/+258bac reuses the guest-table CRC owner and stores only W0.

    Signed nonpositive lengths do not read payload bytes. Packed/object/data
    aliases are supported outside the native stack; spills/PAC are unproved.
    """
    from vm9_jni_followup import crc_string_object
    from vm9_objects import _s32
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('CRC callback requires an aligned guest stack')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,16)
    target,receiver=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    if target!=image_base+0x258BAC:raise RefillUnsupported('unexpected second CRC target')
    def exclude(address,width):
        if width and address<entry_stack_address and address+width>entry_stack_address-0x1000:
            raise RefillUnsupported('CRC input aliases unmodeled native spills')
    exclude(argument_block_address,20);exclude(receiver+12,12)
    length=_s32(int.from_bytes(_read_span(p,receiver+12,4),'little'))
    pointer=int.from_bytes(_read_span(p,receiver+16,8),'little')
    exclude(pointer,max(0,length))
    value=crc_string_object(p,image_base,receiver)
    _write_span(p,argument_block_address+16,value.to_bytes(4,'little'))
    p.commit();return value


def apply_request_287474_json_number_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,free,max_bytes=4096,max_nodes=4096):
    """+288854/+261350: append a binary64 number, store one bool byte."""
    from vm9_configuration_init import add_json_number_to_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON number callback requires an aligned guest stack')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,32)
    target,obj,key,bits=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16,24))
    if target!=image_base+0x261350:raise RefillUnsupported('unexpected second JSON number target')
    for a,n in ((argument_block_address,33),(obj,16)):
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('JSON number callback input aliases native spills')
    parent=int.from_bytes(_read_span(p,obj+8,8),'little')
    result=add_json_number_to_object(p,parent_address=parent,key_address=key,number_bits=bits,
        entry_stack_address=entry_stack_address,image_base=image_base,allocate=allocate,free=free,
        max_bytes=max_bytes,max_nodes=max_nodes)
    _write_span(p,argument_block_address+32,bytes([int(result)]))
    p.commit();return result


def apply_request_287474_mutex_lock_callback(pages, *, argument_block_address,
        entry_stack_address,import_bindings):
    """+2889a8: explicit loader target, normal lock, exact packed+16 W0 store.

    Bindings are caller-supplied loader input. No NULL target is inferred or
    repaired here. Reuse the serialized uncontended mutex owner; this does
    not model atomicity or host concurrency.
    """
    from vm9_objects import lock_uncontended_mutex
    target=import_bindings.get('pthread_mutex_lock') if isinstance(import_bindings,dict) else None
    if type(target) is not int or not 0<target<1<<64 or target&3:
        raise RefillUnsupported('second mutex lock requires an explicit aligned import binding')
    if (type(entry_stack_address) is not int or not 48<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('second mutex lock requires an aligned native stack')
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-20:
        raise RefillUnsupported('second mutex packed address wraps uint64')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,16)
    actual,mutex=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    if actual!=target:raise RefillUnsupported('unexpected second mutex lock import target')
    if not 0<mutex<=(1<<64)-2:
        raise RefillUnsupported('second mutex address wraps uint64')
    for a,n in ((argument_block_address,20),(mutex,2)):
        if a<entry_stack_address and a+n>entry_stack_address-48:
            raise RefillUnsupported('second mutex callback aliases native spills')
    result=lock_uncontended_mutex(p,mutex_address=mutex)
    _write_span(p,argument_block_address+16,result.to_bytes(4,'little'))
    p.commit();return result


def apply_request_287474_json_print_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,thread_pointer,allocate,free,
        thread_id=None,diagnostic_observer=None,prepare_format=None,
        max_bytes=0x100000,max_nodes=4096,max_depth=64):
    """+288990/+2616b4: hidden X8 reference output, no packed store."""
    from vm9_configuration_init import construct_printed_json_reference
    if (type(entry_stack_address) is not int or not 0x4040<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON print callback requires an aligned guest stack')
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-24:
        raise RefillUnsupported('JSON print packed address wraps uint64')
    p=_PageTransaction(pages);raw=_read_span(p,argument_block_address,24)
    target,output,receiver=(int.from_bytes(raw[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x2616B4:raise RefillUnsupported('unexpected second JSON print target')
    for a,n in ((argument_block_address,24),(receiver,16)):
        if a<entry_stack_address and a+n>entry_stack_address-0x4040:
            raise RefillUnsupported('JSON print callback input aliases native spills')
    node=int.from_bytes(_read_span(p,receiver+8,8),'little')
    result=construct_printed_json_reference(p,output_reference_address=output,node_address=node,
        entry_stack_address=entry_stack_address-16,image_base=image_base,thread_pointer=thread_pointer,
        allocate=allocate,free=free,thread_id=thread_id,diagnostic_observer=diagnostic_observer,
        prepare_format=prepare_format,max_bytes=max_bytes,max_nodes=max_nodes,max_depth=max_depth)
    p.commit();return result


def apply_request_287474_json_bool_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,free,max_bytes=4096,max_nodes=4096):
    """+288968/+261580: append a low-bit boolean, store one result byte."""
    from vm9_configuration_init import add_json_bool_to_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON bool callback requires an aligned guest stack')
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-26:
        raise RefillUnsupported('JSON bool packed address wraps uint64')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,25)
    target,obj,key=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x261580:raise RefillUnsupported('unexpected second JSON bool target')
    for a,n in ((argument_block_address,26),(obj,16)):
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('JSON bool callback input aliases native spills')
    parent=int.from_bytes(_read_span(p,obj+8,8),'little')
    result=add_json_bool_to_object(p,parent_address=parent,key_address=key,value_byte=packed[24],
        entry_stack_address=entry_stack_address,image_base=image_base,allocate=allocate,free=free,
        max_bytes=max_bytes,max_nodes=max_nodes)
    _write_span(p,argument_block_address+25,bytes([int(result)]))
    p.commit();return result


def apply_request_287474_configuration_string_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,max_nodes=4096,max_bytes=0x100000):
    """+28890c/+256ce0 hidden-X8 output; receiver/key at packed+16/+24."""
    from vm9_registry import read_configuration_string_object
    if (type(entry_stack_address) is not int or not 0x1010<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('configuration string callback requires an aligned stack')
    if (type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-32):
        raise RefillUnsupported('configuration string packed address wraps uint64')
    if argument_block_address<entry_stack_address and argument_block_address+32>entry_stack_address-0x1010:
        raise RefillUnsupported('configuration string packed input aliases native spills')
    p=_PageTransaction(pages);raw=_read_span(p,argument_block_address,32)
    target,output,receiver,key=(int.from_bytes(raw[i:i+8],'little') for i in (0,8,16,24))
    if target!=image_base+0x256CE0:raise RefillUnsupported('unexpected second configuration string target')
    value=read_configuration_string_object(p,registry_address=receiver,output_object_address=output,
        key_address=key,entry_stack_address=entry_stack_address-16,image_base=image_base,
        allocate=allocate,max_nodes=max_nodes,max_bytes=max_bytes,
        excluded_spans=((entry_stack_address-16,16),))
    p.commit();return value


def apply_request_287474_numeric_string_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,free,get_tls):
    """+2888f4/+28794c builds the request's libc++ numeric string.

    Nine live u32 globals each gain '|', followed by one live TLS u32.
    Reserve128 allocates144 bytes; at most109 output bytes need no growth.
    Final reserve(0) copies length+1, frees the old buffer and changes the
    representation. This is libc++ SSO, distinct from Medusa string objects.

    Only staged pages roll back. Providers must preserve the output descriptor;
    aliases into native spills, inputs or active allocations are unsupported.
    Temporary stack bytes, canary/PAC and physical return registers are unproved.
    """
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('numeric string requires an aligned guest stack')
    def address(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('numeric string address is invalid or wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('numeric string aliases unmodeled native spills')
    if type(image_base) is not int or not 0<=image_base<=(1<<64)-0x3D19AC:
        raise RefillUnsupported('numeric string image address wraps uint64')
    if not all(callable(s) for s in (allocate,free,get_tls)):
        raise RefillUnsupported('numeric string requires allocation, free and TLS providers')
    address(argument_block_address,24)
    p=_PageTransaction(pages);raw=_read_span(p,argument_block_address,24)
    target,output,receiver=(int.from_bytes(raw[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x28794C:raise RefillUnsupported('unexpected second numeric string target')
    globals_address=image_base+0x3D1988;control=image_base+0x382920
    inputs=((argument_block_address,24),(globals_address,36),(control,32))
    def overlaps(a,n,b,m):return a<b+m and b<a+n
    address(output,24)
    for a,n in inputs:
        address(a,n)
        if overlaps(output,24,a,n):raise RefillUnsupported('numeric string output aliases inputs')
    _read_span(p,globals_address,36)
    active=[]
    def service(provider,*args):
        descriptor=_read_span(p,output,24)
        result=provider(p,*args)
        if _read_span(p,output,24)!=descriptor:
            raise RefillUnsupported('numeric string provider changed its output descriptor')
        return result
    def allocation(size):
        pointer=service(allocate,size);address(pointer,size)
        for a,n in (*inputs,(output,24),*active):
            if overlaps(pointer,size,a,n):
                raise RefillUnsupported('numeric string allocation aliases live state')
        _read_span(p,pointer,size);active.append((pointer,size));return pointer
    _write_span(p,output,bytes(24))
    buffer=allocation(144)
    _write_span(p,buffer,b'\0')
    _write_span(p,output,(145).to_bytes(8,'little')+bytes(8)+buffer.to_bytes(8,'little'))
    length=0
    def append(data):
        nonlocal length
        if length+len(data)>109:raise RefillUnsupported('numeric string exceeded its uint32 bound')
        _write_span(p,buffer+length,data)
        length+=len(data)
        _write_span(p,output+8,length.to_bytes(8,'little'))
        _write_span(p,buffer+length,b'\0')
    for index in range(9):
        value=int.from_bytes(_read_span(p,globals_address+index*4,4),'little')
        append(str(value).encode('ascii')+b'|')
    pointer=service(get_tls,control);address(pointer,4)
    for a,n in ((output,24),*active):
        if overlaps(pointer,4,a,n):raise RefillUnsupported('numeric string TLS payload aliases output')
    value=int.from_bytes(_read_span(p,pointer,4),'little')
    append(str(value).encode('ascii'))
    if length<=22:
        _write_span(p,output+1,_read_span(p,buffer,length+1))
        service(free,buffer)
        _write_span(p,output,bytes([length*2]))
    else:
        size=(length+16)&~15
        destination=allocation(size)
        _write_span(p,destination,_read_span(p,buffer,length+1))
        service(free,buffer)
        _write_span(p,output+16,destination.to_bytes(8,'little'))
        _write_span(p,output,(size|1).to_bytes(8,'little')+length.to_bytes(8,'little'))
    p.commit();return output


def apply_request_287474_json_string_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,free,max_bytes=4096,max_nodes=4096):
    """+2888d0/+2613e4: append a cstring node and store one bool byte."""
    from vm9_configuration_init import add_json_string_to_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON string callback requires an aligned guest stack')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,33)
    target,obj,key,value=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16,24))
    if target!=image_base+0x2613E4:raise RefillUnsupported('unexpected second JSON string target')
    for a,n in ((argument_block_address,33),(obj,16),(key,1),(value,1)):
        if a and a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('JSON string callback input aliases native spills')
    parent=int.from_bytes(_read_span(p,obj+8,8),'little')
    result=add_json_string_to_object(p,parent_address=parent,key_address=key,value_address=value,
        entry_stack_address=entry_stack_address,image_base=image_base,allocate=allocate,free=free,
        max_bytes=max_bytes,max_nodes=max_nodes)
    _write_span(p,argument_block_address+32,bytes([int(result)]))
    p.commit();return result


def apply_request_287474_tls_u32_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,get_tls):
    """+288898/+2850a8: reuse the explicit TLS provider, store one W value.

    The target ignores its receiver. Physical spills and provider side effects
    outside staged pages are not modeled; resolved payload aliases are refused.
    """
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('TLS u32 callback requires an aligned guest stack')
    if (type(argument_block_address) is not int or not 0<=argument_block_address<=(1<<64)-20
            or type(image_base) is not int or not 0<=image_base<=(1<<64)-0x382940):
        raise RefillUnsupported('TLS u32 callback addresses wrap uint64')
    if not callable(get_tls):raise RefillUnsupported('TLS u32 callback requires its owning TLS service')
    def exclude(address,width):
        if address<entry_stack_address and address+width>entry_stack_address-0x1000:
            raise RefillUnsupported('TLS u32 callback aliases unmodeled native spills')
    control=image_base+0x382920
    exclude(argument_block_address,20);exclude(control,32)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,20)
    if int.from_bytes(packed[:8],'little')!=image_base+0x2850A8:
        raise RefillUnsupported('unexpected second TLS u32 target')
    pointer=get_tls(p,control)
    if type(pointer) is not int or not 0<pointer<=(1<<64)-4:
        raise RefillUnsupported('TLS u32 provider returned an invalid payload address')
    exclude(pointer,4)
    value=int.from_bytes(_read_span(p,pointer,4),'little')
    _write_span(p,argument_block_address+16,value.to_bytes(4,'little'))
    p.commit();return value


def apply_request_287474_global_u32_callback(pages, *, argument_block_address,
        entry_stack_address,image_base):
    """+28863c/+1c3018: load global W0 and store exactly four packed bytes.

    The wrapper saves native registers below SP; aliases of that region are
    refused because physical spills/PAC are outside this bounded model.
    """
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('global u32 callback requires an aligned guest stack')
    p=_PageTransaction(pages)
    target=int.from_bytes(_read_span(p,argument_block_address,8),'little')
    sources={0x1C3018:0x37A794,0x1C3024:0x37A790,0x1E53D0:0x3D60D4}
    if target-image_base not in sources:
        raise RefillUnsupported('unexpected second global u32 target')
    if argument_block_address<entry_stack_address and argument_block_address+12>entry_stack_address-0x1000:
        raise RefillUnsupported('global u32 packed input aliases unmodeled native spills')
    raw=_read_span(p,image_base+sources[target-image_base],4)
    _write_span(p,argument_block_address+8,raw)
    p.commit();return int.from_bytes(raw,'little')


def apply_request_287474_json_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,thread_pointer,allocate,free,
        thread_id=None,diagnostic_observer=None,max_bytes=4096):
    """+28883c hidden-X8 empty JSON reference; no packed result store."""
    from vm9_configuration_init import construct_empty_json_reference
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('JSON callback requires an aligned guest stack')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,24)
    target,output,source=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x261404:raise RefillUnsupported('unexpected second JSON target')
    for a,n in ((argument_block_address,24),(output,16),(source,1 if source else 0)):
        if n and a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('JSON input aliases unmodeled native spills')
    result=construct_empty_json_reference(p,output_reference_address=output,source_address=source,
        entry_stack_address=entry_stack_address-16,image_base=image_base,
        thread_pointer=thread_pointer,allocate=allocate,free=free,thread_id=thread_id,
        diagnostic_observer=diagnostic_observer,max_bytes=max_bytes)
    p.commit();return result


def _copy_request_287474_bytes(pages,destination,source,length):
    """+2a9280 ordered scalar/vector loads and forward/backward aligned loops."""
    end_source,end_destination=source+length,destination+length
    def load(address,width=16):return _read_span(pages,address,width)
    def store(address,data):_write_span(pages,address,data)
    if length<=32:
        if length>=16:width=16
        elif length>=8:width=8
        elif length>=4:width=4
        elif length:
            first,last,middle=load(source,1),load(end_source-1,1),load(source+(length>>1),1)
            store(destination,first);store(destination+(length>>1),middle);store(end_destination-1,last)
            return
        else:return
        first,last=load(source,width),load(end_source-width,width)
        store(destination,first);store(end_destination-width,last)
        return
    if length<=128:
        first,second,last_two,last=load(source),load(source+16),load(end_source-32),load(end_source-16)
        if length>64:
            third,fourth=load(source+32),load(source+48)
            if length>96:
                tail_four,tail_three=load(end_source-64),load(end_source-48)
                store(end_destination-64,tail_four);store(end_destination-48,tail_three)
            store(destination,first);store(destination+16,second)
            store(destination+32,third);store(destination+48,fourth)
        else:
            store(destination,first);store(destination+16,second)
        store(end_destination-32,last_two);store(end_destination-16,last)
        return
    if destination==source:return
    if (destination-source)&0xFFFFFFFFFFFFFFFF>=length:
        first=load(source);alignment=destination&15
        output=destination&~15;current=source-alignment
        a=load(current+16);store(destination,first)
        b,c,d=load(current+32),load(current+48),load(current+64)
        current+=64;remaining=length+alignment-144
        while remaining>0:
            store(output+16,a);a=load(current+16)
            store(output+32,b);b=load(current+32)
            store(output+48,c);c=load(current+48)
            store(output+64,d);output+=64;current+=64;d=load(current)
            remaining-=64
        tail_a=load(end_source-64);store(output+16,a)
        tail_b=load(end_source-48);store(output+32,b)
        tail_c=load(end_source-32);store(output+48,c)
        tail_d=load(end_source-16);store(output+64,d)
        store(end_destination-64,tail_a);store(end_destination-48,tail_b)
        store(end_destination-32,tail_c);store(end_destination-16,tail_d)
    else:
        last=load(end_source-16);alignment=end_destination&15
        current=end_source-alignment;output=end_destination-alignment
        a=load(current-16);store(end_destination-16,last)
        b,c,d=load(current-32),load(current-48),load(current-64)
        current-=64;remaining=length-alignment-128
        while remaining>0:
            store(output-16,a);a=load(current-16)
            store(output-32,b);b=load(current-32)
            store(output-48,c);c=load(current-48)
            store(output-64,d);output-=64;current-=64;d=load(current)
            remaining-=64
        head_d=load(source+48);store(output-16,a)
        head_c=load(source+32);store(output-32,b)
        head_b=load(source+16);store(output-48,c)
        head_a=load(source);store(output-64,d)
        store(destination+48,head_d);store(destination+32,head_c)
        store(destination+16,head_b);store(destination,head_a)


def apply_request_287474_protobuf_size_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, max_bytes=1 << 20, max_fields=4096,
        max_nodes=1024, max_depth=16):
    """+2889c4/+2a3378: bounded proto3 size, exact eight-byte packed+16 store."""
    from vm9_protobuf import get_packed_size
    if (type(entry_stack_address) is not int or not 0x1000 <= entry_stack_address < 1 << 64
            or entry_stack_address & 15):
        raise RefillUnsupported('protobuf size callback requires an aligned stack')
    if (type(argument_block_address) is not int or
            not 0 < argument_block_address <= (1 << 64) - 24):
        raise RefillUnsupported('protobuf size packed address wraps uint64')
    if argument_block_address < entry_stack_address and argument_block_address + 24 > entry_stack_address - 0x1000:
        raise RefillUnsupported('protobuf size packed block aliases native spills')
    p = _PageTransaction(pages)
    target = int.from_bytes(_read_span(p, argument_block_address, 8), 'little')
    if target != image_base + 0x2A3378:
        raise RefillUnsupported('unexpected second protobuf size target')
    message = int.from_bytes(_read_span(p, argument_block_address + 8, 8), 'little')
    value = get_packed_size(p, message_address=message, max_bytes=max_bytes,
        max_fields=max_fields, max_nodes=max_nodes, max_depth=max_depth,
        forbidden_ranges=((entry_stack_address - 0x1000, entry_stack_address),))
    _write_span(p, argument_block_address + 16, value.to_bytes(8, 'little'))
    p.commit()
    return value


def apply_request_287474_string_fill_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, allocate, reallocate, free, max_bytes=0x100000):
    """+2889e0 tail-calls +248dd8; reuse fill owner, no packed result store.

    Explicit providers may change the declared length; validate input/buffer
    ranges after each effect. Header/packed/payload aliases and native spill
    aliases reject. Page rollback cannot reverse an external allocator ledger.
    """
    from vm9_objects import fill_string_object, _s32
    if (type(entry_stack_address) is not int or not 0x1000 <= entry_stack_address < 1 << 64
            or entry_stack_address & 15):
        raise RefillUnsupported('string fill callback requires an aligned stack')
    if type(max_bytes) is not int or not 1 <= max_bytes <= 0x100000:
        raise RefillUnsupported('invalid string fill byte bound')
    if any(not callable(provider) for provider in (allocate, reallocate, free)):
        raise RefillUnsupported('string fill callback requires explicit allocation providers')
    def span(address, size):
        if type(address) is not int or not 0 < address < 1 << 64 or address + size > 1 << 64:
            raise RefillUnsupported('string fill address wraps uint64')
        if address < entry_stack_address and address + size > entry_stack_address - 0x1000:
            raise RefillUnsupported('string fill input aliases native spills')
    span(argument_block_address, 21)
    p = _PageTransaction(pages)
    packed = _read_span(p, argument_block_address, 21)
    target, receiver = (int.from_bytes(packed[i:i+8], 'little') for i in (0, 8))
    if target != image_base + 0x248DD8:
        raise RefillUnsupported('unexpected second string fill target')
    span(receiver, 24)
    if receiver < argument_block_address + 21 and argument_block_address < receiver + 24:
        raise RefillUnsupported('string fill receiver aliases packed input')
    length, fill = int.from_bytes(packed[16:20], 'little'), packed[20]
    if _s32(length) >= 0 and length + 1 > max_bytes:
        raise RefillUnsupported('string fill output exceeds explicit byte bound')
    def buffer_span(pointer, size):
        span(pointer, size)
        for address, width in ((argument_block_address, 21), (receiver, 24)):
            if pointer < address + width and address < pointer + size:
                raise RefillUnsupported('string fill payload aliases active input')
    def check(current, after_provider=False):
        if _read_span(current, argument_block_address, 21) != packed:
            raise RefillUnsupported('string fill provider changed packed input')
        capacity = _s32(int.from_bytes(_read_span(current, receiver + 8, 4), 'little'))
        pointer = int.from_bytes(_read_span(current, receiver + 16, 8), 'little')
        if after_provider:
            current_length = _s32(int.from_bytes(_read_span(current, receiver + 12, 4), 'little'))
            if not 0 <= current_length <= max_bytes:
                raise RefillUnsupported('string fill provider length exceeds explicit bound')
        if capacity > max_bytes:
            raise RefillUnsupported('string fill capacity exceeds explicit byte bound')
        if capacity > 0 and pointer:
            buffer_span(pointer, capacity)
    check(p)
    def malloc(tx, size):
        pointer = allocate(tx, size)
        check(tx, True)
        if pointer:buffer_span(pointer, size)
        return pointer
    def realloc(tx, pointer, size):
        result = reallocate(tx, pointer, size)
        check(tx, True)
        if result:buffer_span(result, size)
        return result
    def release(tx, pointer):
        result = free(tx, pointer)
        check(tx, True)
        return result
    status = fill_string_object(p, object_address=receiver, length=length, fill=fill,
        allocate=malloc, reallocate=realloc, free=release, max_bytes=max_bytes)
    check(p, True)
    p.commit()
    return status & 0xFFFFFFFF


def apply_request_287474_protobuf_pack_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, max_bytes=1 << 20, max_fields=4096,
        max_nodes=1024, max_depth=16):
    """+2889f4/+2a337c: encode to packed+16 pointer, store8-byte count at+24."""
    from vm9_protobuf import pack_message
    if (type(entry_stack_address) is not int or not 0x1000 <= entry_stack_address < 1 << 64
            or entry_stack_address & 15):
        raise RefillUnsupported('protobuf pack callback requires an aligned stack')
    if (type(argument_block_address) is not int or
            not 0 < argument_block_address <= (1 << 64) - 32):
        raise RefillUnsupported('protobuf pack packed address wraps uint64')
    if argument_block_address < entry_stack_address and argument_block_address + 32 > entry_stack_address - 0x1000:
        raise RefillUnsupported('protobuf pack packed block aliases native spills')
    p = _PageTransaction(pages)
    raw = _read_span(p, argument_block_address, 24)
    target, message, output = (int.from_bytes(raw[i:i+8], 'little') for i in (0, 8, 16))
    if target != image_base + 0x2A337C:
        raise RefillUnsupported('unexpected second protobuf pack target')
    value = pack_message(p, message_address=message, output_address=output,
        max_bytes=max_bytes, max_fields=max_fields, max_nodes=max_nodes, max_depth=max_depth,
        forbidden_ranges=((entry_stack_address - 0x1000, entry_stack_address),
                          (argument_block_address, argument_block_address + 32)))
    _write_span(p, argument_block_address + 24, value.to_bytes(8, 'little'))
    p.commit()
    return value


def apply_request_287474_mutex_unlock_callback(pages, *, argument_block_address,
        entry_stack_address,import_bindings):
    """+2889a8: explicit loader target, normal unlock, exact packed+16 W0 store.

    Bindings are caller-supplied loader input. No NULL target is inferred or
    repaired here. Reuse the serialized uncontended mutex owner; this does
    not model atomicity or host concurrency.
    """
    from vm9_objects import unlock_uncontended_mutex
    target=import_bindings.get('pthread_mutex_unlock') if isinstance(import_bindings,dict) else None
    if type(target) is not int or not 0<target<1<<64 or target&3:
        raise RefillUnsupported('second mutex unlock requires an explicit aligned import binding')
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('second mutex unlock requires an aligned native stack')
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-20:
        raise RefillUnsupported('second mutex packed address wraps uint64')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,16)
    actual,mutex=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    if actual!=target:raise RefillUnsupported('unexpected second mutex unlock import target')
    if not 0<mutex<=(1<<64)-2:
        raise RefillUnsupported('second mutex address wraps uint64')
    for a,n in ((argument_block_address,20),(mutex,2)):
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('second mutex callback aliases native spills')
    result=unlock_uncontended_mutex(p,mutex_address=mutex)
    _write_span(p,argument_block_address+16,result.to_bytes(4,'little'))
    p.commit();return result


def apply_request_287474_json_delete_callback(pages, *, argument_block_address,
        entry_stack_address, image_base, free, max_nodes=4096, max_depth=64):
    """+288a24 tailcall: target/receiver at0/8, void and no packed store."""
    from vm9_json_cleanup import delete_json_object
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-16:
        raise RefillUnsupported('JSON delete packed address wraps uint64')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,16)
    target,obj=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    if target!=image_base+0x2614EC:raise RefillUnsupported('unexpected JSON deleting destructor target')
    delete_json_object(p,object_address=obj,entry_stack_address=entry_stack_address,
        image_base=image_base,free=free,protected_ranges=((argument_block_address,16),),
        max_nodes=max_nodes,max_depth=max_depth)
    p.commit()


def apply_request_287474_configuration_lookup_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,thread_pointer,vm_module,allocate,reallocate,free,
        get_singleton,thread_id=None,diagnostic_observer=None,max_entries=4096,max_bytes=0x100000):
    """+288a30/+263174: hidden output8, config16/key24, no packed result."""
    from vm9_configuration_lookup import lookup_configuration_reference
    if type(argument_block_address) is not int or not 0<argument_block_address<=(1<<64)-32:
        raise RefillUnsupported('configuration lookup packed address wraps uint64')
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,32)
    target,output,receiver,key=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16,24))
    if target!=image_base+0x263174:raise RefillUnsupported('unexpected configuration lookup target')
    result=lookup_configuration_reference(p,output_reference_address=output,
        configuration_address=receiver,key_object_address=key,entry_stack_address=entry_stack_address,
        image_base=image_base,thread_pointer=thread_pointer,vm_module=vm_module,
        allocate=allocate,reallocate=reallocate,free=free,get_singleton=get_singleton,
        thread_id=thread_id,diagnostic_observer=diagnostic_observer,
        protected_ranges=((argument_block_address,32),),max_entries=max_entries,max_bytes=max_bytes)
    p.commit();return result


def apply_request_287474_decoded_reference_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,thread_pointer,allocate,free,thread_id=None,
        diagnostic_observer=None,max_bytes=0x100000):
    """+288A4C/+258E7C: hidden X8 output8/source16; no packed result.

    Reuse the decoded reference owner with the wrapper's 16-byte LR save.
    Known input, output and allocation aliases reject. Page rollback cannot
    reverse an external allocator/free ledger or OS mappings.
    """
    from vm9_objects import construct_decoded_configuration_reference
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('decoded reference requires an aligned guest stack')
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000:
        raise RefillUnsupported('decoded reference requires a bounded source')
    if not callable(allocate) or not callable(free):
        raise RefillUnsupported('decoded reference requires allocation and free services')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('decoded reference address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('decoded reference aliases native spills')
    span(argument_block_address,24)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,24)
    target,output,source=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x258E7C:raise RefillUnsupported('unexpected decoded reference target')
    fixed=((argument_block_address,24),(output,16),(source,24))
    for a,n in fixed:span(a,n);_read_span(p,a,n)
    if any(a<b+m and b<a+n for i,(a,n) in enumerate(fixed) for b,m in fixed[i+1:]):
        raise RefillUnsupported('decoded reference inputs alias')
    length=int.from_bytes(_read_span(p,source+12,4),'little')
    if length>max_bytes:raise RefillUnsupported('decoded reference source exceeds byte bound')
    live=[]
    def check_payload(tx):
        if _read_span(tx,argument_block_address,24)!=packed:
            raise RefillUnsupported('decoded reference provider changed packed input')
        pointer=int.from_bytes(_read_span(tx,source+16,8),'little')
        if length:
            span(pointer,length);_read_span(tx,pointer,length)
            if any(pointer<a+n and a<pointer+length for a,n in fixed+tuple(live)):
                raise RefillUnsupported('decoded reference source aliases active storage')
        return pointer
    check_payload(p)
    def checked_allocate(tx,n):
        result=allocate(tx,n)
        if type(result) is not int or not 0<=result<=(1<<64)-max(n,1):
            raise RefillUnsupported('decoded reference allocator returned invalid address')
        pointer=check_payload(tx)
        if result:
            span(result,max(n,1))
            protected=fixed+tuple(live)+(((pointer,length),) if length else ())
            if any(result<a+m and a<result+max(n,1) for a,m in protected):
                raise RefillUnsupported('decoded reference allocation aliases active storage')
            live.append((result,max(n,1)))
        return result
    def checked_free(tx,a):
        free(tx,a)
        live[:]=[(b,n) for b,n in live if b!=a]
        check_payload(tx)
    construct_decoded_configuration_reference(p,object_address=output,
        source_object_address=source,image_base=image_base,allocate=checked_allocate,
        free=checked_free,max_source_bytes=max_bytes,entry_stack_address=entry_stack_address-16,
        diagnostic_services=dict(thread_pointer=thread_pointer,thread_id=thread_id,
            diagnostic_observer=diagnostic_observer))
    p.commit();return output


def apply_request_287474_string_clone_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,max_bytes=0x100000):
    """+288A64 tailcalls +2483E0; target0/destination8/source16, no store.

    Preserve the clone owner's declared binary length and late pointer read.
    Known input/payload/allocation aliases and native spill aliases reject;
    page rollback does not undo external allocation effects.
    """
    from vm9_objects import clone_string_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('string clone requires an aligned guest stack')
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000 or not callable(allocate):
        raise RefillUnsupported('string clone requires a bound and allocation service')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('string clone address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('string clone aliases native spills')
    span(argument_block_address,24)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,24)
    target,output,source=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    if target!=image_base+0x2483E0:raise RefillUnsupported('unexpected string clone target')
    fixed=((argument_block_address,24),(output,24),(source,24))
    for a,n in fixed:span(a,n);_read_span(p,a,n)
    if any(a<b+m and b<a+n for i,(a,n) in enumerate(fixed) for b,m in fixed[i+1:]):
        raise RefillUnsupported('string clone inputs alias')
    length=int.from_bytes(_read_span(p,source+12,4),'little')
    if length<0x80000000 and length>max_bytes:
        raise RefillUnsupported('string clone source exceeds byte bound')
    def payload(tx):
        pointer=int.from_bytes(_read_span(tx,source+16,8),'little')
        if 0<length<0x80000000:
            span(pointer,length);_read_span(tx,pointer,length)
            if any(pointer<a+n and a<pointer+length for a,n in fixed):
                raise RefillUnsupported('string clone payload aliases input')
        return pointer
    payload(p)
    def checked_allocate(tx,n):
        result=allocate(tx,n)
        if _read_span(tx,argument_block_address,24)!=packed:
            raise RefillUnsupported('string clone provider changed packed input')
        pointer=payload(tx)
        if type(result) is not int or not 0<=result<=(1<<64)-n:
            raise RefillUnsupported('string clone allocator returned invalid address')
        if result:
            span(result,n)
            protected=fixed+(((pointer,length),) if length else ())
            if any(result<a+m and a<result+n for a,m in protected):
                raise RefillUnsupported('string clone allocation aliases active input')
        return result
    clone_string_object(p,object_address=output,source_object_address=source,
        image_base=image_base,allocate=checked_allocate,max_payload_bytes=max_bytes)
    p.commit();return output


def apply_request_287474_sized_string_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,allocate,max_bytes=0x100000):
    """+288A74 tailcalls +2481FC; target0/destination8/source16/length32at24.

    Reuse the sized-string owner; negative lengths and malloc NULL clear both
    length words. Read source bytes after allocation only for a nonempty copy.
    Return the destination address; native physical X0 is outside this API.
    Page rollback cannot undo external allocation effects.
    """
    from vm9_objects import construct_sized_string_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('sized string requires an aligned guest stack')
    if type(max_bytes) is not int or not 1<=max_bytes<=0x100000 or not callable(allocate):
        raise RefillUnsupported('sized string requires a bound and allocation service')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('sized string address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('sized string aliases native spills')
    span(argument_block_address,28)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,28)
    target,output,source=(int.from_bytes(packed[i:i+8],'little') for i in (0,8,16))
    length=int.from_bytes(packed[24:28],'little')
    if target!=image_base+0x2481FC:raise RefillUnsupported('unexpected sized string target')
    fixed=((argument_block_address,28),(output,24))
    span(output,24);_read_span(p,output,24)
    if output<argument_block_address+28 and argument_block_address<output+24:
        raise RefillUnsupported('sized string output aliases packed input')
    copying=0<length<0x80000000
    if length<0x80000000 and length>max_bytes:
        raise RefillUnsupported('sized string source exceeds byte bound')
    if copying:
        span(source,length)
        if any(source<a+n and a<source+length for a,n in fixed):
            raise RefillUnsupported('sized string source aliases active input')
    def checked_allocate(tx,n):
        result=allocate(tx,n)
        if _read_span(tx,argument_block_address,28)!=packed:
            raise RefillUnsupported('sized string provider changed packed input')
        if type(result) is not int or not 0<=result<=(1<<64)-n:
            raise RefillUnsupported('sized string allocator returned invalid address')
        if result:
            span(result,n)
            protected=fixed+(((source,length),) if copying else ())
            if any(result<a+m and a<result+n for a,m in protected):
                raise RefillUnsupported('sized string allocation aliases active input')
        return result
    construct_sized_string_object(p,object_address=output,source_address=source,
        length=length,image_base=image_base,allocate=checked_allocate,max_payload_bytes=max_bytes)
    p.commit();return output


def apply_request_287474_memory_fill_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,max_bytes=0x100000):
    """+288AB4 tailcalls memset: target0/destination8/fillBYTE16/sizeQ24.

    Zero size does not access destination. Known packed/spill aliases reject;
    cross-page guest writes commit together. No packed result is stored.
    """
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('memory fill requires an aligned guest stack')
    if type(max_bytes) is not int or not 0<=max_bytes<=0x100000:
        raise RefillUnsupported('invalid memory fill byte bound')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('memory fill address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('memory fill aliases native spills')
    span(argument_block_address,32)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,32)
    target,output=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    fill=packed[16];length=int.from_bytes(packed[24:32],'little')
    if target!=image_base+0x347F20:raise RefillUnsupported('unexpected memory fill target')
    if length>max_bytes:raise RefillUnsupported('memory fill exceeds byte bound')
    if length:
        span(output,length)
        if output<argument_block_address+32 and argument_block_address<output+length:
            raise RefillUnsupported('memory fill output aliases packed input')
        _write_span(p,output,bytes([fill])*length)
    p.commit();return output


def apply_request_287474_flagged_cleanup_callback(pages, *, argument_block_address,
        entry_stack_address,image_base,free):
    """+288AC8 tailcalls +1B55F8; target0/receiver8, no packed result.

    Only a nonzero byte at receiver+24 invokes the existing string destructor.
    The flag is not cleared. Page rollback cannot undo external free effects;
    unknown allocation extents and native physical X0 remain outside this API.
    """
    from vm9_objects import destroy_string_object
    if (type(entry_stack_address) is not int or not 0x1000<=entry_stack_address<1<<64
            or entry_stack_address&15):
        raise RefillUnsupported('flagged cleanup requires an aligned guest stack')
    def span(a,n):
        if type(a) is not int or not 0<a<=(1<<64)-n:
            raise RefillUnsupported('flagged cleanup address wraps uint64')
        if a<entry_stack_address and a+n>entry_stack_address-0x1000:
            raise RefillUnsupported('flagged cleanup aliases native spills')
    span(argument_block_address,16)
    p=_PageTransaction(pages);packed=_read_span(p,argument_block_address,16)
    target,receiver=(int.from_bytes(packed[i:i+8],'little') for i in (0,8))
    if target!=image_base+0x1B55F8:raise RefillUnsupported('unexpected flagged cleanup target')
    span(receiver,25)
    if receiver<argument_block_address+16 and argument_block_address<receiver+25:
        raise RefillUnsupported('flagged cleanup receiver aliases packed input')
    if _read_span(p,receiver+24,1)[0]:
        if not callable(free):raise RefillUnsupported('active cleanup requires an explicit free provider')
        pointer=int.from_bytes(_read_span(p,receiver+16,8),'little')
        if pointer:
            span(pointer,1);_read_span(p,pointer,1)
            if any(a<=pointer<a+n for a,n in ((argument_block_address,16),(receiver,25))):
                raise RefillUnsupported('flagged cleanup payload aliases active input')
        def checked_free(tx,address):
            free(tx,address)
            if _read_span(tx,argument_block_address,16)!=packed:
                raise RefillUnsupported('flagged cleanup provider changed packed input')
        destroy_string_object(p,object_address=receiver,image_base=image_base,free=checked_free)
    p.commit();return receiver
