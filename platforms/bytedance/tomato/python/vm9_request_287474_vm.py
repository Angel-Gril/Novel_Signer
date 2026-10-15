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
                    (0x2884CC,0x2481AC),(0x2884CC,0x2484B8),
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
            elif consumer_services is not None and (wrapper,target)==(0x288670,0x257880):
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
            elif consumer_services is not None and (wrapper,target)==(0x28880C,0x248908):
                output=apply_request_287474_string_format_callback(staged,argument_block_address=argument,
                    entry_stack_address=frame.native_stack_address-0x180,image_base=image,
                    allocate=consumer_services['allocate'],reallocate=consumer_services.get('reallocate'),
                    free=consumer_services['free'],prepare_format=consumer_services.get('prepare_format'))
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
    elif pair==(0x2884CC,0x2484B8):
        result=objects.destroy_string_object(p,object_address=destination,
            image_base=image_base,free=free)
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
    """+288670 -> +257880: store cached W0 at packed+16; retain +20 padding."""
    from vm9_registry import read_configuration_cached_u32
    transaction = _PageTransaction(pages)
    def word(offset):return int.from_bytes(_read_span(transaction,argument_block_address+offset,8),'little')
    target,receiver=word(0),word(8)
    if target!=image_base+0x257880:
        raise RefillUnsupported('unexpected second configuration cached value target')
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
        entry_stack_address,image_base,allocate,reallocate,free,prepare_format=None,max_bytes=0x100000):
    """+28880c tail-calls the existing formatter with one zero-extended W2.

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
    p=_PageTransaction(pages);raw=_read_span(p,argument_block_address,28)
    target=int.from_bytes(raw[:8],'little');output=int.from_bytes(raw[8:16],'little')
    fmt=int.from_bytes(raw[16:24],'little');value=int.from_bytes(raw[24:28],'little')
    if target!=image_base+0x248908:raise RefillUnsupported('unexpected second string format target')
    for address,width in ((argument_block_address,28),(output,24),(fmt,1),(value,1)):
        if address<entry_stack_address and address+width>entry_stack_address-0x1000:
            raise RefillUnsupported('string format input aliases unmodeled native spills')
    result=format_string_object(p,object_address=output,format_address=fmt,argument_addresses=(value,),
        image_base=image_base,allocate=allocate,reallocate=reallocate,free=free,
        prepare_format=prepare_format,max_bytes=max_bytes)
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
