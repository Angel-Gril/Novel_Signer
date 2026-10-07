"""Fresh request VM helper through shared-reader/string-copy callbacks.

Only +0x256ed4 / VM +0x99020's normal string getter is covered. The caller
provides initialized reader/string state and allocation; there is no JVM,
URL/headers/JNI conversion, native callback execution, or Medusa output here.
"""
from __future__ import annotations

from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
from vm9_request_caller import prepare_request_vm_caller
from vm9_request_dispatcher import prepare_request_dispatch_frame
from vm9_request_nested import execute_request_nested_prefix, movhi_request_word, ori_request_word
import vm9_objects as objects

MASK64 = (1 << 64) - 1


class _BackingRegisters:
    """VM slots own their guest bytes, including indirect stores into slots."""

    def __init__(self, pages, base):
        self.pages, self.base = pages, base

    def __len__(self):
        return 32

    def __getitem__(self, index):
        if not isinstance(index, int) or not 0 <= index < 32:
            raise IndexError(index)
        return int.from_bytes(_read_span(self.pages, self.base + index * 8, 8), "little")

    def __setitem__(self, index, value):
        if not isinstance(index, int) or not 0 <= index < 32:
            raise IndexError(index)
        _write_span(self.pages, self.base + index * 8, (value & MASK64).to_bytes(8, "little"))

    def __iter__(self):
        return (self[index] for index in range(32))


def nested_getter_inputs_from_request(pages, *, request_frame,
                                     callback_argument_address,
                                     thread_pointer, image_base):
    """Decode +0x285978's packed ABI and derive the existing VM frame.

    The native wrapper loads x9/x8 from arg[0:16], x0 from arg+16 and
    pushes one 16-byte LR frame. The generic VM's physical SP, x29,
    x28 and x19 come from the request caller frame. This derives inputs;
    it does not model the wrapper/whole caller's native epilogue.
    """
    packed = _read_span(pages, callback_argument_address, 24)
    function, output, receiver = (int.from_bytes(packed[i:i + 8], "little")
                                  for i in (0, 8, 16))
    if function != image_base + 0x256ED4:
        raise RefillUnsupported("request string getter wrapper has an unknown target")
    return dict(image_base=image_base, object_address=receiver,
                preserved_x8=output, return_address=image_base + 0x285988,
                entry_stack_address=request_frame.native_stack_address - 0x190,
                saved_frame_pointer=request_frame.native_stack_address - 0x60,
                saved_x28=request_frame.register_backing_address,
                saved_x19=request_frame.register_backing_address - 8,
                thread_pointer=thread_pointer)


def execute_nested_string_getter(pages, inputs, vm_module, *, allocate,
                                 max_vm_steps=256, max_payload_bytes=0x100000):
    """Compose the fresh caller/prefix and normal acquire -> clone -> release.

    The existing semantic VM runs only the remaining +0x99058..+0x99150
    words. Its virtual register file is backed by the same staged guest pages;
    a list copied from a native snapshot is never used. Callback inputs and
    slot states are recorded for comparison, not injected from oracle output.

    Guest changes publish only after VM exit and all three callbacks. External
    allocator state belongs to its provider; this function does not promise
    to roll back an arbitrary provider's allocation side effects.
    """
    if not isinstance(max_vm_steps, int) or max_vm_steps < 1:
        raise RefillUnsupported("nested string getter budget must be positive")
    if not isinstance(max_payload_bytes, int) or not 0 <= max_payload_bytes <= 0x100000:
        raise RefillUnsupported("nested string payload bound is invalid")
    if not callable(allocate):
        raise RefillUnsupported("nested string getter requires an explicit allocator")
    image = inputs["image_base"]
    object_address = inputs["object_address"]
    output_address = inputs["preserved_x8"]
    staged = _PageTransaction(pages)
    _read_span(staged, output_address, 24)
    # Verify the declared source before using a potentially stateful allocator.
    source = object_address + 0x118
    length = int.from_bytes(_read_span(staged, source + 12, 4), "little")
    if length < 0x80000000:
        if length > max_payload_bytes:
            raise RefillUnsupported("nested string source exceeds the payload bound")
        pointer = int.from_bytes(_read_span(staged, source + 16, 8), "little")
        _read_span(staged, pointer, length)
    caller = prepare_request_vm_caller(staged, **inputs)
    frame = prepare_request_dispatch_frame(entry_stack_address=inputs["entry_stack_address"],
                                           image_base=image)
    first = execute_request_nested_prefix(staged, frame)
    common = dict(image_base=image, x19=frame.x19, x20=frame.x20,
                  x22=frame.x22, x23=frame.x23, x28=frame.x28, x29=frame.x29, x30=frame.x30)
    movhi = movhi_request_word(staged, **common)
    if movhi["next_handler_offset"] != 0x16E32C:
        raise RefillUnsupported("nested string getter did not select ORi")
    ori = ori_request_word(staged, **common)
    if ori["next_handler_offset"] != 0x16F8E0:
        raise RefillUnsupported("nested string getter did not select LOAD64")
    callbacks, word_trace = [], []

    class StrictMem(vm_module.Mem):
        def __init__(self):
            self.pages = staged

        def _pg(self, address):
            if address >> 12 not in self.pages:
                raise RefillUnsupported(f"unmapped nested string getter address {address:#x}")
            return self.pages[address >> 12]

    previous_base = vm_module.B
    try:
        vm_module.B = image
        vm = vm_module.VM(StrictMem(), 0x99020, caller.packed_arguments_address,
                         image + 0x35B650, image + 0x35B660, image + 0x257050,
                         inputs["return_address"], maxsteps=max_vm_steps)
        vm.pc = int.from_bytes(_read_span(staged, frame.x19, 8), "little")
        vm.R = _BackingRegisters(staged, frame.x28)
        vm.register_backing_base = frame.x28

        def step(vm, word, op, sub):
            if not image + 0x99058 <= vm.pc <= image + 0x99150:
                raise RefillUnsupported("nested string getter left the verified VM range")
            _write_span(staged, frame.x19, vm.pc.to_bytes(8, "little"))
            word_trace.append({"pc": vm.pc, "word": word, "op": op, "sub": sub})

        def callback(vm, function, argument):
            index = len(callbacks)
            wrapper = function - image
            target = int.from_bytes(_read_span(staged, argument, 8), "little")
            first_arg = int.from_bytes(_read_span(staged, argument + 8, 8), "little")
            reader = object_address + 0x88
            if index == 0 and (wrapper, target, first_arg) == (0x25705C, image + 0x32A444, reader):
                words = (target, first_arg)
                kind = "acquire"
            elif index == 1 and (wrapper, target, first_arg) == (0x257068, image + 0x2483E0, output_address):
                second_arg = int.from_bytes(_read_span(staged, argument + 16, 8), "little")
                if second_arg != source:
                    raise RefillUnsupported("nested string clone has an unexpected source")
                words = (target, first_arg, second_arg)
                kind = "clone"
            elif index == 2 and (wrapper, target, first_arg) == (0x25705C, image + 0x32A4FC, reader):
                words = (target, first_arg)
                kind = "release"
            else:
                raise RefillUnsupported(f"unknown nested string callback +{wrapper:#x} -> {target:#x}")
            entry = {"kind": kind, "wrapper_offset": wrapper, "target_offset": target - image,
                     "argument_address": argument, "words": words,
                     "registers": tuple(vm.R), "vm_pc": vm.pc, "vm_step": vm.steps}
            if kind == "acquire":
                entry["reader_count"] = objects.acquire_uncontended_shared_reader(staged,
                    mutex_address=reader)
            elif kind == "clone":
                entry["result"] = objects.clone_string_object(staged,
                    object_address=output_address, source_object_address=source,
                    allocate=allocate, image_base=image, max_payload_bytes=max_payload_bytes)
            else:
                entry["reader_count"] = objects.release_uncontended_shared_reader(staged,
                    mutex_address=reader)
            callbacks.append(entry)

        vm.step_hook = step
        vm.native_hook = callback
        try:
            vm.run()
        except vm_module.VMExit:
            if len(callbacks) != 3 or vm.pc != image + 0x99150:
                raise RefillUnsupported("nested string getter exited before the verified return")
        except RuntimeError as error:
            if str(error).startswith("step limit @"):
                raise RefillUnsupported("nested string getter VM budget exhausted") from error
            raise
        else:
            raise RefillUnsupported("nested string getter did not exit")
        registers = tuple(vm.R)
        staged.commit()
        return {"frame": frame, "caller": caller, "prefix": first, "movhi": movhi, "ori": ori,
                "callbacks": callbacks, "word_trace": word_trace,
                "vm_steps": vm.steps, "vm_exit_pc": vm.pc, "registers": registers,
                "output_address": output_address, "source_address": source,
                "declared_length": length, "native_input_snapshot_used": False}
    finally:
        vm_module.B = previous_base
