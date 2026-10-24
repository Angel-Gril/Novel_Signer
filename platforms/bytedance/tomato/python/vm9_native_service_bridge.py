"""Explicit external service bindings for the native verification runner.

Providers use the same page API as recovered Python components, backed by live
CPU memory. This module imports no native runner or Unicorn at import time.
It does not replace native JNI wrappers or implicitly map pages. An explicit
effect journal can roll back provider-owned effects when a hook fails.
"""
from collections.abc import MutableMapping
from dataclasses import dataclass
from vm9_allocator import RefillUnsupported
from vm9_effects import require_effect_journal

MASK64 = (1 << 64) - 1


def _page_address(page):
    if type(page) is not int or not 0 <= page < 1 << 52:
        raise RefillUnsupported('native page index must fit uint64')
    return page << 12


class _LivePage:
    def __init__(self, cpu, address):
        self.cpu, self.address = cpu, address

    def __len__(self):
        return 4096

    def __bytes__(self):
        return bytes(self.cpu.mem_read(self.address, 4096))

    def __iter__(self):
        return iter(bytes(self))

    def _span(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(4096)
            if step != 1:
                raise RefillUnsupported('native page slices require unit stride')
            return start, max(start, stop), False
        if type(key) is not int or not -4096 <= key < 4096:
            raise IndexError('native page byte index is out of range')
        start = key % 4096
        return start, start + 1, True

    def __getitem__(self, key):
        start, stop, scalar = self._span(key)
        raw = bytes(self.cpu.mem_read(self.address + start, stop - start))
        return raw[0] if scalar else raw

    def __setitem__(self, key, value):
        start, stop, scalar = self._span(key)
        raw = bytes([value]) if scalar else bytes(value)
        if len(raw) != stop - start:
            raise RefillUnsupported('native page writes cannot resize a page')
        if raw:
            self.cpu.mem_write(self.address + start, raw)


class LiveCpuPages(MutableMapping):
    """A write-through view of mapped guest pages; no implicit mapping."""
    def __init__(self, cpu):
        self.cpu = cpu

    def __contains__(self, page):
        address = _page_address(page)
        return any(start <= address and address + 4095 <= end
                   for start, end, _ in self.cpu.mem_regions())

    def __getitem__(self, page):
        address = _page_address(page)
        if page not in self:
            raise KeyError(page)
        return _LivePage(self.cpu, address)

    def __setitem__(self, page, value):
        address = _page_address(page)
        if page not in self:
            raise RefillUnsupported('native service cannot map guest pages')
        raw = bytes(value)
        if len(raw) != 4096:
            raise RefillUnsupported('native service requires a complete page')
        self.cpu.mem_write(address, raw)

    def __delitem__(self, page):
        raise RefillUnsupported('native service cannot unmap guest pages')

    def __iter__(self):
        for start, end, _ in self.cpu.mem_regions():
            yield from range(start >> 12, (end >> 12) + 1)

    def __len__(self):
        return sum((end >> 12) - (start >> 12) + 1
                   for start, end, _ in self.cpu.mem_regions())


@dataclass(frozen=True)
class NativeService:
    target: int
    arity: int
    invoke: object

    def __post_init__(self):
        if type(self.target) is not int or not 0 < self.target <= MASK64 or self.target & 3:
            raise RefillUnsupported('native service target must be aligned uint64')
        if type(self.arity) is not int or not 0 <= self.arity <= 8:
            raise RefillUnsupported('native service arity must fit X0 through X7')
        if not callable(self.invoke):
            raise RefillUnsupported('native service requires an explicit provider')


def _snapshot_cpu_regions(cpu):
    """Capture mapped CPU bytes for explicit provider-failure rollback."""
    regions = tuple(cpu.mem_regions())
    return tuple((start, end, perms, bytes(cpu.mem_read(start, end - start)))
                 for start, end, perms in regions), regions


def _restore_cpu_regions(cpu, snapshot, regions):
    if tuple(cpu.mem_regions()) != regions:
        raise RefillUnsupported('native provider changed CPU mappings; rollback is unavailable')
    for start, end, _perms, raw in snapshot:
        cpu.mem_write(start, raw)


def make_native_service_imports(bindings, *, image_base, effect_journal=None,
        rollback_pages=False):
    """Return native-runner imports; each provider gets (live_pages, fn, args).

    Callers explicitly map executable target pages and select the provider for
    each current JavaVM/JNI table entry. Unknown targets remain unsupported.
    Provider exceptions are re-raised. With ``effect_journal`` enabled, the
    provider's registered undo operations run on failure; with
    ``rollback_pages`` enabled, mapped CPU bytes are also restored. Mapping
    topology changes still fail closed because ``LiveCpuPages`` never maps or
    unmaps pages implicitly.
    """
    if type(image_base) is not int or not 0 <= image_base <= MASK64:
        raise RefillUnsupported('native service image base must fit uint64')
    effect_journal = require_effect_journal(effect_journal)
    if type(rollback_pages) is not bool:
        raise RefillUnsupported('native service rollback_pages must be boolean')
    bindings = tuple(bindings)
    if any(not isinstance(binding, NativeService) for binding in bindings):
        raise RefillUnsupported('native imports require declared service bindings')
    if len({binding.target for binding in bindings}) != len(bindings):
        raise RefillUnsupported('native service targets must be unique')
    from unicorn import arm64_const as arm
    imports = {}
    for binding in bindings:
        def call(cpu, binding=binding):
            if cpu.reg_read(arm.UC_ARM64_REG_PC) != binding.target:
                raise RefillUnsupported('native service hook target mismatch')
            args = tuple(cpu.reg_read(getattr(arm, 'UC_ARM64_REG_X' + str(i)))
                         for i in range(binding.arity))
            mark = effect_journal.checkpoint() if effect_journal is not None else None
            snapshot = regions = None
            if rollback_pages:
                snapshot, regions = _snapshot_cpu_regions(cpu)
            try:
                result = binding.invoke(LiveCpuPages(cpu), binding.target, args)
                if type(result) is not int or not -(1 << 63) <= result <= MASK64:
                    raise RefillUnsupported('native service result must fit its ABI word')
                return result & MASK64
            except BaseException as exc:
                rollback_error = None
                if effect_journal is not None:
                    try:
                        effect_journal.rollback(mark)
                    except BaseException as undo_error:
                        rollback_error = undo_error
                if rollback_pages:
                    try:
                        _restore_cpu_regions(cpu, snapshot, regions)
                    except BaseException as page_error:
                        if rollback_error is None:
                            rollback_error = page_error
                if rollback_error is not None:
                    raise rollback_error from exc
                raise
        imports[binding.target - image_base] = call
    return imports
