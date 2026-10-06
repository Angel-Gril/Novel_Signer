"""Input-driven configuration comparison, lookup and red-black insertion.

Matching guest image only. No native output, captured pages or decoded key
constants are supplied to these models. Allocation/free remain explicit
staged-page effects; their external ledgers are not rolled back with pages.
"""
from __future__ import annotations

from collections.abc import Callable
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span
import vm9_objects as objects


def construct_configuration_tree(pages, *, container_address: int, descriptor_address: int,
                                 image_base: int, allocate: Callable) -> int:
    """Model +0x25bf14 from caller-owned cleanup/comparator descriptor words."""
    transaction = _PageTransaction(pages)
    descriptor = tuple(int.from_bytes(_read_span(transaction, descriptor_address + i, 8), "little")
                       for i in (0, 8, 16))
    controller = objects._callback_container(transaction, container_address, descriptor,
        image_base, allocate, vtable_offset=0x35B7C0, hook_offset=0x24B560)
    transaction.commit()
    return controller


def compare_string_fields(pages, *, first_address: int, second_address: int,
                          max_bytes: int = 0x100000) -> int:
    """Model +0x2473dc, including invalid -32768 and equal-NUL early return."""
    objects._string_bound(max_bytes)
    if not first_address or not second_address:
        return -32768
    first = int.from_bytes(_read_span(pages, first_address + 8, 8), "little")
    if not first:
        return -32768
    second = int.from_bytes(_read_span(pages, second_address + 8, 8), "little")
    if not second:
        return -32768
    a = int.from_bytes(_read_span(pages, first_address + 4, 4), "little")
    if a & 0x80000000:
        return -32768
    b = int.from_bytes(_read_span(pages, second_address + 4, 4), "little")
    if b & 0x80000000:
        return -32768
    if a == b and (first == second or a == 0):
        return 0
    width = min(a, b)
    for offset in range(width):
        if offset >= max_bytes:
            raise RefillUnsupported("configuration comparison exceeds the explicit byte bound")
        x = _read_span(pages, first + offset, 1)[0]
        y = _read_span(pages, second + offset, 1)[0]
        if x != y:
            return x - y
        if not x:
            return 0
    return 1 if a > b else -1 if b > a else 0


def compare_string_objects(pages, *, first_address: int, second_address: int,
                           max_bytes: int = 0x100000) -> int:
    """Model +0x188a94's nullable string-object to fields adapter."""
    return compare_string_fields(pages, first_address=first_address + 8 if first_address else 0,
        second_address=second_address + 8 if second_address else 0, max_bytes=max_bytes)


class _ConfigurationTree:
    def __init__(self, pages, container, image_base, max_nodes, max_bytes):
        if not isinstance(max_nodes, int) or not 1 <= max_nodes <= 0x100000:
            raise ValueError("invalid configuration tree node bound")
        self.pages, self.container, self.base = pages, container, image_base
        self.limit, self.byte_limit = max_nodes, max_bytes
        objects._string_bound(max_bytes)
        address = lambda offset: objects._image_address(image_base, offset)
        if self.u64(container) != address(0x35B7C0) or self.u64(container + 24) != address(0x188A94):
            raise RefillUnsupported("unknown configuration container/comparator")
        self.controller = self.u64(container + 32)
        if (self.u64(self.controller + 16) != address(0x188A94)
                or self.u64(self.controller + 24) != address(0x24B560)):
            raise RefillUnsupported("unknown configuration tree callback/hook")
        self.sentinel = self.u64(self.controller)
        count = self.u64(self.controller + 8)
        if count > max_nodes or not self.sentinel:
            raise RefillUnsupported("configuration tree exceeds the explicit node bound")
        if not count and (self.u64(self.sentinel + 8) or self.u64(self.sentinel + 16) != self.sentinel
                          or self.u64(self.sentinel + 24) != self.sentinel):
            raise RefillUnsupported("inconsistent empty configuration tree")

    def u64(self, address):
        return int.from_bytes(_read_span(self.pages, address, 8), "little")

    def put(self, address, value):
        _write_span(self.pages, address, objects._word(value))

    def color(self, node):
        value = int.from_bytes(_read_span(self.pages, node, 4), "little")
        if value not in (0, 1):
            raise RefillUnsupported("unknown configuration node color")
        return value

    def paint(self, node, color):
        _write_span(self.pages, node, color.to_bytes(4, "little"))

    def pair_key(self, pair):
        return self.u64(pair)

    def key(self, node):
        return self.pair_key(self.u64(node + 32))

    def compare(self, first, second):
        return compare_string_objects(self.pages, first_address=first, second_address=second,
                                      max_bytes=self.byte_limit)

    def visit(self, seen, node):
        if node in seen or len(seen) >= self.limit:
            raise RefillUnsupported("cyclic or excessive configuration tree traversal")
        seen.add(node)

    def lower_bound(self, key):
        candidate, node, seen = self.sentinel, self.u64(self.sentinel + 8), set()
        while node:
            self.visit(seen, node)
            less = self.compare(self.key(node), key) < 0
            if not less:
                candidate = node
            node = self.u64(node + (24 if less else 16))
        return candidate

    def find(self, key):
        candidate = self.lower_bound(key)
        return self.sentinel if candidate == self.sentinel or self.compare(key, self.key(candidate)) < 0 else candidate

    def predecessor(self, node):
        seen = set()
        left = self.u64(node + 16)
        if left:
            node = left
            while self.u64(node + 24):
                self.visit(seen, node)
                node = self.u64(node + 24)
            return node
        parent = self.u64(node + 8)
        while self.u64(parent + 16) == node:
            self.visit(seen, node)
            node, parent = parent, self.u64(parent + 8)
        return parent

    def rotate(self, node, *, left):
        child_offset, inner_offset = (24, 16) if left else (16, 24)
        child = self.u64(node + child_offset)
        if not child:
            raise RefillUnsupported("configuration rotation lacks a child")
        inner = self.u64(child + inner_offset)
        self.put(node + child_offset, inner)
        if inner:
            self.put(inner + 8, node)
        parent = self.u64(node + 8)
        self.put(child + 8, parent)
        if self.u64(self.sentinel + 8) == node:
            self.put(self.sentinel + 8, child)
        else:
            self.put(parent + (16 if self.u64(parent + 16) == node else 24), child)
        self.put(child + inner_offset, node)
        self.put(node + 8, child)

    def rebalance(self, node):
        self.paint(node, 0)
        for _ in range(self.limit + 1):
            root = self.u64(self.sentinel + 8)
            if node == root:
                self.paint(node, 1)
                return
            parent = self.u64(node + 8)
            if self.color(parent):
                self.paint(root, 1)
                return
            grand = self.u64(parent + 8)
            parent_left = self.u64(grand + 16) == parent
            uncle = self.u64(grand + (24 if parent_left else 16))
            if uncle and self.color(uncle) == 0:
                self.paint(parent, 1)
                self.paint(uncle, 1)
                node = grand
                self.paint(node, 0)
                continue
            inner = self.u64(parent + (24 if parent_left else 16))
            if inner == node:
                self.rotate(parent, left=parent_left)
                node = parent
                parent = self.u64(node + 8)
                grand = self.u64(parent + 8)
            self.paint(parent, 1)
            self.paint(grand, 0)
            self.rotate(grand, left=not parent_left)
        raise RefillUnsupported("configuration rebalance exceeds the explicit node bound")

    def insert_pair(self, pair, allocate):
        parent, node, left, seen = self.sentinel, self.u64(self.sentinel + 8), True, set()
        while node:
            self.visit(seen, node)
            left = self.compare(self.pair_key(pair), self.key(node)) < 0
            parent, node = node, self.u64(node + (16 if left else 24))
        candidate = parent
        if left and candidate != self.u64(self.sentinel + 16):
            candidate = self.predecessor(candidate)
        elif left:
            candidate = 0
        if candidate and self.compare(self.key(candidate), self.pair_key(pair)) >= 0:
            return candidate, False
        if self.u64(self.controller + 8) >= self.limit:
            raise RefillUnsupported("configuration insertion exceeds the explicit node bound")
        # +0x24bf54 chooses its side BEFORE malloc, then reloads tree links.
        left = parent == self.sentinel or self.compare(self.pair_key(pair), self.key(parent)) < 0
        created = objects._allocate(self.pages, allocate, 40)
        self.paint(created, 0)
        _write_span(self.pages, created + 8, bytes(32))
        self.put(created + 32, pair)
        self.put(parent + (16 if left else 24), created)
        sentinel = self.u64(self.controller)
        if left:
            if parent == sentinel:
                self.put(parent + 8, created)
                self.put(sentinel + 24, created)
            elif self.u64(sentinel + 16) == parent:
                self.put(sentinel + 16, created)
        elif self.u64(sentinel + 24) == parent:
            self.put(sentinel + 24, created)
        _write_span(self.pages, created + 16, bytes(16))
        self.put(created + 8, parent)
        self.sentinel = self.u64(self.controller)
        self.rebalance(created)
        self.put(self.controller + 8, (self.u64(self.controller + 8) + 1) & ((1 << 64) - 1))
        return created, True


def lookup_configuration_value(pages, *, container_address: int, key_address: int,
                               image_base: int, max_nodes: int = 4096,
                               max_bytes: int = 0x100000) -> int:
    """Model +0x25c168/+0x24b960; return the value pointer or zero."""
    tree = _ConfigurationTree(pages, container_address, image_base, max_nodes, max_bytes)
    node = tree.find(key_address)
    if node == tree.sentinel:
        return 0
    # +0x24b960 repeats compare(query, candidate) after +0x24c4fc.
    if tree.compare(key_address, tree.key(node)) < 0:
        return 0
    return tree.u64(tree.u64(node + 32) + 8)


def insert_configuration_pair(pages, *, container_address: int, key_address: int,
                              value_address: int, image_base: int, allocate: Callable,
                              free: Callable, max_nodes: int = 4096,
                              max_bytes: int = 0x100000) -> int:
    """Model +0x25bf3c: transferred key/value, pair allocation and RB insertion.

    Duplicate keys destroy the incoming string object and free the old u32
    value before replacing its pointer. Supported cleanup callbacks are
    +0x182d6c (string delete) / +0x165334 (raw free). Native's insertion-time
    duplicate after allocator mutation retains its newly allocated pair.
    Return the resulting pair address, not the unspecified native X0.
    """
    transaction = _PageTransaction(pages)
    tree = _ConfigurationTree(transaction, container_address, image_base, max_nodes, max_bytes)
    node = tree.find(key_address)
    if node != tree.sentinel:
        pair = tree.u64(node + 32)
        if (tree.u64(container_address + 8) != objects._image_address(image_base, 0x182D6C)
                or tree.u64(container_address + 16) != objects._image_address(image_base, 0x165334)):
            raise RefillUnsupported("unknown configuration pair cleanup callbacks")
        objects.destroy_string_object(transaction, object_address=key_address, image_base=image_base,
                                      free=free, delete_object=True)
        free(transaction, tree.u64(pair + 8))
        tree.put(pair + 8, value_address)
    else:
        pair = objects._allocate(transaction, allocate, 16)
        tree.put(pair, key_address)
        tree.put(pair + 8, value_address)
        node, _ = tree.insert_pair(pair, allocate)
        pair = tree.u64(node + 32)
    transaction.commit()
    return pair


def set_configuration_u32(pages, *, registry_address: int, key_address: int, value: int,
                          entry_stack_address: int, image_base: int, allocate: Callable,
                          free: Callable, get_tls: Callable, initialize_registry: Callable,
                          broadcast: Callable, max_nodes: int = 4096,
                          max_bytes: int = 0x100000) -> int:
    """Model +0x2568c8, including the actual scoped writer acquire/release.

    Return the previous u32 or native missing-key marker 0x000a985f. A missing
    key clones the caller's string; an existing key retains its original
    key/value objects. Stack input supplies the guard and copied TLS padding.
    TLS resolution/initialization and condition wake are explicit boundaries.
    Contention and multiple live TLS mutex entries reject in the scoped model.
    """
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("configuration value must be a u32")
    transaction = _PageTransaction(pages)
    guard = entry_stack_address - 0x60
    objects.construct_single_scoped_lock(transaction, object_address=guard,
        mutex_address=registry_address + 0x80, scratch_address=guard - 0x48,
        image_base=image_base, allocate=allocate, get_tls=get_tls,
        initialize_registry=initialize_registry)
    pointer = lookup_configuration_value(transaction, container_address=registry_address + 8,
        key_address=key_address, image_base=image_base, max_nodes=max_nodes, max_bytes=max_bytes)
    if pointer:
        previous = int.from_bytes(_read_span(transaction, pointer, 4), "little")
        _write_span(transaction, pointer, value.to_bytes(4, "little"))
    else:
        key = objects._allocate(transaction, allocate, 24)
        objects.clone_string_object(transaction, object_address=key, source_object_address=key_address,
            image_base=image_base, allocate=allocate, max_payload_bytes=max_bytes)
        pointer = objects._allocate(transaction, allocate, 4)
        _write_span(transaction, pointer, value.to_bytes(4, "little"))
        insert_configuration_pair(transaction, container_address=registry_address + 8,
            key_address=key, value_address=pointer, image_base=image_base,
            allocate=allocate, free=free, max_nodes=max_nodes, max_bytes=max_bytes)
        previous = 0xA985F
    objects.destroy_single_scoped_lock(transaction, object_address=guard, image_base=image_base,
        free=free, get_tls=get_tls, initialize_registry=initialize_registry, broadcast=broadcast,
        entry_stack_address=guard)
    transaction.commit()
    return previous


def construct_registry320(pages, *, object_address: int, entry_stack_address: int,
                          image_base: int, allocate: Callable, free: Callable,
                          read_clock: Callable, get_tls: Callable,
                          initialize_registry: Callable, broadcast: Callable,
                          max_nodes: int = 4096, max_bytes: int = 0x100000):
    """Model +0x2566ec through return with explicit realtime/TLS boundaries.

    The three containers, mutex, empty string, clock reference, initial config
    insertion and temporary string cleanup are all included. This constructor
    does not publish the +0x15e694 lazy singleton or supply process startup.
    Caller-owned stack padding remains an input, including during malloc.
    """
    transaction = _PageTransaction(pages)
    layout = objects.construct_registry_layout320(transaction, object_address=object_address,
                                                  image_base=image_base, allocate=allocate)
    objects.construct_registry_clock_reference(transaction, object_address=object_address + 0x130,
                                               allocate=allocate, read_clock=read_clock)
    _write_span(transaction, object_address + 0x138, bytes(4))
    temporary = entry_stack_address - 0xF0
    objects.construct_string_object(transaction, object_address=temporary,
        source_address=objects._image_address(image_base, 0x3DE690), allocate=allocate,
        vtable_address=objects._image_address(image_base, 0x34F5F8),
        empty_descriptor_address=objects._image_address(image_base, 0x6E168), max_source_bytes=max_bytes)
    set_configuration_u32(transaction, registry_address=object_address, key_address=temporary,
        value=1, entry_stack_address=temporary, image_base=image_base, allocate=allocate, free=free,
        get_tls=get_tls, initialize_registry=initialize_registry, broadcast=broadcast,
        max_nodes=max_nodes, max_bytes=max_bytes)
    objects.destroy_string_object(transaction, object_address=temporary, image_base=image_base, free=free)
    transaction.commit()
    return layout


def get_registry320_reference(pages, *, entry_stack_address: int, image_base: int,
                              allocate: Callable, free: Callable, read_clock: Callable,
                              get_tls: Callable, initialize_registry: Callable,
                              broadcast: Callable, thread_id: int | None = None,
                              max_nodes: int = 4096, max_bytes: int = 0x100000):
    """Model +0x15e694 with the verified serialized lazy-reference contract.

    Guard/slot are +0x3d1558/+0x3d1550. Cold initialization owns the complete
    registry body, then its reference count and publication. This uses the
    existing successful single-thread guard boundary, not host synchronization.
    """
    def initialize(staged, pointer):
        construct_registry320(staged, object_address=pointer, entry_stack_address=entry_stack_address - 0x20,
            image_base=image_base, allocate=allocate, free=free, read_clock=read_clock,
            get_tls=get_tls, initialize_registry=initialize_registry, broadcast=broadcast,
            max_nodes=max_nodes, max_bytes=max_bytes)
    transaction = _PageTransaction(pages)
    result = objects.construct_lazy_reference(transaction,
        guard_address=objects._image_address(image_base, 0x3D1558),
        slot_address=objects._image_address(image_base, 0x3D1550), payload_size=320,
        allocate=allocate, initialize_payload=initialize, thread_id=thread_id)
    if result.payload_address:
        # Matching bionic pthread_mutex_unlock (+0x68d5c) saves the guard
        # release frame pointer here. A subsequent setter at the same caller
        # SP copies its upper seven bytes into its TLS pair. Derive the value
        # from caller SP; never inject bytes captured after a native call.
        _write_span(transaction, entry_stack_address - 0xA0, objects._word(entry_stack_address - 0x50))
    transaction.commit()
    return result


def construct_singleton136(pages, *, object_address: int, entry_stack_address: int,
                           image_base: int, allocate: Callable, free: Callable,
                           read_clock: Callable, get_tls: Callable,
                           initialize_registry: Callable, broadcast: Callable,
                           thread_id: int | None = None, max_nodes: int = 4096,
                           max_bytes: int = 0x100000, allocate_at_stack: Callable | None = None):
    """Model +0x166370 through return, including five actual registry getters.

    Each getter resolves/publishes its dependency in order; five decoded ELF
    keys register the u32 fields at +68/+70/+78/+7c/+50. Temporary strings
    are cleaned after every setter, then object+8 receives completion state 2.
    No decoded keys or native constructor outputs are embedded in this model.
    """
    transaction = _PageTransaction(pages)
    layout = objects.construct_singleton_layout136(transaction, object_address=object_address,
                                                  image_base=image_base, allocate=allocate,
        entry_stack_address=entry_stack_address,allocate_at_stack=allocate_at_stack)
    current_stack = entry_stack_address - 0x100
    common = dict(image_base=image_base, allocate=allocate, free=free, read_clock=read_clock,
        get_tls=get_tls, initialize_registry=initialize_registry, broadcast=broadcast,
        thread_id=thread_id, max_nodes=max_nodes, max_bytes=max_bytes)
    for index, (source, field) in enumerate(((0x3D1690, 0x68), (0x3D16C0, 0x70),
                                          (0x3D16F0, 0x78), (0x3D1720, 0x7C), (0x3D1750, 0x50))):
        reference = get_registry320_reference(transaction, entry_stack_address=current_stack, **common)
        dependency = int.from_bytes(_read_span(transaction, reference.wrapper_address, 8), "little")
        temporary = entry_stack_address - 0x80 - index * 0x20
        objects.construct_string_object(transaction, object_address=temporary,
            source_address=objects._image_address(image_base, source), allocate=allocate,
            vtable_address=objects._image_address(image_base, 0x34F5F8),
            empty_descriptor_address=objects._image_address(image_base, 0x6E168), max_source_bytes=max_bytes)
        value = int.from_bytes(_read_span(transaction, object_address + field, 4), "little")
        set_configuration_u32(transaction, registry_address=dependency, key_address=temporary, value=value,
            entry_stack_address=current_stack, image_base=image_base, allocate=allocate, free=free,
            get_tls=get_tls, initialize_registry=initialize_registry, broadcast=broadcast,
            max_nodes=max_nodes, max_bytes=max_bytes)
        objects.destroy_string_object(transaction, object_address=temporary, image_base=image_base, free=free)
    _write_span(transaction, object_address + 8, (2).to_bytes(4, "little"))
    transaction.commit()
    return layout


def get_singleton136_reference(pages, *, entry_stack_address: int, image_base: int,
                               allocate: Callable, free: Callable, read_clock: Callable,
                               get_tls: Callable, initialize_registry: Callable,
                               broadcast: Callable, thread_id: int | None = None,
                               max_nodes: int = 4096, max_bytes: int = 0x100000, allocate_at_stack: Callable | None = None):
    """Model +0x161068; publish only after its complete constructor body."""
    def initialize(staged, pointer):
        construct_singleton136(staged, object_address=pointer, entry_stack_address=entry_stack_address - 0x20,
            image_base=image_base, allocate=allocate, free=free, read_clock=read_clock,
            get_tls=get_tls, initialize_registry=initialize_registry, broadcast=broadcast,
            thread_id=thread_id, max_nodes=max_nodes, max_bytes=max_bytes,allocate_at_stack=allocate_at_stack)
    transaction = _PageTransaction(pages)
    result = objects.construct_lazy_reference(transaction,
        guard_address=objects._image_address(image_base, 0x3D1680),
        slot_address=objects._image_address(image_base, 0x3D1678), payload_size=136,
        allocate=allocate, initialize_payload=initialize, thread_id=thread_id)
    if result.payload_address:
        _write_span(transaction, entry_stack_address - 0xA0, objects._word(entry_stack_address - 0x50))
    transaction.commit()
    return result
