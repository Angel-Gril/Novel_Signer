"""Matching-libc guest thread exit with explicit allocator, TLS and OS services.

This models the observed libc state machine, not a host pthread runtime.
Successful whole-mapping munmap removes pages from the explicit GuestOS owner.
Actual concurrency, allocator boot and unspecified destructor bodies reject.
"""
from __future__ import annotations
from dataclasses import dataclass
from vm9_allocator import _PageTransaction, _read_span, _write_span, RefillUnsupported
import vm9_objects as objects
import vm9_startup as startup


def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')
def _w(p,a,v,n=8):_write_span(p,a,(v&((1<<(n*8))-1)).to_bytes(n,'little'))
def _bound(value):
    if not isinstance(value,int) or not 1<=value<=4096:raise ValueError('invalid thread destructor bound')


def register_libc_thread_destructor(pages, *, function_address, object_address,
        dso_address, libc_base, allocate, get_tls):
    """Matching libc +0x6b23c: 32-byte node, actual emutls head descriptor."""
    p=_PageTransaction(pages);node=objects._allocate(p,allocate,32)
    _w(p,node,function_address);_w(p,node+8,object_address)
    _w(p,node+16,dso_address);_w(p,node+24,0)
    head=get_tls(p,libc_base+0xdb3a8)
    _w(p,node+24,_u(p,head));_w(p,head,node)
    p.commit();return 0


def finalize_libc_thread_destructors(pages, *, libc_base, get_tls, invoke,
        free, max_nodes=64):
    """+0x6b2a4: pop before actual callback, free, then re-read head.

    The DSO field is stored by registration but not consulted in this body.
    Unknown callbacks must be rejected by invoke, never replaced with RET.
    """
    _bound(max_nodes);p=_PageTransaction(pages);head=get_tls(p,libc_base+0xdb3a8);count=0
    while _u(p,head):
        if count>=max_nodes:raise RefillUnsupported('libc thread destructor bound exceeded')
        node=_u(p,head);_w(p,head,_u(p,node+24))
        invoke(p,_u(p,node),_u(p,node+8));free(p,node);count+=1
    p.commit();return count


def run_thread_cleanup_handlers(pages, *, thread_address, invoke, max_nodes=64):
    """pthread_exit +0x68158: [next,function,argument], no node free."""
    _bound(max_nodes);p=_PageTransaction(pages);count=0;slot=thread_address+0x58
    while _u(p,slot):
        if count>=max_nodes:raise RefillUnsupported('pthread cleanup handler bound exceeded')
        node=_u(p,slot);_w(p,slot,_u(p,node))
        invoke(p,_u(p,node+8),_u(p,node+16));count+=1
    p.commit();return count


def unlink_detached_thread(pages, *, thread_address, libc_base):
    """+0x6837c serialized thread-list unlink under the actual list mutex.

    Thread links are [next,previous]; native re-reads both after the first
    neighbor write. The thread's own links are retained. No host concurrency.
    """
    p=_PageTransaction(pages);mutex=libc_base+0xe01d0
    objects.lock_uncontended_mutex(p,mutex_address=mutex)
    following=_u(p,thread_address)
    if following:_w(p,following+8,_u(p,thread_address+8))
    following=_u(p,thread_address);previous=_u(p,thread_address+8)
    if previous:_w(p,previous,following)
    else:_w(p,libc_base+0xe01f8,following)
    objects.unlock_uncontended_mutex(p,mutex_address=mutex);p.commit()


@dataclass(frozen=True)
class GuestThreadExitResult:
    libc_destructors: int
    cleanup_handlers: int
    detached: bool
    unlinked: bool
    unmapped_regions: int
    terminal_exit_code: int = 0
    host_thread_terminated: bool = False


def _run_pthread_exit(tx, *, image_base, libc_base, thread_pointer,
        return_value, get_libc_tls, free, os_call, invoke=None,
        set_specific=None, get_image_tls=None, broadcast=None,
        invoke_shared=None, join_thread=None, max_nodes=64):
    """Full observed +0x68138 body under explicit serialized guest services.

    os_call(pages, operation, *fields) supplies effects/return values. Fields
    are ABI values, not host pointers: sigaltstack(sp=0,flags=2), munmap,
    set_tid_address(0), sigprocmask(how=2,mask=~0,old=0,size=8), exit(0).
    Native ignores these returns. A nonnegative munmap result releases one
    complete owned mapping; negative results preserve it. Errors may update
    guest errno through the provider. exit is a terminal guest event, never a
    real host termination. GuestOS/page effects roll back on rejection;
    external provider effects cannot be undone.
    """
    _bound(max_nodes)
    if not isinstance(return_value,int) or not 0<=return_value<1<<64:
        raise RefillUnsupported('pthread exit return value outside guest ABI')
    p=tx.pages
    def dispatch(staged,function,argument):
        if function in (image_base+0x268cf0,image_base+0x326984):
            startup.invoke_registered_thread_destructor(staged,function_address=function,
                object_address=argument,image_base=image_base,free=free,join_thread=join_thread)
        elif invoke is not None:invoke(staged,function,argument)
        else:raise RefillUnsupported('unrecovered libc/pthread registered callback')
    cxa=finalize_libc_thread_destructors(p,libc_base=libc_base,
        get_tls=get_libc_tls,invoke=dispatch,free=free,max_nodes=max_nodes)
    thread=_u(p,thread_pointer+8);_w(p,thread+0x70,return_value)
    handlers=run_thread_cleanup_handlers(p,thread_address=thread,invoke=dispatch,max_nodes=max_nodes)
    startup.run_worker_thread_key_cleanup(p,image_base=image_base,thread_pointer=thread_pointer,
        generation_table=libc_base+0xe0200,free=free,set_specific=set_specific,
        get_tls=get_image_tls,invoke_destructor=dispatch,broadcast=broadcast,invoke_shared=invoke_shared,join_thread=join_thread)
    unmapped=0
    def call(operation,*fields):
        result=os_call(p,operation,*fields)
        if not isinstance(result,int) or not -(1<<63)<=result<1<<64:
            raise RefillUnsupported('invalid guest OS service result')
        return result-(1<<64) if result>=1<<63 else result
    def unmap(address,length):
        nonlocal unmapped
        if call('munmap',address,length)>=0:
            tx.unmap_exact(address,length);unmapped+=1
    alternate=_u(p,thread+0x78)
    if alternate:
        call('sigaltstack',0,2);unmap(alternate,0x5000);_w(p,thread+0x78,0)
    # Serialized strong CAS: compare zero, publish EXITED=1; DETACHED=3
    # reaches removal. Other states exit without removing or reclaiming.
    state=_u(p,thread+0x50,4)
    if state==0:_w(p,thread+0x50,1,4)
    detached=state==3
    if detached:
        call('set_tid_address',0)
        unlink_detached_thread(p,thread_address=thread,libc_base=libc_base)
        size=_u(p,thread+0xa8)
        if size:
            call('sigprocmask',2,(1<<64)-1,0,8)
            address=_u(p,thread+0x20);size=_u(p,thread+0xa8)
            unmap(address,size)
            # The pthread struct may already be unmapped. Never read it again.
    call('exit',0)
    return GuestThreadExitResult(cxa,handlers,detached,detached,unmapped)


def run_pthread_exit(guest_os, *, image_base, libc_base, thread_pointer,
        return_value, get_libc_tls, free, os_call, invoke=None,
        set_specific=None, get_image_tls=None, broadcast=None,
        invoke_shared=None, join_thread=None, max_nodes=64):
    """Commit the shared serialized pthread-exit body on complete success."""
    tx=guest_os.begin()
    result=_run_pthread_exit(tx,image_base=image_base,libc_base=libc_base,
        thread_pointer=thread_pointer,return_value=return_value,get_libc_tls=get_libc_tls,
        free=free,os_call=os_call,invoke=invoke,set_specific=set_specific,get_image_tls=get_image_tls,
        broadcast=broadcast,invoke_shared=invoke_shared,join_thread=join_thread,max_nodes=max_nodes)
    tx.commit();return result
