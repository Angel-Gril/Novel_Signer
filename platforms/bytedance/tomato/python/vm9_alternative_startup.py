"""B short hash/descriptor selection and the factory blob XOR prefix.

The module root/array/hash buckets are explicit inputs. Native factory and
publication observations are verified separately; independent Python factory
+0x2cbdc8, constructor input generation and complete B VM remain open.
Only selector lengths 0..8 and the XOR pre-reader prefix are implemented;
unsupported branches fail closed.
"""
from __future__ import annotations
from dataclasses import dataclass
from vm9_allocator import RefillUnsupported, _PageTransaction, _read_span, _write_span

MASK64=(1<<64)-1


def hash_short_descriptor_name(payload):
    """Actual +0x2aa744 length 0..8 branches, including its uint32 LSL.

    The 4..8 branch truncates first_u32 << 3 to uint32 before adding length;
    replacing it with an unbounded or uint64 shift changes high-bit inputs.
    This is the recovered function's hash, not a full std::hash API.
    """
    if not isinstance(payload,(bytes,bytearray)) or len(payload)>8:
        raise RefillUnsupported('descriptor hash supports only 0..8 byte inputs')
    length=len(payload);k2=0x9AE16A3B2F90404F
    if not length:return k2
    if length<4:
        first,middle,last=payload[0],payload[length//2],payload[-1]
        value=(((first | (middle<<8))*k2)&MASK64) ^ (((length+(last<<2))*0xC949D7C7509E6557)&MASK64)
        return ((value ^ (value>>47))*k2)&MASK64
    first=int.from_bytes(payload[:4],'little');last=int.from_bytes(payload[-4:],'little')
    multiplier=0x9DDFEA08EB382D69
    a=length+((first<<3)&0xFFFFFFFF)
    mixed=((a^last)*multiplier)&MASK64
    mixed=((last^mixed^(mixed>>47))*multiplier)&MASK64
    return ((mixed^(mixed>>47))*multiplier)&MASK64


def _u(p,a,n=8):return int.from_bytes(_read_span(p,a,n),'little')


@dataclass(frozen=True)
class ShortDescriptorLookupResult:
    descriptor_address: int
    hash_word: int
    bucket_index: int | None
    query_length: int
    visited_nodes: tuple[int,...]


def lookup_short_descriptor(pages, *, root_address, name_address,
        entry_stack_address, max_nodes=4096):
    """+0x2a9620 -> +0x2aa528 for short queries, with short/long stored keys.

    root[0] is the descriptor pointer array; root+0x20 owns hash buckets.
    Each bucket points to a predecessor node, whose next word is the first
    candidate. Node+8 caches the hash, +0x10 is a libc++ string, and +0x28 is
    the descriptor array index. Stop at another bucket, not at array count.
    Synthetic hash metadata may be supplied for differential controls.
    Waiting/throw paths, long queries and factory decoding are not recovered.
    """
    if (not isinstance(entry_stack_address,int) or entry_stack_address<0xC0
            or entry_stack_address>MASK64 or entry_stack_address&15):
        raise RefillUnsupported('descriptor selector stack must be aligned with scratch space')
    if (not isinstance(root_address,int) or not 0<root_address<=MASK64-0x30
            or not isinstance(name_address,int) or not 0<name_address<=MASK64-9):
        raise RefillUnsupported('descriptor selector requires mapped nonzero uint64 addresses')
    if not isinstance(max_nodes,int) or not 1<=max_nodes<=4096:
        raise RefillUnsupported('descriptor selector node bound must be 1..4096')
    p=_PageTransaction(pages);query=bytearray()
    for index in range(9):
        value=_read_span(p,name_address+index,1)[0]
        if value==0:break
        query.append(value)
    else:raise RefillUnsupported('descriptor selector query exceeds eight bytes')
    if len(query)>8:raise RefillUnsupported('descriptor selector query exceeds eight bytes')
    temporary=entry_stack_address-0x58
    _write_span(p,temporary,bytes([len(query)*2])+bytes(query)+b'\0')
    hashed=hash_short_descriptor_name(query);count=_u(p,root_address+0x28)
    if count>4096:raise RefillUnsupported('descriptor bucket count exceeds the explicit bound')
    bucket=None;visited=[];descriptor=0
    if count:
        power=(count&(count-1))==0
        bucket=(hashed&(count-1)) if power else hashed%count
        predecessor=_u(p,_u(p,root_address+0x20)+bucket*8)
        node=_u(p,predecessor) if predecessor else 0
        while node:
            if node in visited or len(visited)>=max_nodes:
                raise RefillUnsupported('descriptor node cycle or visit bound reached')
            visited.append(node);node_hash=_u(p,node+8)
            node_bucket=(node_hash&(count-1)) if power else node_hash%count
            if node_bucket!=bucket:break
            if node_hash==hashed:
                tag=_u(p,node+0x10,1)
                length=_u(p,node+0x18) if tag&1 else tag>>1
                if length==len(query):
                    data_address=_u(p,node+0x20) if tag&1 else node+0x11
                    if _read_span(p,data_address,length)==bytes(query):
                        index=_u(p,node+0x28)
                        address=(_u(p,root_address)+((index<<3)&MASK64))&MASK64
                        descriptor=_u(p,address)
                        break
            node=_u(p,node)
    result=ShortDescriptorLookupResult(descriptor,hashed,bucket,len(query),tuple(visited))
    p.commit();return result


@dataclass(frozen=True)
class FactoryBlobXorResult:
    blob_size: int
    selected_codec_row: int | None
    key_was_zero: bool | None


def decode_factory_blob_xor(pages, *, blob_address, blob_size,
        codec_table_address, codec_table_count, max_blob_bytes=16*1024*1024):
    """Bounded +0x2cbdc8 entry through +0x2cbf24, before the reader call.

    The extra stack arguments select row size % count from 24-byte codec
    records, using byte +2. For count zero the native unsigned division leaves
    quotient zero, selecting row size. Size zero skips the table entirely.
    This is only the in-place XOR prefix, not parsing or a module factory.
    Pages commit together; missing input/destination pages fail closed.
    """
    if (not isinstance(blob_address,int) or not 0<blob_address<=MASK64
            or not isinstance(blob_size,int) or not 0<=blob_size<=MASK64
            or not isinstance(max_blob_bytes,int) or not 0<=max_blob_bytes<=MASK64
            or blob_size>max_blob_bytes or blob_address+blob_size>MASK64+1):
        raise RefillUnsupported('factory XOR blob exceeds the explicit address/size bound')
    if (not isinstance(codec_table_count,int) or not 0<=codec_table_count<=MASK64
            or not isinstance(codec_table_address,int) or not 0<=codec_table_address<=MASK64):
        raise RefillUnsupported('factory XOR codec metadata is outside the guest ABI')
    if not blob_size:return FactoryBlobXorResult(0,None,None)
    row=blob_size%codec_table_count if codec_table_count else blob_size
    key_address=codec_table_address+row*24+2
    if not codec_table_address or key_address>MASK64:
        raise RefillUnsupported('factory XOR codec row address overflows or is null')
    p=_PageTransaction(pages)
    key=_u(p,key_address,1)
    if key:
        payload=_read_span(p,blob_address,blob_size)
        _write_span(p,blob_address,bytes(value^key for value in payload))
    p.commit()
    return FactoryBlobXorResult(blob_size,row,key==0)
