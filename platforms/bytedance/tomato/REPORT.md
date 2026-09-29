# Tomato reverse-engineering report

## Scope and version

The live checks used the Tomato Android client profile `v7.1.3.32` (`aid=1967`) and the current `libmetasec_ml` VM bridge available in the isolated workspace. The original development directory was not used for these trials.

## What is established

The complete content path is reproducible with the current Java/Unidbg bridge:

```text
device_register
  → registerkey
  → directory
  → reader/full
  → AES-CBC chapter decode
```

The directory response contained 611 chapter entries. The reader response was HTTP 200 with `crypt_status=0`; decrypting it with the key returned by the registerkey exchange produced 6,496 bytes of HTML. The decoded chapter hash is recorded in `evidence/EVIDENCE_INDEX.json`.

The registerkey request uses a fixed application content-encryption constant and returns a per-session chapter key. The published report records only the key version and output hashes; the per-session key, device identifiers, UUIDs, tickets, and complete headers remain private trial data.

## Pure algorithms already separated from the VM

The following are implemented and have sample-level or vector-level checks:

- `X-Khronos`: seconds timestamp;
- `X-Neptune`: soft timestamp field; it was removed by the open bridge and is not a hard reading-interface dependency;
- `X-Gorgon`: current 0404 form has the 0x8404 prefix and a one-way KSA/PRGA path;
- `X-Ladon`: Speck-like 34-round block transform;
- `X-Argus`: the Tomato variant uses SHA-256/AES details different from the common Douyin implementation; the live reading matrix did not require it;
- `X-Helios`: the 34-round VM was translated to Python and its key-table/header samples matched captured vectors;
- registerkey and chapter AES-CBC/decompression routines.

## Medusa status

There are two materially different claims:

1. The old 12a2a000 snapshot has a pure-Python body interpreter. It can accept a query string and reproduce its 225-byte body vectors. This is useful for studying field layout and VM semantics.
2. The current `v04.09.09.01-bugfixS` VM9 path can be run by the Java/Unidbg bridge. It produces short (228-byte raw) and long (803–804-byte raw) branches that were accepted by the live reading endpoints. The current VM9 body has also been reconstructed from A/B traces (777/779 bytes), but the reconstruction is trace-assisted. Independent execution still reaches native target `0x125081ac`, whose constructor calls allocator target `0x12607fd0`; after that boundary the standalone comparator lacks the returned object and diverges.

The latest checkpoint audit separates two results that must not be merged: the historical Seg3 replay still reaches `1057/1057` events with 87 callbacks when the captured `event0_cb66_vm9_*` image and callback 9/64/66 pages are used, while the newer full-Seg2 checkpoint diverges at trace 758 after callback 8 (`0x1296b940` versus `0x1296ba60`). The former is a reproducible diagnostic replay; it is not evidence that the latter has become a general parameterized signer. See [VM9_PROGRESS.md](VM9_PROGRESS.md) for the exact matrix.

Consequently, this repository does not call current Medusa “pure Python parameterized” and does not enable it in the default Rust build. The exact next proof is an independent constructor/allocator implementation followed by fresh current-version vectors and the same live endpoint matrix.

## Six/seven gods and “16/24 gods”

“God” in the historical notes means a request header, not a VM layer. The six hard historical names are Gorgon, Ladon, Argus, Khronos, Helios, and Medusa; Neptune is an additional soft field in seven-header descriptions. Perseus is a separate VM header and is tracked independently.

The current material proves a Medusa selector of `state & 0x0f`, so there are 16 selector values in the VM dispatch space. The available old notes and samples cover only selected variants. The names `jadx_out16` and `jadx_out24` are analysis-directory names, not evidence of 16 or 24 completed algorithms. No reliable 24-variant result is claimed here.

## Evidence use

Use the paired matrix entries when arguing about a required header. A single successful request only proves that one complete request worked. The `drop_medusa` versus `drop_perseus` pairs prove that Medusa is a hard dependency for these reading endpoints while Perseus was optional in this time window. Use the registerkey key-version, `crypt_status`, decoded length, and decoded hash together to prove that the response was decrypted rather than served as a plaintext cache.
