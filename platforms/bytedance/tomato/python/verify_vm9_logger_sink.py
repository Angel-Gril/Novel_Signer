"""Compare the fresh Python literal logger/sink state with native controls.

The native control enters +0x26e9e0 while +0x26cdc4 owns a 24-byte string
object, then formats the decoded fallback literal and enters +0x271ddc. This
verifier compares pointer relations, the owned 24-byte object prefix, the
literal payload and the unavailable-sink global state. It deliberately leaves
the live file/socket callback and native descriptor publication open.
"""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path
import verify_vm9_native_logger_trace as native_trace
import verify_vm9_outer_constructor_boundary as boundary
import verify_vm9_outer_signer_native as native
import verify_vm9_signer_objects as oracle
import verify_vm9_worker_allocator as worker

LIBRARY = Path(r"C:\AI\6\libmetasec_ml_71332.so")
LIBC = Path(r"C:\AI\6\_vlibc.so")
BASES = (0x122C0000, 0x775C205000)
PROFILES = {"absent": None, "sdk_30": b"30"}
MESSAGE = b"Invalid JavaVM, fallback to test path."
TAG = b"METASEC\0"

def _int(value):
    return int(value, 16) if isinstance(value, str) else value

def _trace(trace, offset):
    rows=[item for item in trace if item.get("offset")==offset]
    if len(rows)!=1: raise AssertionError(f"native {offset} count changed: {len(rows)}")
    return rows[0]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--library",type=Path,default=LIBRARY)
    ap.add_argument("--libc",type=Path,default=LIBC)
    ap.add_argument("--output",type=Path,required=True)
    # Kept as a compatibility alias for the previous verifier invocation.
    ap.add_argument("--apply-logger-model",action="store_true")
    args=ap.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==worker.LIBC_SHA256
    os.environ["TOMATO_LIBMETASEC"]=str(args.library.resolve())
    import vm_full
    cases=[]
    for image in BASES:
        for label,property_value in PROFILES.items():
            trace=[]
            native_result=native.case(args.library,args.libc,image,property_value,trace=trace)
            native_entry=_trace(trace,"0x26e9e0")
            native_formatter=_trace(trace,"0x271ec8")
            native_sink=_trace(trace,"0x271ddc")
            native_after=_trace(trace,"0x271f18")
            result=boundary.case(args.library,args.libc,image,label,property_value,vm_full,
                apply_logger_model=False,capture_logger_handoff=False,
                apply_handoff_model=False)
            observations=result.get("logger_observations",[])
            before=[row for row in observations if row.get("phase")=="before_sink"]
            after=[row for row in observations if row.get("phase")=="after_sink"]
            if len(before)!=1 or len(after)!=1:
                raise AssertionError(f"logger observation count changed: {len(before)}/{len(after)}")
            before,after=before[0],after[0]
            native_object=bytes.fromhex(native_entry["x0_bytes_0x80"])[:24]
            python_object=bytes.fromhex(before["object_bytes_0x80"])[:24]
            native_tag=bytes.fromhex(native_formatter["x1_bytes_0x80"])
            python_tag=bytes.fromhex(before["tag_bytes_0x40"])
            native_output=bytes.fromhex(native_sink["x2_bytes_0x420"])
            python_output=bytes.fromhex(before["output_bytes_0x420"])
            checks={
                "object_address_match": _int(native_entry["x0"])==_int(before["object_address"]),
                "object_24_byte_prefix_match": native_object==python_object,
                "format_address_match": _int(native_formatter["x2"])==_int(before["format_address"]),
                "tag_address_match": _int(native_formatter["x1"])==_int(before["tag_address"]),
                "output_address_match": _int(native_sink["x2"])==_int(before["output_address"]),
                "tag_payload_match": python_tag[:len(TAG)]==native_tag[:len(TAG)]==TAG,
                "formatted_message_match": python_output.split(b"\0",1)[0]==native_output.split(b"\0",1)[0]==MESSAGE,
                "level_match": int(before["level"],16)==6 and _int(native_sink["x0"])==6,
                "global_before_match": before["logger_global_0x40"]==native_sink["logger_global_0x40"],
                "global_after_match": after["logger_global_0x40"]==native_after["logger_global_0x40"],
                "sink_return_match": _int(after["return_value"])==_int(native_after["x0"]) and _int(native_after["x0"]) in (0xFFFFFFFF,0xFFFFFF9F),
            }
            if not all(checks.values()): raise AssertionError(f"sink mismatch: {checks}")
            cases.append({
                "image_base":hex(image),"property_profile":label,
                "fresh_elf_inputs":True,"native_input_snapshot_used":False,
                "native_path":["0x26cdc4","0x26cf08","0x26e9e0","0x271ec8","0x271ddc","0x271f18"],
                "python_path":["construct_default_shared_reference","log_literal_unavailable","initialize_unavailable_logger"],
                "checks":checks,
                "logger_object_size_modeled":24,
                "logger_object_window_observed":128,
                "sink_callback_body_recovered":False,
                "descriptor_trampoline_recovered":False,
                "fresh_medusa_output_verified":False,
                "native_outer_getter_returned":native_result["native_outer_getter_returned"],
            })
            print("logger sink",hex(image),label,"PASS",flush=True)
    report={
        "schema":"vm9-logger-sink-boundary-v1","sample_sha256":oracle.LIBRARY_SHA256,
        "libc_sha256":worker.LIBC_SHA256,"controls":len(cases),"cases":cases,
        "native_input_snapshot_used":False,"logger_object_size_modeled":24,
        "logger_object_window_not_treated_as_object":True,
        "literal_formatter_recovered":True,"unavailable_sink_state_recovered":True,
        "sink_callback_body_recovered":False,"descriptor_trampoline_recovered":False,
        "fresh_medusa_output_verified":False,"current_online_header_matrix_verified":False,
        "complete_python_medusa":False,
        "limitations":[
            "Only the 24-byte string-object prefix and literal unavailable-sink state are matched; the 128-byte native window contains adjacent stack data.",
            "The model deliberately rejects conversion formats, live file/socket writes and final callback publication.",
            "No online signature, Rust download, search/pagination, Douyin, Qidian or Pages/Actions result is implied."
        ]
    }
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print("logger sink",len(cases),"fresh controls PASS; live sink callback remains open",flush=True)

if __name__=="__main__": main()
