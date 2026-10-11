"""Actual JNI finalizer callable moves, destruction and ownership guards."""
from pathlib import Path
import argparse,hashlib,json
import verify_vm9_startup_b_callable_20261011 as existing
from vm9_allocator import _write_span,RefillUnsupported
import vm9_startup as startup

def controls(args):
    labels=('move_inline','move_heap','move_empty','destroy_inline','destroy_heap','destroy_empty',
        'reset_inline','reset_heap','assign_inline','assign_heap','assign_self_inline','assign_self_heap','assign_replace')
    rows=[existing.compare(args,base,0x34F010,label) for base in (0x122C0000,0x775C205000) for label in labels]
    rows.extend(existing.compare(args,base,0x34F010,'move_inline',padding)
        for base in (0x122C0000,0x775C205000) for padding in (0,0x39,0xFF))
    return rows

def negatives(args):
    base=0x122C0000;rows=[]
    for label,operation,offset in (
        ('clone_slot','move_inline',0x34F028),('clone_instruction','move_inline',0x204330),
        ('inline_destructor','destroy_inline',0x34F030),('heap_destructor','destroy_heap',0x34F038),
        ('reset_destructor','reset_inline',0x34F030),('assign_clone','assign_inline',0x34F028)):
        p,dest=existing.prepare(args,base,0x34F010,operation)
        _write_span(p,base+offset,bytes(4 if offset==0x204330 else 8));before={k:bytes(v) for k,v in p.items()}
        try:existing.model(p,base,operation,dest)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(label=label,rejected=True,all_pages_unchanged=True))
    for index in (-1,2,True):
        p,dest=existing.prepare(args,base,0x34F010,'move_inline');before={k:bytes(v) for k,v in p.items()}
        try:startup.submit_default_callable(p,source_address=existing.SOURCE,scratch_address=existing.DEST,
            image_base=base,allocate=lambda *a:0,create_thread=lambda *a:0,register_destructor=lambda *a:0,
            thread_id=137,signal_condition=lambda *a:0,queue_index=index)
        except RefillUnsupported:pass
        else:raise AssertionError('accepted queue '+str(index))
        assert before=={k:bytes(v) for k,v in p.items()}
        rows.append(dict(label='queue_index_'+str(index),rejected=True,all_pages_unchanged=True))
    return rows

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('library','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==existing.oracle.LIBRARY_SHA256
    rows=controls(args);guards=negatives(args)
    report=dict(schema='vm9-jni-finalizer-callable-fresh-v1',evidence_date='2026-10-11',evidence_timezone='Asia/Shanghai',
        sample_sha256=existing.oracle.LIBRARY_SHA256,native_Python_callable_controls=len(rows),rollback_controls=len(guards),
        native_input_snapshot_used=False,private_names_or_payloads_published=False,finalizer_callback_body_executed=False,
        cases=rows,negative_cases=guards)
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('JNI finalizer callable',len(rows),'native controls',len(guards),'guards passed',flush=True)

if __name__=='__main__':main()
