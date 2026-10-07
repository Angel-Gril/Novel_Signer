"""Same original A JNI execution through queue wait/stop/return/free.

Uses the existing controlled startup fixture. Matching libc executes wait;
its futex boundary supplies EINTR and explicitly publishes queue stop. No
real OS thread, TLS destructors or pthread_exit is claimed.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import verify_vm9_jni_A_default_worker_20261008 as startup
import verify_vm9_jni_initialization_fresh_20261007 as initialization


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==startup.cold.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==initialization.LIBC_SHA256
    cases=[]
    for base in (0x122C0000,0x775C205000):
        row=startup.case(args,base,'worker_stop',bind_memset=True)
        assert row['worker_normal_return_verified'] and row['argument_free_calls']==1
        assert row['argument_poison_verified'] and row['support_wrapper_retained_in_TLS']
        assert row['nested_VM_returns']==48 and row['default_task_body_return_verified']
        assert row['worker_condition_wait_executed'] and not row['worker_exit_verified']
        cases.append(row);print('A JNI worker wait/stop/return/free:',hex(base),'passed',flush=True)
    evidence=dict(schema='vm9-jni-A-worker-stop-v1',evidence_date='2026-10-07',evidence_timezone='UTC',
        host_trial_label='20261008',sample_sha256=startup.cold.LIBRARY_SHA256,
        matching_libc_sha256=initialization.LIBC_SHA256,worker_stop_return_observations=len(cases),cases=cases,
        base_startup_evidence_file='vm9_jni_A_default_worker_20261008.json',
        original_JNI_return_and_six_default_callers_in_same_run_verified=True,
        matching_libc_condition_wait_executed=True,explicit_EINTR_and_queue_stop_services_used=True,
        argument_free_and_poison_verified=True,support_retained_in_TLS=True,
        worker_TLS_destructors_executed=False,full_guest_pthread_exit_executed=False,
        real_OS_threads_created=False,actual_OS_thread_termination=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,
        native_input_snapshot_used=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('A same-run worker stop: 2 observations passed',flush=True)


if __name__=='__main__':main()
