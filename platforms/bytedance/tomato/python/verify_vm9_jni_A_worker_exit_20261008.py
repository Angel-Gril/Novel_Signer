"""Same original A JNI/default worker through matching-libc TLS cleanup/exit.

The controlled allocator, virtual thread switch, empty libc cxa list and OS
exit service are explicit. This proves native composition, not Python boot.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import verify_vm9_jni_A_default_worker_20261008 as startup
import verify_vm9_jni_initialization_fresh_20261007 as initialization


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==startup.cold.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==initialization.LIBC_SHA256
    cases=[]
    for base in (0x122C0000,0x775C205000):
        for mode in ('worker_tls_cleanup','worker_pthread_exit'):
            row=startup.case(args,base,mode,bind_memset=True)
            assert row['worker_normal_return_verified'] and row['argument_free_calls']==1
            assert row['total_owned_free_calls']==3 and row['all_freed_blocks_poison_verified']
            assert row['nested_VM_returns']==48 and row['default_task_body_return_verified']
            assert row['worker_condition_wait_executed'] and row['actual_support_TLS_slot_cleared']
            assert row['support_payload_and_wrapper_released'] and not row['support_wrapper_retained_in_TLS']
            assert row['full_guest_pthread_exit_executed']==(mode=='worker_pthread_exit')
            assert not row['worker_exit_verified'] and not row['actual_OS_thread_termination']
            cases.append(row)
            print('A same JNI worker exit:',hex(base),mode,'passed',flush=True)
    evidence=dict(schema='vm9-jni-A-worker-exit-v1',evidence_date='2026-10-07',evidence_timezone='UTC',
        host_trial_label='20261008',sample_sha256=startup.cold.LIBRARY_SHA256,
        matching_libc_sha256=initialization.LIBC_SHA256,cases=cases,
        same_JNI_TLS_cleanup_observations=2,same_JNI_guest_pthread_exit_observations=2,
        base_startup_evidence_file='vm9_jni_A_default_worker_20261008.json',
        no_cleanup_control_evidence_file='vm9_jni_A_worker_stop_20261008.json',
        original_JNI_return_six_default_callers_and_exit_in_same_run_verified=True,
        actual_support_TLS_clear_and_ordered_three_frees_verified=True,
        explicit_allocator_JNI_OS_and_virtual_worker_services_used=True,
        explicit_worker_return_to_exit_driver_used=True,explicit_empty_cxa_thread_list_used=True,
        joinable_guest_state_zero_to_one_verified=True,explicit_syscall_93_exit_used=True,
        real_OS_threads_created=False,actual_OS_thread_termination=False,
        actual_thread_stack_mapping_reclaimed=False,detached_exit_path_verified=False,
        complete_python_bootstrap_controls=0,complete_python_medusa=False,
        native_input_snapshot_used=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('A same JNI worker exit: 4 observations passed',flush=True)


if __name__=='__main__':main()
