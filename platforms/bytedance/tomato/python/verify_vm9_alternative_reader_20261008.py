"""Native B reader fed by independently decoded fresh-ELF Python input.

No Python reader/AST construction is claimed. Controlled allocation and a
synthetic output object/stack remain explicit. Only vector sizes are exported.
"""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import verify_vm9_alternative_factory_20261008 as factory


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--libc',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert hashlib.sha256(args.library.read_bytes()).hexdigest()==factory.oracle.LIBRARY_SHA256
    assert hashlib.sha256(args.libc.read_bytes()).hexdigest()==factory.initialization.LIBC_SHA256
    cases=[]
    for base in (0x122C0000,0x775C205000):
        row=factory.case(args,base,mode='reader')
        assert row['native_reader_return_verified'] and row['reader_status']==0
        assert row['controlled_allocation_calls']==1658 and not row['native_input_snapshot_used']
        cases.append(row);print('B native reader from Python ELF XOR:',hex(base),'passed',flush=True)
    evidence=dict(schema='vm9-alternative-reader-native-v1',evidence_date='2026-10-07',evidence_timezone='UTC',
        host_trial_label='20261008',sample_sha256=factory.oracle.LIBRARY_SHA256,
        matching_libc_sha256=factory.initialization.LIBC_SHA256,cases=cases,
        reader_native_return_observations=len(cases),independent_Python_XOR_prefix_used=True,
        native_input_snapshot_used=False,Python_reader_implemented=False,Python_AST_output_compared=False,
        independent_Python_factory_implemented=False,complete_python_bootstrap_controls=0,
        complete_python_medusa=False,fresh_signer_output_verified=False,live_server_matrix_verified=False)
    args.output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    print('B reader: 2 native observations passed; Python reader remains open',flush=True)


if __name__=='__main__':main()
