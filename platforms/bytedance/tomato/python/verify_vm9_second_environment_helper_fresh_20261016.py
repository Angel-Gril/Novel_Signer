"""Fresh +28863c helper returns from independent TLS, stack and packed words."""
from pathlib import Path
import argparse,hashlib,json
from unicorn import arm64_const as arm
import verify_vm9_signer_objects as oracle
import verify_vm9_request_environment_return_fresh_20261015 as prior
import vm9_request_caller as model
from vm9_allocator import RefillUnsupported,_read_span,_write_span

BASES=prior.BASES
WRAPPER=0x28863C
LABELS=('zero','one','high_W','max_W','patterned_stack','relocated_stack',
    'cross_page_packed','result_alias_wrapper_lr','result_alias_wrapper_x19',
    'result_alias_helper_x28','result_alias_helper_fp','TLS_frame_alias','TLS_result_alias')


def fixture(library,image,label):
    pages,inputs,local=prior.fixture(library,image,0x204E50,label)
    _write_span(pages,inputs['entry_stack_address']-0x28,(image+0x28864C).to_bytes(8,'little'))
    inputs['wrapper_offset']=WRAPPER
    return pages,inputs,local


def original(library,pages,inputs,local):
    registers=[];image=inputs['image_base'];stack=inputs['entry_stack_address'];entry=stack-16
    def observe(cpu,address):
        if address==image+0x288654:
            registers.append(tuple(cpu.reg_read(getattr(arm,'UC_ARM64_REG_'+name))
                for name in ('X30','SP','X0','X19','X28','X29','X30')))
    watch={(oracle.GUEST,0xA000):None,(stack-0x600,0x600):None}
    result,_,allocations,services=oracle.native(library,image,0x204EAC,[],pages,
        extra_registers={arm.UC_ARM64_REG_SP:local,arm.UC_ARM64_REG_X29:entry-0x20,
            arm.UC_ARM64_REG_X19:inputs['thread_pointer'],arm.UC_ARM64_REG_TPIDR_EL0:inputs['thread_pointer']},
        observed_memory=watch,instruction_observer=observe,instruction_limit=1000)
    assert not allocations and not services and len(registers)==1 and result==registers[0][2]
    return registers[0],watch


def red(library):
    rows=[]
    for image in BASES:
        pages,inputs,local=fixture(library,image,'one');original(library,pages,inputs,local)
        before={k:bytes(v) for k,v in pages.items()}
        try:model.finish_request_environment_wrapper_caller(pages,**inputs)
        except (TypeError,RefillUnsupported) as exc:reason=str(exc)
        else:raise AssertionError('new wrapper unexpectedly supported before change')
        assert before=={k:bytes(v) for k,v in pages.items()}
        rows.append(dict(image_base=hex(image),original_new_wrapper_returned=True,
            prior_model_rejected=True,reason=reason,native_snapshot_input=False))
    return rows


def compare(library,image,label):
    pages,inputs,local=fixture(library,image,label);initial={k:bytearray(v) for k,v in pages.items()}
    state=model.finish_request_environment_wrapper_caller(pages,**inputs)
    registers,watch=original(library,initial,inputs,local)
    assert registers==tuple(getattr(state,k) for k in ('pc','sp','x0','x19','x28','x29','x30')),label
    assert all(data==_read_span(pages,a,n) for (a,n),data in watch.items()),label
    return dict(image_base=hex(image),case=label,original_new_wrapper_returned=True,
        all_seven_physical_return_values_equal=True,complete_declared_guest_and_stack_bytes_equal=True,
        packed_W_result_and_padding_equal=True,native_snapshot_input=False)


def guards(library):
    rows=[]
    for label in ('unknown_wrapper','bool_wrapper','wrong_helper','unaligned_stack','missing_frame',
            'missing_TLS','canary_mismatch','old_helper_LR','tagged_wrapper_LR','missing_result',
            'wrong_exit_pc','wrong_exit_word','old_exit_target','unknown_exit_wrapper'):
        pages,inputs,local=fixture(library,BASES[0],'one');stack=inputs['entry_stack_address'];entry=stack-16
        exit_inputs=dict(helper_offset=0x204E50,image_base=BASES[0],pc=BASES[0]+0x8A4E8,
            registers=[0]*31+[BASES[0]+0x28864C],wrapper_offset=WRAPPER)
        if label=='unknown_wrapper':inputs['wrapper_offset']=WRAPPER+4
        elif label=='bool_wrapper':inputs['wrapper_offset']=True
        elif label=='wrong_helper':inputs['helper_offset']=1
        elif label=='unaligned_stack':inputs['entry_stack_address']+=1
        elif label=='missing_frame':del pages[local>>12]
        elif label=='missing_TLS':inputs['thread_pointer']=oracle.GUEST+0x10000
        elif label=='canary_mismatch':_write_span(pages,entry-0x28,bytes(8))
        elif label=='old_helper_LR':_write_span(pages,entry-0x18,(BASES[0]+0x2814D8).to_bytes(8,'little'))
        elif label=='tagged_wrapper_LR':_write_span(pages,stack-16,(1<<60).to_bytes(8,'little'))
        elif label=='missing_result':_write_span(pages,entry-8,(oracle.GUEST+0x10000).to_bytes(8,'little'))
        elif label=='wrong_exit_pc':exit_inputs['pc']+=4
        elif label=='wrong_exit_word':_write_span(pages,exit_inputs['pc'],bytes(4))
        elif label=='old_exit_target':exit_inputs['registers'][31]=BASES[0]+0x2814D8
        elif label=='unknown_exit_wrapper':exit_inputs['wrapper_offset']=WRAPPER+4
        before={k:bytes(v) for k,v in pages.items()}
        try:
            if label in ('wrong_exit_pc','wrong_exit_word','old_exit_target','unknown_exit_wrapper'):
                model.validate_request_environment_vm_exit(pages,**exit_inputs)
            else:model.finish_request_environment_wrapper_caller(pages,**inputs)
        except (RefillUnsupported,ValueError):pass
        else:raise AssertionError(label)
        assert before=={k:bytes(v) for k,v in pages.items()},label
        rows.append(dict(case=label,rejected=True,all_pages_unchanged=True))
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--library',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--group',choices=('red','returns','guards','all'),default='all')
    args=parser.parse_args();assert hashlib.sha256(args.library.read_bytes()).hexdigest()==oracle.LIBRARY_SHA256
    report=dict(schema='vm9-second-environment-helper-fresh-v1',evidence_date='2026-10-16',
        sample_sha256=oracle.LIBRARY_SHA256,cases=[],negative_cases=[],native_snapshot_input=False,
        whole_second_native_differential_verified=False,complete_python_medusa=False,
        fresh_signer_output_verified=False,live_server_matrix_verified=False)
    if args.group=='red':report['red_cases']=red(args.library)
    if args.group in ('returns','all'):report['cases']=[compare(args.library,image,label) for image in BASES for label in LABELS]
    if args.group in ('guards','all'):report['negative_cases']=guards(args.library)
    report.update(native_Python_controls=len(report['cases']),rollback_guards=len(report['negative_cases']))
    args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8',newline='\n')
    print('PASS second environment helper',args.group,report['native_Python_controls'],report['rollback_guards'],flush=True)


if __name__=='__main__':main()
