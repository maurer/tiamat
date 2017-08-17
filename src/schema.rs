use holmes::simple::*;
use bap::holmes_support::{ArchType, BitVectorType};
use var::VarType;
use std::sync::Arc;
use ubvs::UBVSType;
use bvlist::BVListType;
use stack::StackType;
use sema::SemaType;
use trace::TraceType;

pub fn setup(holmes: &mut Engine) -> Result<()> {
    try!(holmes.add_type(Arc::new(BitVectorType)));
    try!(holmes.add_type(Arc::new(ArchType)));
    try!(holmes.add_type(Arc::new(UBVSType)));
    try!(holmes.add_type(Arc::new(BVListType)));
    try!(holmes.add_type(Arc::new(SemaType)));
    try!(holmes.add_type(Arc::new(StackType)));
    try!(holmes.add_type(Arc::new(VarType)));
    holmes.add_type(Arc::new(TraceType))?;
    holmes_exec!(holmes, {
        predicate!(file(string, largebytes));
        // Filename, contents, start addr, end addr, r, w, x
        predicate!(segment(string,
                           uint64,
                           largebytes,
                           bitvector,
                           bitvector,
                           bool,
                           bool,
                           bool));
        predicate!(entry(string, string, bitvector, bitvector));
        predicate!(disasm(string, bitvector, string));
        predicate!(succ(string, bitvector, bitvector, bool));
        predicate!(succ_over(string, bitvector, bitvector));
        predicate!(live(string, bitvector));
        predicate!(seglive(string, uint64, bitvector, uint64, uint64));
        predicate!(sema(string, bitvector, sema, bitvector));
        predicate!(arch(string, arch));
        predicate!(may_jump(string, bitvector, ubvs));
        predicate!(linkage(string, string));
        predicate!(link_pad(string, string, bitvector));
        // Filename, malloc_site, exit, var, freed
        predicate!(path_alias([source_binary string], [malloc_site bitvector], [stack stack], [cur_binary string], [def_site bitvector], [def_var var], [freed bool]));
        predicate!(path_alias_trace([source_binary string], [malloc_site bitvector], [stack stack], [cur_binary string], [def_site bitvector], [def_var var], [freed bool], [trace trace]));
        predicate!(free_call(string, bitvector));
        predicate!(malloc_call(string, bitvector));
        predicate!(using_call(string, bitvector));
        // filename, source, errpoint, errvar
        predicate!(use_after_free_flow([source_binary string], [source bitvector "Allocation site for the use-after-free"], [stack stack "callstack at time of use"], [sink_binary string], [sink bitvector "Use site for the use after free"], [loc var "Where the pointer was when it was dereferenced"]) : "Possible use-after-free paths");
        predicate!(use_after_free([source_binary string], [source bitvector "Allocation site for the use-after-free"], [stack stack "callstack at time of use"], [sink_binary string], [sink bitvector "Use site for the use after free"], [loc var "Where the pointer was when it was dereferenced"], [trace trace]) : "Possible use-after-free paths");
        predicate!(func([binary string], [entry bitvector], [addr bitvector]) : "addr is reachable from the function at entry without a return");
        predicate!(call_site([source_binary string], [source_addr bitvector], [dest_binary string], [dest_addr bitvector]));
        predicate!(path_step([source_binary string], [source_addr bitvector], [dest_binary string], [dest_addr bitvector]));
        predicate!(is_ret([binary string], [addr bitvector]) : "Instruction at this address is a conventional return");
        predicate!(is_call([binary string], [addr bitvector], bool));
        predicate!(true_positive([binary string], [addr bitvector], [bad_parent string]));
        predicate!(false_positive([binary string], [addr bitvector], [good_parent string]));
        predicate!(deb_file([deb_name string], [contents largebytes]));
        predicate!(skip_func(string, bitvector))
    })
}
