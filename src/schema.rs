use holmes::simple::*;
use bap::holmes_support::{ArchType, BitVectorType};
use var::VarType;
use std::sync::Arc;
use ubvs::UBVSType;
use bvlist::BVListType;
use chop::ChopType;
use sema::SemaType;

pub fn setup(holmes: &mut Engine) -> Result<()> {
    try!(holmes.add_type(Arc::new(BitVectorType)));
    try!(holmes.add_type(Arc::new(ArchType)));
    try!(holmes.add_type(Arc::new(UBVSType)));
    try!(holmes.add_type(Arc::new(BVListType)));
    try!(holmes.add_type(Arc::new(SemaType)));
    try!(holmes.add_type(Arc::new(VarType)));
    try!(holmes.add_type(Arc::new(ChopType)));
    try!(holmes_exec!(holmes, {
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
        predicate!(lift(
                [binary string],
                [address bitvector],
                [bil sema],
                [fallthrough bitvector],
                [disassembly largestring],
                [is_call bool],
                [is_ret bool]));

        predicate!(succ(string, bitvector, bitvector, bool));
        predicate!(succ_over(string, bitvector, bitvector));
        predicate!(live(string, bitvector));
        predicate!(seglive(string, uint64, bitvector, uint64, uint64));
        predicate!(arch(string, arch));
        predicate!(link_pad(string, string, bitvector));
        predicate!(stack([id uint64], [prev uint64], [bin string], [addr bitvector], [len uint64]));
        predicate!(trace([id uint64], [stack uint64], [prev uint64], [bin string], [addr bitvector], [len uint64]));
        // Filename, malloc_site, exit, var, freed
        predicate!(path_alias([source_binary string], [malloc_site bitvector], [alias_set uint64], [stack uint64], [chop chop], [cur_binary string], [def_site bitvector], [def_var var], [freed bool]));
        predicate!(path_alias_trace([source_binary string], [malloc_site bitvector], [alias_set uint64], [def_var var], [freed bool], [trace uint64]));
        predicate!(free_call(string, bitvector));
        predicate!(malloc_call(string, bitvector));
        // filename, source, errpoint, errvar
        predicate!(use_after_free_flow([source_binary string], [source bitvector "Allocation site for the use-after-free"], [alias_set uint64], [stack uint64 "callstack at time of use"], [sink_binary string], [sink bitvector "Use site for the use after free"], [loc var "Where the pointer was when it was dereferenced"]) : "Possible use-after-free paths");
        predicate!(use_after_free([source_binary string], [source bitvector "Allocation site for the use-after-free"], [alias_set uint64], [sink_binary string], [sink bitvector "Use site for the use after free"], [loc var "Where the pointer was when it was dereferenced"], [trace uint64]) : "Possible use-after-free paths");
        predicate!(func([binary string], [entry bitvector], [addr bitvector]) : "addr is reachable from the function at entry without a return");
        predicate!(call_site([source_binary string], [source_addr bitvector], [dest_binary string], [dest_addr bitvector]));
        predicate!(path_step([source_binary string], [source_addr bitvector], [dest_binary string], [dest_addr bitvector]));
        predicate!(true_positive([binary string], [addr bitvector], string));
        predicate!(false_positive([binary string], [addr bitvector], string));
        predicate!(deb_file([deb_name string], [contents largebytes]));
        predicate!(skip_func(string, bitvector));
        predicate!(poss_const(string, bitvector, var, bitvector));
        predicate!(poss_string(string, bitvector, var, string));
        predicate!(func_uses(string, bitvector, var));
        predicate!(printf_like(string));
        predicate!(is_normal(string, bitvector));
        predicate!(bad_stack(uint64, string));
        predicate!(good_stack(uint64, string))
    }));
    holmes.run_sql("index.sql");
    Ok(())
}
