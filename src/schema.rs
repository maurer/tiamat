use holmes::simple::*;
use bap::holmes_support::{ArchType, BitVectorType};
use var::VarType;
use std::sync::Arc;
use ubvs::UBVSType;
use bvlist::BVListType;
use stack::StackType;
use typing::BlockTypeType;
use sema::SemaType;

pub fn setup(holmes: &mut Engine) -> Result<()> {
    try!(holmes.add_type(Arc::new(BitVectorType)));
    try!(holmes.add_type(Arc::new(ArchType)));
    try!(holmes.add_type(Arc::new(UBVSType)));
    try!(holmes.add_type(Arc::new(BVListType)));
    try!(holmes.add_type(Arc::new(BlockTypeType)));
    try!(holmes.add_type(Arc::new(SemaType)));
    try!(holmes.add_type(Arc::new(StackType)));
    try!(holmes.add_type(Arc::new(VarType)));
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
        predicate!(live(string, bitvector));
        predicate!(seglive(string, uint64, bitvector, uint64, uint64));
        predicate!(sema(string, bitvector, sema, bitvector));
        predicate!(arch(string, arch));
        predicate!(may_jump(string, bitvector, ubvs));
        predicate!(insn_type(string, bitvector, blocktype));
        predicate!(linkage(string, string));
        predicate!(link_pad(string, string, bitvector));
        // Filename, malloc_site, exit, var, freed
        predicate!(stack_addr([binary string], [var var], [addr bitvector]));
        predicate!(stack_free([binary string], [var var], [addr bitvector]));
        predicate!(free_call(string, bitvector));
        predicate!(malloc_call(string, bitvector));
        predicate!(using_call(string, bitvector));
        predicate!(func([binary string], [entry bitvector], [addr bitvector]) : "addr is reachable from the function at entry without a return");
        predicate!(call_site([source_binary string], [source_addr bitvector], [dest_binary string], [dest_addr bitvector]));
        predicate!(path_step([source_binary string], [source_addr bitvector], [dest_binary string], [dest_addr bitvector]));
        predicate!(is_ret([binary string], [addr bitvector]) : "Instruction at this address is a conventional return");
        predicate!(is_call([binary string], [addr bitvector], bool));
        predicate!(stack_escape([binary string], [addr bitvector]))
    })
}
