use holmes::simple::*;
use bap::holmes_support::{ArchType, BitVectorType};
use var::VarType;
use std::sync::Arc;
use ubvs::UBVSType;
use typing::BlockTypeType;
use sema::SemaType;

pub fn setup(holmes: &mut Engine) -> Result<()> {
    try!(holmes.add_type(Arc::new(BitVectorType)));
    try!(holmes.add_type(Arc::new(ArchType)));
    try!(holmes.add_type(Arc::new(UBVSType)));
    try!(holmes.add_type(Arc::new(BlockTypeType)));
    try!(holmes.add_type(Arc::new(SemaType)));
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
        predicate!(entry(string, string, bitvector));
        predicate!(disasm(string, bitvector, string));
        predicate!(succ(string, bitvector, bitvector));
        predicate!(live(string, bitvector));
        predicate!(seglive(string, uint64, bitvector, uint64, uint64));
        predicate!(sema(string, bitvector, sema, bitvector));
        predicate!(arch(string, arch));
        predicate!(may_jump(string, bitvector, ubvs));
        predicate!(insn_type(string, bitvector, blocktype));
        predicate!(linkage(string, string));
        predicate!(link_pad(string, string, bitvector));
        // Filename, malloc_site, exit, var, freed
        predicate!(path_alias(string, bitvector, bitvector, var, bool));

        predicate!(free_call(string, bitvector));
        predicate!(malloc_call(string, bitvector));
        // filename, source, errpoint, errvar
        predicate!(use_after_free([binary string], [source bitvector "Allocation site for the use-after-free"], [sink bitvector "Use site for the use after free"], [qq var "Where the pointer was when it was dereferenced"]) : "Possible use-after-free paths")
    })
}
