use holmes::simple::*;
use bap::holmes_support::{ArchType, BitVectorType, VarType};
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
        // Filename, entry, var, exit, var
        predicate!(path_alias(string, bitvector, var, bitvector, var))
    })
}
