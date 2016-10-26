use holmes::Holmes;
use holmes;
use bap::holmes_support::{ArchType, BitVectorType};
use std::sync::Arc;
use ubvs::UBVSType;
use typing::BlockTypeType;
use sema::SemaType;

pub fn setup(holmes : &mut Holmes) -> holmes::Result<()> {
    try!(holmes.add_type(Arc::new(BitVectorType)));
    try!(holmes.add_type(Arc::new(ArchType)));
    try!(holmes.add_type(Arc::new(UBVSType)));
    try!(holmes.add_type(Arc::new(BlockTypeType)));
    try!(holmes.add_type(Arc::new(SemaType)));
    holmes_exec!(holmes, {
      predicate!(file(string, largebytes));
      //Filename, contents, start addr, end addr, r, w, x
      predicate!(segment(string, uint64, largebytes, bitvector, bitvector, bool, bool, bool));
      predicate!(entry(string, bitvector));
      predicate!(succ(string, bitvector, bitvector));
      predicate!(live(string, bitvector));
      predicate!(seglive(string, uint64, bitvector, uint64, uint64));
      predicate!(sema(string, bitvector, sema, bitvector));
      predicate!(arch(string, arch));
      predicate!(may_jump(string, bitvector, ubvs));
      predicate!(insn_type(string, bitvector, blocktype))
    })
}
