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
      predicate!(file(string, bytes));
      //Filename, contents, start addr, end addr, r, w, x
      predicate!(segment(string, bytes, bitvector, bitvector, bool, bool, bool));
      predicate!(entry(string, string, bitvector));
      predicate!(live(string, bitvector));
      predicate!(sema(string, bitvector, sema, bitvector));
      predicate!(chunk(string, bitvector, bytes));
      predicate!(arch(string, arch));
      predicate!(may_jump(string, bitvector, ubvs));
      predicate!(insn_type(string, bitvector, blocktype))
    })
}
