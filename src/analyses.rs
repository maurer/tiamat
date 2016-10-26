use bap::{Segment, Arch, BitVector, lift, Endian, Stmt, Expr, Symbol};
use bap::expert::Stmt::*;
use ubvs::UpperBVSet;
use sema::Sema;
use std::cmp::min;
use num::ToPrimitive;
use holmes::pg::dyn::values::LargeBWrap;

pub fn rebase((base, end, addr, len) : (&BitVector, &BitVector, &BitVector, &u64)) -> Vec<(u64, u64)> {
  let addr = addr.to_u64().unwrap();
  let end = end.to_u64().unwrap();
  let base = base.to_u64().unwrap();
  if (addr >= base) && (addr < end) {
    let datlen = end - base;
    let start = addr - base;
    let end = min(start + len, datlen);
    vec![(start, end)]
  } else {
    vec![]
  }
}

static mut ids : u64 = 0;

fn fresh() -> u64 {
  unsafe {
  ids = ids + 1;
  ids
  }
}

pub fn seg_wrap(contents : &Vec<u8>) -> Vec<(u64, LargeBWrap, BitVector, BitVector, bool, bool, bool)> {
  let segs = Segment::from_file_contents(&contents);
  segs.into_iter().map(|seg| {
    (fresh(),
     LargeBWrap {inner: seg.data},
     seg.start,
     seg.end,
     seg.r,
     seg.w,
     seg.x)
  }).collect::<Vec<_>>()
}

pub fn stmt_succ(stmts : &[Stmt]) -> (Vec<BitVector>, bool) {
  if stmts.len() == 0 {
    return (Vec::new(), true)
  }
  match &stmts[0] {
    &Jump(Expr::BitVector(ref v)) => (vec![v.clone()], false),
    &Jump(_) => (vec![], false),
    &While{cond : _, ref body} => {
      let (mut tgts, fall) = stmt_succ(&body);
      if fall {
        let (mut tgts2, fall2) = stmt_succ(&stmts[1..]);
        let mut tgt_res = Vec::new();
        tgt_res.append(&mut tgts);
        tgt_res.append(&mut tgts2);
        (tgt_res, fall2)
      } else {
        (tgts, fall)
      }
    }
    &IfThenElse{cond : _, ref then_clause, ref else_clause} => {
      let (mut then_tgts, then_fall) = stmt_succ(&then_clause);
      let (mut else_tgts, else_fall) = stmt_succ(&else_clause);
      let fall = then_fall || else_fall;
      let mut tgt_res = Vec::new();
      tgt_res.append(&mut then_tgts);
      tgt_res.append(&mut else_tgts);
      if fall {
        let (mut tgts2, fall2) = stmt_succ(&stmts[1..]);
        tgt_res.append(&mut tgts2);
        (tgt_res, fall2)
      } else {
        (tgt_res, fall)
      }
    }
    _ => stmt_succ(&stmts[1..])
  }
}

pub fn successors((sema, fall_addr) : (&Sema, &BitVector)) -> Vec<BitVector> {
  let (mut targets, fall) = stmt_succ(&sema.stmts);
  if fall {
    targets.push(fall_addr.clone());
  }
  targets
}

pub fn lift_wrap((arch, addr, bin) : (&Arch, &BitVector, &Vec<u8>)) -> (Sema, BitVector) {
   let (_, mut fall_addr, sema, _) =
   match lift(addr, Endian::Little, *arch, bin).into_iter().next() {
      Some(x) => x,
      None => panic!("Lifting failure") //return Vec::new()
   };
   fall_addr = fall_addr + 1;
   (Sema {stmts: sema}, fall_addr)
}

pub fn succ_wrap_upper((sema, fall_addr) : (&Sema, &BitVector)) -> UpperBVSet {
    let bvs = successors((sema, fall_addr));
    //TODO allow empty vec for cases where program will actually terminate
    if bvs.len() == 0 {
        UpperBVSet::Top
    } else {
        UpperBVSet::BVSet(bvs)
    }
}

pub fn sym_wrap(b : &Vec<u8>) -> Vec<BitVector> {
  Symbol::from_file_contents(&b).into_iter().map(|x|{x.start}).collect::<Vec<_>>()
}

pub fn get_arch_val(v : &Vec<u8>) -> Arch {
  Arch::from_file_contents(v)
}
