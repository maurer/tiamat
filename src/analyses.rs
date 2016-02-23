use bap::{Segment, Arch, BitVector, lift, Endian, Stmt, Expr, Symbol};
use bap::expert::Stmt::*;
use num::bigint::BigUint;
use num::traits::{ToPrimitive, FromPrimitive};

pub fn seg_wrap(contents : &Vec<u8>) -> Vec<(Vec<u8>, u64, u64, bool, bool, bool)> {
  let segs = Segment::from_file_contents(&contents);
  segs.into_iter().map(|seg| {
    (seg.data,
     seg.start.val.to_u64().unwrap(),
     seg.end.val.to_u64().unwrap(),
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

pub fn successors(arch : Arch, bin : &[u8], addr : BitVector) -> Vec<BitVector> {
  use num::bigint::BigUint;
  use num::traits::One;
  let (_, mut fall_addr, sema, is_call) =
    match lift(&addr, Endian::Little, arch, bin).into_iter().next() {
      Some(x) => x,
      None => return Vec::new()
    };
  fall_addr.val = fall_addr.val + BigUint::one();
  if is_call {
    return vec![fall_addr]
  }
  let (mut targets, fall) = stmt_succ(&sema);
  if fall {
    targets.push(fall_addr);
  }
  targets
}

pub fn succ_wrap((arch, addr, bin) : (&u64, &u64, &Vec<u8>)) -> Vec<u64> {
  successors(Arch::of_bap(unsafe {::std::mem::transmute(arch)}), bin, BitVector {
            val : BigUint::from_u64(*addr).unwrap(),
            width : 32
        }).iter().map(|x|{x.val.to_u64().unwrap()}).collect::<Vec<_>>()
}

pub fn sym_wrap(b : &Vec<u8>) -> Vec<u64> {
  Symbol::from_file_contents(&b).iter().map(|x|{x.start.val.to_u64().unwrap()}).collect::<Vec<_>>()
}

pub fn get_arch_val(v : &Vec<u8>) -> u64 {
  Arch::from_file_contents(v).to_bap() as u64
}
