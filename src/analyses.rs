use bap::{Segment, Arch, BitVector, lift, Endian, Stmt, Expr, Symbol};
use bap::expert::Stmt::*;
use bap;
use bap::expert::Var;
use var::HVar;
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
   let (_, mut fall_addr, sema, _, _) =
   match lift(addr, Endian::Little, *arch, bin).into_iter().next() {
      Some(x) => x,
      None => panic!("Lifting failure") //return Vec::new()
   };
   fall_addr = fall_addr + 1;
   (Sema {stmts: sema}, fall_addr)
}

//TODO: holmes doesn't allow multiple heads yet, so we lift twice to get the disasm
pub fn disas_wrap((arch, addr, bin) : (&Arch, &BitVector, &Vec<u8>)) -> String {
   let (_, _, _, _, dis) =
   match lift(addr, Endian::Little, *arch, bin).into_iter().next() {
      Some(x) => x,
      None => panic!("Lifting failure") //return Vec::new()
   };
   dis
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

pub fn sym_wrap(b : &Vec<u8>) -> Vec<(String, BitVector)> {
  Symbol::from_file_contents(&b).into_iter().map(|x|{(x.name, x.start)}).collect::<Vec<_>>()
}

pub fn get_arch_val(v : &Vec<u8>) -> Arch {
  Arch::from_file_contents(v)
}

use std::process::Command;
use num::{BigUint, FromPrimitive};
//TODO - get rid of objdump; stop using filename and use contents
pub fn get_pads(v: &String) -> Vec<(String, BitVector)> {
    let out : String = String::from_utf8(Command::new("bash").arg("-c").arg(format!(
            "objdump -d {} | grep plt\\>:", v)).output().expect("objdump grep pipeline failure").stdout).unwrap();
    out.split("\n").filter(|x| *x != "").map(|line| {
        let mut it = line.split(" ");
        let addr64 = u64::from_str_radix(it.next().unwrap(), 16).unwrap();
        let addr = BitVector::new_unsigned(BigUint::from_u64(addr64).unwrap(), 64);
        let unparsed = it.next().expect(&format!("No name? {}", line));
        let name = unparsed[1..].split("@").next().unwrap();
        (name.to_string(), addr)
    }).collect()
}

fn hv_match(bad: &Vec<HVar>, e: &Expr) -> bool {
    match *e {
        Expr::Var(ref v) => bad.contains(&HVar{inner: v.clone(), offset: None}),
        Expr::Load{index: ref idx, ..} => {
            match promote_idx(idx) {
                Some(hv) => bad.contains(&hv),
                None => false
            }
        }
        _ => false
    }
}

fn is_reg(r: &Var) -> bool {
    match r.typ {
        bap::expert::Type::BitVector(_) => true,
        _ => false
    }
}

fn is_mem(m: &Var) -> bool {
    match m.typ {
        bap::expert::Type::Memory{..} => true,
        _ => false
    }
}

fn add_hvar(mut bad: Vec<HVar>, hv: HVar) -> Vec<HVar> {
    if !bad.contains(&hv) {
        bad.push(hv)
    }
    bad
}

fn rem_hvar(bad: Vec<HVar>, hv: HVar) -> Vec<HVar> {
    bad.into_iter().filter(|x| *x != hv).collect()
}

fn promote_idx(idx: &Expr) -> Option<HVar> {
    match *idx {
        Expr::Var(ref v) => Some(HVar{inner: v.clone(), offset: Some(BitVector::new_unsigned(BigUint::from_u32(0).unwrap(), 64))}),
        Expr::BinOp{op: bap::BinOp::Plus,
                    lhs: ref lhs,
                    rhs: ref rhs} => {
                        match **lhs {
                            Expr::Var(ref v) => {
                                match **rhs {
                                    Expr::BitVector(ref bv) => Some(HVar{inner: v.clone(), offset: Some(bv.clone())}),
                                    _ => None
                                }
                            }
                            Expr::BitVector(ref bv) => {
                                match **rhs {
                                    Expr::Var(ref v) => Some(HVar{inner: v.clone(), offset: Some(bv.clone())}),
                                    _ => None
                                }
                            }
                            _ => None
                        }
                    }
        _ => None
    }
}

fn proc_stmt(bad: Vec<HVar>, stmt: &Stmt) -> Vec<HVar> {
    match *stmt {
        // Register update
        Move {lhs: ref reg, rhs: ref e} if is_reg(&reg) => {
            if hv_match(&bad, &e) {
                add_hvar(bad, HVar{inner: reg.clone(), offset: None})
            } else {
                rem_hvar(bad, HVar{inner: reg.clone(), offset: None})
            }
        }
        // Memory Write
        Move {lhs: ref mem, rhs: ref e} if is_mem(&mem) => {
            match *e {
                Expr::Store {
                    memory: _,
                    index: ref idx,
                    value: ref val,
                    endian: _,
                    size: _
                } => {
                    if hv_match(&bad, &val) {
                        promote_idx(idx).map_or(bad.clone(), |hidx| add_hvar(bad, hidx))
                    } else {
                        promote_idx(idx).map_or(bad.clone(), |hidx| rem_hvar(bad, hidx))
                    }
                }
                _ => bad
            }
        }
        _ => bad
    }
}

pub fn xfer_taint((sema, var) : (&Sema, &HVar)) -> Vec<HVar> {
    sema.stmts.iter().fold(vec![var.clone()], proc_stmt)
}

pub fn deref_var((sema, var) : (&Sema, &HVar)) -> bool {
    sema.stmts.iter().any(|stmt| deref_var_step(stmt, var))
}

fn check_idx(idx: &Expr, var: &HVar) -> bool {
    let res = match *idx {
        Expr::Var(ref v) => (var.offset == None) && (var.inner == *v),
        _ => false
    };
    println!("idx: {:?}: {:?} -> {:?}", idx, var, res);
    res
}

fn deref_var_expr(expr: &Expr, var: &HVar) -> bool {
     match *expr {
        Expr::Load {index: ref idx,..} => {
            check_idx(idx, var)
        }

        Expr::Store {index: ref idx,..} => {
            check_idx(idx, var)
        }

        Expr::Cast {ref val,..} => deref_var_expr(val, var),
        _ => false
    }
}

fn deref_var_step(stmt: &Stmt, var: &HVar) -> bool {
    let res = match *stmt {
        Move {rhs: ref e,..} => deref_var_expr(e, var),
        _ => false
    };
    println!("{:?}: {:?} -> {:?}", stmt, var, res);
    res
}
