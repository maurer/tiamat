use bap::basic::{Image, Segment, Arch, Endian, Symbol, Bap, BasicDisasm};
use bap::high::bil::{Statement, Expression, Variable, Type, BinOp};
use bap::high::bitvector::BitVector;
use ubvs::UpperBVSet;
use sema::Sema;
use std::cmp::min;
use num::ToPrimitive;
use holmes::pg::dyn::values::LargeBWrap;
use var::HVar;

pub fn rebase((base, end, addr, len): (&BitVector, &BitVector, &BitVector, &u64))
              -> Vec<(u64, u64)> {
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

static mut ids: u64 = 0;

fn fresh() -> u64 {
    unsafe {
        ids = ids + 1;
        ids
    }
}

pub fn seg_wrap(contents: &Vec<u8>)
                -> Vec<(u64, LargeBWrap, BitVector, BitVector, bool, bool, bool)> {
    Bap::with(|bap| {
        let image = Image::from_data(&bap, &contents).unwrap();
        let out = {
            let segs = image.segments();
            segs.iter()
                .map(|seg| {
                    let mem = seg.memory();
                    (fresh(),
                     LargeBWrap { inner: mem.data() },
                     BitVector::from_basic(&mem.min_addr()),
                     BitVector::from_basic(&mem.max_addr()),
                     seg.is_readable(),
                     seg.is_writable(),
                     seg.is_executable())
                })
                .collect()
        };
        out
    })
}

pub fn stmt_succ(stmts: &[Statement]) -> (Vec<BitVector>, bool) {
    if stmts.len() == 0 {
        return (Vec::new(), true);
    }
    use bap::high::bil::Statement::*;
    match &stmts[0] {
        &Jump(Expression::Const(ref v)) => (vec![v.clone()], false),
        &Jump(_) => (vec![], false),
        &While { cond: _, ref body } => {
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
        &IfThenElse { cond: _, ref then_clause, ref else_clause } => {
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
        _ => stmt_succ(&stmts[1..]),
    }
}

pub fn successors((sema, fall_addr): (&Sema, &BitVector)) -> Vec<BitVector> {
    let (mut targets, fall) = stmt_succ(&sema.stmts);
    if fall {
        targets.push(fall_addr.clone());
    }
    targets
}

pub fn lift_wrap((arch, addr, bin): (&Arch, &BitVector, &Vec<u8>)) -> (Sema, BitVector) {
    Bap::with(|bap| {
        let disas = BasicDisasm::new(&bap, *arch).unwrap();
        let code = disas.disasm(bin, addr.to_u64().unwrap()).unwrap();
        let len = code.len();
        let fall = addr + len;
        let insn = code.insn();
        let sema = insn.semantics();
        let stmts: Vec<_> = sema.iter().map(|bb| Statement::from_basic(&bb)).collect();
        (Sema { stmts: stmts }, fall)
    })
}

// TODO: holmes doesn't allow multiple heads yet, so we lift twice to get the disasm
pub fn disas_wrap((arch, addr, bin): (&Arch, &BitVector, &Vec<u8>)) -> String {
    Bap::with(|bap| {
        let disas = BasicDisasm::new(&bap, *arch).unwrap();
        let out = {
            let code = disas.disasm(bin, addr.to_u64().unwrap()).unwrap();
            code.insn().to_string()
        };
        out
    })
}

pub fn succ_wrap_upper((sema, fall_addr): (&Sema, &BitVector)) -> UpperBVSet {
    let bvs = successors((sema, fall_addr));
    // TODO allow empty vec for cases where program will actually terminate
    if bvs.len() == 0 {
        UpperBVSet::Top
    } else {
        UpperBVSet::BVSet(bvs)
    }
}

pub fn sym_wrap(b: &Vec<u8>) -> Vec<(String, BitVector)> {
    Bap::with(|bap| {
        let image = Image::from_data(&bap, b).unwrap();
        let out = {
            let syms = image.symbols();
            let out = syms.iter()
                .map(|x| (x.name(), BitVector::from_basic(&x.memory().min_addr())))
                .collect();
            out
        };
        out
    })
}

pub fn get_arch_val(v: &Vec<u8>) -> Arch {
    Bap::with(|bap| {
        let image = Image::from_data(&bap, v).unwrap();
        image.arch().unwrap()
    })
}

use std::process::Command;
use num::{BigUint, FromPrimitive};
// TODO - get rid of objdump; stop using filename and use contents
pub fn get_pads(v: &String) -> Vec<(String, BitVector)> {
    let out: String = String::from_utf8(Command::new("bash")
            .arg("-c")
            .arg(format!("objdump -d {} | grep plt\\>:", v))
            .output()
            .expect("objdump grep pipeline failure")
            .stdout)
        .unwrap();
    out.split("\n")
        .filter(|x| *x != "")
        .map(|line| {
            let mut it = line.split(" ");
            let addr64 = u64::from_str_radix(it.next().unwrap(), 16).unwrap();
            let addr = BitVector::new_unsigned(BigUint::from_u64(addr64).unwrap(), 64);
            let unparsed = it.next().expect(&format!("No name? {}", line));
            let name = unparsed[1..].split("@").next().unwrap();
            (name.to_string(), addr)
        })
        .collect()
}

fn hv_match(bad: &Vec<HVar>, e: &Expression) -> bool {
    match *e {
        Expression::Var(ref v) => {
            bad.contains(&HVar {
                inner: v.clone(),
                offset: None,
            })
        }
        Expression::Load { index: ref idx, .. } => {
            match promote_idx(idx) {
                Some(hv) => bad.contains(&hv),
                None => false,
            }
        }
        _ => false,
    }
}

fn is_reg(r: &Variable) -> bool {
    match r.type_ {
        Type::Immediate(_) => true,
        _ => false,
    }
}

fn is_mem(m: &Variable) -> bool {
    match m.type_ {
        Type::Memory { .. } => true,
        _ => false,
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

fn promote_idx(idx: &Expression) -> Option<HVar> {
    match *idx {
        Expression::Var(ref v) => {
            Some(HVar {
                inner: v.clone(),
                offset: Some(BitVector::new_unsigned(BigUint::from_u32(0).unwrap(), 64)),
            })
        }
        Expression::BinOp { op: BinOp::Add, lhs: ref lhs, rhs: ref rhs } => {
            match **lhs {
                Expression::Var(ref v) => {
                    match **rhs {
                        Expression::Const(ref bv) => {
                            Some(HVar {
                                inner: v.clone(),
                                offset: Some(bv.clone()),
                            })
                        }
                        _ => None,
                    }
                }
                Expression::Const(ref bv) => {
                    match **rhs {
                        Expression::Var(ref v) => {
                            Some(HVar {
                                inner: v.clone(),
                                offset: Some(bv.clone()),
                            })
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn proc_stmt(bad: Vec<HVar>, stmt: &Statement) -> Vec<HVar> {
    use bap::high::bil::Statement::*;
    match *stmt {
        // Register update
        Move { lhs: ref reg, rhs: ref e } if is_reg(&reg) => {
            if hv_match(&bad, &e) {
                add_hvar(bad,
                         HVar {
                             inner: reg.clone(),
                             offset: None,
                         })
            } else {
                rem_hvar(bad,
                         HVar {
                             inner: reg.clone(),
                             offset: None,
                         })
            }
        }
        // Memory Write
        Move { lhs: ref mem, rhs: ref e } if is_mem(&mem) => {
            match *e {
                Expression::Store { memory: _,
                                    index: ref idx,
                                    value: ref val,
                                    endian: _,
                                    size: _ } => {
                    if hv_match(&bad, &val) {
                        promote_idx(idx).map_or(bad.clone(), |hidx| add_hvar(bad, hidx))
                    } else {
                        promote_idx(idx).map_or(bad.clone(), |hidx| rem_hvar(bad, hidx))
                    }
                }
                _ => bad,
            }
        }
        _ => bad,
    }
}

pub fn xfer_taint((sema, var): (&Sema, &HVar)) -> Vec<HVar> {
    sema.stmts.iter().fold(vec![var.clone()], proc_stmt)
}

pub fn deref_var((sema, var): (&Sema, &HVar)) -> bool {
    sema.stmts.iter().any(|stmt| deref_var_step(stmt, var))
}

fn check_idx(idx: &Expression, var: &HVar) -> bool {
    let res = match *idx {
        Expression::Var(ref v) => (var.offset == None) && (var.inner == *v),
        _ => false,
    };
    trace!("idx: {:?}: {:?} -> {:?}", idx, var, res);
    res
}

fn deref_var_expr(expr: &Expression, var: &HVar) -> bool {
    match *expr {
        Expression::Load { index: ref idx, .. } => check_idx(idx, var),

        Expression::Store { index: ref idx, .. } => check_idx(idx, var),

        Expression::Cast { ref arg, .. } => deref_var_expr(arg, var),
        _ => false,
    }
}

fn deref_var_step(stmt: &Statement, var: &HVar) -> bool {
    use bap::high::bil::Statement::*;
    let res = match *stmt {
        Move { rhs: ref e, .. } => deref_var_expr(e, var),
        _ => false,
    };
    trace!("{:?}: {:?} -> {:?}", stmt, var, res);
    res
}
