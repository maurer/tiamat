use bap::basic::{Image, Segment, Arch, Endian, Symbol, Bap, BasicDisasm};
use bap::high::bil::{Statement, Expression};
use bap::high::bitvector::BitVector;
use ubvs::UpperBVSet;
use sema::Sema;
use std::cmp::min;
use num::ToPrimitive;
use holmes::pg::dyn::values::LargeBWrap;

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
