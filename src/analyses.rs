use std::fmt::Write;
use bap::basic::{Image, Arch, Bap, BasicDisasm, Cast, BitSize};
use bap::high::bil::{Statement, Expression, Variable, Type, BinOp};
use bap::high::bitvector::BitVector;
use bap;
use ubvs::UpperBVSet;
use sema::Sema;
use std::cmp::min;
use num::ToPrimitive;
use holmes::pg::dyn::values::LargeBWrap;
use var::HVar;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use var;

macro_rules! get_image {
    ($bap:expr, $contents:expr) => {{
        match Image::from_data(&$bap, &$contents) {
            Ok(i) => i,
            Err(_) => return vec![]
        }
    }}
}

//TODO get first class fact IDs so that I don't need to engage in this farce
pub fn hashify((i, n, a): (&u64, &String, &BitVector)) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    i.hash(&mut hasher);
    n.hash(&mut hasher);
    a.hash(&mut hasher);
    hasher.finish()
}

pub fn trace_len_inc(len: usize) -> Box<Fn(&u64) -> Vec<u64>> {
    Box::new(move |i| if *i < len as u64 { vec![*i + 1] } else { vec![] })
}

pub fn stack_len_inc(i: &u64) -> Vec<u64> {
    if *i < 5 { vec![*i + 1] } else { vec![] }
}

pub fn fmt_str_vars(fmt: &String) -> Vec<HVar> {
    let mut args: i8 = 1;
    for w in fmt.chars().collect::<Vec<_>>().as_slice().windows(2) {
        if w[0] == '%' {
            if w[1] == '%' {
                args -= 1;
            } else {
                args += 1;
            }
        }
    }
    (0..args).map(|i| var::get_arg_n(i as u8)).collect()
}

pub fn unpack_deb(mut fd: &File) -> Vec<(String, LargeBWrap)> {
    use std::fs::File;
    use std::io::prelude::*;
    use mktemp::Temp;
    use std::path::Path;
    let mut buf = Vec::new();
    fd.seek(SeekFrom::Start(0)).unwrap();
    fd.read_to_end(&mut buf).unwrap();
    let deb_temp = Temp::new_file().unwrap();
    let deb_path_buf = deb_temp.to_path_buf();
    let deb_path = deb_path_buf.to_str().unwrap();
    {
        let mut deb_file = File::create(deb_path).unwrap();
        deb_file.write_all(&buf).unwrap();
    }
    let unpack_temp_dir = Temp::new_dir().unwrap();
    let unpack_path_buf = unpack_temp_dir.to_path_buf();
    let unpack_path = unpack_path_buf.to_str().unwrap();
    Command::new("dpkg")
        .args(&["-x", deb_path, unpack_path])
        .output()
        .expect("failed to unpack");
    let find_out = Command::new("find")
        .args(
            &[
                unpack_path,
                "-exec",
                "bash",
                "-c",
                "file {} | grep -c ELF &>/dev/null",
                ";",
                "-print",
            ],
        )
        .output()
        .expect("failed to search unpack directory");
    let lines = find_out.stdout.lines();
    lines
        .map(|line| {
            let raw_path = line.unwrap();
            let path = Path::new(&raw_path);
            let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
            let mut elf_file = File::open(path).unwrap();
            let mut out = Vec::new();
            elf_file.read_to_end(&mut out).unwrap();
            (file_name, LargeBWrap { inner: out })
        })
        .collect()
}

fn compute_op(op: ::bap::basic::BinOp, lhs: BitVector, rhs: BitVector) -> Option<BitVector> {
    use bap::basic::BinOp::*;
    match op {
        Add => Some(&lhs + &rhs),
        _ => None
    }
}
fn compute_cast(k: Cast, bs: BitSize, v: BitVector) -> Option<BitVector> {
    match k {
        Cast::Low => {
            let mut bv = v.into_bitvec();
            bv.truncate(bs as usize);
            Some(BitVector::new(&bv))
        }
        Cast::Unsigned => Some(BitVector::new_unsigned(v.unum(), bs as usize)),
        _ => None,
    }
}

fn compute_expr(e: &Expression, ks: &HashMap<HVar, BitVector>) -> Option<BitVector> {
    use bap::high::bil::Expression::*;
    match *e {
        Var(ref v) => {
            ks.get(&HVar {
                inner: v.clone(),
                offset: None,
            }).cloned()
        }
        Load { index: ref idx, .. } => promote_idx(idx).and_then(|v| ks.get(&v)).cloned(),
        Const(ref bv) => Some(bv.clone()),
        Cast { kind, width: bs, arg: ref expr } =>
            match compute_expr(expr, ks) {
                Some(bv) => compute_cast(kind, bs, bv),
                None => None
            },
        BinOp { op: op, lhs: ref lhs, rhs: ref rhs } =>
            match (compute_expr(lhs, ks), compute_expr(rhs, ks)) {
                (Some(lhs_v), Some(rhs_v)) => compute_op(op, lhs_v, rhs_v),
                _ => None
            },
        _ => None,
    }
}

fn const_prop_h(stmt: &Statement, ks: &mut HashMap<HVar, BitVector>) {
    use bap::high::bil::Statement::*;
    match *stmt {
        // Register update
        Move {
            lhs: ref reg,
            rhs: ref e,
        } if is_reg(&reg) => {
            let var = HVar {
                inner: reg.clone(),
                offset: None,
            };
            match compute_expr(e, ks) {
                Some(bv) => {
                    ks.insert(var, bv);
                    ()
                }
                None => {
                    ks.remove(&var);
                    ()
                }
            }
        }
        // Memory Write
        Move {
            lhs: ref mem,
            rhs: ref e,
        } if is_mem(&mem) => {
            match *e {
                Expression::Store {
                    memory: _,
                    index: ref idx,
                    value: ref val,
                    endian: _,
                    size: _,
                } => {
                    match (promote_idx(idx), compute_expr(val, ks)) {
                        (Some(var), Some(bv)) => {
                            ks.insert(var, bv);
                            ()
                        }
                        (Some(var), None) => {
                            ks.remove(&var);
                            ()
                        }
                        _ => (),
                    }
                }
                _ => (),
            }
        }
        _ => (),
    }
}

pub fn is_computed_jump(sema: &Sema) -> bool {
    //TODO this isn't quite accurate, it doesn't deal with ITE at all
    //The point is to detect indirect calls though, so it'll suffice for now
    for stmt in sema.stmts.iter() {
        match stmt {
        &Statement::Jump(Expression::Const(_)) => (),
        &Statement::Jump(_) => return true,
        _ => ()
        }
    }
    return false
}

pub fn const_init(sema: &Sema) -> Vec<(HVar, BitVector)> {
    let mut ks = HashMap::new();
    for stmt in sema.stmts.iter() {
        const_prop_h(stmt, &mut ks)
    }
    // No temporaries or flags
    ks.into_iter()
        .filter(|kv| {
            !kv.0.inner.tmp && (kv.0.inner.type_ != bap::high::bil::Type::Immediate(1))
        })
        .collect()
}

fn stack_hvar(hv: &HVar) -> bool {
    let name = &hv.inner.name;
    (name == "RBP") || (name == "RSP")
}

fn heap_prop(stmt: &Statement, ks: &mut Vec<HashSet<HVar>>) {
    let mut all_tracked = HashSet::new();
    for ass in ks.iter_mut() {
        *ass = HashSet::from_iter(proc_stmt(ass.iter().cloned().collect::<Vec<_>>(), stmt).into_iter());
        all_tracked.extend(ass.iter().cloned());
    }
    match *stmt {
        Statement::Move {
            ref lhs,
            ref rhs
        } if is_reg(lhs) => {
            match *rhs {
                Expression::Load {
                    ref index,
                    ..
                } => {
                    let hvar = HVar {
                        inner: lhs.clone(),
                        offset: None
                    };
                    if !all_tracked.contains(&hvar) {
                        // This variable doesn't contain a tracked pointer already
                        match promote_idx(index) {
                            Some(ref hv) if !stack_hvar(hv) => {
                                let mut x = HashSet::new();
                                x.insert(hvar);
                                ks.push(x);
                            }
                            _ => ()
                        }
                    }
                }
                _ => ()
            }
        }
        _ => ()
    }
}

pub fn heap_init(sema: &Sema) -> Vec<(u64, Vec<HVar>)> {
    let mut hs = Vec::new();
    for stmt in sema.stmts.iter() {
        heap_prop(stmt, &mut hs)
    }
    // No temporaries or flags
    hs.into_iter()
        .map(|vv| {
            vv.into_iter().filter(|kv| {
            !kv.inner.tmp && (kv.inner.type_ != bap::high::bil::Type::Immediate(1))
            }).collect::<Vec<_>>()
        }).enumerate().map(|(k, v)| (k as u64, v))
        .collect()
}

pub fn const_prop((sema, var, k): (&Sema, &HVar, &BitVector)) -> Vec<(HVar, BitVector)> {
    let mut ks = HashMap::new();
    ks.insert(var.clone(), k.clone());
    for stmt in sema.stmts.iter() {
        const_prop_h(stmt, &mut ks)
    }
    // No temporaries or flags
    ks.into_iter()
        .filter(|kv| {
            !kv.0.inner.tmp && (kv.0.inner.type_ != bap::high::bil::Type::Immediate(1))
        })
        .collect()
}

pub fn rebase(
    (base, end, addr, len): (&BitVector, &BitVector, &BitVector, &u64),
) -> Vec<(u64, u64)> {
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

static mut IDS: u64 = 0;

fn fresh() -> u64 {
    unsafe {
        IDS = IDS + 1;
        IDS
    }
}

pub fn seg_wrap(mut fd: &File) -> Vec<(u64, LargeBWrap, BitVector, BitVector, bool, bool, bool)> {
    let mut contents = Vec::new();
    fd.seek(SeekFrom::Start(0)).unwrap();
    fd.read_to_end(&mut contents).unwrap();
    Bap::with(|bap| {
        let image = get_image!(bap, contents);
        let out = {
            let segs = image.segments();
            segs.iter()
                .map(|seg| {
                    let mem = seg.memory();
                    (
                        fresh(),
                        LargeBWrap { inner: mem.data() },
                        BitVector::from_basic(&mem.min_addr()),
                        BitVector::from_basic(&mem.max_addr()),
                        seg.is_readable(),
                        seg.is_writable(),
                        seg.is_executable(),
                    )
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
        &IfThenElse {
            cond: _,
            ref then_clause,
            ref else_clause,
        } => {
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

pub fn lift_wrap(
    (arch, addr, mut fd, start): (&Arch, &BitVector, &File, &u64),
) -> Vec<(Sema, BitVector, String, bool, bool)> {
    fd.seek(SeekFrom::Start(*start)).unwrap();
    to_vec(Bap::with(move |bap| {
        let mut bin: [u8; 16] = [0; 16];
        let mut fd = fd;
        let mut may_jump = false;
        let mut stmts = Vec::new();
        let mut is_call = false;
        let mut is_ret = false;
        let mut disasm = String::new();
        let mut fall: BitVector = addr.clone();
        let mut pre_read = 0;
        let mut first = true;
        let mut addr: BitVector = addr.clone();
        while !may_jump {
            fd.read_exact(&mut bin[pre_read..]).unwrap();
            let disas = BasicDisasm::new(&bap, *arch)?;
            let code = disas.disasm(&bin, addr.to_u64().unwrap())?;
            let len = code.len();
            let insn = code.insn();
            let sema = insn.semantics();
            if !first && (insn.is_call() || insn.is_return()) {
                // We want to put calls + rets in their own BBs to make
                // analysis rules a bit easier
                break;
            }
            first = false;
            stmts.extend(sema.iter().map(|bb| Statement::from_basic(&bb)));
            write!(&mut disasm, "{}\n", insn.to_string()).unwrap();
            is_call = insn.is_call();
            is_ret = insn.is_return();
            fall = addr.clone() + len;
            may_jump = insn.may_affect_control_flow();
            if !may_jump {
                addr = fall.clone();
                pre_read = 16 - len;
                for i in 0..pre_read {
                    bin[i] = bin[i + len];
                }
            }
        }

        disasm.pop();
        Ok((Sema { stmts: stmts }, fall, disasm, is_call, is_ret))
    }))
}

fn to_vec<T>(r: bap::basic::Result<T>) -> Vec<T> {
    match r {
        Ok(x) => vec![x],
        _ => vec![],
    }
}

pub fn str_extract(
    (start, end, addr, mut fd): (&BitVector, &BitVector, &BitVector, &File),
) -> Vec<String> {
    // If the address is not in range, abort
    if !((start <= addr) && (addr < end)) {
        return vec![];
    }
    let off = addr.to_u64().unwrap() - start.to_u64().unwrap();
    fd.seek(SeekFrom::Start(off)).unwrap();
    let mut bytes: Vec<u8> = Vec::new();
    for vb in fd.bytes() {
        let v = vb.unwrap();
        if v == 0 {
            break;
        }
        bytes.push(v);
    }
    match String::from_utf8(bytes) {
        Ok(out) => vec![out],
        _ => vec![],
    }
}

// TODO: holmes doesn't allow multiple heads yet, so we lift twice to get the disasm
pub fn disas_wrap((arch, addr, mut fd, start): (&Arch, &BitVector, &File, &u64)) -> Vec<String> {

    let mut bin: [u8; 16] = [0; 16];
    fd.seek(SeekFrom::Start(*start)).unwrap();
    fd.read_exact(&mut bin).unwrap();

    to_vec(Bap::with(|bap| {
        let disas = BasicDisasm::new(&bap, *arch)?;
        let out = {
            let code = disas.disasm(&bin, addr.to_u64().unwrap())?;
            code.insn().to_string()
        };
        Ok(out)
    }))
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

pub fn sym_wrap(mut fd: &File) -> Vec<(String, BitVector, BitVector)> {
    let mut b = Vec::new();
    fd.seek(SeekFrom::Start(0)).unwrap();
    fd.read_to_end(&mut b).unwrap();
    Bap::with(|bap| {
        let image = get_image!(bap, b);
        let out = {
            let syms = image.symbols();
            let out = syms.iter()
                .map(|x| {
                    (
                        x.name(),
                        BitVector::from_basic(&x.memory().min_addr()),
                        BitVector::from_basic(&x.memory().max_addr()),
                    )
                })
                .collect();
            out
        };
        out
    })
}

pub fn get_arch_val(mut fd: &File) -> Vec<Arch> {
    let mut b = Vec::new();
    fd.seek(SeekFrom::Start(0)).unwrap();
    fd.read_to_end(&mut b).unwrap();
    Bap::with(|bap| {
        let image = get_image!(bap, b);
        vec![image.arch().unwrap()]
    })
}

use std::process::Command;
use num::{BigUint, FromPrimitive};
// TODO - get rid of objdump
pub fn get_pads(mut fd: &File) -> Vec<(String, BitVector)> {
    use mktemp::Temp;
    use std::io::prelude::*;
    let mut buf = Vec::new();
    fd.seek(SeekFrom::Start(0)).unwrap();
    fd.read_to_end(&mut buf).unwrap();
    let elf_temp = Temp::new_file().unwrap();
    let elf_path_buf = elf_temp.to_path_buf();
    let elf_path = elf_path_buf.to_str().unwrap();
    {
        let mut elf_file = File::create(elf_path).unwrap();
        elf_file.write_all(&buf).unwrap();
    }
    let out: String = String::from_utf8(
        Command::new("bash")
            .arg("-c")
            .arg(format!("objdump -d {} | grep plt\\>:", elf_path))
            .output()
            .expect("objdump grep pipeline failure")
            .stdout,
    ).unwrap();
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
        Expression::BinOp {
            op: BinOp::Add,
            ref lhs,
            ref rhs,
        } => {
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
        Move {
            lhs: ref reg,
            rhs: ref e,
        } if is_reg(&reg) => {
            if hv_match(&bad, &e) {
                add_hvar(
                    bad,
                    HVar {
                        inner: reg.clone(),
                        offset: None,
                    },
                )
            } else {
                rem_hvar(
                    bad,
                    HVar {
                        inner: reg.clone(),
                        offset: None,
                    },
                )
            }
        }
        // Memory Write
        Move {
            lhs: ref mem,
            rhs: ref e,
        } if is_mem(&mem) => {
            match *e {
                Expression::Store {
                    memory: _,
                    index: ref idx,
                    value: ref val,
                    endian: _,
                    size: _,
                } => {
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
    sema.stmts
        .iter()
        .fold(vec![var.clone()], proc_stmt)
        .into_iter()
        .filter(|v| v.not_temp())
        .collect()
}

pub fn deref_var((sema, var): (&Sema, &HVar)) -> bool {
    let mut vars = vec![var.clone()];
    for stmt in sema.stmts.iter() {
        for var in vars.iter() {
            if deref_var_step(stmt, var) {
                return true;
            }
        }
        vars = proc_stmt(vars, stmt);
    }
    return false;
}

fn check_idx(idx: &Expression, var: &HVar) -> bool {
    let res = match *idx {
        Expression::Var(ref v) => (var.offset == None) && (var.inner == *v),
        Expression::BinOp {
            op: _,
            ref lhs,
            ref rhs,
        } => check_idx(lhs, var) || check_idx(rhs, var),
        _ => false,
    };
    //trace!("idx: {:?}: {:?} -> {:?}", idx, var, res);
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
    //trace!("{:?}: {:?} -> {:?}", stmt, var, res);
    res
}
