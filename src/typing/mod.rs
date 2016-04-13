mod repr;
pub use self::repr::*;
use sema::Sema;
use bap::{BitVector, Stmt, Expr};
use bap::expert::{Var, Type};
use std::collections::{BTreeMap, HashSet};
use std;

//TODO: this is a hack, split on arch
static REGISTERS: &'static [&'static str] = & [
    "LR",
    "R0",
    "R1",
    "SP"
];

fn init_base() -> BlockType {
    let mut register_file: BTreeMap<String, ValType> = BTreeMap::new();
    let mut var_alloc = 0;
    for reg in REGISTERS {
        let regvar = var_alloc;
        var_alloc += 1;
        register_file.insert(reg.to_string(), ValType::Var(regvar));
    };
    BlockType {
        register_file: register_file,
        stack: Stack::Var(0),
        assumes: Vec::new()
    }
}

fn init_type() -> BlockType {
    let mut bt = init_base();
    bt.assumes.push(Assume::FallType{typ:init_type()});
    bt
}

fn update_ctx(regs: &mut BTreeMap<String, ValType>, var: &Var, typ: ValType) {
    regs.insert(var.name.to_string(), typ);
}

fn subst_stack(v: u64, typ: &ValType, stack: &mut Stack) {
    use self::repr::Stack::*;
    match *stack {
        Var(_) => (),
        Alloc(ref mut inner) | Release (ref mut inner) =>
            subst_stack(v, typ, inner),
        With {base: ref mut base,
              slots: ref mut slots} => {
            subst_stack(v, typ, base);
            for (_, typ2) in slots.iter_mut() {
                subst_typ(v, typ, typ2)
            }
        }
        Shift {base: ref mut base,
               shift: _} => subst_stack(v, typ, base)
    }
}

fn expr_width(expr : &Expr) -> usize {
    match *expr {
        Expr::Var(ref v) => match v.typ {
            Type::BitVector(s) => s as usize,
            Type::Memory{..} => std::usize::MAX
        },
        Expr::BitVector(ref bv) => bv.len(),
        Expr::Load {size: size, ..} => size as usize,
        Expr::Store {..} => std::usize::MAX,
        Expr::BinOp {lhs: ref lhs,..} => expr_width(lhs),
        Expr::UnOp {arg: ref arg,..} => expr_width(arg),
        Expr::Cast {width: width,..} => width as usize,
        Expr::Let {body_expr: ref body,..} => expr_width(body),
        Expr::Unknown {typ: ref typ,..} => match *typ {
            Type::BitVector(s) => s as usize,
            Type::Memory{..} => std::usize::MAX
        },
        Expr::IfThenElse {true_branch: ref e,..} => expr_width(e),
        Expr::Extract {high_bit: high_bit, low_bit: low_bit,..} => (high_bit - low_bit + 1) as usize,
        Expr::Concat {low: ref low, high: ref high} => expr_width(low) + expr_width(high)
    }
}

fn subst_typ(v: u64, typ: &ValType, term: &mut ValType) {
    use self::repr::ValType::*;
    match *term {
        Var(v2) => if v == v2 {*term = (*typ).clone()},
        R{..} | UInt{..} | Int{..} => (),
        Ptr(ref mut vt) => subst_typ(v, typ, vt),
        PPtr(ref mut m) => {
            for (_, term) in m.iter_mut() {
                subst_typ(v, typ, term)
            }
        }
        Code(ref mut bt) => subst(bt, v, typ)
    }
}

fn subst(in_type: &mut BlockType, v: u64, typ: &ValType) {
    for (_, term) in &mut in_type.register_file {
        subst_typ(v, typ, term)
    }
    subst_stack(v, typ, &mut in_type.stack);
    for ass in &mut in_type.assumes {
        match *ass {
            Assume::AddrType {typ: ref mut atyp, ..}
            | Assume::FallType {typ: ref mut atyp, ..} =>
                subst(atyp, v, typ)
        }
    }
}

fn unify(mut in_type: BlockType, typ: ValType, typ2: ValType) -> Vec<(BlockType, ValType)> {
    if typ == typ2 {
        vec![(in_type, typ)]
    } else {
        match (typ, typ2) {
            (ValType::Var(v), typ) | (typ, ValType::Var(v)) => {
                subst(&mut in_type, v, &typ);
                vec![(in_type, typ)]
            }
            (ValType::R {width: w}, ValType::UInt {width: w2}) | (ValType::UInt{width: w2}, ValType::R{width: w}) =>
                if w == w2 {vec![(in_type, ValType::UInt{width: w2})]} else {vec![]},
            (typ, typ2) => panic!("unify: {} ~ {}", typ, typ2)
        }
    }
}

fn check_expr(mut in_type: BlockType, expr: &Expr, typ: ValType) -> Vec<(BlockType, ValType)> {
    use bap::Expr::*;
    match *expr {
        Var(ref v) => {
            let cur_typ = in_type.register_file.get(&v.name).map(|x|{(*x).clone()});
            match cur_typ {
                None => {
                    in_type.register_file.insert(v.name.clone(), typ.clone());
                    vec![(in_type, typ)]
                }
                Some(typ2) =>
                    unify(in_type, typ, typ2).into_iter().map(|(mut ctx, typ)| {
                        ctx.register_file.insert(v.name.clone(), typ.clone());
                        (ctx, typ)}).collect()
            }
        }
        BitVector(ref bv) => {
            match typ {
                ValType::R { width: width} | ValType::UInt { width: width } | ValType::Int { width: width} => {
                    if bv.len() == width {
                        vec![(in_type, typ)]
                    } else {
                        vec![]
                    }
                }
                _ => vec![]
            }
        }
        ref e => {
            let mut backing = vec![];
            for (bt, et) in synth_expr(in_type, e) {
                for (bt2, etu) in unify(bt, et, typ.clone()) {
                    backing.push((bt2, etu))
                }
            }
            backing
        }
    }
}

//TODO support signed ints
fn arith(mut in_type: BlockType, lhs: &Expr, rhs: &Expr) -> Vec<(BlockType, ValType)> {
    let lhs_width = expr_width(lhs);
    let rhs_width = expr_width(rhs);
    if lhs_width != rhs_width {
        return vec![]
    }
    check_expr(in_type, lhs, ValType::UInt {width: lhs_width}).into_iter()
        .flat_map(|(lhs_ctx, lhs_typ)| {
            let mut buf = vec![];
            for (ctx, _) in check_expr(lhs_ctx, rhs, ValType::UInt {width: rhs_width}).into_iter() {
                buf.push((ctx, lhs_typ.clone()))
            }
            buf.into_iter()
        }).collect()
}

fn synth_expr(mut in_type: BlockType, expr: &Expr) -> Vec<(BlockType, ValType)> {
    use bap::Expr::*;
    match *expr {
        Var(ref v) => match in_type.register_file.get(&v.name) {
            Some(ref typ) => vec![(in_type.clone(), (*typ).clone())],
            None => panic!("synth_expr: Context did not contain variable {}", v)
        },
        BinOp {ref lhs, ref op, ref rhs} => {
            match *op {
                ::bap::BinOp::LeftShift => {
                    let lhs_width = expr_width(lhs);
                    let rhs_width = expr_width(rhs);
                    check_expr(in_type, lhs, ValType::R {width: lhs_width}).into_iter()
                        .flat_map(|(lhs_ctx, lhs_typ)| {
                            let mut buf = vec![];
                            for (ctx, _) in check_expr(lhs_ctx, rhs, ValType::UInt {width: rhs_width}).into_iter() {
                                buf.push((ctx, lhs_typ.clone()))
                            }
                            buf.into_iter()
                        }).collect()
                }
                ::bap::BinOp::Plus => {
                    let base = arith(in_type.clone(), lhs, rhs);
                    //TODO ptr stuff
                    base
                }

                _ => panic!("synth_expr binop unimpl: {}", op)
            }
        },
        _ => panic!("synth_expr unimpl: {}", expr)
    }
}

fn synth_stmt(mut in_type: BlockType, stmt: &Stmt) -> Vec<BlockType> {
    use bap::Stmt::*;
    match *stmt {
        Jump(ref tgt) => check_expr(in_type.clone(), tgt, ValType::Code(Box::new(in_type))).into_iter().unzip::<_, _, Vec<_>, Vec<_>>().0,
        Special(_) => vec![], // There's no way to type this
        CPUException(_) => vec![in_type], // Anything can do this "safely", program stops
        Move {ref lhs, ref rhs} => {
            synth_expr(in_type, rhs).into_iter().map(|(mut ctx, typ)| {
                let mut fall = ctx.clone();
                update_ctx(&mut fall.register_file, lhs, typ);
                ctx.assumes.push(Assume::FallType{ typ: fall});
                ctx
            }).collect()
        }
        While {..} => panic!("While not yet supported"),
        IfThenElse {ref cond, ref then_clause, ref else_clause} => panic!("ITE not yet supported")
    }
}

fn find_fall(stmt_typ: &BlockType) -> Option<&BlockType> {
    for ass in stmt_typ.assumes.iter() {
        match *ass {
            Assume::FallType{typ: ref f} => return Some(f),
            _ => ()
        }
    }
    None
}

fn subst_substack(stack: &mut Stack, var: u64, substack: Stack) {
    panic!("bzzt")
}

fn stack_compose(mut base: BlockType, core_stack: Stack, aux_stack: &Stack) -> Vec<BlockType> {
    match (core_stack, aux_stack) {
        (Stack::Var(n), aux_stack) => {
            subst_substack(&mut base.stack, n, aux_stack.clone());
            vec![base]
        }
        (Stack::Alloc(s), Stack::Alloc(ref s2)) |
        (Stack::Release(s), Stack::Release(ref s2)) => stack_compose(base, s, s2),
        (Stack::With {base: inner, slots: slots}, Stack::With {base: aux_base, slots: aux_slots}) => {
            for (offs, typ) in &inner {

            stack_compose(base, aux_base)
        (aux_stack, Stack::Var(n)) => panic!("Variable on rhs without a variable being on the left. Doing this correctly would require stack_compose to be able to update the assumes for the fall clause, which is currently ro. If this happens, I need to redesign this chunk."),
    }
    panic!("crash")
}

fn compose_fall(init_base: BlockType, fall: BlockType) -> BlockType {
    let mut bases = vec![init_base];
    for (reg, typ) in &fall.register_file {
        let mut new_bases = vec![];
        for base in bases {
            let ass_typ = find_fall(&base).unwrap().register_file[reg].clone();
            new_bases.append(&mut unify(base, typ.clone(), ass_typ).into_iter().map(|(bt, _)| {bt}).collect());
        }
        bases = new_bases
    }
    bases = bases.into_iter().flat_map(|mut base| {
        let bs = base.stack.clone();
        stack_compose(base, bs, &fall.stack).into_iter()
    }).collect(); 
    panic!("BANG BANG")
}

pub fn local_type(sema : &Sema) -> Vec<BlockType> {
    let mut typs = vec![init_type()];
    for stmt in sema.stmts.iter() {
        typs = typs.into_iter().flat_map(|typ| {
           let back = match find_fall(&typ) {
               Some(base) => synth_stmt(base.clone(), stmt).into_iter().map(|stmt_typ| {compose_fall(typ.clone(), stmt_typ)}).collect(),
               None => vec![typ.clone()]
           };
           back.into_iter()
        }).collect()
    }
    typs
}
