#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
extern crate num;

use holmes::{DB, Holmes};
use holmes::native_types::HValue;
use getopts::Options;
use std::env;
use bap::{Segment, Arch, BitVector, lift, Endian, Stmt, Expr, Symbol};
use bap::expert::Stmt::*;
use num::bigint::BigUint;
use num::traits::{ToPrimitive, FromPrimitive};

fn main() {
  let db_default_addr = "postgresql://holmes:holmes@localhost/holmes";
  let default_in = "a.out";
  let mut opts = Options::new();
  opts.optopt("i", "in", "binary to process", default_in);
  opts.optopt("d", "database", "database connection string",
              "postgresql://holmes:holmes@localhost/holmes");
  opts.optflag("h", "help", "print usage and exit");
  let mut args = env::args();
  let prog_name = args.next().unwrap();
  let matches = opts.parse(args).unwrap_or_else(|x|{panic!(x)});
  if matches.opt_present("h") {
    let brief = format!("{} -i INFILE -d DBSTRING", prog_name);
    println!("{}", opts.usage(&brief));
    return
  }
  let db_addr = matches.opt_str("d").unwrap_or(db_default_addr.to_string());
  let in_path = matches.opt_str("i").unwrap_or(default_in.to_string());

  let db = DB::Postgres(db_addr);
  let mut holmes = Holmes::new(db).unwrap();
  holmes_prog(&mut holmes, &in_path).unwrap();
}

fn stmt_succ(stmts : &[Stmt]) -> (Vec<BitVector>, bool) {
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

fn successors(arch : Arch, bin : &[u8], addr : BitVector) -> Vec<BitVector> {
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

fn succ_wrap(v : HValue) -> HValue {
  match v {
    HValue::ListV(ref l) => {
      match (&l[0], &l[1], &l[2]) {
        (&HValue::UInt64V(arch),
         &HValue::UInt64V(addr),
         &HValue::BlobV(ref bin)) => HValue::ListV(successors(Arch::of_bap(unsafe {::std::mem::transmute(arch)}), &bin, BitVector {
            val : BigUint::from_u64(addr).unwrap(),
            width : 32
        }).iter().map(|x|{HValue::UInt64V(x.val.to_u64().unwrap())}).collect()),
        _ => panic!("Wrong type")
      }
    }
    _ => panic!("Wrong type")
  }
}

fn sym_wrap(v : HValue) -> HValue {
  match v {
    HValue::BlobV(ref b) =>
      HValue::ListV(Symbol::from_file_contents(&b).iter().map(|x|{HValue::UInt64V(x.start.val.to_u64().unwrap())}).collect()),
    _ => panic!("Wrong type")
  }
}

fn get_arch_val(v : HValue) -> HValue {
  match v {
    HValue::BlobV(ref b) =>
      HValue::UInt64V(Arch::from_file_contents(&b).to_bap() as u64),
    _ => panic!("Wrong type")
  }
}

fn holmes_prog(holmes : &mut Holmes, in_path : &str) -> holmes::Result<()> {
    use holmes::native_types::*;

    let mut in_bin = Vec::new();
    {
      use std::io::Read;
      let mut in_file = try!(std::fs::File::open(in_path));
      try!(in_file.read_to_end(&mut in_bin));
    }

    holmes_exec!(holmes, {
      predicate!(file(string, blob));
      //Filename, contents, start addr, end addr, r, w, x
      predicate!(segment(string, blob, uint64, uint64, uint64, uint64, uint64));
      predicate!(entry(string, uint64));
      predicate!(succ(string, uint64, uint64));
      predicate!(live(string, uint64));
      predicate!(chunk(string, uint64, blob));
      predicate!(arch(string, uint64));
      func!(let get_arch_val : blob -> uint64 = get_arch_val);
      func!(let seg_wrap : blob -> [(blob, uint64, uint64, uint64, uint64, uint64)] = | v : HValue | {
        let contents = match v {
          HValue::BlobV(v) => v,
          _ => panic!("Non-blob passed to segmentor")
        };
        let segs = Segment::from_file_contents(&contents);
        HValue::ListV(segs.into_iter().map(|seg| {
          HValue::ListV(vec![
            HValue::BlobV(seg.data),
            HValue::UInt64V(seg.start.val.to_u64().unwrap()),
            HValue::UInt64V(seg.end.val.to_u64().unwrap()),
            HValue::UInt64V(if seg.r {1} else {0}),
            HValue::UInt64V(if seg.w {1} else {0}),
            HValue::UInt64V(if seg.x {1} else {0})
          ])
        }).collect())
      });
      func!(let chunk : (uint64, blob) -> [(uint64, blob)] = |v : HValue| {
        let (base, data) = match v {
          HValue::ListV(l) => {
            assert_eq!(l.len(), 2);
            match (&l[0], &l[1]) {
              (&HValue::UInt64V(base),
               &HValue::BlobV(ref data)) => (base, data.clone()),
              _ => panic!("Wrong type")
            }
          },
          _ => panic!("Wrong type")
        };
        HValue::ListV(data.windows(16).enumerate().map(|(offset, window)| {
          HValue::ListV(vec![HValue::UInt64V(base + (offset as u64)),
                             HValue::BlobV(window.to_owned())])
        }).collect())
      });
      func!(let byteweight : (uint64, uint64, uint64, blob) -> uint64 = |v : HValue| {
        let (arch, start, end, data) = match v {
          HValue::ListV(l) => {
            assert_eq!(l.len(), 4);
            match (&l[0], &l[1], &l[2], &l[3]) {
              (&HValue::UInt64V(arch),
               &HValue::UInt64V(start),
               &HValue::UInt64V(end),
               &HValue::BlobV(ref data)) => (arch, start, end, data.clone()),
              _ => panic!("Wrong type")
            }
          }
          _ => panic!("Wrong type")
        };
        let seg = Segment {
          name : "dummy".to_string(),
          r : true,
          w : false,
          x : true,
          start : BitVector {
            val : BigUint::from_u64(start).unwrap(),
            width : 32
          },
          end   : BitVector {
            val : BigUint::from_u64(end).unwrap(),
            width : 32
          },
          data : data
        };
        HValue::ListV(seg.byteweight(Arch::of_bap(unsafe {::std::mem::transmute(arch)})).iter().map(|sym| {
          HValue::UInt64V(sym.start.val.to_u64().unwrap())
        }).collect())
      });
      func!(let find_succs : (uint64, blob) -> [uint64] = succ_wrap);
      func!(let find_syms  : blob -> [uint64] = sym_wrap);
      rule!(segment(name, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
      rule!(chunk(name, addr, chunk) <= segment(name, data, base, [_], [_], [_], [_]), {
        let [ {addr, chunk} ] = {chunk([base], [data])}
      });
      rule!(entry(name, addr) <= arch(name, arch) & segment(name, data, start, end, (1), [_], (1)), {
        let [ addr ] = {byteweight([arch], [start], [end], [data])}
      });
      rule!(entry(name, addr) <= file(name, in_bin), {
        let [ addr ] = {find_syms([in_bin])}
      });
      rule!(live(name, addr) <= entry(name, addr));
      rule!(succ(name, src, sink) <= live(name, src) & chunk(name, src, bin) & arch(name, arch), {
        let [ sink ] = {find_succs([arch], [src], [bin])}
      });
      rule!(live(name, sink) <= live(name, src) & succ(name, src, sink));
      rule!(arch(name, arch) <= file(name, contents), {
        let arch = {get_arch_val([contents])}
      });
      fact!(file(in_path, in_bin))
    })
}
