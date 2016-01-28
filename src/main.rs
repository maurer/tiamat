#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
extern crate num;

use holmes::{DB, Holmes};
use getopts::Options;
use std::env;
use bap::high_level::{Segment, Arch, BitVector, lift};
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
      predicate!(successor(uint64, uint64));
      predicate!(live(string, uint64));
      predicate!(chunk(string, uint64, blob));
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
      func!(let byteweight : (uint64, uint64, blob) -> uint64 = |v : HValue| {
        let (start, end, data) = match v {
          HValue::ListV(l) => {
            assert_eq!(l.len(), 3);
            match (&l[0], &l[1], &l[2]) {
              (&HValue::UInt64V(start),
               &HValue::UInt64V(end),
               &HValue::BlobV(ref data)) => (start, end, data.clone()),
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
            width : 64
          },
          end   : BitVector {
            val : BigUint::from_u64(end).unwrap(),
            width : 64
          },
          data : data
        };
        HValue::ListV(seg.byteweight(Arch::X86).iter().map(|sym| {
          HValue::UInt64V(sym.start.val.to_u64().unwrap())
        }).collect())
      });
      rule!(segment(name, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
      rule!(chunk(name, addr, chunk) <= segment(name, data, base, [_], [_], [_], [_]), {
        let [ {addr, chunk} ] = {chunk([base], [data])}
      });
      rule!(entry(name, addr) <= segment(name, data, start, end, (1), [_], (1)), {
        let [ addr ] = {byteweight([start], [end], [data])}
      });
      rule!(live(name, addr) <= entry(name, addr));
      fact!(file(in_path, in_bin))
    })
}
