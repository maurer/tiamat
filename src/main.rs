//#![feature(trace_macros)]
//trace_macros!(true);

#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
extern crate num;

use holmes::{DB, Holmes};
use getopts::Options;
use std::env;
use bap::high_level::Segment;

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
      func!(let seg_wrap : blob -> [(blob, uint64, uint64, uint64, uint64, uint64)] = | v : HValue | {
        let contents = match v {
          HValue::BlobV(v) => v,
          _ => panic!("Non-blob passed to segmentor")
        };
        let segs = Segment::from_file_contents(&contents);
        HValue::ListV(segs.into_iter().map(|seg| {
          use num::traits::ToPrimitive;
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
      rule!(segment(name, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
      fact!(file(in_path, in_bin))
    })
}
