#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
#[macro_use]
extern crate postgres;
extern crate postgres_array;
extern crate bit_vec;

use holmes::{DB, Holmes};
use getopts::Options;
use std::env;
use bap::BitVector;

pub mod analyses;
pub mod schema;
pub mod ubvs;

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
  holmes_prog(&mut holmes, in_path).unwrap();
}

fn holmes_prog(holmes : &mut Holmes, in_path : String) -> holmes::Result<()> {
    let mut in_bin = Vec::new();
    {
      use std::io::Read;
      let mut in_file = try!(std::fs::File::open(&in_path));
      try!(in_file.read_to_end(&mut in_bin));
    }

    try!(schema::setup(holmes));

    holmes_exec!(holmes, {
      func!(let get_arch_val : bytes -> uint64 = analyses::get_arch_val);
      func!(let seg_wrap : bytes -> [(bytes, bitvector, bitvector, bool, bool, bool)] = analyses::seg_wrap);
      func!(let chunk : (bitvector, bytes) -> [(bitvector, bytes)] = |(base, data) : (&BitVector, &Vec<u8>)| {
        data.windows(16).enumerate().map(|(offset, window)| {
          (base + offset,
           window.to_owned())
        }).collect::<Vec<_>>()
      });
      func!(let find_succs : (arch, bitvector, bytes) -> [bitvector] = analyses::succ_wrap);
      func!(let find_succs_upper : (arch, bitvector, bytes) -> ubvs = analyses::succ_wrap_upper);
      func!(let find_syms  : bytes -> [bitvector] = analyses::sym_wrap);
      rule!(segment(name, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
      rule!(chunk(name, addr, chunk) <= segment(name, data, base, [_], [_], [_], [_]), {
        let [ {addr, chunk} ] = {chunk([base], [data])}
      });
      rule!(entry(name, addr) <= file(name, in_bin), {
        let [ addr ] = {find_syms([in_bin])}
      });
      rule!(live(name, addr) <= entry(name, addr));
      rule!(succ(name, src, sink) <= live(name, src) & chunk(name, src, bin) & arch(name, arch), {
        let [ sink ] = {find_succs([arch], [src], [bin])}
      });
      rule!(may_jump(name, src, sinks) <= live(name, src) & chunk(name, src, bin) & arch(name, arch), {
        let sinks = {find_succs_upper([arch], [src], [bin])}
      });
      rule!(live(name, sink) <= live(name, src) & succ(name, src, sink));
      rule!(arch(name, arch) <= file(name, contents), {
        let arch = {get_arch_val([contents])}
      });
      fact!(file(in_path, in_bin))
    })
}
