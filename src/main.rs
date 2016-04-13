#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
#[macro_use]
extern crate postgres;
extern crate postgres_array;
extern crate bit_vec;
extern crate rustc_serialize;

use holmes::{DB, Holmes};
use getopts::Options;
use std::env;
use bap::BitVector;

mod analyses;
mod schema;
mod ubvs;
mod typing;
mod sema;

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
      func!(let find_succs : (sema, bitvector) -> [bitvector] = analyses::successors);
      func!(let find_succs_upper : (sema, bitvector) -> ubvs = analyses::succ_wrap_upper);
      func!(let find_syms  : bytes -> [(string, bitvector)] = analyses::sym_wrap);
      func!(let lift : (arch, bitvector, bytes) -> (sema, bitvector) = analyses::lift_wrap);
      func!(let local_type : sema -> blocktype = typing::local_type);
      rule!(segment(name, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
      rule!(chunk(name, addr, chunk) <= segment(name, data, base, [_], [_], [_], [_]), {
        let [ {addr, chunk} ] = {chunk([base], [data])}
      });
      rule!(entry(name, sym_name, addr) <= file(name, in_bin), {
        let [ {sym_name, addr} ] = {find_syms([in_bin])}
      });
      rule!(live(file, addr) <= entry(file, ("main"), addr));
      rule!(sema(name, addr, sema, fall) <= live(name, addr) & chunk(name, addr, bin) & arch(name, arch), {
         let sema, fall = {lift([arch], [addr], [bin])}
      });
      rule!(insn_type(sema, typ) <= sema(name, [_], sema, [_]), {
          let typ = {local_type([sema])}
      });
      rule!(may_jump(name, src, sinks) <= sema(name, src, sema, fall), {
        let sinks = {find_succs_upper([sema], [fall])}
      });
      rule!(arch(name, arch) <= file(name, contents), {
        let arch = {get_arch_val([contents])}
      });
      fact!(file(in_path, in_bin))
    })
}
