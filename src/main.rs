#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
extern crate num;
#[macro_use]
extern crate postgres;
extern crate postgres_array;
extern crate bit_vec;
extern crate rustc_serialize;
extern crate url;

use holmes::{DB, Holmes};
use getopts::Options;
use std::env;
use bap::BitVector;
use url::percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET};
use holmes::pg::dyn::values::LargeBWrap;

mod analyses;
mod schema;
mod ubvs;
mod typing;
mod sema;

fn url_encode(input : &[u8]) -> String {
      percent_encode(input, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn main() {
  let db_default_addr = match env::var("TIAMAT_PG_SOCK_DIR") {
      Ok(dir) => format!("postgresql://holmes@{}/holmes", url_encode(&dir.into_bytes())),
      _ => format!("postgres://holmes@%2Fvar%2Frun%2Fpostgresql/holmes")
  };
  let default_in = "a.out";
  let mut opts = Options::new();
  opts.optopt("i", "in", "binary to process", default_in);
  opts.optopt("d", "database", "database connection string",
              &db_default_addr); 
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
    let mut in_raw = Vec::new();
    {
      use std::io::Read;
      let mut in_file = try!(std::fs::File::open(&in_path));
      try!(in_file.read_to_end(&mut in_raw));
    }

    let in_bin = LargeBWrap {inner: in_raw}; 

    try!(schema::setup(holmes));

    holmes_exec!(holmes, {
      func!(let get_arch_val : bytes -> uint64 = analyses::get_arch_val);
      func!(let seg_wrap : bytes -> [(bytes, uint64, bitvector, bitvector, bool, bool, bool)] = analyses::seg_wrap);
      func!(let find_succs : (sema, bitvector) -> [bitvector] = analyses::successors);
      func!(let find_succs_upper : (sema, bitvector) -> ubvs = analyses::succ_wrap_upper);
      func!(let find_syms  : bytes -> [bitvector] = analyses::sym_wrap);
      func!(let lift : (arch, bitvector, bytes) -> (sema, bitvector) = analyses::lift_wrap);
      func!(let rebase : (bitvector, bitvector, bitvector, uint64) -> [(uint64, uint64)] = analyses::rebase);
      rule!(segment(name, id, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {id, seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
      rule!(entry(name, addr) <= file(name, in_bin), {
        let [ addr ] = {find_syms([in_bin])}
      });
      rule!(live(name, addr) <= entry(name, addr));
      rule!(seglive(name, id, addr, start, end) <= live(name, addr) & segment(name, id, [_], seg_start, seg_end, [_], [_], [_]), {
        let [ {start, end} ] = {rebase([seg_start], [seg_end], [addr], (16))}
      }); 
      rule!(sema(name, addr, sema, fall) <= seglive(name, id, addr, start, end) & segment(name, id, {[start], [end], bin}, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let sema, fall = {lift([arch], [addr], [bin])}
      });
      rule!(succ(name, src, sink) <= sema(name, src, sema, fall), {
        let [ sink ] = {find_succs([sema], [fall])}
      });
      rule!(may_jump(name, src, sinks) <= sema(name, src, sema, fall), {
        let sinks = {find_succs_upper([sema], [fall])}
      });
      rule!(live(name, sink) <= live(name, src) & succ(name, src, sink));
      rule!(arch(name, arch) <= file(name, contents), {
        let arch = {get_arch_val([contents])}
      });
      fact!(file(in_path, in_bin))
    })
}
