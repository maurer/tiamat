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
extern crate env_logger;
use std::io::BufRead;
use holmes::PgDB;
use holmes::simple::*;
#[macro_use]
extern crate log;

use getopts::Options;
use std::env;
use url::percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET};
use holmes::pg::dyn::values::LargeBWrap;
use std::io::Write;

mod analyses;
mod schema;
mod ubvs;
mod typing;
mod sema;
mod var;

fn url_encode(input: &[u8]) -> String {
    percent_encode(input, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn main() {
    env_logger::init().unwrap();
    let db_default_addr = match env::var("TIAMAT_PG_SOCK_DIR") {
        Ok(dir) => {
            format!("postgresql://holmes@{}/holmes",
                    url_encode(&dir.into_bytes()))
        }
        _ => format!("postgres://holmes@%2Fvar%2Frun%2Fpostgresql/holmes"),
    };
    let default_in = "a.out";
    let mut opts = Options::new();
    opts.optmulti("i", "in", "binary to process", default_in);
    opts.optopt("d",
                "database",
                "database connection string",
                &db_default_addr);
    opts.optflag("h", "help", "print usage and exit");
    opts.optflag("s",
                 "step",
                 "single step when enter is hit, close stdin to go to quiescence");
    let mut args = env::args();
    let prog_name = args.next().unwrap();
    let matches = opts.parse(args).unwrap_or_else(|x| panic!(x));
    if matches.opt_present("h") {
        let brief = format!("{} -i INFILE -d DBSTRING", prog_name);
        println!("{}", opts.usage(&brief));
        return;
    }
    let db_addr = matches.opt_str("d").unwrap_or(db_default_addr.to_string());
    let in_paths = matches.opt_strs("i");

    let mut core = Core::new().unwrap();
    let db = PgDB::new(&db_addr).unwrap();
    let mut holmes = Engine::new(db, core.handle());
    holmes_prog(&mut holmes, in_paths).unwrap();
    let stdin = ::std::io::stdin();
    let ls = stdin.lock();
    if matches.opt_present("s") {
        for line in ls.lines() {
            core.turn(None);
        }
    }
    core.run(holmes.quiesce()).unwrap();
    let data = holmes.render(&"use_after_free".to_string()).unwrap();
    let mut out_fd = std::fs::File::create("out.html").unwrap();
    out_fd.write_all(data.as_bytes()).unwrap();
}

fn holmes_prog(holmes: &mut Engine, in_paths: Vec<String>) -> Result<()> {
    let mut ins = Vec::new();
    for in_path in in_paths {
        use std::io::Read;
        let mut in_raw = Vec::new();
        let mut in_file = std::fs::File::open(&in_path).unwrap();
        in_file.read_to_end(&mut in_raw).unwrap();
        ins.push((in_path, LargeBWrap { inner: in_raw }))
    }


    try!(schema::setup(holmes));

    holmes_exec!(holmes, {
        func!(let get_arch_val : bytes -> uint64 = analyses::get_arch_val);
        func!(let seg_wrap : bytes -> [(bytes, uint64, bitvector, bitvector, bool, bool, bool)] = analyses::seg_wrap);
        func!(let find_succs : (sema, bitvector) -> [bitvector] = analyses::successors);
        func!(let find_succs_upper : (sema, bitvector) -> ubvs = analyses::succ_wrap_upper);
        func!(let find_syms  : bytes -> [bitvector] = analyses::sym_wrap);
        func!(let lift : (arch, bitvector, bytes) -> (sema, bitvector) = analyses::lift_wrap);
        func!(let disas : (arch, bitvector, bytes) -> string = analyses::disas_wrap);
        func!(let rebase : (bitvector, bitvector, bitvector, uint64) -> [(uint64, uint64)] = analyses::rebase);
        func!(let find_pads : string -> [(string, bitvector)] = analyses::get_pads);
        func!(let xfer_taint : (sema, var) -> [var] = analyses::xfer_taint);
        func!(let deref_var : (sema, var) -> bool = analyses::deref_var);
        rule!(segment(name, id, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {id, seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
        rule!(link_pad(bin_name, func_name, addr)  <= file(bin_name, [_]), {
        let [ {func_name, addr} ] = {find_pads([bin_name])}
      });
        rule!(entry(name, sym_name, addr) <= file(name, in_bin), {
        let [ {sym_name, addr} ] = {find_syms([in_bin])}
      });
        rule!(live(name, addr) <= entry(name, [_], addr));
        rule!(seglive(name, id, addr, start, end) <= live(name, addr) & segment(name, id, [_], seg_start, seg_end, [_], [_], [_]), {
        let [ {start, end} ] = {rebase([seg_start], [seg_end], [addr], (16))}
      });
        rule!(disasm(name, addr, dis) <= seglive(name, id, addr, start, end) & segment(name, id, {[start], [end], bin}, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let dis = {disas([arch], [addr], [bin])}
      });
        rule!(sema(name, addr, sema, fall) <= seglive(name, id, addr, start, end) & segment(name, id, {[start], [end], bin}, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let {sema, fall} = {lift([arch], [addr], [bin])}
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

        // Add stepover edge (this is kinda janky, since this is a place I'd like to circumscribe)
        rule!(succ(name, addr, next) <= succ(name, addr, tgt) & link_pad(name, [_], tgt) & sema(name, addr, [_], next));

        rule!(free_call(name, addr) <= link_pad(name, ("free"), tgt) & succ(name, addr, tgt));
        rule!(malloc_call(name, addr) <= link_pad(name, ("malloc"), tgt) & succ(name, addr, tgt));

        rule!(path_alias(name, addr, step, (var::get_ret()), (false)) <= malloc_call(name, addr) & sema(name, addr, [_], step));
        rule!(path_alias(name, src, next, (var::get_arg0()), (true)) <= path_alias(name, src, free_addr, (var::get_arg0()), [_]) & free_call(name, free_addr) & sema(name, free_addr, [_], next));
        // Upgrade set on free
        rule!(path_alias(name, src, cur, var, (true)) <= path_alias(name, src, cur, var, (false)) & path_alias(name, src, cur, [_], (true)));
        rule!(path_alias(name, src, fut, var2, t) <= path_alias(name, src, cur, var, t) & sema(name, cur, sema, [_]) & succ(name, cur, fut), {
          let [ var2 ] = {xfer_taint([sema], [var])}
      });
        rule!(use_after_free(name, src, loc, var) <= path_alias(name, src, loc, var, (true)) & sema(name, loc, sema, [_]), {
          let (true) = {deref_var([sema], [var])}
      })
    })?;
    for (in_path, in_bin) in ins {
        fact!(holmes, file(in_path, in_bin))?
    }
    Ok(())
}
