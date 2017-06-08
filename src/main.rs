#![feature(alloc_system)]

extern crate alloc_system;
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
extern crate time;
use std::io::BufRead;
use holmes::PgDB;
use holmes::simple::*;
#[macro_use]
extern crate log;

extern crate mktemp;

use getopts::Options;
use url::percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET};
use holmes::pg::dyn::values::LargeBWrap;
use std::io::Write;
use std::env;
use log::{LogRecord, LogLevelFilter};
use env_logger::LogBuilder;

mod analyses;
mod schema;
mod ubvs;
mod bvlist;
mod stack;
mod typing;
mod sema;
mod var;

fn url_encode(input: &[u8]) -> String {
    percent_encode(input, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn init_logger() {
    let format = |record: &LogRecord| {
        let t = time::now();
        format!("{},{:03} - {} - {}",
                time::strftime("%Y-%m-%d %H:%M:%S", &t).unwrap(),
                t.tm_nsec / 1000_000,
                record.level(),
                record.args())
    };

    let rust_log = env::var("RUST_LOG").unwrap();

    LogBuilder::new()
        .format(format)
        .filter(None, LogLevelFilter::Off)
        .parse(&rust_log)
        .init()
        .unwrap();
}

fn main() {
    init_logger();
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
    let db_addr = matches
        .opt_str("d")
        .unwrap_or(db_default_addr.to_string());
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
    dump(&mut holmes, "disasm");
    dump(&mut holmes, "succ");
    dump(&mut holmes, "true_positive");
    dump(&mut holmes, "false_positive");
    dump(&mut holmes, "use_after_free");
}

fn dump(holmes: &mut Engine, target: &str) {
    let data = holmes.render(&target.to_string()).unwrap();
    let mut out_fd = std::fs::File::create(format!("{}.html", target)).unwrap();
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

    let empty_stack = stack::Stack(vec![], bvlist::BVList(vec![]));

    try!(schema::setup(holmes));

    holmes_exec!(holmes, {
        func!(let get_arch_val : largebytes -> [uint64] = analyses::get_arch_val);
        func!(let seg_wrap : largebytes -> [(largebytes, uint64, bitvector, bitvector, bool, bool, bool)] = analyses::seg_wrap);
        func!(let find_succs : (sema, bitvector) -> [bitvector] = analyses::successors);
        func!(let find_succs_upper : (sema, bitvector) -> ubvs = analyses::succ_wrap_upper);
        func!(let find_syms  : bytes -> [bitvector] = analyses::sym_wrap);
        func!(let lift : (arch, bitvector, largebytes, uint64) -> [(sema, bitvector)] = analyses::lift_wrap);
        func!(let disas : (arch, bitvector, largebytes, uint64) -> [string] = analyses::disas_wrap);
        func!(let rebase : (bitvector, bitvector, bitvector, uint64) -> [(uint64, uint64)] = analyses::rebase);
        func!(let find_pads : largebytes -> [(string, bitvector)] = analyses::get_pads);
        func!(let xfer_taint : (sema, var) -> [var] = analyses::xfer_taint);
        func!(let push_stack : (stack, string, bitvector) -> stack = analyses::push_stack);
        func!(let pop_stack : stack -> [(stack, string, bitvector)] = analyses::pop_stack);
        func!(let deref_var : (sema, var) -> bool = analyses::deref_var);
        func!(let is_ret : (arch, bitvector, largebytes, uint64) -> [bool] = analyses::is_ret);
        func!(let is_call : (arch, bitvector, largebytes, uint64) -> [bool] = analyses::is_call);
        func!(let find_parent : (string, string, bitvector, bitvector, bitvector, stack, string) -> [string] = analyses::find_parent);
        func!(let unpack_deb : largebytes -> [(string, largebytes)] = analyses::unpack_deb);
        rule!(segment(name, id, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {id, seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
        rule!(link_pad(bin_name, func_name, addr)  <= file(bin_name, contents), {
        let [ {func_name, addr} ] = {find_pads([contents])}
      });
        rule!(entry(name, sym_name, addr, end) <= file(name, in_bin), {
        let [ {sym_name, addr, end} ] = {find_syms([in_bin])}
      });
        rule!(live(name, addr) <= entry(name, [_], addr, [_]));
        rule!(seglive(name, id, addr, start, end) <= live(name, addr) & segment(name, id, [_], seg_start, seg_end, [_], [_], [_]), {
        let [ {start, end} ] = {rebase([seg_start], [seg_end], [addr], (16))}
      });
        rule!(disasm(name, addr, dis) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let [ dis ] = {disas([arch], [addr], [bin], [start])}
      });
        rule!(sema(name, addr, sema, fall) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let [ {sema, fall} ] = {lift([arch], [addr], [bin], [start])}
      });
        rule!(succ(name, src, sink, c) <= sema(name, src, sema, fall) & is_call(name, src, c), {
        let [ sink ] = {find_succs([sema], [fall])}
      });
        rule!(may_jump(name, src, sinks) <= sema(name, src, sema, fall), {
        let sinks = {find_succs_upper([sema], [fall])}
      });
        rule!(live(name, sink) <= live(name, src) & succ(name, src, sink, [_]));
        rule!(live(name, fall) <= sema(name, src, [_], fall) & is_call(name, src, (true)));
        rule!(is_ret(name, addr) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
            let [ (true) ] = {is_ret([arch], [addr], [bin], [start])}
        });
        rule!(is_call(name, addr, call) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
            let [ call ] = {is_call([arch], [addr], [bin], [start])}
        });
        rule!(arch(name, arch) <= file(name, contents), {
        let [ arch ] = {get_arch_val([contents])}
      });

        // Add stepover edge (this is kinda janky, since this is a place I'd like to circumscribe)
        rule!(succ(name, addr, next, (false)) <= succ(name, addr, tgt, (true)) & link_pad(name, [_], tgt) & sema(name, addr, [_], next));

        rule!(free_call(name, addr) <= link_pad(name, ("free"), tgt) & succ(name, addr, tgt, (true)));
        rule!(malloc_call(name, addr) <= link_pad(name, ("malloc"), tgt) & succ(name, addr, tgt, (true)));
        rule!(using_call(name, addr) <= link_pad(name, ("puts"), tgt) & succ(name, addr, tgt, (true)));
        rule!(path_alias(src_name, addr, (empty_stack.clone()), src_name, step, (var::get_ret()), (false)) <= malloc_call(src_name, addr) & sema(src_name, addr, [_], step));
        rule!(path_alias(src_name, src, stack, free_name, next, (var::get_arg0()), (true)) <= path_alias(src_name, src, stack, free_name, free_addr, (var::get_arg0()), [_]) & free_call(free_name, free_addr) & sema(free_name, free_addr, [_], next));
        // Upgrade set on free
        // If two pointers come from the same allocation site, they may alias. Upgrade them to
        // freed if anything was freed, just in case
        rule!(path_alias(name, src, stack, cur_name, cur, var, (true)) <= path_alias(name, src, stack, cur_name, cur, var, (false)) & path_alias(name, src, stack, cur_name, cur, [_], (true)));
        // If there's a successor, follow that and transfer taint (but not if it's a call)
        rule!(path_alias(name, src, stack, cur_name, fut, var2, t) <= path_alias(name, src, stack, cur_name, cur, var, t) & sema(cur_name, cur, sema, [_]) & succ(cur_name, cur, fut, (false)), {
          let [ var2 ] = {xfer_taint([sema], [var])}
      });
        // If it's a call, a call_site instance will be generated, resolving dynamic calls if
        // needed. Add this onto the stack so any returns actually go here rather than anywhere
        rule!(path_alias(name, src, stack2, next_name, fut, var2, t) <= path_alias(name, src, stack, cur_name, cur, var, t) & sema(cur_name, cur, sema, fall) & call_site(cur_name, cur, next_name, fut), {
        let stack2 = {push_stack([stack], [cur_name], [fall])};
        let [ var2 ] = {xfer_taint([sema], [var])}
        });

        // If it's a return and an empty stack, return anywhere we were called
        rule!(path_alias(src_name, src_addr, (empty_stack.clone()), call_name, dst_addr, var, t) <= path_alias(src_name, src_addr, (empty_stack.clone()), ret_name, ret_addr, var, t) & func(ret_name, func_addr, ret_addr) & call_site(call_name, call_addr, ret_name, func_addr) & is_ret(ret_name, ret_addr) & sema(call_name, call_addr, [_], dst_addr));
        // If it's a return and we have a stack, pop it
        rule!(path_alias(src_name, src_addr, stack2, dst_name, dst_addr, var, t) <= path_alias(src_name, src_addr, stack, ret_name, ret_addr, var, t) & is_ret(ret_name, ret_addr), {
            let [ {stack2, dst_name, dst_addr} ] = {pop_stack([stack]) }
        });
        rule!(use_after_free(name, src, stack, other, loc, var) <= path_alias(name, src, stack, other, loc, var, (true)) & sema(other, loc, sema, [_]), {
          let (true) = {deref_var([sema], [var])}
        });
        // puts uses the variable, but we're not anlyzing libc for now
        rule!(use_after_free(name, src, stack, other, loc, (var::get_arg0())) <= path_alias(name, src, stack, other, loc, (var::get_arg0()), (true)) & using_call(other, loc));

        rule!(func(bin_name, addr, addr) <= entry(bin_name, func_name, addr, [_]));
        rule!(func(bin_name, entry, addr2) <= func(bin_name, entry, addr) & succ(bin_name, addr, addr2, (false)));
        rule!(call_site(src_name, src_addr, src_name, dst_addr) <= succ(src_name, src_addr, dst_addr, (true)));
        rule!(call_site(src_name, src_addr, dst_name, dst_addr) <= link_pad(src_name, func_name, tgt) & succ(src_name, src_addr, tgt, (true)) & entry(dst_name, func_name, dst_addr, [_]));
        // TODO there's a bit of overrestriction on name here
        rule!(true_positive(name, src, parent) <= use_after_free(name, src, stack, [_], [_], [_]) & entry(name, sym_name, sym_start, sym_end), {
            let [parent] = {find_parent([name], [sym_name], [sym_start], [sym_end], [src], [stack], ("_bad"))}
        });
        rule!(false_positive(name, src, parent) <= use_after_free(name, src, stack, [_], [_], [_]) & entry(name, sym_name, sym_start, sym_end), {
            let [parent] = {find_parent([name], [sym_name], [sym_start], [sym_end], [src], [stack], ("_good"))}
        });
        rule!(file(path, bin) <= deb_file([_], deb_bin), {
            let [ {path, bin} ] = {unpack_deb([deb_bin])}
        })
    })?;
    for (in_path, in_bin) in ins {
        fact!(holmes, deb_file(in_path, in_bin))?
    }
    Ok(())
}
