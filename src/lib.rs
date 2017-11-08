#[macro_use]
extern crate holmes;
extern crate bap;
extern crate num;
#[macro_use]
extern crate postgres;
extern crate postgres_array;
extern crate bit_vec;
extern crate rustc_serialize;
use holmes::simple::*;
#[macro_use]
extern crate log;

extern crate mktemp;

use holmes::pg::dyn::values::LargeBWrap;
use bap::high::bitvector::BitVector;

mod analyses;
pub mod ubvs;
pub mod schema;
pub mod bvlist;
pub mod sema;
pub mod var;
pub mod chop;
use chop::Chop;
pub fn load_files(holmes: &mut Engine, in_paths: &[String]) -> Result<()> {
    let mut ins = Vec::new();
    for in_path in in_paths {
        use std::io::Read;
        let mut in_raw = Vec::new();
        let mut in_file = std::fs::File::open(&in_path).unwrap();
        in_file.read_to_end(&mut in_raw).unwrap();
        ins.push((in_path, LargeBWrap { inner: in_raw }))
    }
    for (in_path, in_bin) in ins {
        let in_path_owned = in_path.clone();
        fact!(holmes, file(in_path_owned, in_bin))?
    }
    Ok(())
}

// Feature summary:
// MULTI: Will buy us low fixed factor speedups throughout
// * Most of the gain could be found by merging is_call, lift, disas, and is_ret into a single
// record, since all properties are set on the output of the lifter
// * Gain that couldn't be gotten that way is mostly arch + segs, which are literally one-time deals
// DBPRED: Will buy us next to nothing
// * Only spot where this is useful at the moment is for looking up data in segments
// * Analyzed binary groups have normally had no more than 6 segments, this isn't a scaling situation
// * If analyzing a binary alongside a large number of shared libraries, this could become a
// problem
// * We currently _rarely_ access segments - just for ro string detection and once per instruction
// to lift, so no more than once per offset of the binary
// * If we ever add an executor which reads memory, this will become important
// FACT_ID: Minor performance improvement, medium code cleanliness and repeatability improvement
// * Segment ID becomes nondet if you load multiple binaries into the database, since order is not
// gauranteed
// * Using a hash for trace and stack IDs is icky
// * While we have an index that will make lookup by trace_id fast, lookup by their literal primary
// key will be faster.
// SHINGLE: Medium speed improvement, minor accuracy improvement?
// * Fewer jumps into bap
// * No changes to Holmes required
// * Avoid prematurely merging variable state sets (as often)
// * Shorter traces
pub fn basic_setup(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        // MULTI, low fixed cost
        func!(let get_arch_val : largebytes -> [uint64] = analyses::get_arch_val);
        // MULTI, low fixed cost
        // FACT_ID, small nondet
        func!(let seg_wrap : largebytes -> [(largebytes, uint64, bitvector, bitvector, bool, bool, bool)] = analyses::seg_wrap);
        func!(let find_succs : (sema, bitvector) -> [bitvector] = analyses::successors);
        func!(let find_succs_upper : (sema, bitvector) -> ubvs = analyses::succ_wrap_upper);
        // MULTI, low fixed cost
        func!(let find_syms  : bytes -> [bitvector] = analyses::sym_wrap);
        // SHINGLE MULTI, medium variable cost
        // Shingling will change it to just a 4x cost
        func!(let lift : (arch, bitvector, largebytes, uint64) -> [(sema, bitvector, string, bool, bool)] = analyses::lift_wrap);
        // SHINGLE MULTI, medium variable cost
        // Shingling will change it to just a 4x cost
        func!(let disas : (arch, bitvector, largebytes, uint64) -> [string] = analyses::disas_wrap);
        // DBPRED Could be eliminated with builtin lt predicate
        func!(let rebase : (bitvector, bitvector, bitvector, uint64) -> [(uint64, uint64)] = analyses::rebase);
        // Should be replaced with native impl
        func!(let find_pads : largebytes -> [(string, bitvector)] = analyses::get_pads);
        func!(let is_ret_reg : var -> bool = |v: &var::HVar| v == &var::get_ret());
        func!(let unpack_deb : largebytes -> [(string, largebytes)] = analyses::unpack_deb);
        func!(let is_computed_jump : sema -> bool = analyses::is_computed_jump);
        rule!(bap_dump_segments: segment(name, id, seg_contents, start, end, r, w, x) <= file(name, file_contents), {
        let [ {id, seg_contents, start, end, r, w, x} ] = {seg_wrap([file_contents])}
      });
        rule!(objdump_dump_plt: link_pad(bin_name, func_name, addr)  <= file(bin_name, contents), {
        let [ {func_name, addr} ] = {find_pads([contents])}
      });
        rule!(bap_dump_syms: entry(name, sym_name, addr, end) <= file(name, in_bin), {
        let [ {sym_name, addr, end} ] = {find_syms([in_bin])}
      });
        rule!(entries_live: live(name, addr) <= entry(name, [_], addr, [_]));
        rule!(segment_offsets: seglive(name, id, addr, start, end) <= live(name, addr) & segment(name, id, [_], seg_start, seg_end, [_], [_], [_]), {
        let [ {start, end} ] = {rebase([seg_start], [seg_end], [addr], (16))}
      });
        rule!(bap_sema: lift {
            binary = name,
            address = addr,
            bil = sema,
            disassembly = disasm,
            fallthrough = fall,
            is_call = call,
            is_ret = ret} <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let [ {sema, fall, disasm, call, ret} ] = {lift([arch], [addr], [bin], [start])}
      });
        rule!(sema_succ: succ(name, src, sink, c) <= lift {binary = name, address = src, bil = sema, fallthrough = fall, is_call = c}, {
        let [ sink ] = {find_succs([sema], [fall])}
      });
        rule!(skip_computed_calls: succ(name, src, fall, (false)) <= lift { binary = name, address = src, bil = sema, fallthrough = fall, is_call = (true)}, {
            let (true) = {is_computed_jump([sema])}
        });
        rule!(live_succ_live: live(name, sink) <= succ(name, src, sink, [_]));
        rule!(live_call_live: live(name, fall) <= lift { binary = name, address = src, fallthrough = fall, is_call = (true)});
        rule!(bap_arch: arch(name, arch) <= file(name, contents), {
        let [ arch ] = {get_arch_val([contents])}
      });

        // FACT May be better implemented via a pre-populated predicate
        func!(let is_free_name : string -> bool = |s : &String| (s == "free") || (s == "qfree") || (s == "g_free"));
        // FACT May be better implemented via a pre-populated predicate
        func!(let is_malloc_name : string -> bool = |s : &String| (s.contains("malloc")) || (s.contains("calloc")));
        rule!(free_call_by_name: free_call(name, addr) <= link_pad(name, func_name, tgt) & succ(name, addr, tgt, (true)), {
            let (true) = {is_free_name([func_name])}
        });
        rule!(malloc_call_by_name: malloc_call(name, addr) <= link_pad(name, func_name, tgt) & succ(name, addr, tgt, (true)), {
            let (true) = {is_malloc_name([func_name])}
        });
        rule!(puts_hack: func_uses(name, addr, (var::get_arg0())) <= link_pad(name, ("puts"), tgt) & succ(name, addr, tgt, (true)));
        rule!(skip_malloc: skip_func(name, addr) <= malloc_call(name, addr));
        rule!(skip_free: skip_func(name, addr) <= free_call(name, addr));
        //TODO This would be a place we want to circumscribe - we want to step over any function
        //that isn't present, but not the ones we have loaded up.
        rule!(skip_dyn: skip_func(name, addr) <= link_pad(name, [_], tgt) & succ(name, addr, tgt, (true)));
       rule!(unpack_deb: file(path, bin) <= deb_file([_], deb_bin), {
            let [ {path, bin} ] = {unpack_deb([deb_bin])}
        })
    })?;
    Ok(())
}

pub fn setup_stage2(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        rule!(succ_over_normal: succ_over(name, addr, next) <= succ(name, addr, next, (false)));
        rule!(succ_over_skip_call: succ_over(name, addr, next) <= succ(name, addr, tgt, (true)) & lift(name, addr, [_], next));
        rule!(call_site_internal: call_site(src_name, src_addr, src_name, dst_addr) <= succ(src_name, src_addr, dst_addr, (true)));
        rule!(call_site_dyn: call_site(src_name, src_addr, dst_name, dst_addr) <= link_pad(src_name, func_name, tgt) & succ(src_name, src_addr, tgt, (true)) & entry(dst_name, func_name, dst_addr, [_]));
        rule!(func_start: func(bin_name, addr, addr) <= entry(bin_name, func_name, addr, [_]));
        rule!(func_walk_over: func(bin_name, entry, addr2) <= func(bin_name, entry, addr) & succ_over(bin_name, addr, addr2))
    })
}

pub fn uaf_stage1(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        func!(let xfer_taint : (sema, var) -> [var] = analyses::xfer_taint);
        func!(let deref_var : (sema, var) -> bool = analyses::deref_var);
        func!(let stack_len_inc : uint64 -> [ uint64 ] = analyses::stack_len_inc);
        func!(let heap_init : sema -> [var] = analyses::heap_init);
        // This function is a bit unholy, and is working around the lack of ability to refer to
        // FactIds in the language itself.
        // FACTID nondet across revisions of compiler, perf hit, harder to read output
        func!(let hashify : (uint64, string, bitvector) -> uint64 = analyses::hashify);
        func!(let chop_check: (chop, bitvector) -> [chop] = |(chop, func): (&Chop, &BitVector)| chop.check(func));

        rule!(flow_start: path_alias(src_name, addr, (0), (0), (Chop::new()), src_name, step, (var::get_ret()), (false)) <= malloc_call(src_name, addr) & lift(src_name, addr, [_], step));
        rule!(flow_start_heap: path_alias(src_name, addr, sa, (0), (Chop::new()), src_name, step, heap_var, (false)) <= lift(src_name, addr, sema, step), {
            let [ {sa, [heap_var]} ] = {heap_init([sema])}
        });
        rule!(flow_free: path_alias(src_name, src, sa, stack, chop, free_name, next, af, (true)) <= path_alias(src_name, src, sa, stack, chop, free_name, free_addr, af, [_]) & path_alias(src_name, src, sa, stack, chop, free_name, free_addr, (var::get_arg0()), [_]) & free_call(free_name, free_addr) & lift(free_name, free_addr, [_], next));
        // TODO THIS CANNOT EXIST IN NORMAL CODE - IT WILL MAKE FREE FREE THE CONTENTS OF RSI,
        // WHICH WERE NOT PASSED TO IT
        rule!(flow_free_2_hack: path_alias(src_name, src, sa, stack, chop, free_name, next, af, (true)) <= path_alias(src_name, src, sa, stack, chop, free_name, free_addr, af, [_]) & path_alias(src_name, src, sa, stack, chop, free_name, free_addr, (var::get_arg_n(1)), [_]) & free_call(free_name, free_addr) & lift(free_name, free_addr, [_], next));
        // If there's a successor, follow that and transfer taint (but not if it's a call)
        rule!(flow_prop: path_alias(name, src, sa, stack, chop, cur_name, fut, var2, t) <= path_alias(name, src, sa, stack, chop, cur_name, cur, var, t) & lift(cur_name, cur, sema, [_]) & succ(cur_name, cur, fut, (false)), {
          let [ var2 ] = {xfer_taint([sema], [var])}
      });

        // Normally, if we don't have the function present, we have to stop the path analysis
        // In the case of malloc, we special case to just filter out the return variable
        // TODO clobber return _and_ standard clobbers
        // TODO do we need to xfer taint here? Maybe omit
        rule!(flow_skip_func: path_alias(name, src, sa, stack, chop, cur_name, fall, var2, t) <= path_alias(name, src, sa, stack, chop, cur_name, cur, var, t) & skip_func(cur_name, cur) & lift(cur_name, cur, sema, fall) , {
          let [ var2 ] = {xfer_taint([sema], [var])};
          let (false) = {is_ret_reg([var2])}
      });

        fact!(stack(0, 0, "", (BitVector::nil()), 0));

        // If we're at a call site, create a stack record
        rule!(flow_stack_push: stack(stack2, stack, cur_name, fall, len2) <= path_alias([_], [_], [_], stack, [_], cur_name, cur, var, [_]) & lift(cur_name, cur, sema, fall) & call_site(cur_name, cur, next_name, [_]) & stack{id = stack, len = len}, {
            let [ len2 ] = {stack_len_inc([len])};
            let stack2 = {hashify([stack], [cur_name], [fall])}
        });
        // If it's a call, a call_site instance will be generated, resolving dynamic calls if
        // needed. Add this onto the stack so any returns actually go here rather than anywhere
        rule!(flow_call: path_alias(name, src, sa, stack2, chop2, next_name, fut, var2, t) <= path_alias(name, src, sa, stack, chop, cur_name, cur, var, t) & lift(cur_name, cur, sema, fall) & call_site(cur_name, cur, next_name, fut) & stack(stack2, stack, cur_name, fall), {
            let [ chop2 ] = {chop_check([chop], [fut])};
            let [ var2 ] = {xfer_taint([sema], [var])}
        });
        // If it's a return and we have a stack, pop it
        rule!(flow_ret_pop: path_alias(src_name, src_addr, sa, stack2, chop, dst_name, dst_addr, var, t) <= path_alias(src_name, src_addr, sa, stack, chop, ret_name, ret_addr, var, t) & lift {binary = ret_name, address = ret_addr, is_ret = (true)} & stack(stack, stack2, dst_name, dst_addr));
        rule!(flow_final: use_after_free_flow(name, src, sa, stack, other, loc, var) <= path_alias(name, src, sa, stack, [_], other, loc, var, (true)) & lift(other, loc, sema, [_]), {
          let (true) = {deref_var([sema], [var])}
        });
        // puts uses the variable, but we're not anlyzing libc for now
        rule!(flow_final_func_use: use_after_free_flow(name, src, sa, stack, other, loc, var) <= path_alias(name, src, sa, stack, [_], other, loc, var, (true)) & func_uses(other, loc, var))

    })?;
    Ok(())
}

pub fn uaf_stage2(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        // If it's a return and an empty stack, return anywhere we were called
        rule!(flow_ret_notarget: path_alias(src_name, src_addr, sa, (0), chop2, call_name, dst_addr, var, t) <= path_alias(src_name, src_addr, sa, (0), chop, ret_name, ret_addr, var, t) & func(ret_name, func_addr, ret_addr) & call_site(call_name, call_addr, ret_name, func_addr) & lift {binary = ret_name, address = ret_addr, is_ret = (true)} & lift(call_name, call_addr, [_], dst_addr), {
            let [ chop2 ] = {chop_check([chop], [func_addr])}
        })
    })
}

pub fn const_prop(holmes: &mut Engine) -> Result<()> {
    // This is woefully inadequate for true constant propagation - since each instruction can read
    // multiple variables, and I don't have any kind of aggregation, monotonic or otherwise
    // available, I'd have to make a custom aggregation rule to do that. This would work, but would
    // slow down operation, and right now I don't really care about tracking through ops, just
    // through movs
    // This is also _wrong_ at the moment in that it's strict linear stepping - it ignores any
    // notion of jumps or calls or anything else. This is in large part because it is only an
    // advisory hack to discover the addresses of RO string constants for printf at the moment >_>
    holmes_exec!(holmes, {
        func!(let const_init : sema -> [(var, bitvector)] = analyses::const_init);
        func!(let const_prop : (sema, var, bitvector) -> [(var, bitvector)] = analyses::const_prop);
        rule!(const_init: poss_const(name, addr, var, k) <= lift(name, [_], sema, addr), {
            let [{var, k}] = {const_init([sema])}
        });
        rule!(const_prop: poss_const(name, addr, var2, k2) <= lift(name, prev, sema, addr) & poss_const(name, prev, var, k), {
            let [{var2, k2}] = {const_prop([sema], [var], [k])}
        })
    })
}

pub fn str_const(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        // DBPRED skip segment scan
        func!(let str_extract: (bitvector, bitvector, bitvector, largebytes) -> [string] = analyses::str_extract);
        // If it's an RO segment, go ahead and try to extract a string
        // TODO: for some reason, rodata segments are getting marked as unreadable. Skipping check
        // on that...
        rule!(addr_to_string: poss_string(name, addr, var, s) <= segment(name, [_], bin, start, end, [_], [_], [_]) & poss_const(name, addr, var, p), {
            let [ s ] = {str_extract([start], [end], [p], [bin])}
        })
    })
}

pub fn printf_formats(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        func!(let fmt_str_vars: string -> [var] = analyses::fmt_str_vars);
        fact!(printf_like(("failure")));
        // If it's an RO segment, go ahead and try to extract a string
        // TODO: for some reason, rodata segments are getting marked as unreadable. Skipping check
        // on that...
        rule!(format_string_calc: func_uses(name, addr, var) <= printf_like(func_name) & link_pad(name, func_name, tgt) & succ(name, addr, tgt, (true)) & poss_string(name, addr, (var::get_arg0()), fmt), {
            let [ var ] = {fmt_str_vars([fmt])}
        })
    })
}


pub fn uaf_trace_stage1(holmes: &mut Engine, trace_len: usize) -> Result<()> {
    holmes_exec!(holmes, {
        func!(let trace_inc_len : uint64 -> [ uint64 ] = analyses::trace_len_inc(trace_len));

        rule!(trace_start: path_alias_trace(src_name, addr, alias_set, (0), src_name, naddr, var, (false), (0)) <= use_after_free_flow {source_binary = src_name, source = addr, alias_set = alias_set} & path_alias(src_name, addr, sa, [_], [_], src_name, naddr, var) & succ_over(src_name, addr, naddr));

        rule!(trace_free: path_alias_trace(src_name, src, sa, stack, free_name, next, af, (true), len2) <= path_alias_trace(src_name, src, sa, stack, free_name, free_addr, af, [_], len) & path_alias_trace(src_name, src, sa, stack, free_name, free_addr, (var::get_arg0()), [_], len) & free_call(free_name, free_addr) & lift(free_name, free_addr, [_], next), {
            let [ len2 ] = {trace_inc_len([len])}
        });
        
        // TODO THIS CANNOT EXIST IN NORMAL CODE - IT WILL MAKE FREE FREE THE CONTENTS OF RSI,
        // WHICH WERE NOT PASSED TO IT
        rule!(trace_free_2_hack: path_alias_trace(src_name, src, sa, stack, free_name, next, af, (true), len2) <= path_alias_trace(src_name, src, sa, stack, free_name, free_addr, af, [_], len) & path_alias_trace(src_name, src, sa, stack, free_name, free_addr, (var::get_arg_n(1)), [_], len) & free_call(free_name, free_addr) & lift(free_name, free_addr, [_], next), {
            let [len2] = {trace_inc_len([len])}
        });
        // If there's a successor, follow that and transfer taint (but not if it's a call)
        rule!(trace_prop: path_alias_trace(name, src, sa, stack, cur_name, fut, var2, t, len2) <= path_alias_trace(name, src, sa, stack, cur_name, cur, var, t, len) & lift(cur_name, cur, sema, [_]) & succ(cur_name, cur, fut, (false)), {
          let [ var2 ] = {xfer_taint([sema], [var])};
          let [len2] = {trace_inc_len([len])}
        });

        // Normally, if we don't have the function present, we have to stop the path analysis
        // In the case of malloc, we special case to just filter out the return variable
        // TODO clobber return _and_ standard clobbers
        // TODO do we need to xfer taint here? Maybe omit
        rule!(trace_skip_func: path_alias_trace(name, src, sa, stack, cur_name, fall, var2, t, len2) <= path_alias_trace(name, src, sa, stack, cur_name, cur, var, t, len) & skip_func(cur_name, cur) & lift(cur_name, cur, sema, fall) , {
          let [ var2 ] = {xfer_taint([sema], [var])};
          let (false) = {is_ret_reg([var2])};
          let [ len2 ] = {trace_inc_len([len])}
      });

        // If it's a call, a call_site instance will be generated, resolving dynamic calls if
        // needed. Add this onto the stack so any returns actually go here rather than anywhere
        rule!(flow_call: path_alias_trace(name, src, sa, stack2, next_name, fut, var2, t, len2) <= path_alias_trace(name, src, sa, stack, cur_name, cur, var, t, len) & lift(cur_name, cur, sema, fall) & call_site(cur_name, cur, next_name, fut) & stack(stack2, stack, cur_name, fall), {
            let [ var2 ] = {xfer_taint([sema], [var])};
            let [ len2 ] = {trace_inc_len([len])}
        });
        // If it's a return and we have a stack, pop it
        rule!(trace_ret_pop: path_alias_trace(src_name, src_addr, sa, stack2, dst_name, dst_addr, var, t, len2) <= path_alias_trace(src_name, src_addr, sa, stack, ret_name, ret_addr, var, t, len) & lift {binary = ret_name, address = ret_addr, is_ret = (true)} & stack(stack, stack2, dst_name, dst_addr), {
            let [ len2 ] = {trace_inc_len([len])}
        })
    })?;
    Ok(())
}

pub fn uaf_trace_stage2(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, { 
        rule!(trace_ret_notarget: path_alias_trace(src_name, src_addr, sa, (0), call_name, dst_addr, var, t, len2) <= path_alias_trace(src_name, src_addr, sa, (0), ret_name, ret_addr, var, t, len) & func(ret_name, func_addr, ret_addr) & call_site(call_name, call_addr, ret_name, func_addr) & lift {binary = ret_name, address = ret_addr, is_ret = (true)} & lift(call_name, call_addr, [_], dst_addr), {
            let [ len2 ] = {trace_inc_len([len])}
        })
    })
}

pub fn grading(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        rule!(uaf_finalize: use_after_free(name, src, sa, other, loc, var, stack, len) <= path_alias_trace(name, src, sa, stack, other, loc, var, (true), len) & lift(other, loc, sema, [_]), {
          let (true) = {deref_var([sema], [var])}
        });
        // puts uses the variable, but we're not anlyzing libc for now
        rule!(uaf_finalize_func_uses: use_after_free(name, src, sa, other, loc, var, stack, len) <= path_alias_trace(name, src, sa, stack, other, loc, var, (true), len) & func_uses(other, loc, var));
        rule!(uaf_true_pos: true_positive(name, src, parent) <= use_after_free(name, src, sa, [_], [_], [_], stack, [_]) & bad_stack(stack, parent));
        rule!(uaf_false_pos: false_positive(name, src, parent) <= use_after_free(name, src, sa, [_], [_], [_], stack, [_]) & good_stack(stack, parent));
        rule!(uaf_bad_stack_prop: bad_stack(stack, parent) <= bad_stack(sub, parent) & stack(stack, sub, [_], [_]));
        rule!(uaf_good_stack_prop: good_stack(stack, parent) <= good_stack(sub, parent) & stack(stack, sub, [_], [_]));
        func!(let has_substr : (string, string) -> bool = |(hay, need) : (&String, &String)| hay.contains(need));
        rule!(uaf_bad_stack_base: bad_stack(stack, func_name) <= stack(stack, [_], name, addr) & func(name, func_addr, addr) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_bad"))}
        });
        rule!(uaf_good_stack_base: good_stack(stack, func_name) <= stack(stack, [_], name, addr) & func(name, func_addr, addr) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_good"))}
        });
        rule!(uaf_true_pos_top: true_positive(name, src, func_name) <= use_after_free(name, src, sa, name, loc) & func(name, func_addr, loc) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_bad"))}
        });
        rule!(uaf_false_pos_top: false_positive(name, src, func_name) <= use_after_free(name, src, sa, name, loc) & func(name, func_addr, loc) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_good"))}
        })
    })
}

pub fn uaf(in_paths: Vec<String>, trace_len: usize, kprop: bool) -> Box<Fn(&mut Engine, &mut Core) -> Result<()>> {
    Box::new(move |holmes, core| {
        schema::setup(holmes)?;
        load_files(holmes, &in_paths)?;
        info!("Files loaded");
        basic_setup(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("Basic analysis complete");
        setup_stage2(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("Basic analysis post-processing complete");
        if kprop {
            const_prop(holmes)?;
            core.run(holmes.quiesce()).unwrap();
            info!("Constant propagation complete");
            str_const(holmes)?;
            core.run(holmes.quiesce()).unwrap();
            info!("String constant detection complete");
            printf_formats(holmes)?;
            core.run(holmes.quiesce()).unwrap();
            info!("Printf-like argument usage information detected");
        }
        uaf_stage1(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("UAF Stage 1 complete");
        uaf_stage2(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("UAF Stage 2 complete");
        info!("Starting trace with length {}", trace_len);
        uaf_trace_stage1(holmes, trace_len)?;
        core.run(holmes.quiesce()).unwrap();
        info!("UAF Tracing Stage 1 complete");
        uaf_trace_stage2(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("UAF Tracing Stage 2 complete");
        grading(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("Grading Complete");
        Ok(())
    })
}
