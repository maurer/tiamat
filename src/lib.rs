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
        func!(let lift : (arch, bitvector, largebytes, uint64) -> [(sema, bitvector)] = analyses::lift_wrap);
        // SHINGLE MULTI, medium variable cost
        // Shingling will change it to just a 4x cost
        func!(let disas : (arch, bitvector, largebytes, uint64) -> [string] = analyses::disas_wrap);
        // DBPRED Could be eliminated with builtin lt predicate
        func!(let rebase : (bitvector, bitvector, bitvector, uint64) -> [(uint64, uint64)] = analyses::rebase);
        // Should be replaced with native impl
        func!(let find_pads : largebytes -> [(string, bitvector)] = analyses::get_pads);
        // SHINGLE MULTI, medium variable cost
        // Shingling will change it to just a 4x cost
        func!(let is_ret : (arch, bitvector, largebytes, uint64) -> [bool] = analyses::is_ret);
        // SHINGLE MULTI, medium variable cost
        // Shingling will change it to just a 4x cost
        func!(let is_call : (arch, bitvector, largebytes, uint64) -> [bool] = analyses::is_call);
        func!(let is_ret_reg : var -> bool = |v: &var::HVar| v == &var::get_ret());
        func!(let unpack_deb : largebytes -> [(string, largebytes)] = analyses::unpack_deb);
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
        rule!(bap_disasm: disasm(name, addr, dis) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let [ dis ] = {disas([arch], [addr], [bin], [start])}
      });
        rule!(bap_sema: sema(name, addr, sema, fall) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
         let [ {sema, fall} ] = {lift([arch], [addr], [bin], [start])}
      });
        rule!(sema_succ: succ(name, src, sink, c) <= sema(name, src, sema, fall) & is_call(name, src, c), {
        let [ sink ] = {find_succs([sema], [fall])}
      });
        rule!(live_succ_live: live(name, sink) <= live(name, src) & succ(name, src, sink, [_]));
        rule!(live_call_live: live(name, fall) <= sema(name, src, [_], fall) & is_call(name, src, (true)));
        rule!(bap_is_ret: is_ret(name, addr) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
            let [ (true) ] = {is_ret([arch], [addr], [bin], [start])}
        });
        rule!(bap_is_call: is_call(name, addr, call) <= seglive(name, id, addr, start, end) & segment(name, id, bin, [_], [_], [_], [_], [_]) & arch(name, arch), {
            let [ call ] = {is_call([arch], [addr], [bin], [start])}
        });
        rule!(bap_arch: arch(name, arch) <= file(name, contents), {
        let [ arch ] = {get_arch_val([contents])}
      });

        rule!(succ_over_normal: succ_over(name, addr, next) <= succ(name, addr, next, (false)));
        rule!(succ_over_skip_call: succ_over(name, addr, next) <= succ(name, addr, tgt, (true)) & sema(name, addr, [_], next));

        // FACT May be better implemented via a pre-populated predicate
        func!(let is_free_name : string -> bool = |s : &String| (s == "free") || (s == "qfree"));
        // FACT May be better implemented via a pre-populated predicate
        func!(let is_malloc_name : string -> bool = |s : &String| (s == "malloc") || (s == "xmalloc") || (s == "calloc") || (s == "xcalloc") || (s == "qcalloc") || (s == "qmalloc"));
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
        rule!(func_start: func(bin_name, addr, addr) <= entry(bin_name, func_name, addr, [_]));
        rule!(func_walk_over: func(bin_name, entry, addr2) <= func(bin_name, entry, addr) & succ_over(bin_name, addr, addr2));
        rule!(call_site_internal: call_site(src_name, src_addr, src_name, dst_addr) <= succ(src_name, src_addr, dst_addr, (true)));
        rule!(call_site_dyn: call_site(src_name, src_addr, dst_name, dst_addr) <= link_pad(src_name, func_name, tgt) & succ(src_name, src_addr, tgt, (true)) & entry(dst_name, func_name, dst_addr, [_]));
        rule!(unpack_deb: file(path, bin) <= deb_file([_], deb_bin), {
            let [ {path, bin} ] = {unpack_deb([deb_bin])}
        })
    })?;
    Ok(())
}

pub fn uaf_stage1(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        func!(let xfer_taint : (sema, var) -> [var] = analyses::xfer_taint);
        func!(let deref_var : (sema, var) -> bool = analyses::deref_var);
        func!(let stack_len_inc : uint64 -> [ uint64 ] = analyses::stack_len_inc);
        // This function is a bit unholy, and is working around the lack of ability to refer to
        // FactIds in the language itself.
        // FACTID nondet across revisions of compiler, perf hit, harder to read output
        func!(let hashify : (uint64, string, bitvector) -> uint64 = analyses::hashify);
        rule!(flow_start: path_alias(src_name, addr, (0), src_name, step, (var::get_ret()), (false)) <= malloc_call(src_name, addr) & sema(src_name, addr, [_], step));
        rule!(flow_free: path_alias(src_name, src, stack, free_name, next, af, (true)) <= path_alias(src_name, src, stack, free_name, free_addr, af, [_]) & path_alias(src_name, src, stack, free_name, free_addr, (var::get_arg0()), [_]) & free_call(free_name, free_addr) & sema(free_name, free_addr, [_], next));
        // TODO THIS CANNOT EXIST IN NORMAL CODE - IT WILL MAKE FREE FREE THE CONTENTS OF RSI,
        // WHICH WERE NOT PASSED TO IT
        rule!(flow_free_2_hack: path_alias(src_name, src, stack, free_name, next, af, (true)) <= path_alias(src_name, src, stack, free_name, free_addr, af, [_]) & path_alias(src_name, src, stack, free_name, free_addr, (var::get_arg_n(1)), [_]) & free_call(free_name, free_addr) & sema(free_name, free_addr, [_], next));
        // If there's a successor, follow that and transfer taint (but not if it's a call)
        rule!(flow_prop: path_alias(name, src, stack, cur_name, fut, var2, t) <= path_alias(name, src, stack, cur_name, cur, var, t) & sema(cur_name, cur, sema, [_]) & succ(cur_name, cur, fut, (false)), {
          let [ var2 ] = {xfer_taint([sema], [var])}
      });

        // Normally, if we don't have the function present, we have to stop the path analysis
        // In the case of malloc, we special case to just filter out the return variable
        // TODO clobber return _and_ standard clobbers
        // TODO do we need to xfer taint here? Maybe omit
        rule!(flow_skip_func: path_alias(name, src, stack, cur_name, fall, var2, t) <= path_alias(name, src, stack, cur_name, cur, var, t) & skip_func(cur_name, cur) & sema(cur_name, cur, sema, fall) , {
          let [ var2 ] = {xfer_taint([sema], [var])};
          let (false) = {is_ret_reg([var2])}
      });

        fact!(stack(0, 0, "", (BitVector::nil()), 0));

        // If we're at a call site, create a stack record
        rule!(flow_stack_push: stack(stack2, stack, cur_name, fall, len2) <= path_alias([_], [_], stack, cur_name, cur, var, [_]) & sema(cur_name, cur, sema, fall) & call_site(cur_name, cur, next_name, [_]) & stack{id = stack, len = len}, {
            let [ len2 ] = {stack_len_inc([len])};
            let stack2 = {hashify([stack], [cur_name], [fall])}
        });
        // If it's a call, a call_site instance will be generated, resolving dynamic calls if
        // needed. Add this onto the stack so any returns actually go here rather than anywhere
        rule!(flow_call: path_alias(name, src, stack2, next_name, fut, var2, t) <= path_alias(name, src, stack, cur_name, cur, var, t) & sema(cur_name, cur, sema, fall) & call_site(cur_name, cur, next_name, fut) & stack(stack2, stack, cur_name, fall), {
        let [ var2 ] = {xfer_taint([sema], [var])}
        });

        // If it's a return and we have a stack, pop it
        rule!(flow_ret_pop: path_alias(src_name, src_addr, stack2, dst_name, dst_addr, var, t) <= path_alias(src_name, src_addr, stack, ret_name, ret_addr, var, t) & is_ret(ret_name, ret_addr) & stack(stack, stack2, dst_name, dst_addr));
        rule!(flow_final: use_after_free_flow(name, src, stack, other, loc, var) <= path_alias(name, src, stack, other, loc, var, (true)) & sema(other, loc, sema, [_]), {
          let (true) = {deref_var([sema], [var])}
        });
        // puts uses the variable, but we're not anlyzing libc for now
        rule!(flow_final_func_use: use_after_free_flow(name, src, stack, other, loc, var) <= path_alias(name, src, stack, other, loc, var, (true)) & func_uses(other, loc, var))

    })?;
    Ok(())
}

pub fn uaf_stage2(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        // If it's a return and an empty stack, return anywhere we were called
        rule!(flow_ret_notarget: path_alias(src_name, src_addr, (0), call_name, dst_addr, var, t) <= path_alias(src_name, src_addr, (0), ret_name, ret_addr, var, t) & func(ret_name, func_addr, ret_addr) & call_site(call_name, call_addr, ret_name, func_addr) & is_ret(ret_name, ret_addr) & sema(call_name, call_addr, [_], dst_addr))
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
        rule!(const_init: poss_const(name, addr, var, k) <= sema(name, [_], sema, addr), {
            let [{var, k}] = {const_init([sema])}
        });
        rule!(const_prop: poss_const(name, addr, var2, k2) <= sema(name, prev, sema, addr) & poss_const(name, prev, var, k), {
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


pub fn uaf_trace_stage1(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        func!(let trace_len_inc : uint64 -> [ uint64 ] = analyses::trace_len_inc);

        // is_normal is derived for calls which don't need special handling
        rule!(uaf_trace_normal_call: is_normal(name, addr) <= link_pad(name, func_name, tgt) & succ(name, addr, tgt, (true)), {
            let (false) = {is_malloc_name([func_name])};
            let (false) = {is_free_name([func_name])}
        });

        // Produce a one-step trace with an empty stack at every uaf_flow malloc site
        rule!(trace_null_malloc: trace(trace, (0), (0), name, addr, (1)) <= use_after_free_flow(name, addr, [_], [_], [_], [_]), {
            let trace = {hashify((0), [name], [addr])}
        });

        // If we hae a non-call succ, just extend the trace
        rule!(trace_step: trace(trace2, stack, trace, name, addr2, len2) <= trace(trace, stack, [_], name, addr, len) & succ(name, addr, addr2, (false)), {
            let [ len2 ] = {trace_len_inc([len])};
            let trace2 = {hashify([trace], [name], [addr2])}
        }); 

        // If we have a skipped function, just extend the trace to the fallthrough
        rule!(trace_skip_func: trace(trace2, stack, trace, name, fall, len2) <= trace(trace, stack, [_], name, addr, len) & skip_func(name, addr) & sema(name, addr, [_], fall), {
            let [ len2 ] = {trace_len_inc([len])};
            let trace2 = {hashify([trace], [name], [fall])}
        }); 

        // If we have a return and a stack, extend the trace to the return value
        rule!(trace_ret_pop: trace(trace2, stack2, trace, dst_name, dst_addr, len2) <= trace(trace, stack, [_], ret_name, ret_addr, len) & is_ret(ret_name, ret_addr) & stack(stack, stack2, dst_name, dst_addr), {
            let [ len2 ] = {trace_len_inc([len])};
            let trace2 = {hashify([trace], [dst_name], [dst_addr])}
        });

        // If we have a trace to a call, extend the stack
        rule!(trace_call_push: trace(trace2, stack2, trace, tgt_name, tgt_addr, len2) <= trace(trace, stack, [_], call_name, call_addr, len) & call_site(call_name, call_addr, tgt_name, tgt_addr) & sema(call_name, call_addr, [_], fall) & stack(stack2, stack, call_name, fall), {
            let [ len2 ] = {trace_len_inc([len])};
            let trace2 = {hashify([trace], [tgt_name], [tgt_addr])}
        });

        // If we have a return and no stack, extend the trace anywhere we can go
        rule!(trace_ret_untargeted: trace(trace2, (0), trace, call_name, dst_addr, len2) <= trace(trace, (0), [_], ret_name, ret_addr, len)  & func(ret_name, func_addr, ret_addr) & call_site(call_name, call_addr, ret_name, func_addr) & is_ret(ret_name, ret_addr) & sema(call_name, call_addr, [_], dst_addr), {
            let [ len2 ] = {trace_len_inc([len])};
            let trace2 = {hashify([trace], [call_name], [dst_addr])}
        })
    })
}

pub fn uaf_trace_stage2(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, { 
        // Initialize with a trace right after malloc
        rule!(uaf_trace_malloc: path_alias_trace(src_name, addr, (var::get_ret()), (false), trace) <= use_after_free_flow(src_name, addr, [_], [_], [_], [_]) & trace(trace, (0), (0), src_name, addr, [_]));

        // If something is free'd, upgrade the alias set at that tracepoint
        rule!(uaf_trace_free: path_alias_trace(src_name, src, var, (true), trace2) <= path_alias_trace(src_name, src, (var::get_arg0()), [_], trace) & path_alias_trace(src_name, src, var, [_], trace) & free_call(free_name, free_addr) & trace(trace2, [_], trace, free_name, free_addr, [_]));

        // If the instruction is not a call or return, advance
        rule!(uaf_trace_step: path_alias_trace(name, src, var2, t, trace2) <= path_alias_trace(name, src, var, t, trace) & trace(trace2, [_], trace, cur_name, cur, [_]) & sema(cur_name, cur, sema, [_]) & succ(cur_name, cur, [_], (false)), {
          let [ var2 ] = {xfer_taint([sema], [var])}
        });

        // Erase return reg on skipped function call
        rule!(uaf_trace_skip_func: path_alias_trace(name, src, var, t, trace2) <= path_alias_trace(name, src, var, t, trace) & skip_func(cur_name, cur) & sema(cur_name, cur, sema, [_]) & trace(trace2, [_], trace, cur_name, cur, [_]), {
            let (false) = {is_ret_reg([var])}
        });

        // On followed function call, propagate
        rule!(uaf_trace_call: path_alias_trace(name, src, var, t, trace2) <= path_alias_trace(name, src, var, t, trace) & trace(trace2, [_], trace, cur_name, cur, [_]) & succ(cur_name, cur, next, (true)));
        // On followed return, propagate
        rule!(uaf_trace_ret: path_alias_trace(name, src, var, t, trace2) <= path_alias_trace(name, src, var, t, trace) & trace(trace2, [_], trace, cur_name, cur, [_]) & is_ret(cur_name, cur))
    })
}

pub fn grading(holmes: &mut Engine) -> Result<()> {
    holmes_exec!(holmes, {
        rule!(uaf_finalize: use_after_free(name, src, other, loc, var, trace2) <= path_alias_trace(name, src, var, (true), trace) & trace(trace2, [_], trace, other, loc, [_]) & sema(other, loc, sema, [_]), {
          let (true) = {deref_var([sema], [var])}
        });
        // puts uses the variable, but we're not anlyzing libc for now
        rule!(uaf_finalize_func_uses: use_after_free(name, src, other, loc, var, trace) <= path_alias_trace(name, src, var, (true), trace) & func_uses(other, loc, var) & trace(trace2, [_], trace, other, loc, [_]));
        rule!(uaf_true_pos: true_positive(name, src, parent) <= use_after_free(name, src, [_], [_], [_], trace) & trace(trace, stack, [_], [_], [_], [_]) & bad_stack(stack, parent));
        rule!(uaf_false_pos: false_positive(name, src, parent) <= use_after_free(name, src, [_], [_], [_], trace) & trace(trace, stack, [_], [_], [_], [_]) & good_stack(stack, parent));
        rule!(uaf_bad_stack_prop: bad_stack(stack, parent) <= bad_stack(sub, parent) & stack(stack, sub, [_], [_]));
        rule!(uaf_good_stack_prop: good_stack(stack, parent) <= good_stack(sub, parent) & stack(stack, sub, [_], [_]));
        func!(let has_substr : (string, string) -> bool = |(hay, need) : (&String, &String)| hay.contains(need));
        rule!(uaf_bad_stack_base: bad_stack(stack, func_name) <= stack(stack, [_], name, addr) & func(name, func_addr, addr) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_bad"))}
        });
        rule!(uaf_good_stack_base: good_stack(stack, func_name) <= stack(stack, [_], name, addr) & func(name, func_addr, addr) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_good"))}
        });
        rule!(uaf_true_pos_top: true_positive(name, src, func_name) <= use_after_free(name, src, [_], [_], [_], trace) & trace(trace, [_], [_], name, loc, [_]) & func(name, func_addr, loc) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_bad"))}
        });
        rule!(uaf_false_pos_top: false_positive(name, src, func_name) <= use_after_free(name, src, [_], [_], [_], trace) & trace(trace, [_], [_], name, loc, [_]) & func(name, func_addr, loc) & entry(name, func_name, func_addr, [_]), {
            let (true) = {has_substr([func_name], ("_good"))}
        })
    })
}

pub fn uaf(in_paths: Vec<String>) -> Box<Fn(&mut Engine, &mut Core) -> Result<()>> {
    Box::new(move |holmes, core| {
        schema::setup(holmes)?;
        load_files(holmes, &in_paths)?;
        info!("Files loaded");
        basic_setup(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("Basic analysis complete");
        //const_prop(holmes)?;
        //core.run(holmes.quiesce()).unwrap();
        //info!("Constant propagation complete");
        //str_const(holmes)?;
        //core.run(holmes.quiesce()).unwrap();
        //info!("String constant detection complete");
        //printf_formats(holmes)?;
        //core.run(holmes.quiesce()).unwrap();
        //info!("Printf-like argument usage information detected");
        uaf_stage1(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("UAF Stage 1 complete");
        uaf_stage2(holmes)?;
        core.run(holmes.quiesce()).unwrap();
        info!("UAF Stage 2 complete");
        uaf_trace_stage1(holmes)?;
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
