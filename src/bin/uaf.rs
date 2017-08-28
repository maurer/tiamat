#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate bap;
extern crate num;
extern crate postgres;
extern crate postgres_array;
extern crate bit_vec;
extern crate rustc_serialize;
extern crate url;
extern crate env_logger;
extern crate time;
use holmes::PgDB;
use holmes::simple::*;
extern crate log;

extern crate mktemp;

extern crate tiamat;

use getopts::Options;
use url::percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET};
use std::io::Write;
use std::env;
use log::{LogRecord, LogLevelFilter};
use env_logger::LogBuilder;

fn url_encode(input: &[u8]) -> String {
    percent_encode(input, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn init_logger() {
    let format = |record: &LogRecord| {
        let t = time::now();
        format!(
            "{},{:03} - {} - {}",
            time::strftime("%Y-%m-%d %H:%M:%S", &t).unwrap(),
            t.tm_nsec / 1000_000,
            record.level(),
            record.args()
        )
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
            format!(
                "postgresql://holmes@{}/holmes",
                url_encode(&dir.into_bytes())
            )
        }
        _ => format!("postgres://holmes@%2Fvar%2Frun%2Fpostgresql/holmes"),
    };
    let default_in = "a.out";
    let mut opts = Options::new();
    opts.optmulti("i", "in", "binary to process", default_in);
    opts.optopt(
        "d",
        "database",
        "database connection string",
        &db_default_addr,
    );
    opts.optflag("h", "help", "print usage and exit");
    opts.optflag("s", "skip", "skip over functions not present in the current binary");
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
    let uaf = tiamat::uaf(in_paths);
    uaf(&mut holmes, &mut core).unwrap();
    if matches.opt_present("s") {
        rule!(holmes, skip_func(name, addr) <= link_pad(name, [_], tgt)).unwrap();
    }
    // Judge
    {
        use std::collections::HashSet;
        let mut true_positives = HashSet::new();
        for row in query!(holmes, true_positive([_], [_], name))
            .unwrap()
            .into_iter()
        {
            true_positives.insert(row[0].get().downcast_ref::<String>().unwrap().clone());
        }
        let mut false_positives = HashSet::new();
        for row in query!(holmes, false_positive([_], [_], name))
            .unwrap()
            .into_iter()
        {
            false_positives.insert(row[0].get().downcast_ref::<String>().unwrap().clone());
        }
        println!("True Positives: {}\nFalse Positives: {}", true_positives.len(), false_positives.len());
    }
    dump(&mut holmes, "use_after_free");
    dump(&mut holmes, "use_after_free_flow");
    dump(&mut holmes, "path_alias");
    dump(&mut holmes, "path_alias_trace");
}

fn dump(holmes: &mut Engine, target: &str) {
    let data = holmes.render(&target.to_string()).unwrap();
    let mut out_fd = std::fs::File::create(format!("{}.html", target)).unwrap();
    out_fd.write_all(data.as_bytes()).unwrap();
}
