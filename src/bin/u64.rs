#[macro_use]
extern crate holmes;
extern crate getopts;
extern crate url;
extern crate env_logger;
extern crate time;
use holmes::PgDB;
use holmes::simple::*;
extern crate log;
extern crate bap;
extern crate tiamat;
extern crate num;

use bap::high::bitvector::BitVector;

use getopts::Options;
use url::percent_encoding::{percent_encode, PATH_SEGMENT_ENCODE_SET};
use std::env;
use log::{LogRecord, LogLevelFilter};
use env_logger::LogBuilder;
use num::traits::ToPrimitive;
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
    opts.optflag(
        "s",
        "skip",
        "skip over functions not present in the current binary",
    );
    let mut args = env::args();
    let prog_name = args.next().unwrap();
    let matches = opts.parse(args).unwrap_or_else(|x| panic!(x));
    if matches.opt_present("h") {
        let brief = format!("{} -i INFILE -d DBSTRING", prog_name);
        println!("{}", opts.usage(&brief));
        return;
    }
    let db_addr = matches.opt_str("d").unwrap_or(db_default_addr.to_string());

    let mut core = Core::new().unwrap();
    let db = PgDB::new(&db_addr).unwrap();
    let mut holmes = Engine::new(db, core.handle());
    tiamat::schema::setup(&mut holmes).unwrap();
    predicate!(holmes, path_alias_u(uint64, uint64, var, bool)).unwrap();
    func!(holmes, let to64 : bitvector -> uint64 = |bv: &BitVector| bv.to_u64().unwrap()).unwrap();
    rule!(holmes, path_alias_to_u64: path_alias_u(alloc64, cur64, var, freed) <= path_alias([_], alloc, [_], [_], cur, var, freed), {
        let cur64 = {to64([cur])};
        let alloc64 = {to64([alloc])}
    }).unwrap();
    core.run(holmes.quiesce()).unwrap();
}
