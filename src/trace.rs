use bap::high::bitvector::BitVector;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres_array::Array;
use postgres::types::ToSql;
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use bit_vec::BitVec;
use std::any::Any;
use std::sync::Arc;

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq)]
pub struct Trace {
    names: Vec<String>,
    addrs: Vec<BitVector>,
    sql_addrs: Vec<BitVec>,
}

impl Trace {
    pub fn push(&mut self, name: String, addr: BitVector) {
        self.names.push(name);
        self.sql_addrs.push(addr.to_bitvec().clone());
        self.addrs.push(addr);
    }
    pub fn nil() -> Self {
        Self::load(vec![], vec![])
    }
    pub fn new(name: String, addr: BitVector) -> Self {
        Self::load(vec![name], vec![addr])
    }
    pub fn load(names: Vec<String>, addrs: Vec<BitVector>) -> Self {
        let sql_addrs = addrs
            .iter()
            .map(|addr| addr.to_bitvec().clone())
            .collect();
        Trace {
            names: names,
            addrs: addrs,
            sql_addrs: sql_addrs,
        }
    }
}

impl ::std::fmt::Display for Trace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        let mut ti = self.names.iter().zip(self.addrs.iter());
        write!(f, "{{")?;
        match ti.next() {
            None => (),
            Some((bin_name, addr)) => write!(f, "{}:{}", bin_name, addr)?,
        }
        for (bin_name, addr) in ti {
            write!(f, ", {}:{}", bin_name, addr)?
        }
        write!(f, "}}")
    }
}

#[derive(Debug,Clone,Hash,PartialEq)]
pub struct TraceType;
impl TypeT for TraceType {
    fn name(&self) -> Option<&'static str> {
        Some("trace")
    }
    fn extract(&self, rows: &mut RowIter) -> Option<Value> {
        let raw_names: Array<String> = rows.next().unwrap();
        let raw_addrs: Array<BitVec> = rows.next().unwrap();
        Some(Arc::new(Trace::load(raw_names.into_iter().collect(),
                                  raw_addrs.iter().map(|bv| BitVector::new(bv)).collect())))
    }
    fn repr(&self) -> Vec<String> {
        vec!["varchar[]".to_string(), "bit varying[]".to_string()]
    }
    typet_inner!();
    typet_inner_eq!();
    fn large(&self) -> Vec<usize> {
        vec![0]
    }
}

impl ValueT for Trace {
    fn type_(&self) -> Type {
        Arc::new(TraceType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![&self.names, &self.sql_addrs]
    }
    valuet_boiler!();
}

impl ToValue for Trace {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
