use bap::high::bitvector::BitVector;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres::Result;
use postgres::types::{ToSql, IsNull};
use postgres_array::Array;
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use bit_vec::BitVec;
use std::any::Any;
use std::sync::Arc;
use std::io::prelude::Write;
use bvlist::BVList;

#[derive(Debug, Clone, Hash, PartialOrd, PartialEq)]
pub struct Stack(pub Vec<String>, pub BVList);

impl ::std::fmt::Display for Stack {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        use std::fmt::Debug;
        self.0.fmt(f)?;
        (self.1).0.fmt(f)
    }
}

#[derive(Debug, Clone, Hash, PartialEq)]
pub struct StackType;
impl TypeT for StackType {
    fn name(&self) -> Option<&'static str> {
        Some("stack")
    }
    fn extract(&self, rows: &mut RowIter) -> Option<Value> {
        let names: Array<String> = rows.next().unwrap();
        let addrs: Array<BitVec> = rows.next().unwrap();
        Some(Arc::new(Stack(
            names.iter().cloned().collect(),
            BVList(addrs.iter().map(|bv| BitVector::new(bv)).collect()),
        )))
    }
    fn repr(&self) -> Vec<String> {
        vec![
            "varchar[] not null".to_string(),
            "bit varying[] not null".to_string(),
        ]
    }
    typet_boiler!();
}

impl ValueT for Stack {
    fn type_(&self) -> Type {
        Arc::new(StackType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![&self.0, &self.1]
    }
    valuet_boiler!();
}

impl ToValue for Stack {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
