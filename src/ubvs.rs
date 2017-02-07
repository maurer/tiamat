use bap::high::bitvector::BitVector;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres::Result;
use postgres::types::{ToSql, IsNull, SessionInfo};
use postgres_array::Array;
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use bit_vec::BitVec;
use std::any::Any;
use std::sync::Arc;
use std::io::prelude::Write;

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq)]
pub enum UpperBVSet {
    Top,
    BVSet(Vec<BitVector>),
}

impl ::std::fmt::Display for UpperBVSet {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        match *self {
            UpperBVSet::Top => write!(f, "T"),
            UpperBVSet::BVSet(ref bvs) => {
                let mut bvi = bvs.iter();
                write!(f, "{{")?;
                match bvi.next() {
                    None => (),
                    Some(bv) => write!(f, "{}", bv)?,
                }
                for bv in bvi {
                    write!(f, ", {}", bv)?;
                }
                write!(f, "}}")
            }
        }
    }
}

#[derive(Debug,Clone,Hash,PartialEq)]
pub struct UBVSType;
impl TypeT for UBVSType {
    fn name(&self) -> Option<&'static str> {
        Some("ubvs")
    }
    fn extract(&self, rows: &mut RowIter) -> Option<Value> {
        let raw: Option<Array<BitVec>> = rows.next().unwrap();
        Some(Arc::new(match raw {
            None => UpperBVSet::Top,
            Some(repr) => UpperBVSet::BVSet(repr.iter().map(|bv| BitVector::new(bv)).collect()),
        }))
    }
    fn repr(&self) -> Vec<String> {
        vec!["bit varying[]".to_string()]
    }
    typet_boiler!();
}

impl ValueT for UpperBVSet {
    fn type_(&self) -> Type {
        Arc::new(UBVSType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![self]
    }
    valuet_boiler!();
}

impl ToSql for UpperBVSet {
    accepts!(::postgres::types::Type::VarbitArray);
    to_sql_checked!();
    fn to_sql(&self,
              ty: &::postgres::types::Type,
              out: &mut Vec<u8>,
              ctx: &SessionInfo)
              -> ::std::result::Result<IsNull, Box<::std::error::Error + Send + Sync>> {
        match *self {
            UpperBVSet::Top => Ok(IsNull::Yes),
            UpperBVSet::BVSet(ref bvs) => {
                let med: Array<&BitVec> =
                    Array::from_vec(bvs.iter().map(|bv| bv.to_bitvec()).collect(), 0);
                med.to_sql(ty, out, ctx)
            }
        }
    }
}

impl ToValue for UpperBVSet {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
