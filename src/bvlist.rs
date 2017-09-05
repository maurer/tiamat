use bap::high::bitvector::BitVector;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres::types::{ToSql, IsNull};
use postgres_array::Array;
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use bit_vec::BitVec;
use std::any::Any;
use std::sync::Arc;

#[derive(Debug, Clone, Hash, PartialOrd, PartialEq)]
pub struct BVList(pub Vec<BitVector>);

impl ::std::fmt::Display for BVList {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        use std::fmt::Debug;
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Hash, PartialEq)]
pub struct BVListType;
impl TypeT for BVListType {
    fn name(&self) -> Option<&'static str> {
        Some("bvlist")
    }
    fn extract(&self, rows: &mut RowIter) -> Option<Value> {
        let raw: Array<BitVec> = rows.next().unwrap();
        Some(Arc::new(
            BVList(raw.iter().map(|bv| BitVector::new(bv)).collect()),
        ))
    }
    fn repr(&self) -> &'static str {
        "bit varying[] not null"
    }
    typet_boiler!();
}

impl ValueT for BVList {
    fn type_(&self) -> Type {
        Arc::new(BVListType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![self]
    }
    valuet_boiler!();
}

impl ToSql for BVList {
    accepts!(::postgres::types::VARBIT_ARRAY);
    to_sql_checked!();
    fn to_sql(
        &self,
        ty: &::postgres::types::Type,
        out: &mut Vec<u8>,
    ) -> ::std::result::Result<IsNull, Box<::std::error::Error + Send + Sync>> {
        let med: Array<&BitVec> =
            Array::from_vec(self.0.iter().map(|bv| bv.to_bitvec()).collect(), 0);
        med.to_sql(ty, out)
    }
}

impl ToValue for BVList {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
