use bap::high::bitvector::BitVector;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres::types::{ToSql, IsNull};
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use std::any::Any;
use std::sync::Arc;
use rustc_serialize::json::{Json, Decoder, ToJson, encode};
use rustc_serialize::Decodable;

#[derive(Debug, Clone, Hash, PartialOrd, PartialEq, RustcDecodable, RustcEncodable, Eq)]
pub struct Chop {
    members: Vec<BitVector>,
}

impl ToJson for Chop {
    fn to_json(&self) -> Json {
        let buf = encode(self).unwrap();
        Json::from_str(&buf).unwrap()
    }
}

const MAX_CHOP: usize = 3;

impl Chop {
    pub fn new() -> Self {
        Chop {
            members: Vec::new()
        }
    }
    pub fn check(&self, func: &BitVector) -> Vec<Chop> {
        let mut members = self.members.clone();
        if !members.contains(func) {
            members.push(func.clone());
            members.sort();
        }
        if members.len() <= MAX_CHOP {
            vec![Chop { members: members } ]
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq)]
pub struct ChopType;
impl TypeT for ChopType {
    fn name(&self) -> Option<&'static str> {
        Some("chop")
    }
    fn extract(&self, rows: &mut RowIter) -> Option<Value> {
        let raw: Json = rows.next().unwrap();
        let mut decoder = Decoder::new(raw);
        Some(Arc::new(Chop::decode(&mut decoder).unwrap()))
    }
    fn repr(&self) -> &'static str {
        "jsonb"
    }
    typet_boiler!();
}

impl ValueT for Chop {
    fn type_(&self) -> Type {
        Arc::new(ChopType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![self]
    }
    valuet_boiler!();
}

impl ToSql for Chop {
    accepts!(::postgres::types::JSONB, ::postgres::types::JSON);
    to_sql_checked!();
    fn to_sql(
        &self,
        ty: &::postgres::types::Type,
        out: &mut Vec<u8>,
    ) -> ::std::result::Result<IsNull, Box<::std::error::Error + Send + Sync>> {
        self.to_json().to_sql(ty, out)
    }
}

impl ToValue for Chop {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}

// TODO placeholder
impl ::std::fmt::Display for Chop {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        write!(f, "{:?}", self.members)
    }
}
