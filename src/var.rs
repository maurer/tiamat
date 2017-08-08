use bap;
use bap::high::bitvector::BitVector;
use bap::high::bil::Variable;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres::types::{ToSql, IsNull};
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use std::any::Any;
use std::sync::Arc;
use rustc_serialize::json::{Json, Decoder, ToJson, encode};
use rustc_serialize::Decodable;

#[derive(Debug, Clone, Hash, PartialOrd, PartialEq, RustcDecodable, RustcEncodable)]
pub struct HVar {
    pub inner: Variable,
    pub offset: Option<BitVector>,
}

impl HVar {
    pub fn not_temp(&self) -> bool {
        !self.inner.tmp
    }
}

impl ToJson for HVar {
    fn to_json(&self) -> Json {
        let buf = encode(self).unwrap();
        Json::from_str(&buf).unwrap()
    }
}

pub fn get_arg0() -> HVar {
    HVar {
        inner: Variable {
            name: "RDI".to_string(),
            type_: bap::high::bil::Type::Immediate(64),
            tmp: false,
            index: 0,
        },
        offset: None,
    }
}

pub fn get_ret() -> HVar {
    HVar {
        inner: Variable {
            name: "RAX".to_string(),
            type_: bap::high::bil::Type::Immediate(64),
            tmp: false,
            index: 0,
        },
        offset: None,
    }
}

#[derive(Debug, Clone, Hash, PartialEq)]
pub struct VarType;
impl TypeT for VarType {
    fn name(&self) -> Option<&'static str> {
        Some("var")
    }
    fn extract(&self, rows: &mut RowIter) -> Option<Value> {
        let raw: Json = rows.next().unwrap();
        let mut decoder = Decoder::new(raw);
        Some(Arc::new(HVar::decode(&mut decoder).unwrap()))
    }
    fn repr(&self) -> Vec<String> {
        vec!["jsonb".to_string()]
    }
    typet_boiler!();
}

impl ValueT for HVar {
    fn type_(&self) -> Type {
        Arc::new(VarType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![self]
    }
    valuet_boiler!();
}

impl ToSql for HVar {
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

impl ToValue for HVar {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}

// TODO placeholder
impl ::std::fmt::Display for HVar {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        write!(f, "{}", self.inner)?;
        match self.offset {
            Some(ref off) => write!(f, "+{}", off),
            None => Ok(()),
        }
    }
}
