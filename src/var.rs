use bap::expert::Var;
use bap;
use bit_vec::BitVec;
use bap::expert::Type::BitVector;
use holmes::pg::dyn::values::{ValueT, ToValue};
use holmes::pg::dyn::types::TypeT;
use postgres::Result;
use postgres::types::{ToSql, IsNull, SessionInfo};
use holmes::pg::RowIter;
use holmes::pg::dyn::{Type, Value};
use std::any::Any;
use std::sync::Arc;
use std::io::prelude::Write;
use rustc_serialize::json::{Json,Decoder,ToJson,encode};
use rustc_serialize::Decodable;

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq,RustcDecodable,RustcEncodable)]
pub struct HVar {
    pub inner: Var,
    pub offset: Option<bap::bitvector::BitVector>
}

impl ToJson for HVar {
    fn to_json(&self) -> Json {
        let buf = encode(self).unwrap();
        Json::from_str(&buf).unwrap()
    }
}

pub fn get_arg0() -> HVar {
    HVar {
        inner: Var {
            name: "RDI".to_string(),
            typ: BitVector(64),
            tmp: false,
            version: 0
        },
        offset: None
    }
}

pub fn get_ret() -> HVar {
    HVar {
        inner: Var {
            name: "RAX".to_string(),
            typ: BitVector(64),
            tmp: false,
            version: 0
        },
        offset: None
    }
}

#[derive(Debug,Clone,Hash,PartialEq)]
pub struct VarType;
impl TypeT for VarType {
    fn name(&self) -> Option<&'static str> {
        Some("var")
    }
    fn extract(&self, rows : &mut RowIter) -> Value {
        let raw : Json = rows.next().unwrap();
        let mut decoder = Decoder::new(raw);
        Arc::new(HVar::decode(&mut decoder).unwrap())
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
  accepts!(::postgres::types::Type::Jsonb, ::postgres::types::Type::Json);
  to_sql_checked!();
  fn to_sql<W: ?Sized>(&self, ty: &::postgres::types::Type, out: &mut W, ctx: &SessionInfo) -> Result<IsNull> 
      where Self: Sized, W: Write {
          self.to_json().to_sql(ty, out, ctx)
      }
}

impl ToValue for HVar {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
