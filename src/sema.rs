use bap::Stmt;
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
use std::fmt;

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq,RustcDecodable,RustcEncodable)]
pub struct Sema {
    pub stmts: Vec<Stmt>
}

impl fmt::Display for Sema {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str("{\n"));
        for stmt in self.stmts.iter() {
            try!(write!(f, "{}\n", stmt));
        }
        f.write_str("}")
    }
}

impl ToJson for Sema {
    fn to_json(&self) -> Json {
        let buf = encode(self).unwrap();
        Json::from_str(&buf).unwrap()
    }
}

#[derive(Debug,Clone,Hash,PartialEq)]
pub struct SemaType;
impl TypeT for SemaType {
    fn name(&self) -> Option<&'static str> {
        Some("sema")
    }
    fn extract(&self, rows : &mut RowIter) -> Value {
        let raw : Json = rows.next().unwrap();
        let typed : Sema = {
            let mut decoder = Decoder::new(raw);
            Sema::decode(&mut decoder).unwrap()
        };
        Arc::new(typed)
    }
    fn repr(&self) -> Vec<String> {
        vec!["json".to_string()]
    }
    typet_boiler!(); 
}

impl ValueT for Sema {
    fn type_(&self) -> Type {
        Arc::new(SemaType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![self]
    }
    valuet_boiler!();
}

impl ToSql for Sema {
  accepts!(::postgres::types::Type::Jsonb, ::postgres::types::Type::Json);
  to_sql_checked!();
  fn to_sql<W: ?Sized>(&self, ty: &::postgres::types::Type, out: &mut W, ctx: &SessionInfo) -> Result<IsNull> 
      where Self: Sized, W: Write {
          self.to_json().to_sql(ty, out, ctx)
      }
}

impl ToValue for Sema {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
