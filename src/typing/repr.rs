use bap::BitVector;
use std::collections::BTreeMap;
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
pub enum ValType {
    Var(u64),
    R { width : usize },
    UInt { width : usize },
    Int { width : usize },
    Ptr (Box<ValType>),
    PPtr (BTreeMap<i64, ValType>),
    Code (Box<BlockType>)
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ValType::*;
        match *self {
            Var(v) => write!(f, "τ{}", v),
            R {width: width} => write!(f, "r{}", width),
            UInt {width: width} => write!(f, "u{}", width),
            Int {width: width} => write!(f, "i{}", width),
            Ptr(ref typ) => write!(f, "{}*", typ),
            //TODO(low) fix these printers to be prettier
            PPtr(ref map) => write!(f, "{{{:?}}}", map),
            Code(ref bt) => write!(f, "%{:?}", bt)
        }
    }
}

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq,RustcDecodable,RustcEncodable)]
pub enum Assume {
    AddrType {
        addr: BitVector,
        typ:  BlockType
    },
    FallType {
        typ: BlockType
    }
}

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq,RustcDecodable,RustcEncodable)]
pub enum Stack {
    Var(u64),
    Alloc(Box<Stack>),
    Release(Box<Stack>),
    With {base: Box<Stack>,
          slots: BTreeMap<i64, ValType>},
}

#[derive(Debug,Clone,Hash,PartialOrd,PartialEq,RustcDecodable,RustcEncodable)]
pub struct BlockType {
    pub register_file: BTreeMap<String, ValType>,
    pub stack: Stack,
    pub assumes: Vec<Assume>
}

impl ToJson for BlockType {
    fn to_json(&self) -> Json {
        let buf = encode(self).unwrap();
        Json::from_str(&buf).unwrap()
    }
}

#[derive(Debug,Clone,Hash,PartialEq)]
pub struct BlockTypeType;
impl TypeT for BlockTypeType {
    fn name(&self) -> Option<&'static str> {
        Some("blocktype")
    }
    fn extract(&self, rows : &mut RowIter) -> Value {
        let raw : Json = rows.next().unwrap();
        let typed : BlockType = {
            let mut decoder = Decoder::new(raw);
            BlockType::decode(&mut decoder).unwrap()
        };
        Arc::new(typed)
    }
    fn repr(&self) -> Vec<String> {
        vec!["json".to_string()]
    }
    typet_boiler!(); 
}

impl ValueT for BlockType {
    fn type_(&self) -> Type {
        Arc::new(BlockTypeType)
    }
    fn get(&self) -> &Any {
        self as &Any
    }
    fn to_sql(&self) -> Vec<&ToSql> {
        vec![self]
    }
    valuet_boiler!();
}

impl ToSql for BlockType {
  accepts!(::postgres::types::Type::Jsonb, ::postgres::types::Type::Json);
  to_sql_checked!();
  fn to_sql<W: ?Sized>(&self, ty: &::postgres::types::Type, out: &mut W, ctx: &SessionInfo) -> Result<IsNull> 
      where Self: Sized, W: Write {
          self.to_json().to_sql(ty, out, ctx)
      }
}

impl ToValue for BlockType {
    fn to_value(self) -> Value {
        Arc::new(self)
    }
}
