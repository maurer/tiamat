use bap::BitVector;
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
    BVSet(Vec<BitVector>)
}

#[derive(Debug,Clone,Hash,PartialEq)]
pub struct UBVSType;
impl TypeT for UBVSType {
    fn name(&self) -> Option<&'static str> {
        Some("ubvs")
    }
    fn extract(&self, rows : &mut RowIter) -> Value {
        let raw : Option<Array<BitVec>> = rows.next().unwrap();
        Arc::new(match raw {
            None => UpperBVSet::Top,
            Some(repr) => UpperBVSet::BVSet(repr.iter().map(|bv|{BitVector::new(bv)}).collect())
        })
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
  fn to_sql<W: ?Sized>(&self, ty: &::postgres::types::Type, out: &mut W, ctx: &SessionInfo) -> Result<IsNull> 
      where Self: Sized, W: Write {
          match *self {
              UpperBVSet::Top => Ok(IsNull::Yes),
              UpperBVSet::BVSet(ref bvs) => {
                  let med : Array<&BitVec> = Array::from_vec(bvs.iter().map(|bv|{bv.to_bitvec()}).collect(), 0);
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
