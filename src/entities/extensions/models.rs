use sea_orm::{EntityTrait, QueryFilter, Select, ColumnTrait};
use sea_orm::sea_query::Value;

pub trait ByColumn: EntityTrait + Sized {
    fn by<V>(col: Self::Column, val: V) -> Select<Self>
    where
        V: Into<Value>,
    {
        Self::find().filter(col.eq(val))
    }
}

impl<E> ByColumn for E where E: EntityTrait + Sized {}