pub use sqlx_core::error::Error;
pub use sqlx_core::row::Row;
pub use sqlx_postgres::PgPool;

pub mod postgres {
    pub use sqlx_postgres::PgPoolOptions;
}

pub fn query(
    sql: &str,
) -> sqlx_core::query::Query<'_, sqlx_postgres::Postgres, sqlx_postgres::PgArguments> {
    sqlx_core::query::query::<sqlx_postgres::Postgres>(sql)
}
