use super::super::RedisPool;
use super::super::section;
use super::super::section::dsl::section as all_sections;
use sapper_std::Context;

use chrono::NaiveDateTime;
use diesel;
use diesel::PgConnection;
use diesel::pg::expression::dsl::any;
use diesel::prelude::*;
use uuid::Uuid;

use std::sync::Arc;

#[derive(Queryable, Debug, Clone, Deserialize, Serialize)]
pub struct Section {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub stype: i32, // 0 section, 1 user blog
    pub suser: Option<Uuid>,
    pub created_time: NaiveDateTime,
    pub status: i16, // 0 normal, 1 frozen, 2 deleted
}

impl Section {
    pub fn query(conn: &PgConnection) -> Result<Vec<Self>, String> {
        let res = all_sections
            .filter(section::status.eq(0))
            .order(section::created_time.desc())
            .get_results::<Self>(conn);
        match res {
            Ok(data) => Ok(data),
            Err(err) => Err(format!("{}", err)),
        }
    }

    pub fn query_by_stype(conn: &PgConnection, stype: i32) -> Result<Vec<Self>, String> {
        let res = all_sections
            .filter(section::status.eq(0))
            .filter(section::stype.eq(stype))
            .order(section::created_time.desc())
            .get_results::<Self>(conn);
        match res {
            Ok(data) => Ok(data),
            Err(err) => Err(format!("{}", err)),
        }
    }

    pub fn query_with_section_id(conn: &PgConnection, id: Uuid) -> Result<Self, String> {
        let res = all_sections
            .filter(section::status.eq(0))
            .filter(section::id.eq(id))
            .first::<Self>(conn);
        match res {
            Ok(data) => {
                // println!("data {:?}", data);
                Ok(data)
            }
            Err(err) => Err(format!("{}", err)),
        }
    }

    pub fn query_with_user_id(conn: &PgConnection, id: Uuid) -> Result<Self, String> {
        let res = all_sections
            .filter(section::status.eq(0))
            .filter(section::suser.eq(id))
            .first::<Self>(conn);
        match res {
            Ok(data) => {
                // println!("data {:?}", data);
                Ok(data)
            }
            Err(err) => Err(format!("{}", err)),
        }
    }

    pub fn delete_with_id(conn: &PgConnection, id: Uuid) -> bool {
        diesel::update(all_sections.filter(section::id.eq(id)))
            .set(section::status.eq(2))
            .execute(conn)
            .is_ok()
    }

    pub fn query_with_redis_queue(
        conn: &PgConnection,
        redis_pool: &Arc<RedisPool>,
        key: &'static str,
    ) -> Result<Vec<Self>, String> {
        if redis_pool.exists(key) {
            let section_ids_string = redis_pool.lrange::<Vec<String>>(key, 0, -1);
            let section_ids: Vec<Uuid> = section_ids_string
                .into_iter()
                .map(|id_str| id_str.parse::<Uuid>().unwrap())
                .collect();

            let res = all_sections
                .filter(section::status.eq(0))
                .filter(section::id.eq(any(section_ids)))
                .get_results::<Self>(conn);
            match res {
                Ok(data) => Ok(data),
                Err(err) => Err(format!("{}", err)),
            }
        } else {
            Ok(vec![])
        }
    }

    pub fn query_with_redis_queue_paging(
        conn: &PgConnection,
        redis_pool: &Arc<RedisPool>,
        key: &'static str,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Self>, i64), String> {
        if redis_pool.exists(key) {
            let section_ids_string = redis_pool.lrange::<Vec<String>>(key,  -page * page_size, -((page - 1) * page_size + 1));
            let section_ids_len: i64 = redis_pool.llen(key);
            let section_ids: Vec<Uuid> = section_ids_string
                .into_iter()
                .map(|id_str| id_str.parse::<Uuid>().unwrap())
                .collect();

            let res = all_sections
                .filter(section::status.eq(0))
                .filter(section::id.eq(any(section_ids)))
                .get_results::<Self>(conn);
            match res {
                Ok(data) => Ok((data, section_ids_len)),
                Err(err) => Err(format!("{}", err)),
            }
        } else {
            Ok((vec![], 0))
        }
    }
}

#[derive(Insertable, Debug, Clone, Deserialize, Serialize)]
#[table_name = "section"]
pub struct InsertSection {
    pub title: String,
    pub description: String,
    pub stype: i32,
    pub suser: Option<Uuid>,
}

impl InsertSection {
    pub fn insert(self, conn: &PgConnection) -> bool {
        diesel::insert_into(section::table)
            .values(&self)
            .execute(conn)
            .is_ok()
    }
}

// for redis
#[derive(Deserialize, Serialize)]
pub struct PubNotice {
    pub title: String,
    pub desc: String,
}

impl PubNotice {
    pub fn insert(self, redis_pool: &Arc<RedisPool>) {
        redis_pool.hset("pub_notice", "title", self.title);
        redis_pool.hset("pub_notice", "desc", self.desc);
    }

    pub fn get(web: &mut Context, redis_pool: &Arc<RedisPool>) {
        if redis_pool.exists("pub_notice") {
            let title = redis_pool.hget::<String>("pub_notice", "title");
            let desc = redis_pool.hget::<String>("pub_notice", "desc");
            web.add("title", &title);
            web.add("desc", &desc);
        }
    }
}
