use sapper::{Request, Response, Result as SapperResult, SapperModule, SapperRouter};
use sapper::header::{ContentType, Location};
use sapper::status;
use sapper_std::{set_cookie, JsonParams, QueryParams};
use serde_json;
use uuid::Uuid;

use super::super::{LoginUser, NewArticleStats, Postgresql, RUser, Redis, RegisteredUser,
                   UserNotify, Section};
use super::super::{inner_get_github_nickname_and_address, inner_get_github_token};
use super::super::models::{Article, CommentWithNickName};
use super::super::page_size;
use super::super::{get_real_ip_from_req, get_ruser_from_session, get_user_agent_from_req};

pub struct Visitor;

impl Visitor {
    fn login(req: &mut Request) -> SapperResult<Response> {
        let body: LoginUser = get_json_params!(req);
        let redis_pool = req.ext().get::<Redis>().unwrap();
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();

        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let max_age = if body.get_remember() {
            Some(24 * 90)
        } else {
            None
        };

        match body.verification(&pg_pool, redis_pool, &max_age) {
            Ok(cookies) => {
                let res = json!({
                    "status": true,
                });

                response.write_body(serde_json::to_string(&res).unwrap());

                let _ = set_cookie(
                    &mut response,
                    "forustm_session".to_string(),
                    cookies,
                    None,
                    Some("/".to_string()),
                    None,
                    max_age,
                );
            }
            Err(err) => {
                let res = json!({
                    "status": false,
                    "error": format!("{}", err)
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        };

        Ok(response)
    }

    fn login_with_github(req: &mut Request) -> SapperResult<Response> {
        let params = get_query_params!(req);
        let code = t_param_parse!(params, "code", String);

        let redis_pool = req.ext().get::<Redis>().unwrap();
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();

        let token = inner_get_github_token(&code)?;

        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let (nickname, github_address) = inner_get_github_nickname_and_address(&token)?;
        match LoginUser::login_with_github(&pg_pool, redis_pool, github_address, nickname, &token) {
            Ok(cookie) => {
                let res = json!({
                    "status": true,
                });

                response.set_status(status::Found);
                response.write_body(serde_json::to_string(&res).unwrap());
                response.headers_mut().set(Location("/home".to_owned()));

                let _ = set_cookie(
                    &mut response,
                    "forustm_session".to_string(),
                    cookie,
                    None,
                    Some("/".to_string()),
                    None,
                    Some(24),
                );
            }

            Err(err) => {
                let res = json!({
                    "status": false,
                    "error": format!("{}", err)
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        }

        Ok(response)
    }

    fn sign_up(req: &mut Request) -> SapperResult<Response> {
        let body: RegisteredUser = get_json_params!(req);
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();
        let redis_pool = req.ext().get::<Redis>().unwrap();

        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        match body.register(&pg_pool, redis_pool) {
            Ok(cookies) => {
                let res = json!({
                    "status": true,
                });

                response.write_body(serde_json::to_string(&res).unwrap());

                let _ = set_cookie(
                    &mut response,
                    "forustm_session".to_string(),
                    cookies,
                    None,
                    Some("/".to_string()),
                    None,
                    Some(24),
                );
            }
            Err(err) => {
                let res = json!({
                    "status": false,
                    "error": format!("{}", err)
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        }
        Ok(response)
    }

    fn send_reset_pwd_email(req: &mut Request) -> SapperResult<Response> {
        #[derive(Deserialize, Serialize)]
        struct Account {
            account: String,
        }
        let body: Account = get_json_params!(req);
        if &body.account == "admin@admin.com" {
            let res = json!({
                "status": false,
                "data": "Can't change admin".to_string()
            });
            res_json!(res)
        } else {
            let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();
            let redis_pool = req.ext().get::<Redis>().unwrap();
            let res = match RUser::send_reset_pwd_email(&pg_pool, redis_pool, body.account) {
                Ok(_) => json!({
                    "status": true
                }),
                Err(err) => json!({
                    "status": false,
                    "error": err
                }),
            };
            res_json!(res)
        }
    }

    fn reset_pwd(req: &mut Request) -> SapperResult<Response> {
        #[derive(Deserialize, Serialize)]
        struct Massage {
            password: String,
            cookie: String,
        }
        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let body: Massage = get_json_params!(req);
        let redis_pool = req.ext().get::<Redis>().unwrap();
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();

        match RUser::reset_pwd(&pg_pool, redis_pool, body.password, body.cookie) {
            Ok(cookie) => {
                let res = json!({
                    "status": true,
                });

                response.write_body(serde_json::to_string(&res).unwrap());

                let _ = set_cookie(
                    &mut response,
                    "forustm_session".to_string(),
                    cookie,
                    None,
                    Some("/".to_string()),
                    None,
                    None,
                );
            }
            Err(err) => {
                let res = json!({
                    "status": false,
                    "error": format!("{}", err)
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        };
        Ok(response)
    }

    fn articles_paging(req: &mut Request) -> SapperResult<Response> {
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();

        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let query_params = get_query_params!(req);
        let section_id: Uuid = match t_param!(query_params, "id").clone().parse() {
            Ok(i) => i,
            Err(err) => return res_400!(format!("UUID invalid: {}", err)),
        };

        let page: i64 = match t_param_default!(query_params, "page", "1").parse() {
            Ok(i) => i,
            Err(err) => return res_400!(format!("missing page param: {}", err)),
        };

        let _page_size: &str = &*format!("{}", page_size());
        let mut psize: i64 = match t_param_default!(query_params, "page_size", _page_size).parse() {
            Ok(psi) => psi,
            Err(err) => return res_400!(format!("missing page_size param: {}", err)),
        };
        if psize > 100 {
            psize = 100;
        }

        match Article::query_articles_with_section_id_paging(
            &pg_pool,
            section_id,
            page,
            psize,
        ) {
            Ok(arts_with_count) => {
                let res = json!({
                "status": true,
                "articles": arts_with_count.articles,
                "total": arts_with_count.total,
                "max_page": arts_with_count.max_page,
            });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
            Err(err) => {
                let res = json!({
                "status": false,
                "error": err,
            });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        };
        Ok(response)
    }

    fn article_query(req: &mut Request) -> SapperResult<Response> {
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();
        let redis_pool = req.ext().get::<Redis>().unwrap();
        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let query_params = get_query_params!(req);
        let article_id: Uuid = match t_param!(query_params, "id").clone().parse() {
            Ok(i) => i,
            Err(err) => return res_400!(format!("UUID invalid: {}", err)),
        };

        match Article::query_article_md(&pg_pool, article_id) {
            Ok(data) => {
                let session_user = get_ruser_from_session(req);
                // create article view record
                let article_stats = NewArticleStats {
                    article_id: article_id,
                    ruser_id: session_user.clone().map(|user| user.id),
                    user_agent: get_user_agent_from_req(req),
                    visitor_ip: get_real_ip_from_req(req),
                };
                article_stats.insert(&pg_pool).unwrap();

                // remove user's notify about this article
                if let Some(user) = session_user.clone() {
                    UserNotify::remove_notifys_for_article(user.id, article_id, &redis_pool);
                }

                let res = json!({
                    "status": true,
                    "data": data,
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
            Err(err) => {
                let res = json!({
                "status": false,
                "error": err,
            });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        };
        Ok(response)
    }

    fn blogs_paging(req: &mut Request) -> SapperResult<Response> {
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();

        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let query_params = get_query_params!(req);

        let page: i64 = match t_param_default!(query_params, "page", "1").parse() {
            Ok(i) => i,
            Err(err) => return res_400!(format!("missing page param: {}", err)),
        };

        let _page_size: &str = &*format!("{}", page_size());
        let mut psize: i64 = match t_param_default!(query_params, "page_size", _page_size).parse() {
            Ok(psi) => psi,
            Err(err) => return res_400!(format!("missing page_size param: {}", err)),
        };
        if psize > 100 {
            psize = 100;
        }

        match Article::query_blogs_paging(&pg_pool, 1, page, psize) {
            Ok(arts_with_count) => {
                let res = json!({
                    "status": true,
                    "articles": arts_with_count.articles,
                    "total": arts_with_count.total,
                    "max_page": arts_with_count.max_page,
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
            Err(err) => {
                let res = json!({
                    "status": false,
                    "error": err,
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        };
        Ok(response)
    }

    fn comments_query(req: &mut Request) -> SapperResult<Response> {
        let pg_pool = req.ext().get::<Postgresql>().unwrap().get().unwrap();

        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());

        let query_params = get_query_params!(req);
        let article_id: Uuid = match t_param!(query_params, "id").clone().parse() {
            Ok(i) => i,
            Err(err) => return res_400!(format!("UUID invalid: {}", err)),
        };

        let offset: i64 = t_param_default!(query_params, "offset", "0")
            .parse()
            .unwrap();
        let _page_size: &str = &*format!("{}", page_size());
        let limit: i64 = t_param_default!(query_params, "limit", _page_size)
            .parse()
            .unwrap();

        match CommentWithNickName::query(&pg_pool, limit, offset, article_id) {
            Ok(comments) => {
                let res = json!({
                    "status": true,
                    "comments": comments,
                    "loaded": comments.len()
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
            Err(err) => {
                let res = json!({
                    "status": false,
                    "error": err,
                });

                response.write_body(serde_json::to_string(&res).unwrap());
            }
        };
        Ok(response)
    }

    fn sections_paging(req: &mut Request) -> SapperResult<Response> {
        let mut response = Response::new();
        response.headers_mut().set(ContentType::json());
        let pg_conn = req.ext().get::<Postgresql>().unwrap().get().unwrap();
        let redis_pool = req.ext().get::<Redis>().unwrap();

        let query_params = get_query_params!(req);

        let page: i64 = match t_param_default!(query_params, "page", "1").parse() {
            Ok(i) => i,
            Err(err) => return res_400!(format!("missing page param: {}", err)),
        };

        let _page_size: &str = &*format!("{}", page_size());
        let mut psize: i64 = match t_param_default!(query_params, "page_size", _page_size).parse() {
            Ok(psi) => psi,
            Err(err) => return res_400!(format!("missing page_size param: {}", err)),
        };

        if psize > 100 {
            psize = 100;
        }

        let mut article_len: i64 = match t_param_default!(query_params, "article_len", "3").parse() {
            Ok(len) => len,
            Err(err) => return res_400!(format!("missing article_len param: {}", err)),
        };

        if article_len > 100 {
            article_len = 100;
        }

        let section_type: String = match t_param_default!(query_params, "section_type", "all").parse() {
            Ok(stype) => stype,
            Err(err) => return res_400!(format!("missing section_type param: {}", err)),
        };

        let mut cate_sections_list = vec![];
        let mut cate_sections_total = 0;
        if  section_type == "cate" || section_type == "all" {
            let cate_sections = Section::query_with_redis_queue_paging(&pg_conn, redis_pool, "cate_sections", page, psize);
            if cate_sections.is_ok() {
                let (cate_sections_vec, _cate_sections_total) = cate_sections.unwrap();
                cate_sections_total = _cate_sections_total;
                for (_idx, section) in cate_sections_vec.iter().enumerate() {
                    let mut cate_sections_map = serde_json::map::Map::new();
                    cate_sections_map.insert(String::from("id"), json!(section.id));
                    cate_sections_map.insert(String::from("title"), json!(section.title.clone()));
                    cate_sections_map.insert(String::from("section_type"), json!("cate"));
                    if article_len > 0 {
                        let res = Article::query_articles_with_section_id_and_stype_paging(
                            &pg_conn,
                            section.id,
                            0,
                            1,
                            article_len,
                        );
                        if res.is_ok() {
                            cate_sections_map.insert(
                                String::from("articles"),
                                json!(res.unwrap().articles),
                            );
                        }
                    }
                    cate_sections_list.push(cate_sections_map);
                }
            }
        }

        let mut proj_sections_list = vec![];
        let mut proj_sections_total = 0;
        if  section_type == "proj" || section_type == "all" {
            let proj_sections = Section::query_with_redis_queue_paging(&pg_conn, redis_pool, "proj_sections", page, psize);
            if proj_sections.is_ok() {
                let (proj_sections_vec, _proj_sections_total) = proj_sections.unwrap();
                proj_sections_total = _proj_sections_total;
                for (_idx, section) in proj_sections_vec.iter().enumerate() {
                    let mut proj_sections_map = serde_json::map::Map::new();
                    proj_sections_map.insert(String::from("id"), json!(section.id));
                    proj_sections_map.insert(String::from("title"), json!(section.title.clone()));
                    proj_sections_map.insert(String::from("section_type"), json!("proj"));
                    if article_len > 0 {
                        let res = Article::query_articles_with_section_id_and_stype_paging(
                            &pg_conn,
                            section.id,
                            0,
                            1,
                            article_len,
                        );
                        if res.is_ok() {
                            proj_sections_map.insert(
                                String::from("articles"),
                                json!(res.unwrap().articles),
                            );
                        }
                    }
                    proj_sections_list.push(proj_sections_map);
                }
            }
        }

        let res = match section_type.as_str() {
            "all" => json!({
                "status": true,
                "cate": json!({
                    "sections": cate_sections_list,
                    "total": cate_sections_total,
                }),
                "proj": json!({
                    "sections": proj_sections_list,
                    "total": proj_sections_total,
                })
            }),
            "cate" => json!({
                "status": true,
                "sections": cate_sections_list,
                "total": cate_sections_total,
                "max_page": (cate_sections_total as f64 / psize as f64).ceil() as i64
            }),
            "proj" => json!({
                "status": true,
                "sections": proj_sections_list,
                "total": proj_sections_total,
                "max_page": (proj_sections_total as f64 / psize as f64).ceil() as i64
            }),
            _ => json!({
                "status": false,
                "error": "WTF!",
            }),
        };

        response.write_body(serde_json::to_string(&res).unwrap());

        Ok(response)
    }
}

impl SapperModule for Visitor {
    fn router(&self, router: &mut SapperRouter) -> SapperResult<()> {
        router.post("/user/login", Visitor::login);
        router.post("/user/sign_up", Visitor::sign_up);
        router.post("/user/send_reset_pwd_email", Visitor::send_reset_pwd_email);
        router.post("/user/reset_pwd", Visitor::reset_pwd);

        router.get("/article/paging", Visitor::articles_paging);
        router.get("/article/get", Visitor::article_query);
        router.get("/blogs/paging", Visitor::blogs_paging);
        router.get("/comment/query", Visitor::comments_query);
        router.get("/login_with_github", Visitor::login_with_github);
        router.get("/section/paging", Visitor::sections_paging);
        Ok(())
    }
}
