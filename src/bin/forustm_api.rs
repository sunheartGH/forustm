extern crate sapper;
extern crate sapper_std;
extern crate forustm;

use sapper::{ SapperApp, SapperAppShell, Request, Response, Result as SapperResult };
use forustm::{ Redis, create_redis_pool, create_pg_pool, Postgresql };
use std::sync::Arc;

struct ApiApp;

impl SapperAppShell for ApiApp {
    fn before(&self, req: &mut Request) -> SapperResult<()> {
        sapper_std::init(req, Some("forustm_session"))?;
        Ok(())
    }

    fn after(&self, req: &Request, res: &mut Response) -> SapperResult<()> {
        sapper_std::finish(req, res)?;
        Ok(())
    }
}

fn main() {
    let redis_pool = Arc::new(create_redis_pool(None));
    let pg_pool = create_pg_pool();
    let mut app = SapperApp::new();
    app.address("127.0.0.1")
        .port(8888)
        .init_global(
            Box::new(move |req: &mut Request| {
                req.ext_mut().insert::<Redis>(redis_pool.clone());
                req.ext_mut().insert::<Postgresql>(pg_pool.clone());
                Ok(())
            })
        )
        .with_shell(Box::new(ApiApp))
        .static_service(false);

    println!("Start listen on {}", "127.0.0.1:8888");
    app.run_http();
}
