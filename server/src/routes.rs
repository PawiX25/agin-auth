pub mod api;
// TODO: re-enable after PostgreSQL migration
// pub mod oidc_routes;
pub mod well_known;

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::{ApiDoc, state::AppState};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/api", api::routes())
        .nest("/.well-known", well_known::routes())
}
