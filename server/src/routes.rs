pub mod api;
pub mod oidc_routes;
pub mod well_known;

use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

use crate::{ApiDoc, state::AppState};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .nest("/api", api::routes())
        .nest("/api/oidc", oidc_routes::routes())
        .nest("/.well-known", well_known::routes())
}
