use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use color_eyre::Report;
use serde_json::json;
use tracing::error;

#[derive(Debug)]
pub struct AxumError {
    pub report: Report,
    pub status_code: StatusCode,
}

impl AxumError {
    pub fn new(report: Report) -> Self {
        Self {
            report,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn with_status(report: Report, status_code: StatusCode) -> Self {
        Self {
            report,
            status_code,
        }
    }

    pub fn bad_request(report: Report) -> Self {
        Self::with_status(report, StatusCode::BAD_REQUEST)
    }

    pub fn unauthorized(report: Report) -> Self {
        Self::with_status(report, StatusCode::UNAUTHORIZED)
    }

    pub fn forbidden(report: Report) -> Self {
        Self::with_status(report, StatusCode::FORBIDDEN)
    }

    pub fn not_found(report: Report) -> Self {
        Self::with_status(report, StatusCode::NOT_FOUND)
    }

    #[allow(dead_code)]
    pub fn conflict(report: Report) -> Self {
        Self::with_status(report, StatusCode::CONFLICT)
    }

    #[allow(dead_code)]
    pub fn unprocessable_entity(report: Report) -> Self {
        Self::with_status(report, StatusCode::UNPROCESSABLE_ENTITY)
    }

    pub fn service_unavailable(report: Report) -> Self {
        Self::with_status(report, StatusCode::SERVICE_UNAVAILABLE)
    }
}

impl<E: Into<Report>> From<E> for AxumError {
    fn from(error: E) -> Self {
        Self::new(error.into())
    }
}

impl IntoResponse for AxumError {
    fn into_response(self) -> Response {
        if self.status_code.is_server_error() {
            error!(error = ?self.report, "An error occurred in an axum handler");
        }

        let error_message = if self.status_code.is_server_error() {
            self.status_code
                .canonical_reason()
                .unwrap_or("Internal Server Error")
                .to_string()
        } else {
            self.report.to_string()
        };

        let body = json!({
            "error": error_message
        });
        Response::builder()
            .status(self.status_code)
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap_or_else(|e| format!("{e:?}").into_response())
    }
}

pub type AxumResult<T, E = AxumError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use color_eyre::eyre::eyre;

    use super::*;

    #[tokio::test]
    async fn hides_internal_details_for_server_errors() {
        let response =
            AxumError::new(eyre!("database connection failed: super-secret")).into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"], "Internal Server Error");
    }

    #[tokio::test]
    async fn preserves_messages_for_client_errors() {
        let response =
            AxumError::bad_request(eyre!("Invalid username or password")).into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"], "Invalid username or password");
    }
}
