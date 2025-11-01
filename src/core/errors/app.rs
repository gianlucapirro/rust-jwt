use axum::{http::StatusCode, response::{IntoResponse, Response}};

#[derive(Debug)]
pub enum AppError {
    Conflict(&'static str),
    Unauthorized(&'static str),
    // NotFound(&'static str),
    // BadRequest(&'static str),
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message): (StatusCode, String) = match self {
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.to_string()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.to_string()),
            // AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.to_string()),
            // AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.to_string()),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string()),
        };

        (status, message).into_response()
    }
}