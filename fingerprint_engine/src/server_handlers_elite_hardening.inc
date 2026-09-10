async fn api_elite_hardening_status(
    Extension(_auth): Extension<AuthContext>,
) -> Response {
    (
        StatusCode::OK,
        Json(crate::elite_hardening::status_snapshot()),
    )
        .into_response()
}
