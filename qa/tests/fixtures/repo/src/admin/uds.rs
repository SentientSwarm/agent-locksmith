fn routes() -> Router {
    Router::new()
        .route("/tools", get(list))
        .route(
            "/tools/{name}",
            get(show).put(save),
        )
        .fallback(callback)
}
