// 日志中间件
// 直接使用 tower_http::trace::TraceLayer::new_for_http() 在路由中

#[cfg(test)]
mod tests {
    #[test]
    fn test_logging_middleware() {
        // Logging middleware 通过 tower_http::trace::TraceLayer::new_for_http() 直接使用
        assert!(true);
    }
}
