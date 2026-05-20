use std::fmt::{Debug, Display};

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct TngEndpoint {
    host: String,
    port: u16,
    scheme: String,
}

impl TngEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            scheme: "http".into(),
        }
    }

    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }
}

impl Display for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

impl Debug for TngEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}:{}", self.host, self.port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scheme_is_http() {
        let ep = TngEndpoint::new("localhost", 8080);
        assert_eq!(ep.scheme(), "http");
    }

    #[test]
    fn with_scheme_overrides_default() {
        let ep = TngEndpoint::new("localhost", 443).with_scheme("https");
        assert_eq!(ep.scheme(), "https");
    }
}
