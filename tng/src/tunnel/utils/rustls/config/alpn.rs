#[derive(Debug, Copy, Clone)]
pub enum Alpn {
    Http2,
    Serf,
}

impl Alpn {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Alpn::Http2 => b"h2",
            Alpn::Serf => b"serf",
        }
    }
}
