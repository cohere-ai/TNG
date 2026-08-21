use std::{
    pin::Pin,
    task::{Context, Poll},
};

use hyper::upgrade::Upgraded;
use sync_wrapper::SyncWrapper;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{CommonStreamTrait, TokioIo};

/// Wraps a `!Sync` IO stream so that it becomes `Sync`.
///
/// `SyncWrapper` only ever hands out `&mut T`, which is all the IO traits need to make progress and
/// is enough for the compiler to consider the wrapper `Sync`. No locking is involved.
#[derive(Debug)]
pub struct SyncIo<T>(SyncWrapper<T>);

impl<T: Unpin> SyncIo<T> {
    fn project(self: Pin<&mut Self>) -> Pin<&mut T> {
        Pin::new(self.get_mut().0.get_mut())
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SyncIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SyncIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.project().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().poll_shutdown(cx)
    }
}

/// Turn an upgraded HTTP/2 CONNECT tunnel into a stream usable by the rest of the tunnel plumbing,
/// which requires `Sync`. `Upgraded` itself is `!Sync` and already replays the bytes buffered before
/// the upgrade, so wrapping is preferable to downcasting to the inner IO.
/// reference: https://github.com/hyperium/hyper/issues/3587
pub fn upgraded_to_sync_stream(upgraded: Upgraded) -> impl CommonStreamTrait + Sync {
    SyncIo(SyncWrapper::new(TokioIo::new(upgraded)))
}
