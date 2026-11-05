//! Line IO and a QUIC send wrapper that flushes each write.
//!
//! iroh's send stream copies `poll_write` into a buffer. Callers that then
//! wait to read never see those bytes unless the write is flushed first.
//! The same wrapper is used by iroh-news.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use anyhow::bail;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite};

pub struct Flushing<W> {
    inner: W,
    pending: Option<usize>,
}

impl<W> Flushing<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            pending: None,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Flushing<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(written) = this.pending {
            match Pin::new(&mut this.inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    this.pending = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(())) => {
                    this.pending = None;
                    return Poll::Ready(Ok(written));
                }
            }
        }

        let written = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
        if written == 0 {
            return Poll::Ready(Ok(0));
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                this.pending = Some(written);
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_some() {
            ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
            this.pending = None;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Read one line, including the newline, refusing to buffer more than `max`.
pub async fn read_line_limited<R>(reader: &mut R, max: usize) -> anyhow::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(buf));
        }
        if let Some(pos) = available.iter().position(|byte| *byte == b'\n') {
            let take = pos + 1;
            if buf.len().saturating_add(take) > max {
                bail!("line exceeds {max} bytes");
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(Some(buf));
        }
        if buf.len().saturating_add(available.len()) > max {
            bail!("line exceeds {max} bytes");
        }
        let n = available.len();
        buf.extend_from_slice(available);
        reader.consume(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn limited_read_stops_at_newline_and_rejects_oversize() {
        let (client, server) = tokio::io::duplex(64);
        let mut writer = client;
        writer.write_all(b"abc\nrest").await.unwrap();
        let mut reader = BufReader::new(server);
        let line = read_line_limited(&mut reader, 16).await.unwrap().unwrap();
        assert_eq!(line, b"abc\n");
        let err = read_line_limited(&mut reader, 2).await.unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }
}
