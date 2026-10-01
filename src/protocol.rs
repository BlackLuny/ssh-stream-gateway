//! Version 1 frames: kind:u8, length:u32 big endian, payload (maximum 16 KiB).
use anyhow::{Context, Result, bail};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_FRAME: usize = 16 * 1024;
pub const CONTENT_TYPE: &str = "application/vnd.ssh-stream.v1";
pub const OPEN: u8 = 1;
pub const STDIN: u8 = 2;
pub const EOF: u8 = 3;
pub const CANCEL: u8 = 4;
pub const STDOUT: u8 = 17;
pub const STDERR: u8 = 18;
pub const EXIT: u8 = 19;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub target: String,
    /// Intentionally interpreted by the remote account's shell, never locally.
    pub command: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Exit {
    pub code: i32,
    /// Protocol-level error code, never child command/config/credentials.
    pub error: Option<String>,
}

pub fn encode(kind: u8, data: &[u8]) -> Result<Bytes> {
    if data.len() > MAX_FRAME {
        bail!("frame too large");
    }
    let mut out = BytesMut::with_capacity(5 + data.len());
    out.put_u8(kind);
    out.put_u32(data.len() as u32);
    out.extend_from_slice(data);
    Ok(out.freeze())
}

pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<(u8, Vec<u8>)>> {
    let mut kind = [0];
    if reader.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let size = reader.read_u32().await.context("truncated frame header")? as usize;
    if size > MAX_FRAME {
        bail!("frame too large");
    }
    let mut data = vec![0; size];
    reader
        .read_exact(&mut data)
        .await
        .context("truncated frame payload")?;
    Ok(Some((kind[0], data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn frames_are_binary_safe_and_truncation_is_rejected() {
        let encoded = encode(STDIN, &[0, 255, 10]).unwrap();
        assert_eq!(
            read(&mut &encoded[..]).await.unwrap(),
            Some((STDIN, vec![0, 255, 10]))
        );
        assert!(read(&mut &encoded[..encoded.len() - 1]).await.is_err());
        assert!(read(&mut &[STDIN, 0, 0][..]).await.is_err());
        assert_eq!(read(&mut &b""[..]).await.unwrap(), None);
    }
    #[tokio::test]
    async fn oversized_frame_rejected_before_payload_allocation() {
        assert!(encode(STDIN, &vec![0; MAX_FRAME + 1]).is_err());
        assert!(read(&mut &[STDIN, 255, 255, 255, 255][..]).await.is_err());
    }
}
