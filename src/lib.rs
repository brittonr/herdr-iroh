//! Relay [herdr](https://github.com/herdrdev/herdr)'s newline-delimited JSON
//! socket API over an iroh endpoint, and expose it to a local assistant
//! through a stdio MCP server.
//!
//! Herdr has no iroh or MCP support. This crate does not link herdr. It
//! checks the peer and the method, then copies JSON lines to `herdr.sock`.

pub mod client;
pub mod config;
pub mod keys;
pub mod mcp;
pub mod policy;
pub mod protocol;
pub mod serve;
mod stream;

pub use client::{CallOptions, Node};
pub use policy::{ALWAYS_DENIED, Allowlist, Decision, DenyReason, MethodPolicy};
pub use protocol::ALPN;
pub use serve::{RunningServer, ServeOptions, serve};
