//! The scenarios of `PROTOCOL.md §6`, client and relay together, in a
//! deterministic simulation: virtual time, links with a fixed delay, NATs that
//! rebind, networks that drop UDP, and attackers that replay and spoof.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

mod world;

mod attempts;
mod candidates;
mod dual_stack;
mod matrix;
mod revalidation;

mod client;
mod frames;
mod link;
mod measure;
mod messages;
mod paths;
mod relay;
mod simulation;
