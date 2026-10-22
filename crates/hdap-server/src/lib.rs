//! HDAP network node: storage, REST API and federation.
//! Validates and enforces the protocol rules from `docs/especificacao-hdap.md`
//! §14 (node duties) over a minimal HTTP/1.1 surface (`http`), with
//! at-rest-encrypted content (`store`) persisted to SQLite (`db`) and the
//! route logic in `node`.

pub mod config;
pub mod db;
pub mod fed_client;
pub mod http;
pub mod node;
pub mod pyle;
pub mod store;

pub use config::Config;
pub use fed_client::FedHttpClient;
pub use node::Node;
pub use store::State;
