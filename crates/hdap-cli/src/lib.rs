//! HDAP thin client: builds the protocol from `hdap-core` and speaks minimal
//! HTTP/1.1 to an `hdap-server` node. No protocol logic lives here
//! (skill.md principle 6).

pub mod flow;
pub mod http_client;
pub mod identity_store;

pub use flow::{
    accept_transfer, authenticate, band_mochthos, band_mochthos_progress, claim_choregia,
    countersign_band, delete, download, fetch_node_facts, fetch_prices, list_band, list_ktema,
    proklesis_bits, publish_alias, register, request_transfer, resolve, transfer_inbox,
    transfer_owner, upload, upload_with_band, AuthResult, BandInfo, FlowError, HttpClient,
    HttpResponse, KtemaEntry, MatrixEntry, RegisterResult, SyncSnapshot, TimiQuote,
    TransferAcceptResult, TransferInboxItem, TransferRequestResult, TrustRow,
};
pub use identity_store::{load, save, IdentityStoreError};

/// The identity profile is (still) the entry point for everything else.
pub use hdap_core::identity::Identity;
