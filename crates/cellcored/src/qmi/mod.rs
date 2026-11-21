//! Clean-room native Rust QRTR (`AF_QIPCRTR`) + QMI service codecs for
//! Snapdragon X75 / RM55x modems.

pub mod codec;
pub mod dms;
pub mod nas;
pub mod qrtr;
pub mod uim;
pub mod wda;
pub mod wds;

use std::{fmt, future::Future, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};

pub const SVC_WDS: u32 = 0x01;
pub const SVC_DMS: u32 = 0x02;
pub const SVC_NAS: u32 = 0x03;
pub const SVC_QOS: u32 = 0x04;
pub const SVC_WMS: u32 = 0x05;
pub const SVC_UIM: u32 = 0x0B;
pub const SVC_TS: u32 = 0x17;
pub const SVC_WDA: u32 = 0x1A;
pub const SVC_DSD: u32 = 0x2A;
pub const SVC_DPM: u32 = 0x2F;
pub const SVC_IPA: u32 = 0x31;

pub fn service_name(id: u32) -> &'static str {
    match id {
        SVC_WDS => "WDS",
        SVC_DMS => "DMS",
        SVC_NAS => "NAS",
        SVC_QOS => "QOS",
        SVC_WMS => "WMS",
        0x07 => "AUTH",
        0x08 => "AT",
        0x09 => "VOICE",
        0x0A => "CAT",
        SVC_UIM => "UIM",
        0x0C => "PBM",
        0x10 => "LOC",
        0x11 => "SAR",
        0x12 => "IMS",
        SVC_TS => "TS",
        0x18 => "TMD",
        SVC_WDA => "WDA",
        0x21 => "IMSA",
        0x22 => "COEX",
        0x24 => "PDC",
        SVC_DSD => "DSD",
        0x2B => "SSCTL",
        SVC_DPM => "DPM",
        0x30 => "DFS",
        SVC_IPA => "IPA",
        _ => "UNKNOWN",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpoint {
    pub service: u32,
    pub name: String,
    pub version: u32,
    pub instance: u32,
    pub node: u32,
    pub port: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QmiError {
    Io(String),
    Unsupported(String),
    Timeout,
    ServiceUnavailable(u32),
    Ssr,
    Malformed(String),
    Protocol { code: u16 },
}

impl fmt::Display for QmiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QmiError::Io(m) => write!(f, "QMI I/O error: {m}"),
            QmiError::Unsupported(m) => write!(f, "QRTR unsupported: {m}"),
            QmiError::Timeout => write!(f, "QMI request timed out"),
            QmiError::ServiceUnavailable(svc) => {
                write!(f, "QMI service {} ({svc:#x}) not registered on QRTR", service_name(*svc))
            }
            QmiError::Ssr => write!(f, "modem subsystem restart (QRTR SSR)"),
            QmiError::Malformed(m) => write!(f, "malformed QMI packet: {m}"),
            QmiError::Protocol { code } => write!(f, "QMI error code {code} ({code:#06x})"),
        }
    }
}

impl std::error::Error for QmiError {}

impl From<QmiError> for String {
    fn from(e: QmiError) -> Self {
        e.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QmiIndication {
    pub service: u32,
    pub tag: &'static str,
    pub msg_id: u16,
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

pub type TlvList = Vec<(u8, Vec<u8>)>;
pub type QmiRpcResult = Result<TlvList, QmiError>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe async client interface for a bound QMI service endpoint.
pub trait QmiClient: Send + Sync {
    fn rpc<'a>(&'a self, msg_id: u16, req_tlvs: Vec<u8>, timeout: Duration) -> BoxFuture<'a, QmiRpcResult>;
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::{Arc, Mutex};

    type HandlerFn = Box<dyn FnMut(u16, &[u8]) -> QmiRpcResult + Send>;
    pub type RecordedCalls = Vec<(u16, Vec<u8>)>;

    #[derive(Clone)]
    pub struct MockQmiClient {
        handler: Arc<Mutex<HandlerFn>>,
        pub calls: Arc<Mutex<RecordedCalls>>,
    }

    impl MockQmiClient {
        pub fn new<F>(f: F) -> Self
        where
            F: FnMut(u16, &[u8]) -> QmiRpcResult + Send + 'static,
        {
            Self {
                handler: Arc::new(Mutex::new(Box::new(f))),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl QmiClient for MockQmiClient {
        fn rpc<'a>(
            &'a self,
            msg_id: u16,
            req_tlvs: Vec<u8>,
            _timeout: Duration,
        ) -> BoxFuture<'a, QmiRpcResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push((msg_id, req_tlvs.clone()));
                let mut h = self.handler.lock().unwrap();
                h(msg_id, &req_tlvs)
            })
        }
    }

    #[test]
    fn service_name_maps_standard_and_vendor_ids() {
        assert_eq!(service_name(SVC_WDS), "WDS");
        assert_eq!(service_name(0x10), "LOC");
        assert_eq!(service_name(0x24), "PDC");
        assert_eq!(service_name(SVC_IPA), "IPA");
        assert_eq!(service_name(0x1001), "UNKNOWN");
    }
}
