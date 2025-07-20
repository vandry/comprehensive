use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};
use tokio::net::TcpStream;

pub(crate) fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port)
}

pub(crate) fn pick_unused_port(not_this_one: Option<u16>) -> u16 {
    let start = rand::random::<u16>() & 0x7fff;
    for low_bits in start..start + 50 {
        let port = (low_bits & 0x7fff) | 0x8000;
        if let Some(banned) = not_this_one {
            if port == banned {
                continue;
            }
        }
        if TcpListener::bind(localhost(port)).is_ok() {
            return port;
        }
    }
    panic!("Cannot find a free TCP port");
}

pub(crate) async fn wait_until_serving(addr: &SocketAddr) {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(feature = "tls")]
pub(crate) mod tls {
    use comprehensive_tls::api::rustls;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use crate::tls_testdata;

    pub(crate) struct MockTlsConfig;

    impl comprehensive::Resource for MockTlsConfig {
        type Args = comprehensive::NoArgs;
        type Dependencies = comprehensive::NoDependencies;
        const NAME: &str = "Mock TlsConfig for tests";

        fn new(
            _: comprehensive::NoDependencies,
            _: comprehensive::NoArgs,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            Ok(Self)
        }
    }

    impl MockTlsConfig {
        pub fn server_config<T>(&self) -> rustls::ServerConfig {
            let p = rustls::crypto::aws_lc_rs::default_provider();
            rustls::ServerConfig::builder_with_provider(p.into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from_pem_slice(tls_testdata::USER1_CERT).unwrap()],
                    PrivateKeyDer::from_pem_slice(tls_testdata::USER1_KEY).unwrap(),
                )
                .unwrap()
        }
    }
}
