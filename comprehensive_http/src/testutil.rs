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
    use std::sync::Arc;
    use tokio_rustls::rustls::crypto::CryptoProvider;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_rustls::rustls::server::ClientHello;
    use tokio_rustls::rustls::sign::CertifiedKey;

    use crate::tls_testdata;

    #[derive(Debug)]
    pub(crate) struct Resolver;

    impl tokio_rustls::rustls::server::ResolvesServerCert for Resolver {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            let cert = CertificateDer::from_pem_slice(tls_testdata::USER1_CERT).unwrap();
            let provider = CryptoProvider::get_default().unwrap();
            let key = PrivateKeyDer::from_pem_slice(tls_testdata::USER1_KEY).unwrap();
            let key = provider.key_provider.load_private_key(key).unwrap();
            Some(Arc::new(CertifiedKey::new(vec![cert], key)))
        }
    }

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
        pub fn cert_resolver(&self) -> Result<Arc<Resolver>, comprehensive_tls::ComprehensiveTlsError> {
            Ok(Arc::new(Resolver))
        }
    }
}
