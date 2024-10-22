use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};
use tokio::net::TcpStream;

pub(crate) fn pick_unused_port(not_this_one: Option<u16>) -> u16 {
    let start = rand::random::<u16>() & 0x7fff;
    for low_bits in start..start + 50 {
        let port = (low_bits & 0x7fff) | 0x8000;
        if let Some(banned) = not_this_one {
            if port == banned {
                continue;
            }
        }
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), port);
        if TcpListener::bind(addr).is_ok() {
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
