use std::net::{IpAddr, Ipv4Addr};

// Unspecified (0.0.0.0) exposes to public internet
// Localhost (127.0.0.1) will only allow other processes on machine to ping
pub const TEE_DEFAULT_ENDPOINT_ADDR: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const TEE_DEFAULT_ENDPOINT_PORT: u16 = 7878;
