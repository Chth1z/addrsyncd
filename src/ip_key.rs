use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum IpKey {
    V4(u32),
    V6(u128),
}

impl IpKey {
    pub(crate) fn from_ip(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => Self::V4(u32::from(v4)),
            IpAddr::V6(v6) => Self::V6(u128::from_be_bytes(v6.octets())),
        }
    }

    pub(crate) fn into_ip(self) -> IpAddr {
        match self {
            Self::V4(raw) => IpAddr::V4(raw.into()),
            Self::V6(raw) => IpAddr::V6(raw.to_be_bytes().into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IpKey;
    use std::net::IpAddr;

    #[test]
    fn ip_key_roundtrip() {
        let v4: IpAddr = "10.0.0.1".parse().expect("ip");
        let v6: IpAddr = "2001:db8::1".parse().expect("ip");
        assert_eq!(IpKey::from_ip(v4).into_ip(), v4);
        assert_eq!(IpKey::from_ip(v6).into_ip(), v6);
    }
}
