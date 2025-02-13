#![no_std]

/// Rule for how to handle traffic from specific IP
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpBlockRule {
    /// Block all traffic for the IP
    AnyPort,
    /// Block traffic for specific port
    Port(u16),
}

impl TryFrom<u32> for IpBlockRule {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value & u32::from(u16::MAX) {
            0 => Ok(Self::AnyPort),
            1 => Ok(Self::Port((value >> 16) as u16)),
            _ => Err(()),
        }
    }
}

impl From<IpBlockRule> for u32 {
    fn from(rule: IpBlockRule) -> Self {
        match rule {
            IpBlockRule::AnyPort => 0,
            IpBlockRule::Port(port) => 1 | u32::from(port) << 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_block_rule_conversion() {
        let ip_block_rule = IpBlockRule::AnyPort;
        assert_eq!(
            ip_block_rule,
            IpBlockRule::try_from(u32::from(ip_block_rule)).unwrap()
        );

        for port in [0, 5, u16::MAX] {
            let ip_block_rule = IpBlockRule::Port(port);
            assert_eq!(
                ip_block_rule,
                IpBlockRule::try_from(u32::from(ip_block_rule)).unwrap()
            );
        }
    }
}
