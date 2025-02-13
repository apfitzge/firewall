use {
    aya::{
        maps::{HashMap, MapData},
        programs::{Xdp, XdpFlags},
        Ebpf,
    },
    firewall_common::IpBlockRule,
    std::net::Ipv4Addr,
};

pub struct Firewall<'a> {
    map: HashMap<&'a mut MapData, u32, u32>,
}

impl<'a> Firewall<'a> {
    pub fn try_new(bpf: &'a mut Ebpf) -> Result<Self, anyhow::Error> {
        let Some(map) = bpf.map_mut("BLOCKLIST") else {
            return Err(anyhow::Error::msg("BLOCKLIST map not found"));
        };
        let map = HashMap::try_from(map)?;
        Ok(Self { map })
    }

    pub fn block_ip(&mut self, ip: Ipv4Addr, rule: IpBlockRule) -> Result<(), anyhow::Error> {
        let block_addr = u32::from(ip);
        let rule = u32::from(rule);
        self.map.insert(block_addr, rule, 0)?;
        Ok(())
    }

    pub fn unblock_up(&mut self, ip: Ipv4Addr) -> Result<(), anyhow::Error> {
        let block_addr = u32::from(ip);
        self.map.remove(&block_addr)?;
        Ok(())
    }
}

pub fn setup_default(interface: &str, flags: XdpFlags) -> Result<Ebpf, anyhow::Error> {
    let mut bpf = load_default_firewall()?;
    attach_firewall_program(&mut bpf, interface, flags)?;
    Ok(bpf)
}

fn load_default_firewall() -> Result<Ebpf, anyhow::Error> {
    let bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/firewall"
    )))?;
    Ok(bpf)
}

fn attach_firewall_program(
    bpf: &mut Ebpf,
    interface: &str,
    flags: XdpFlags,
) -> Result<(), anyhow::Error> {
    let program: &mut Xdp = bpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(interface, flags)?;
    Ok(())
}
