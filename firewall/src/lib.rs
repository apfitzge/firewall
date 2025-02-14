use {
    aya::{
        maps::{HashMap, MapData},
        programs::{Xdp, XdpFlags},
        Ebpf,
    },
    firewall_common::IpBlockRule,
    std::net::Ipv4Addr,
};

const MAP_NAME: &str = "BLOCKLIST";

pub struct Firewall {
    bpf: Ebpf,
}

impl Firewall {
    pub fn try_new(bpf: Ebpf) -> Result<Self, anyhow::Error> {
        let mut firewall = Self { bpf };

        // verify that the bpf is valid now, before we attempt to add.
        let _map = firewall.map_mut()?;

        Ok(firewall)
    }

    pub fn block_ip(&mut self, ip: Ipv4Addr, rule: IpBlockRule) -> Result<(), anyhow::Error> {
        let block_addr = u32::from(ip);
        let rule = u32::from(rule);
        self.map_mut()?.insert(block_addr, rule, 0)?;
        Ok(())
    }

    pub fn unblock_up(&mut self, ip: Ipv4Addr) -> Result<(), anyhow::Error> {
        let block_addr = u32::from(ip);
        self.map_mut()?.remove(&block_addr)?;
        Ok(())
    }

    fn map_mut(&mut self) -> Result<HashMap<&mut MapData, u32, u32>, anyhow::Error> {
        let Some(map) = self.bpf.map_mut(MAP_NAME) else {
            return Err(anyhow::Error::msg(format!("{MAP_NAME} map not found")));
        };
        let map: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        Ok(map)
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
