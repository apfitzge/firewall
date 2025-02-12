use {
    aya::{
        programs::{Xdp, XdpFlags},
        Ebpf,
    },
    aya_log::EbpfLogger,
};

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
    EbpfLogger::init(bpf)?;

    let program: &mut Xdp = bpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(interface, flags)?;
    Ok(())
}
