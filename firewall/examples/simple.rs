use {
    aya::programs::XdpFlags,
    aya_log::EbpfLogger,
    clap::Parser,
    firewall::{setup_default, Firewall},
    firewall_common::IpBlockRule,
    log::info,
    std::{
        io::Write,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    },
};

#[derive(Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
pub async fn main() {
    env_logger::init();

    let opt = Opt::parse();
    let mut bpf =
        setup_default(&opt.iface, XdpFlags::default()).expect("failed to setup xdp program");
    EbpfLogger::init(&mut bpf).expect("failed to initialize bpf logger");
    let mut firewall = Firewall::try_new(&mut bpf).expect("failed to create firewall");
    let mut input = String::new();
    loop {
        print!("Enter an IP:PORT to block (type 'q' to quit):");
        std::io::stdout().flush().unwrap();
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();
        let trimmed = input.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            break;
        }

        let Ok(socket) = SocketAddr::from_str(trimmed) else {
            eprintln!("invalid ip: {trimmed}");
            break;
        };

        let IpAddr::V4(ipv4) = socket.ip() else {
            continue;
        };

        info!("blocking {socket}");
        firewall
            .block_ip(ipv4, IpBlockRule::Port(socket.port()))
            .expect("failed to block socket");
    }
}
