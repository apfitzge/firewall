use {
    aya::programs::XdpFlags,
    aya_log::EbpfLogger,
    clap::Parser,
    firewall::{setup_default, Firewall},
    log::info,
    std::{io::Write, net::Ipv4Addr, str::FromStr},
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
        print!("Enter an IP to block (type 'q' to quit):");
        std::io::stdout().flush().unwrap();
        input.clear();
        std::io::stdin().read_line(&mut input).unwrap();
        let trimmed = input.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            break;
        }

        let Ok(ip) = Ipv4Addr::from_str(trimmed) else {
            eprintln!("invalid ip: {trimmed}");
            break;
        };

        info!("blocking {ip}");
        firewall
            .block_ip(ip, IpBlockRule::AnyPort)
            .expect("failed to block ip");
    }
}
