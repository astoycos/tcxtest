use aya::programs::{tc::TcAttachOptions, LinkOrder, SchedClassifier, TcAttachType};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcxtest"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcxtest"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut SchedClassifier = bpf.program_mut("tcxtestfirst").unwrap().try_into()?;
    program.load()?;
    let options = TcAttachOptions::tcxoptions(LinkOrder::first());
    program.attach_with_options(&opt.iface, TcAttachType::Ingress, options)?;

    let program: &mut SchedClassifier = bpf.program_mut("tcxtestlast").unwrap().try_into()?;
    program.load()?;
    let options = TcAttachOptions::tcxoptions(LinkOrder::last());
    program.attach_with_options(&opt.iface, TcAttachType::Ingress, options)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
