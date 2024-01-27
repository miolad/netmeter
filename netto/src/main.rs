mod bpf {
    include!(concat!(env!("OUT_DIR"), "/prog.bpf.rs"));
}
mod ksyms;
mod actors;

use std::{path::PathBuf, time::Duration};
use actix::Actor;
use actix_web::rt::System;
use actors::trace_analyzer::TraceAnalyzer;
use anyhow::anyhow;
use clap::Parser;
use libbpf_rs::num_possible_cpus;
use perf_event_open_sys::{bindings::{perf_event_attr, PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK}, perf_event_open};
use tokio::sync::mpsc::channel;

use crate::actors::pyroscope_exporter::PyroscopeExporter;

#[derive(Parser)]
#[command(name = "netto")]
#[command(author = "Davide Miola <davide.miola99@gmail.com>")]
#[command(about = "eBPF-based network diagnosis tool for Linux")]
#[command(version)]
struct Cli {
    /// Perf-event's sampling frequency in Hz for the NET_RX_SOFTIRQ cost breakdown
    #[arg(short, long, default_value_t = 1000)]
    frequency: u64,

    /// Bind address or hostname for the web frontend
    #[arg(short, long, default_value = "0.0.0.0")]
    address: String,

    /// Bind port for the web frontend
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// User-space controller update period in ms
    #[arg(long, default_value_t = 500)]
    user_period: u64,

    /// Path to a log file to which measurements are to be saved.
    /// If logging is enabled by providing this argument, any other form of web interface will be disabled.
    #[arg(short, long)]
    log_file: Option<PathBuf>,

    /// Enable Prometheus logging in place of the web interface.
    /// The Prometheus-compatible endpoint will be available at `http://address:port`
    #[arg(short = 'P', long, default_value_t = false)]
    prometheus: bool,

    /// List of PIDs of which to track the user-space CPU time via procfs
    #[arg(short, long, value_delimiter = ',')]
    user_pids: Vec<u32>
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    System::new().block_on(async {
        let num_possible_cpus = num_possible_cpus()?;
        
        // Init BPF: open the libbpf skeleton, load the progs and attach them
        let mut open_skel = bpf::ProgSkelBuilder::default().open()?;

        let max_traces = (
            cli.frequency as f64 *
            num_possible_cpus as f64 *
            (cli.user_period as f64 / 1000.0)
        ).round() as u32;
        let stack_traces_max_entries = (cli.frequency as f64 *
            num_possible_cpus as f64 *
            (cli.user_period as f64 / 1000.0) *
            1.1 // Add 10% margin to account for controller scheduling irregularities
        ).ceil() as u32 * 2;
        println!("Allocated memory for stack traces BPF map: {}B", stack_traces_max_entries * 128 * 8);
        open_skel.maps_mut().stack_traces().set_max_entries(stack_traces_max_entries)?;

        let mut skel = open_skel.load()?;

        // Open and attach a perf-event program for each CPU
        let _perf_event_links = unsafe {
            let iter = (0..num_possible_cpus)
                .map(|cpuid| {
                    let mut attrs = perf_event_attr {
                        size: std::mem::size_of::<perf_event_attr>() as _,
                        type_: PERF_TYPE_SOFTWARE,
                        config: PERF_COUNT_SW_CPU_CLOCK as _,

                        // Sampling frequency
                        __bindgen_anon_1: perf_event_open_sys::bindings::perf_event_attr__bindgen_ty_1 {
                            sample_freq: cli.frequency
                        },

                        ..Default::default()
                    };

                    // Only count kernel-space events
                    attrs.set_exclude_user(1);

                    // Use frequency instead of period
                    attrs.set_freq(1);

                    (cpuid, attrs)
                });
            
            let mut v = Vec::with_capacity(num_possible_cpus);
            for (cpuid, mut attrs) in iter {
                // Open the perf-event
                let fd = perf_event_open(&mut attrs, -1, cpuid as _, -1, 0);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                
                // Attach to BPF prog
                v.push(skel.progs_mut().perf_event_prog().attach_perf_event(fd)?);
            }

            v
        };
        
        // Init actors
        let (error_catcher_sender, mut error_catcher_receiver) =
            channel::<anyhow::Error>(1);

        let pyroscope_exporter_actor_addr = PyroscopeExporter::new(
            "http://localhost:4040".to_string(), // TODO: make configurable
            Duration::from_secs(5),
            error_catcher_sender.clone(),
            tokio::runtime::Handle::current(),
            cli.frequency,
            num_possible_cpus as _
        )?.start();

        let _trace_analyzer_actor_addr = TraceAnalyzer::new(
            Duration::from_millis(cli.user_period),
            num_possible_cpus,
            skel,
            stack_traces_max_entries,
            max_traces,
            error_catcher_sender,
            pyroscope_exporter_actor_addr,
            cli.user_pids
        )?.start();

        // Start HTTP server for frontend
        let server_future = async move {
            std::future::pending::<()>().await
        };

        tokio::select! {
            _ = server_future => Ok(()),
            msg = error_catcher_receiver.recv() => match msg {
                None => Err(anyhow!("Actors closed unexpectedly")),
                Some(e) => Err(e)
            },
            _ = tokio::signal::ctrl_c() => {
                println!("Exiting...");
                Ok(())
            }
        }
    })
}
