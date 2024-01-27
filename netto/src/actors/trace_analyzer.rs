use std::{time::{Duration, Instant}, collections::HashMap};
use actix::{Actor, Context, AsyncContext, Addr};
use powercap::{IntelRapl, PowerCap};
use tokio::sync::mpsc::Sender;
use crate::{ksyms::KSyms, bpf::ProgSkel};
use libc::{mmap, PROT_READ, MAP_SHARED, sysconf, _SC_CLK_TCK};
#[cfg(feature = "save-traces")]
use std::fs::File;
use super::{pyroscope_exporter::PyroscopeExporter, FoldedStackTraceBatch, StackTrace};

const USERSPACE_STR: &str = "Userspace";

struct UserProcState {
    pid: u32,
    /// In seconds
    user_time_prev: f64,
    comm: &'static str
}

impl UserProcState {
    fn new(pid: u32, clk_tck: f64) -> anyhow::Result<Self> {
        let comm = {
            let s = Self::stat_nth_entry(pid, 1)?;
            let mut c = s.chars();
            c.next();
            c.next_back();
            c.as_str().to_string()
        };

        let s = Self {
            pid,
            user_time_prev: Self::stat_nth_entry(pid, 13)?.parse::<u64>()? as f64 / clk_tck,
            comm: comm.leak()
        };

        Ok(s)
    }

    fn stat_nth_entry(pid: u32, n: usize) -> anyhow::Result<String> {
        let s = std::fs::read_to_string(format!("/proc/{}/stat", pid))?
            .split_ascii_whitespace()
            .nth(n)
            .ok_or(anyhow::anyhow!("Unable to get nth stat entry, n = {n}"))?
            .to_string();

        Ok(s)
    }
    
    fn user_time_delta(&mut self, clk_tck: f64) -> anyhow::Result<f64> {
        let new = Self::stat_nth_entry(self.pid, 13)?
            .parse::<u64>()? as f64 / clk_tck;

        let delta = new - self.user_time_prev;
        self.user_time_prev = new;

        Ok(delta)
    }
}

/// Actor responsible for interacting with BPF via shared maps,
/// retrieve stack traces from the ring buffer, and analyze them
/// to provide user-facing performance metrics.
pub struct TraceAnalyzer {
    /// User-space invocation period
    run_period: Duration,

    /// libbpf's skeleton
    skel: ProgSkel<'static>,

    /// Pointer to the mmaped stack traces array map
    stack_traces_ptr: *const u64,

    /// Half size of the `stack_traces` eBPF map in number of entries
    stack_traces_slot_size: u32,

    /// Maximum number of traces that could theoretically be recorded for each controller update period
    max_traces: u32,

    /// Kernel symbols for processing the traces
    ksyms: KSyms,
    
    /// Link to the open powercap interface for power queries
    rapl: Option<IntelRapl>,

    /// Interface for sending unrecoverable runtime errors to the
    /// main task, triggering the program termination
    error_catcher_sender: Sender<anyhow::Error>,

    /// Total energy, as reported by RAPL, up to the
    /// previous update cycle
    prev_total_energy: u64,

    prev_update_ts: Instant,
    pyroscope_exporter_actor_addr: Addr<PyroscopeExporter>,

    num_possible_cpus: usize,
    ticks_per_second: f64,
    user_procs_state: Vec<UserProcState>,

    #[cfg(feature = "save-traces")]
    traces_output_buf: Vec<u8>
}

impl TraceAnalyzer {
    /// Build a new TraceAnalyzer instance.
    /// 
    /// Note that the `per_cpu` map is passed by its id in order
    /// to be able to acquire it as an owned `libbpf_rs::Map` and
    /// avoid the reference to the lifetime of the main skel.
    pub fn new(
        run_period: Duration,
        num_possible_cpus: usize,
        skel: ProgSkel<'static>,
        stack_traces_max_entries: u32,
        max_traces: u32,
        error_catcher_sender: Sender<anyhow::Error>,
        pyroscope_exporter_actor_addr: Addr<PyroscopeExporter>,
        user_pids: Vec<u32>
    ) -> anyhow::Result<Self> {
        let stack_traces_ptr = unsafe { mmap(
            std::ptr::null_mut(),
            std::mem::size_of::<u64>() * 128 * stack_traces_max_entries as usize,
            PROT_READ,
            MAP_SHARED,
            skel.maps().stack_traces().fd(),
            0
        ) } as *const u64;

        let rapl = PowerCap::try_default()
            .map(|rapl| rapl.intel_rapl)
            .ok();

        let ticks_per_second = unsafe {
            let v = sysconf(_SC_CLK_TCK);
            if v < 0 {
                anyhow::bail!("Failed to retrieve ticks per second from sysconf");
            }
            v as f64
        };

        let user_procs_state = user_pids
            .into_iter()
            .filter_map(|pid| UserProcState::new(pid, ticks_per_second).ok())
            .collect();

        Ok(Self {
            run_period,
            skel,
            stack_traces_ptr,
            stack_traces_slot_size: stack_traces_max_entries / 2,
            max_traces,
            ksyms: KSyms::load()?,
            rapl,
            error_catcher_sender,
            prev_update_ts: Instant::now(),
            prev_total_energy: 0,
            pyroscope_exporter_actor_addr,
            num_possible_cpus,
            ticks_per_second,
            user_procs_state,
            #[cfg(feature = "save-traces")]
            traces_output_buf: vec![]
        })
    }

    /// Main user-space update loop
    #[inline]
    fn run_interval(&mut self) -> anyhow::Result<()> {
        let now = Instant::now();
        
        // Update state
        let delta_time = {
            let dt = now.duration_since(self.prev_update_ts);
            self.prev_update_ts = now;
            dt
        };
        let _delta_energy = self.rapl.as_ref().map(|rapl| {
            let current_total_energy = rapl
                .sockets
                .values()
                .flat_map(|socket| socket.energy())
                .sum();
            let delta_energy = current_total_energy - self.prev_total_energy;
            self.prev_total_energy = current_total_energy;
            delta_energy
        });

        let mut folded_stack_trace_batch = FoldedStackTraceBatch {
            traces: HashMap::new()
        };
        
        // Drain the stack traces array
        {
            // Swap buffer slots and get the number of stack traces in the previously active slot
            let slot_off = self.skel.bss().stack_traces_slot_off as usize;
            let num_traces_ref;
            (self.skel.bss().stack_traces_slot_off, num_traces_ref) = if slot_off > 0 {
                (0                          , &mut self.skel.bss().stack_traces_count_slot_1)
            } else {
                (self.stack_traces_slot_size, &mut self.skel.bss().stack_traces_count_slot_0)
            };

            // Make sure to read the count *after* swapping the slots
            let num_traces = *num_traces_ref;
            let num_traces = num_traces.min(self.stack_traces_slot_size as _);

            // Estimate CPU consumption from user space processes by how many traces we didn't get compared to the requested number
            // (note that this can potentially fail completely when the requested frequency is reduced automatically by Linux due
            // to high CPU utilization)
            let mut user_samples = (self.max_traces as i64 - num_traces as i64).max(0) as u64;

            for u in &mut self.user_procs_state {
                if let Ok(delta) = u.user_time_delta(self.ticks_per_second) {
                    let max_traces_per_cpu = self.max_traces as f64 / self.num_possible_cpus as f64;
                    let num_proc_traces = (delta * max_traces_per_cpu / delta_time.as_secs_f64()) as u64;
                    user_samples = user_samples.saturating_sub(num_proc_traces);

                    folded_stack_trace_batch.traces.insert(StackTrace {
                        frames: vec![&u.comm, USERSPACE_STR]
                    }, num_proc_traces as _);
                }
            }
            
            folded_stack_trace_batch.traces.insert(StackTrace {
                frames: vec![USERSPACE_STR]
            }, user_samples as _);
            
            let mut trace_buf: Option<StackTrace> = None;

            // Count symbols
            unsafe {
                for trace_ptr in (0..num_traces as usize).map(|trace_idx| self.stack_traces_ptr.add((slot_off + trace_idx) * 128 /* size of a single trace */)) {
                    // Get the cpuid
                    let (trace_size, _cpuid) = {
                        let v = trace_ptr.read_volatile();

                        // Note that the trace size is encoded in bytes in the map, but we care about number of u64s
                        (v >> 35, v & 0xFFFFFFFF)
                    };

                    if let Some(trace) = trace_buf.as_mut() {
                        trace.frames.clear();
                    }

                    let idle = self.ksyms.eval_trace(
                        trace_ptr.add(1),
                        trace_size as _,
                        trace_buf.get_or_insert_with(|| StackTrace {
                            frames: Vec::with_capacity(8)
                        })
                    );
                    
                    let mut trace = trace_buf.take().unwrap(); // Cannot fail
                    if !idle {
                        trace.frames.push("Kernel");
                    }

                    trace_buf = folded_stack_trace_batch.join_trace(trace);
                }
            }

            // Reset the stack traces index for this slot
            *num_traces_ref = 0;
        }

        // Send extracted traces to the pyroscope exporter actor
        self.pyroscope_exporter_actor_addr.do_send(folded_stack_trace_batch);

        Ok(())
    }
}

impl Actor for TraceAnalyzer {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.run_interval(self.run_period, |act, _| {
            if let Err(e) = act.run_interval() {
                act.error_catcher_sender.blocking_send(e).unwrap();
            }
        });
    }

    #[cfg(feature = "save-traces")]
    fn stopped(&mut self, _ctx: &mut Self::Context) {
        use std::io::Write;
        let mut traces_file = File::create("traces").unwrap();
        traces_file.write_all(&self.traces_output_buf).unwrap();
    }
}
