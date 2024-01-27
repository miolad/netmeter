use std::{io::{self, BufReader, BufRead}, fs::File, collections::BTreeMap};
use crate::actors::StackTrace;

/// Helper to load and manage application-defined kernel symbols
#[derive(Default)]
pub struct KSyms {
    syms: BTreeMap<u64, KSymsVal>
}

struct KSymsVal {
    range_end: u64,
    name: &'static str
}

const NET_RX_SOFTIRQ_STR: &str = "NET_RX_SOFTIRQ";
const NET_TX_SOFTIRQ_STR: &str = "NET_TX_SOFTIRQ";
const IDLE_STR:           &str = "- idle -";

impl KSyms {
    /// Load requested kernel symbols from /proc/kallsyms
    pub fn load() -> io::Result<Self> {
        let mut btree = BTreeMap::new();
        let f = BufReader::new(File::open("/proc/kallsyms")?);
        
        // Load all the addresses into a BTreeMap
        for line in f.lines() {
            let line = line?;
            let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
            let name = parts[2];
            let addr = u64::from_str_radix(parts[0], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, line.clone()))?;

            btree.insert(addr, name.to_string());
        }

        // Only keep the symbols we're interested in
        let syms = btree
            .iter()
            .filter_map(|(&range_start, name)| {
                match name.as_str() {
                    "net_rx_action"                => Some(NET_RX_SOFTIRQ_STR),
                    "net_tx_action"                => Some(NET_TX_SOFTIRQ_STR),
                    "__napi_poll"                  => Some("__napi_poll"),
                    "netif_receive_skb" | "netif_receive_skb_core" | "netif_receive_skb_list_internal" | "__netif_receive_skb"
                                                   => Some("*netif_receive_skb*"),
                    "napi_gro_receive"             => Some("napi_gro_receive"),
                    "do_xdp_generic"               => Some("XDP_GENERIC"),
                    "tcf_classify"                 => Some("TC classify"),
                    "br_handle_frame"              => Some("Bridging"),
                    "ip_forward"                   => Some("IPv4 Forwarding"),
                    "ip6_forward"                  => Some("IPv6 Forwarding"),
                    "ip_local_deliver"             => Some("IPv4 Local Deliver"),
                    "ip6_input"                    => Some("IPv6 Local Deliver"),
                    "nf_hook_slow"                 => Some("NetFilter Hook"),
                    "ip_rcv"                       => Some("IPv4 Receive"),
                    "ip6_rcv"                      => Some("IPv6 Receive"),
                    "nf_conntrack_in"              => Some("NetFilter Conntrack"),
   
                    "sock_recvmsg"                 => Some("sock_recvmsg"),
                    "sock_sendmsg"                 => Some("sock_sendmsg"),
                    
                    "syscall_enter_from_user_mode" => Some("Syscall entry overhead"),
                    "syscall_exit_to_user_mode"    => Some("Syscall exit overhead"),

                    "xfrm_trans_reinject"          => Some("IPSec worker"),

                    "wg_receive"                   => Some("WireGuard recv"),
                    "wg_xmit"                      => Some("WireGuard xmit"),
                    "wg_packet_decrypt_worker"     => Some("WireGaurd decryption worker"),
                    "wg_packet_encrypt_worker"     => Some("WireGuard encryption worker"),
                    "wg_packet_tx_worker"          => Some("WireGuard xmit worker"),

                    "tls_sw_recvmsg"               => Some("kTLS recvmsg"),
                    "tls_sw_sendmsg"               => Some("kTLS sendmsg"),

                    "do_idle"                      => Some(IDLE_STR),

                    // Ad-hoc
                    "io_sq_thread"                 => Some("io_uring SQPOLL thread"),
                    "io_run_task_work"             => Some("io_uring task work"),
                    "__x64_sys_epoll_pwait"        => Some("epoll"),
                    "__x64_sys_futex"              => Some("futex"),
                    "__x64_sys_nanosleep"          => Some("nanosleep"),

                    _ => None
                }.map(|name| (range_start, KSymsVal {
                    range_end: btree
                        .range(range_start+1..)
                        .next()
                        .map(|(&addr, _)| addr)
                        .unwrap_or(range_start + 1),
                    name
                }))
            })
            .collect();

        Ok(Self { syms })
    }

    #[inline]
    pub unsafe fn eval_trace(
        &self,
        trace_ptr: *const u64,
        max_frames: usize,
        out_trace: &mut StackTrace
    ) -> bool {
        for frame_idx in 0..max_frames {
            let ip = trace_ptr.add(frame_idx).read_volatile();
            if ip == 0 {
                break;
            }

            if let Some((_, &KSymsVal { range_end, name })) = self
                .syms
                .range(..=ip)
                .next_back() {
                    if ip < range_end {
                        if std::ptr::eq(name, IDLE_STR) {
                            if out_trace.frames.is_empty() {
                                out_trace.frames.push(name);
                                return true;
                            } else {
                                return false;
                            }
                        }
                        
                        out_trace.frames.push(name);

                        if std::ptr::eq(name, NET_RX_SOFTIRQ_STR) || std::ptr::eq(name, NET_TX_SOFTIRQ_STR) {
                            return false;
                        }
                    }
                }
        }
        
        if out_trace.frames.is_empty() {
            out_trace.frames.push("- other -");
        }
        
        false
    }
}
