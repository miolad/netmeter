#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

char LICENSE[] SEC("license") = "GPL";

/**
 * Buffer with all the captured stack traces.
 * The buffer is logically split into two equal-sized slots,
 * that are swapped by the user-space just before each update.
 * 
 * Each element of the array encodes:
 *   - trace size in bytes (32 MSbits) | cpuid (32 LSbits) in the first u64
 *   - actual trace in the next 127 u64s
 * 
 * The array is mmapable to allow fast access from user-space
 * without the need for expensive syscalls.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64)*128);
    __uint(max_entries, 1); // This is set at runtime based on configuration parameters
} stack_traces SEC(".maps");

/**
 * Counters of the number of traces present in each slot of
 * the `stack_traces` buffer.
 * 
 * Their increment must be atomic from the bpf side
 * as they are shared among all the cpus.
 */
u64 stack_traces_count_slot_0 = 0, stack_traces_count_slot_1 = 0;

/**
 * Slot selector into the `stack_traces` map.
 * 
 * The value represents the current offset to be applied to
 * the buffer, and will therefore only ever be 0 or `stack_traces.max_entries/2`.
 * 
 * A non-zero value means select slot1, otherwise use slot0.
 */
u32 stack_traces_slot_off = 0;

SEC("perf_event")
int perf_event_prog(struct bpf_perf_event_data* ctx) {
    struct per_cpu_data* per_cpu_data;
    u32 index, zero = 0;
    u64* buf;
    
    index = __sync_fetch_and_add(
        stack_traces_slot_off ? &stack_traces_count_slot_1 : &stack_traces_count_slot_0,
        1
    ) + stack_traces_slot_off;
    
    if (likely((buf = bpf_map_lookup_elem(&stack_traces, &index)) != NULL)) {
        *buf = (u64)bpf_get_smp_processor_id() |
               ((u64)bpf_get_stack(ctx, buf+1, sizeof(u64)*127, 0) << 32);
    }

    return 0;
}
