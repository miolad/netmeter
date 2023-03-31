/* automatically generated by rust-bindgen 0.64.0 */

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct per_cpu_data {
    pub prev_ts: u64,
    pub total_syscall: u64,
    pub total_softirq: u64,
}
#[test]
fn bindgen_test_layout_per_cpu_data() {
    const UNINIT: ::std::mem::MaybeUninit<per_cpu_data> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<per_cpu_data>(),
        24usize,
        concat!("Size of: ", stringify!(per_cpu_data))
    );
    assert_eq!(
        ::std::mem::align_of::<per_cpu_data>(),
        8usize,
        concat!("Alignment of ", stringify!(per_cpu_data))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).prev_ts) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(per_cpu_data),
            "::",
            stringify!(prev_ts)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).total_syscall) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(per_cpu_data),
            "::",
            stringify!(total_syscall)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).total_softirq) as usize - ptr as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(per_cpu_data),
            "::",
            stringify!(total_softirq)
        )
    );
}
