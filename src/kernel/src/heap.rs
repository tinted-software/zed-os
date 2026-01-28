use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_heap() {
    let heap_start = 0x6000_0000u64;
    let heap_size = 512 * 1024 * 1024; // 512MiB
    crate::kprintln!(
        "GRAVITY HEAP: Initializing at {:x} (size {:x})",
        heap_start,
        heap_size
    );
    unsafe {
        ALLOCATOR.lock().init(heap_start as *mut u8, heap_size);
    }
}
