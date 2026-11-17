//! FIXTURE UJI — nilai sintetis, tidak berfungsi.

/// Membaca u64 lewat pointer mentah.
pub unsafe fn read_u64(ptr: *const u8) -> u64 {
    unsafe { *(ptr as *const u64) }
}
