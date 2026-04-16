const PR_SET_VMA: libc::c_int = 0x53564d41;
const PR_SET_VMA_ANON_NAME: libc::c_int = 0;

fn is_valid_anon_name(name: &str) -> bool {
    if name.is_empty() || name.len() >= 80 {
        return false;
    }

    name.bytes()
        .all(|b| matches!(b, 0x20..=0x7e) && !matches!(b, b'[' | b']' | b'\\' | b'$' | b'`'))
}

/// Best-effort anonymous VMA naming for `/proc/<pid>/maps`.
/// Some Android kernels keep a userspace pointer to the name instead of copying
/// it into kernel memory, so callers should pass a pointer with process-lifetime.
pub(crate) fn set_anon_vma_name_raw(addr: *mut u8, size: usize, name: &'static [u8]) -> Result<(), i32> {
    if addr.is_null() || size == 0 || name.is_empty() || *name.last().unwrap() != 0 {
        return Err(libc::EINVAL);
    }
    let name_bytes = &name[..name.len() - 1];
    let Ok(name_str) = std::str::from_utf8(name_bytes) else {
        return Err(libc::EINVAL);
    };
    if !is_valid_anon_name(name_str) {
        return Err(libc::EINVAL);
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_prctl as libc::c_long,
            PR_SET_VMA as libc::c_long,
            PR_SET_VMA_ANON_NAME as libc::c_ulong,
            addr as libc::c_ulong,
            size as libc::c_ulong,
            name.as_ptr() as libc::c_ulong,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL))
    }
}
