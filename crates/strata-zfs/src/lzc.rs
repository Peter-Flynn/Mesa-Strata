//! libzfs_core bindings for the hot-path operations: snapshot, hold, release, send,
//! destroy, bookmark. Linked only with the `lzc` feature.

#[cfg(feature = "lzc")]
mod ffi {
    use std::ffi::{c_char, c_int};

    #[repr(C)]
    pub struct nvlist_t {
        _p: [u8; 0],
    }
    #[repr(C)]
    pub struct nvpair_t {
        _p: [u8; 0],
    }

    #[link(name = "nvpair")]
    unsafe extern "C" {
        pub fn fnvlist_alloc() -> *mut nvlist_t;
        pub fn fnvlist_free(nvl: *mut nvlist_t);
        pub fn nvlist_free(nvl: *mut nvlist_t);
        pub fn fnvlist_add_boolean(nvl: *mut nvlist_t, name: *const c_char);
        pub fn fnvlist_add_string(nvl: *mut nvlist_t, name: *const c_char, val: *const c_char);
        pub fn fnvlist_add_nvlist(nvl: *mut nvlist_t, name: *const c_char, val: *mut nvlist_t);
        pub fn nvlist_next_nvpair(nvl: *mut nvlist_t, nvp: *mut nvpair_t) -> *mut nvpair_t;
        pub fn nvpair_name(nvp: *mut nvpair_t) -> *const c_char;
        pub fn nvpair_value_int32(nvp: *mut nvpair_t, val: *mut i32) -> c_int;
    }

    #[link(name = "zfs_core")]
    unsafe extern "C" {
        pub fn libzfs_core_init() -> c_int;
        pub fn lzc_snapshot(snaps: *mut nvlist_t, props: *mut nvlist_t, errlist: *mut *mut nvlist_t) -> c_int;
        pub fn lzc_hold(holds: *mut nvlist_t, cleanup_fd: c_int, errlist: *mut *mut nvlist_t) -> c_int;
        pub fn lzc_release(holds: *mut nvlist_t, errlist: *mut *mut nvlist_t) -> c_int;
        pub fn lzc_destroy_snaps(snaps: *mut nvlist_t, defer: c_int, errlist: *mut *mut nvlist_t) -> c_int;
        pub fn lzc_bookmark(bookmarks: *mut nvlist_t, errlist: *mut *mut nvlist_t) -> c_int;
        pub fn lzc_destroy_bookmarks(bookmarks: *mut nvlist_t, errlist: *mut *mut nvlist_t) -> c_int;
        pub fn lzc_send_resume(
            snapname: *const c_char,
            from: *const c_char,
            fd: c_int,
            flags: c_int,
            resumeobj: u64,
            resumeoff: u64,
        ) -> c_int;
    }

    pub const LZC_SEND_FLAG_EMBED_DATA: c_int = 1 << 0;
    pub const LZC_SEND_FLAG_LARGE_BLOCK: c_int = 1 << 1;
    pub const LZC_SEND_FLAG_COMPRESS: c_int = 1 << 2;
    pub const LZC_SEND_FLAG_RAW: c_int = 1 << 3;
}

#[cfg(feature = "lzc")]
mod imp {
    use super::ffi::*;
    use crate::{SendFlags, ZfsError};
    use std::ffi::{CStr, CString, c_int};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::sync::OnceLock;

    pub fn init() -> Result<(), ZfsError> {
        static RC: OnceLock<c_int> = OnceLock::new();
        // SAFETY: libzfs_core_init has no preconditions; it opens /dev/zfs and refcounts
        // itself, and OnceLock runs it once per process.
        let rc = *RC.get_or_init(|| unsafe { libzfs_core_init() });
        if rc != 0 {
            return Err(ZfsError::Failed(format!("libzfs_core_init: {}", std::io::Error::from_raw_os_error(rc))));
        }
        Ok(())
    }

    struct Nv(*mut nvlist_t);

    impl Nv {
        fn new() -> Nv {
            // SAFETY: fnvlist_alloc aborts on allocation failure instead of returning null.
            Nv(unsafe { fnvlist_alloc() })
        }
        fn add_boolean(&mut self, name: &str) -> Result<(), ZfsError> {
            let n = cstr(name)?;
            // SAFETY: self.0 is a live nvlist owned by this Nv; n outlives the call, and
            // fnvlist_add_boolean copies the name.
            unsafe { fnvlist_add_boolean(self.0, n.as_ptr()) };
            Ok(())
        }
        fn add_string(&mut self, name: &str, val: &str) -> Result<(), ZfsError> {
            let (n, v) = (cstr(name)?, cstr(val)?);
            // SAFETY: as in add_boolean; fnvlist_add_string copies both strings.
            unsafe { fnvlist_add_string(self.0, n.as_ptr(), v.as_ptr()) };
            Ok(())
        }
        fn add_list(&mut self, name: &str, val: &Nv) -> Result<(), ZfsError> {
            let n = cstr(name)?;
            // SAFETY: both nvlists are live and owned by their Nv wrappers;
            // fnvlist_add_nvlist copies `val`, so `val` keeps sole ownership of its list.
            unsafe { fnvlist_add_nvlist(self.0, n.as_ptr(), val.0) };
            Ok(())
        }
    }

    impl Drop for Nv {
        fn drop(&mut self) {
            // SAFETY: self.0 came from fnvlist_alloc and is freed only here.
            unsafe { fnvlist_free(self.0) };
        }
    }

    fn cstr(s: &str) -> Result<CString, ZfsError> {
        CString::new(s).map_err(|_| ZfsError::Failed(format!("name contains NUL: {s:?}")))
    }

    fn errno_err(what: &str, rc: c_int) -> ZfsError {
        use rustix::io::Errno;
        match Errno::from_raw_os_error(rc) {
            Errno::NOENT => ZfsError::NotFound(what.into()),
            Errno::EXIST => ZfsError::Exists(what.into()),
            Errno::BUSY => ZfsError::Busy(what.into()),
            _ => ZfsError::Failed(format!("{what}: {}", std::io::Error::from_raw_os_error(rc))),
        }
    }

    fn with_errlist(
        what: &str,
        f: impl FnOnce(*mut *mut nvlist_t) -> c_int,
    ) -> Result<Vec<(String, ZfsError)>, ZfsError> {
        let mut errlist: *mut nvlist_t = std::ptr::null_mut();
        let rc = f(&mut errlist);
        let mut errs = Vec::new();
        if !errlist.is_null() {
            let mut p: *mut nvpair_t = std::ptr::null_mut();
            loop {
                // SAFETY: errlist is a valid nvlist returned by libzfs_core; p is null or
                // the pair the previous call returned.
                p = unsafe { nvlist_next_nvpair(errlist, p) };
                if p.is_null() {
                    break;
                }
                // SAFETY: p is a live pair of errlist; nvpair_name returns a NUL-terminated
                // string owned by the pair, copied before errlist is freed.
                let name = unsafe { CStr::from_ptr(nvpair_name(p)) }.to_string_lossy().into_owned();
                let mut v: i32 = 0;
                // SAFETY: p is a live pair; v is a valid out-pointer. lzc error lists hold
                // int32 errnos; a pair of another type leaves v at 0.
                unsafe { nvpair_value_int32(p, &mut v) };
                errs.push((name.clone(), errno_err(&name, v)));
            }
            // SAFETY: errlist was allocated by libzfs_core for the caller to free.
            unsafe { nvlist_free(errlist) };
        }
        if rc != 0 && errs.is_empty() {
            return Err(errno_err(what, rc));
        }
        Ok(errs)
    }

    fn first_error(r: Result<Vec<(String, ZfsError)>, ZfsError>) -> Result<(), ZfsError> {
        match r?.into_iter().next() {
            Some((_, e)) => Err(e),
            None => Ok(()),
        }
    }

    pub fn snapshot(snaps: &[String], props: &[(&str, &str)]) -> Result<(), ZfsError> {
        init()?;
        let mut s = Nv::new();
        for n in snaps {
            s.add_boolean(n)?;
        }
        let mut p = Nv::new();
        for (k, v) in props {
            p.add_string(k, v)?;
        }
        let what = snaps.join(" ");
        // SAFETY: s and p are live nvlists for the duration of the call; e is the out
        // pointer with_errlist provides.
        first_error(with_errlist(&what, |e| unsafe { lzc_snapshot(s.0, p.0, e) }))
    }

    pub fn hold(snap: &str, tag: &str) -> Result<(), ZfsError> {
        init()?;
        let mut h = Nv::new();
        h.add_string(snap, tag)?;
        // SAFETY: h is live for the call; cleanup_fd -1 makes the hold permanent.
        first_error(with_errlist(snap, |e| unsafe { lzc_hold(h.0, -1, e) }))
    }

    pub fn release(snap: &str, tag: &str) -> Result<(), ZfsError> {
        init()?;
        let mut tags = Nv::new();
        tags.add_boolean(tag)?;
        let mut h = Nv::new();
        h.add_list(snap, &tags)?;
        // SAFETY: h is live for the call.
        first_error(with_errlist(snap, |e| unsafe { lzc_release(h.0, e) }))
    }

    pub fn destroy_snaps(snaps: &[String]) -> Result<Vec<(String, ZfsError)>, ZfsError> {
        init()?;
        let mut s = Nv::new();
        for n in snaps {
            s.add_boolean(n)?;
        }
        // SAFETY: s is live for the call; defer = 0 destroys immediately or fails.
        with_errlist(&snaps.join(" "), |e| unsafe { lzc_destroy_snaps(s.0, 0, e) })
    }

    pub fn bookmark(snap: &str, bookmark: &str) -> Result<(), ZfsError> {
        init()?;
        let mut b = Nv::new();
        b.add_string(bookmark, snap)?;
        // SAFETY: b is live for the call.
        first_error(with_errlist(bookmark, |e| unsafe { lzc_bookmark(b.0, e) }))
    }

    pub fn destroy_bookmarks(bookmarks: &[String]) -> Result<(), ZfsError> {
        init()?;
        let mut b = Nv::new();
        for n in bookmarks {
            b.add_boolean(n)?;
        }
        // SAFETY: b is live for the call.
        first_error(with_errlist(&bookmarks.join(" "), |e| unsafe { lzc_destroy_bookmarks(b.0, e) }))
    }

    pub fn send(
        snap: &str,
        from: Option<&str>,
        flags: SendFlags,
        resume: Option<(u64, u64)>,
        out: &OwnedFd,
    ) -> Result<(), ZfsError> {
        init()?;
        let s = cstr(snap)?;
        let f = from.map(cstr).transpose()?;
        let mut fl = 0;
        if flags.embed {
            fl |= LZC_SEND_FLAG_EMBED_DATA;
        }
        if flags.large_block {
            fl |= LZC_SEND_FLAG_LARGE_BLOCK;
        }
        if flags.compress {
            fl |= LZC_SEND_FLAG_COMPRESS;
        }
        if flags.raw {
            fl |= LZC_SEND_FLAG_RAW;
        }
        let (obj, off) = resume.unwrap_or((0, 0));
        // SAFETY: s and f are NUL-terminated and outlive the call; out is an open
        // descriptor borrowed for the call's duration.
        let rc = unsafe {
            lzc_send_resume(s.as_ptr(), f.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()), out.as_raw_fd(), fl, obj, off)
        };
        if rc != 0 {
            return Err(errno_err(&format!("send {snap}"), rc));
        }
        Ok(())
    }
}

#[cfg(not(feature = "lzc"))]
mod imp {
    use crate::{SendFlags, ZfsError};
    use std::os::fd::OwnedFd;

    pub fn snapshot(_: &[String], _: &[(&str, &str)]) -> Result<(), ZfsError> {
        Err(ZfsError::Unsupported)
    }
    pub fn hold(_: &str, _: &str) -> Result<(), ZfsError> {
        Err(ZfsError::Unsupported)
    }
    pub fn release(_: &str, _: &str) -> Result<(), ZfsError> {
        Err(ZfsError::Unsupported)
    }
    pub fn destroy_snaps(_: &[String]) -> Result<Vec<(String, ZfsError)>, ZfsError> {
        Err(ZfsError::Unsupported)
    }
    pub fn bookmark(_: &str, _: &str) -> Result<(), ZfsError> {
        Err(ZfsError::Unsupported)
    }
    pub fn destroy_bookmarks(_: &[String]) -> Result<(), ZfsError> {
        Err(ZfsError::Unsupported)
    }
    pub fn send(_: &str, _: Option<&str>, _: SendFlags, _: Option<(u64, u64)>, _: &OwnedFd) -> Result<(), ZfsError> {
        Err(ZfsError::Unsupported)
    }
}

pub use imp::*;
