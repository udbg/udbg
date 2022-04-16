use libc::*;

// https://opensource.apple.com/source/dyld/dyld-353.2.1/include/mach-o/dyld_images.h.auto.html

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct dyld_image_info {
    pub imageLoadAddress: *const mach_header, /* base address image is mapped into */
    pub imageFilePath: *const c_char,         /* path dyld used to load the image */
    pub imageFileModDate: usize,              /* time_t of image file */
                                              /* if stat().st_mtime of imageFilePath does not match imageFileModDate, */
                                              /* then file has been modified since dyld loaded it */
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct dyld_uuid_info {
    pub imageLoadAddress: *const mach_header, /* base address image is mapped into */
    pub imageUUID: uuid_t,                    /* UUID of image */
}

// type dyld_image_notifier = extern "C" fn (enum dyld_image_mode mode, uint32_t infoCount, const struct dyld_image_info info[]);
pub type dyld_image_notifier = usize;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct dyld_all_image_infos {
    pub version: u32, /* 1 in Mac OS X 10.4 and 10.5 */
    pub infoArrayCount: u32,
    pub infoArray: *const dyld_image_info,
    pub notification: dyld_image_notifier,
    pub processDetachedFromSharedRegion: bool,
    /* the following fields are only in version 2 (Mac OS X 10.6, iPhoneOS 2.0) and later */
    pub libSystemInitialized: bool,
    pub dyldImageLoadAddress: *const mach_header,
    /* the following field is only in version 3 (Mac OS X 10.6, iPhoneOS 3.0) and later */
    pub jitInfo: *mut (),
    /* the following fields are only in version 5 (Mac OS X 10.6, iPhoneOS 3.0) and later */
    pub dyldVersion: *const c_char,
    pub errorMessage: *const c_char,
    pub terminationFlags: usize,
    /* the following field is only in version 6 (Mac OS X 10.6, iPhoneOS 3.1) and later */
    pub coreSymbolicationShmPage: *mut (),
    /* the following field is only in version 7 (Mac OS X 10.6, iPhoneOS 3.1) and later */
    pub systemOrderFlag: usize,
    /* the following field is only in version 8 (Mac OS X 10.7, iPhoneOS 3.1) and later */
    pub uuidArrayCount: usize,
    pub uuidArray: *const dyld_uuid_info, /* only images not in dyld shared cache */
    /* the following field is only in version 9 (Mac OS X 10.7, iOS 4.0) and later */
    pub dyldAllImageInfosAddress: *mut dyld_all_image_infos,
    /* the following field is only in version 10 (Mac OS X 10.7, iOS 4.2) and later */
    pub initialImageCount: usize,
    /* the following field is only in version 11 (Mac OS X 10.7, iOS 4.2) and later */
    pub errorKind: usize,
    pub errorClientOfDylibPath: *const c_char,
    pub errorTargetDylibPath: *const c_char,
    pub errorSymbol: *const c_char,
    /* the following field is only in version 12 (Mac OS X 10.7, iOS 4.3) and later */
    pub sharedCacheSlide: usize,
    /* the following field is only in version 13 (Mac OS X 10.9, iOS 7.0) and later */
    pub sharedCacheUUID: [u8; 16],
    /* the following field is only in version 14 (Mac OS X 10.9, iOS 7.0) and later */
    pub reserved: [usize; 16],
}

// https://opensource.apple.com/source/xnu/xnu-4570.41.2/bsd/sys/proc_info.h

#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct proc_fileinfo {
    pub fi_openflags: u32,
    pub fi_status: u32,
    pub fi_offset: off_t,
    pub fi_type: i32,
    pub fi_guardflags: u32,
}

#[derive(Default, Clone, Copy, Debug)]
#[repr(C)]
pub struct vinfo_stat {
    pub vst_dev: u32,           /* [XSI] ID of device containing file */
    pub vst_mode: u16,          /* [XSI] Mode of file (see below) */
    pub vst_nlink: u16,         /* [XSI] Number of hard links */
    pub vst_ino: u64,           /* [XSI] File serial number */
    pub vst_uid: uid_t,         /* [XSI] User ID of the file */
    pub vst_gid: gid_t,         /* [XSI] Group ID of the file */
    pub vst_atime: i64,         /* [XSI] Time of last access */
    pub vst_atimensec: i64,     /* nsec of last access */
    pub vst_mtime: i64,         /* [XSI] Last data modification time */
    pub vst_mtimensec: i64,     /* last data modification nsec */
    pub vst_ctime: i64,         /* [XSI] Time of last status change */
    pub vst_ctimensec: i64,     /* nsec of last status change */
    pub vst_birthtime: i64,     /*  File creation time(birth)  */
    pub vst_birthtimensec: i64, /* nsec of File creation time */
    pub vst_size: off_t,        /* [XSI] file size, in bytes */
    pub vst_blocks: i64,        /* [XSI] blocks allocated for file */
    pub vst_blksize: i32,       /* [XSI] optimal blocksize for I/O */
    pub vst_flags: u32,         /* user defined flags for file */
    pub vst_gen: u32,           /* file generation number */
    pub vst_rdev: u32,          /* [XSI] Device ID */
    pub vst_qspare: [i64; 2],   /* RESERVED: DO NOT USE! */
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct vnode_info {
    pub vi_stat: vinfo_stat,
    pub vi_type: i32,
    pub vi_pad: i32,
    pub vi_fsid: fsid_t,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct vnode_info_path {
    pub vip_vi: vnode_info,
    pub vip_path: [c_char; MAXPATHLEN as usize], /* tail end of it  */
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct vnode_fdinfo {
    pub pfi: proc_fileinfo,
    pub pvi: vnode_info,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct vnode_fdinfowithpath {
    pub pfi: proc_fileinfo,
    pub pvip: vnode_info_path,
}
