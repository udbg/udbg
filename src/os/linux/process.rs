use super::*;

use procfs::{process::Process as ProcPs, ProcError};
use std::os::unix::prelude::AsRawFd;
use std::sync::Arc;

#[derive(Deref)]
pub struct Process {
    #[deref]
    pub _proc: ProcPs,
    mem: RwLock<Option<Box<File>>>,
}

impl From<ProcError> for UDbgError {
    fn from(err: ProcError) -> Self {
        Self::Other(err.into())
    }
}

impl Process {
    pub fn from_pid(pid: pid_t) -> UDbgResult<Self> {
        let _proc = ProcPs::new(pid)?;
        Ok(Self {
            _proc,
            mem: RwLock::new(None),
        })
    }

    pub fn from_comm(name: &str) -> UDbgResult<Self> {
        PidIter::proc()?
            .find(|&pid| Self::pid_name(pid).as_ref().map(String::as_str) == Some(name))
            .ok_or(UDbgError::NotFound)
            .and_then(Process::from_pid)
    }

    pub fn from_name(name: &str) -> UDbgResult<Self> {
        PidIter::proc()?
            .find(|&pid| Self::pid_cmdline(pid).get(0).map(String::as_str) == Some(name))
            .ok_or(UDbgError::NotFound)
            .and_then(Process::from_pid)
    }

    pub fn current() -> Self {
        unsafe { Self::from_pid(getpid()).unwrap() }
    }

    pub fn pid_name(pid: pid_t) -> Option<String> {
        Utils::file_lines(format!("/proc/{}/comm", pid))
            .ok()?
            .next()
    }

    pub fn pid_cmdline(pid: pid_t) -> Vec<String> {
        let data = std::fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or(vec![]);
        let mut result = data
            .split(|b| *b == 0u8)
            .map(|b| unsafe { String::from_utf8_unchecked(b.to_vec()) })
            .collect::<Vec<_>>();
        while result.last().map(String::is_empty).unwrap_or(false) {
            result.pop();
        }
        result
    }

    pub fn pid_path(pid: pid_t) -> IoResult<String> {
        read_link(format!("/proc/{}/exe", pid)).map(|p| p.to_string_lossy().into())
    }

    pub fn pid_environ(pid: pid_t) -> IoResult<HashMap<String, String>> {
        let data = std::fs::read(format!("/proc/{}/environ", pid))?;
        let mut result = HashMap::new();
        data.split(|b| *b == 0u8).map(|b| unsafe {
            let item = std::str::from_utf8_unchecked(b);
            let mut i = item.split("=");
            if let Some(name) = i.next() {
                result.insert(name.to_string(), i.next().unwrap().into());
            }
        });
        Ok(result)
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    #[inline]
    pub fn name(&self) -> Option<String> {
        Self::pid_name(self.pid)
    }

    #[inline]
    pub fn cmdline(&self) -> Vec<String> {
        Self::pid_cmdline(self.pid)
    }

    #[inline]
    pub fn image_path(&self) -> IoResult<String> {
        Self::pid_path(self.pid)
    }

    #[inline]
    pub fn environ(&self) -> IoResult<HashMap<String, String>> {
        Self::pid_environ(self.pid)
    }

    pub fn read_mem(mem: &File, address: usize, buf: &mut [u8]) -> usize {
        unsafe {
            let n = pread64(
                mem.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                address as _,
            );
            if n == -1 {
                0
            } else {
                n as _
            }
        }
    }

    #[inline]
    fn open_mem(&self) -> Option<()> {
        if self.mem.read().is_none() {
            *self.mem.write() = Some(Box::new(
                File::options()
                    .read(true)
                    .write(true)
                    .open(format!("/proc/{}/mem", self.pid))
                    .ok()?,
            ));
        }
        Some(())
    }

    pub fn enum_memory(&self) -> IoResult<impl Iterator<Item = MemoryPage>> {
        let mut iter = Utils::file_lines(format!("/proc/{}/maps", self.pid))?;
        Ok(core::iter::from_fn(move || {
            let line = iter.next()?;
            let mut line = LineParser::new(line.as_ref());
            let base = line.till('-').unwrap();
            let base = usize::from_str_radix(base, 16).unwrap();
            line.skip_count(1);
            let end = usize::from_str_radix(line.next().unwrap(), 16).unwrap();
            let size = end - base;
            let prot = line.next().unwrap();
            for i in 0..3 {
                line.next();
            }
            let usage: Arc<str> = line.rest().trim().into();

            let mut result = MemoryPage {
                base,
                size,
                usage,
                prot: [0; 4],
            };
            result.prot.copy_from_slice(prot.as_bytes());
            Some(result)
        }))
    }

    pub fn enum_module(&self) -> IoResult<impl Iterator<Item = Module> + '_> {
        Ok(ModuleIter {
            f: Utils::file_lines(format!("/proc/{}/maps", self.pid))?,
            p: self,
            base: 0,
            size: 0,
            usage: "".into(),
            cached: false,
        })
    }

    pub fn find_module_by_name(&self, name: &str) -> Option<Module> {
        self.enum_module().ok()?.find(|m| m.name.as_ref() == name)
    }
}

impl ReadMemory for Process {
    fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.open_mem()?;
        self.mem.read().as_ref().and_then(move |f| {
            let result = Self::read_mem(f, addr, data);
            if result > 0 {
                Some(&mut data[..result])
            } else {
                None
            }
        })
    }
}

impl WriteMemory for Process {
    fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        self.open_mem()?;
        self.mem.read().as_ref().and_then(move |f| unsafe {
            let n = pwrite64(
                f.as_raw_fd(),
                data.as_ptr().cast(),
                data.len(),
                address as _,
            );
            if n == -1 {
                None
            } else {
                Some(n as _)
            }
        })
    }

    // fn flush_cache(&self, address: usize, len: usize) -> IoResult<()> {
    //     match unsafe { libc::fsync(self.mem.read().as_ref().unwrap().as_raw_fd()) } {
    //         0 => Ok(()),
    //         err => Err(std::io::Error::last_os_error()),
    //     }
    // }
}

struct LineParser<'a> {
    s: &'a str,
}

impl<'a> LineParser<'a> {
    pub fn new(s: &'a str) -> Self {
        Self { s }
    }

    pub fn next(&mut self) -> Option<&'a str> {
        let s = self.s.trim_start();
        let pos = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
        self.s = &s[pos..];
        Some(&s[..pos])
    }

    pub fn till(&mut self, c: char) -> Option<&'a str> {
        let s = self.s.trim_start();
        let pos = s.find(c)?;
        self.s = &self.s[pos..];
        Some(&s[..pos])
    }

    pub fn rest(self) -> &'a str {
        self.s
    }

    pub fn skip_count(&mut self, c: usize) {
        self.s = &self.s[c..];
    }
}

pub struct Module {
    pub base: usize,
    pub size: usize,
    pub name: Arc<str>,
    pub path: Arc<str>,
}

pub struct ModuleIter<'a, I> {
    f: I,
    p: &'a Process,
    cached: bool,
    base: usize,
    size: usize,
    usage: Arc<str>,
}

pub const ELF_SIG: [u8; 4] = [127, b'E', b'L', b'F'];

impl<I: Iterator<Item = String>> ModuleIter<'_, I> {
    fn next_line(&mut self) -> bool {
        let line = match self.f.next() {
            Some(r) => r,
            None => return false,
        };
        let mut line = LineParser::new(line.as_ref());
        let base = line.till('-').unwrap();
        self.base = usize::from_str_radix(base, 16).expect("page base");
        line.skip_count(1);
        let end = usize::from_str_radix(line.next().unwrap(), 16).expect("page end");
        self.size = end - self.base;
        let _prot = line.next().unwrap().to_string();
        for _i in 0..3 {
            line.next();
        }
        self.usage = line.rest().trim().into();
        return true;
    }

    fn next_module(&mut self) -> Option<Module> {
        loop {
            if !self.cached {
                self.cached = self.next_line();
                if !self.cached {
                    return None;
                }
            }

            let mut sig = [0u8; 4];
            if self.usage.len() > 0
                && self.p.read_memory(self.base, &mut sig).is_some()
                && ELF_SIG == sig
            {
                // Moudle Begin
                let base = self.base;
                let path = self.usage.clone();
                let mut size = self.size;
                let name: Arc<str> = Path::new(path.as_ref())
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or("")
                    .into();
                loop {
                    self.cached = self.next_line();
                    if !self.cached || self.usage != path {
                        break;
                    }
                    size += self.size;
                }
                return Some(Module {
                    base,
                    size,
                    name,
                    path,
                });
            } else {
                self.cached = false;
            }
        }
    }
}

impl<'a, I: Iterator<Item = String>> Iterator for ModuleIter<'a, I> {
    type Item = Module;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(r) = self.next_module() {
            if r.path.as_ref() == "[vdso]" {
                continue;
            }
            return Some(r);
        }
        None
    }
}
