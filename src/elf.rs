//! ELF file helper

use goblin::elf::{header::*, sym::Sym, Elf};
use goblin::strtab::Strtab;

#[derive(Deref, Clone)]
pub struct ElfSym<'a> {
    #[deref]
    pub sym: Sym,
    pub name: &'a str,
}

impl ElfSym<'_> {
    #[inline]
    pub fn offset(&self) -> usize {
        self.sym.st_value as usize
    }

    pub fn from_raw<'a>(e: &'a Strtab, s: &Sym) -> Option<ElfSym<'a>> {
        if s.st_value > 0 {
            e.get_at(s.st_name).map(|name| ElfSym { sym: *s, name })
        } else {
            None
        }
    }
}

#[derive(Deref)]
pub struct ElfHelper<'a>(Elf<'a>);

impl<'a> ElfHelper<'a> {
    pub fn enum_export(&'a self) -> impl 'a + Iterator<Item = ElfSym<'a>> {
        self.0.dynsyms.iter().filter_map(move |s| {
            ElfSym::from_raw(&self.0.dynstrtab, &s).or_else(|| ElfSym::from_raw(&self.0.strtab, &s))
        })
    }

    pub fn enum_symbol(&'a self) -> impl 'a + Iterator<Item = ElfSym<'a>> {
        self.0
            .syms
            .iter()
            .filter_map(move |s| ElfSym::from_raw(&self.0.strtab, &s))
    }

    pub fn get_export(&'a self, name: &str) -> Option<ElfSym<'a>> {
        for s in self.enum_export() {
            if s.name == name {
                return Some(s);
            }
        }
        None
    }

    #[inline]
    pub fn arch(&self) -> Option<&'static str> {
        Self::arch_name(self.0.header.e_machine)
    }

    #[inline]
    pub fn entry(&self) -> u64 {
        self.0.entry
    }

    pub fn parse(data: &'a [u8]) -> Option<Self> {
        Elf::parse(data).ok().map(|elf| Self(elf))
    }

    pub fn arch_name(m: u16) -> Option<&'static str> {
        Some(match m {
            EM_386 | EM_860 | EM_960 => "x86",
            EM_X86_64 => "x86_64",
            EM_MIPS => "mips",
            EM_ARM => "arm",
            EM_AARCH64 => "arm64",
            _ => return None,
        })
    }
}
