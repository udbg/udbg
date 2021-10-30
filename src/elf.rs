
use std::ops::Deref;

use goblin::strtab::Strtab;
use goblin::elf::{Elf, sym::Sym};

#[derive(Clone)]
pub struct ElfSym<'a> {
    pub sym: Sym,
    pub name: &'a str,
}

impl Deref for ElfSym<'_> {
    type Target = Sym;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.sym }
}

impl ElfSym<'_> {
    #[inline]
    pub fn offset(&self) -> usize { self.sym.st_value as usize }
}

pub fn get_symbol<'a>(e: &'a Strtab, s: &Sym) -> Option<ElfSym<'a>> {
    if s.st_value > 0 {
        e.get(s.st_name).and_then(|r| r.ok()).map(|name| ElfSym {sym: *s, name})
    } else { None }
}

#[derive(Deref)]
pub struct ElfHelper<'a>(Elf<'a>);

impl<'a> ElfHelper<'a> {
    pub fn enum_export(&'a self) -> impl 'a + Iterator<Item=ElfSym<'a>> {
        self.0.dynsyms.iter().filter_map(move |s| get_symbol(&self.0.dynstrtab, &s))
    }

    pub fn enum_symbol(&'a self) -> impl 'a + Iterator<Item=ElfSym<'a>> {
        self.0.syms.iter().filter_map(move |s| get_symbol(&self.0.strtab, &s))
    }

    pub fn get_export(&'a self, name: &str) -> Option<ElfSym<'a>> {
        for s in self.enum_export() {
            if s.name == name { return Some(s); }
        }
        None
    }

    #[inline]
    pub fn arch(&self) -> Option<&'static str> {
        machine_to_arch(self.0.header.e_machine)
    }

    #[inline]
    pub fn entry(&self) -> u64 { self.0.entry }
}

pub fn parse(data: &[u8]) -> Option<ElfHelper> {
    Elf::parse(data).ok().map(|elf| ElfHelper(elf))
}

pub const EM_386: u16 = 3;    //Intel 80386
pub const EM_860: u16 = 7;    //Intel 80860
pub const EM_960: u16 = 19;
pub const EM_X86_64: u16 = 62;
pub const EM_MIPS: u16 = 8;    //MIPS I Architecture
pub const EM_ARM: u16 = 40;
pub const EM_ARM64: u16 = 183;

pub fn machine_to_arch(m: u16) -> Option<&'static str> {
    Some(match m {
        EM_386 | EM_860 | EM_960 => "x86",
        EM_X86_64 => "x86_64",
        EM_MIPS => "mips",
        EM_ARM => "arm",
        EM_ARM64 => "arm64",
        _ => return None,
    })
}