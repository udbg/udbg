
use crate::{MAX_INSN_SIZE, ReadMemory};

use super::Process;

use iced_x86::{Decoder, DecoderOptions, Instruction};

#[derive(Deref)]
pub struct DisAsmWrapper {
    pub address: usize,
    data: [u8; 16],
    #[deref]
    insn: Instruction,
}

impl DisAsmWrapper {
    pub fn new(address: usize, buffer: &[u8]) -> Option<Self> {
        let mut decoder = if cfg!(target_arch = "x86_64") {
            Decoder::new(64, buffer, DecoderOptions::NONE)
        } else {
            Decoder::new(32, buffer, DecoderOptions::NONE)
        };
        let mut insn = Instruction::default();
        if decoder.can_decode() {
            decoder.decode_out(&mut insn);
            let length = insn.len() as usize;
            let mut data = [0u8; 16];
            (&mut data[..length]).copy_from_slice(&buffer[..length]);
            Some(Self { insn, address, data })
        } else { None }
    }

    #[inline]
    pub fn len(&self) -> usize { self.insn.len() as usize }

    #[inline]
    pub fn bytes(&self) -> &[u8] { &self.data[0..self.len()] }

    pub fn to_string(&self) -> String {
        use iced_x86::{Formatter, IntelFormatter};
        let mut fmt = IntelFormatter::new();
        let mut output = String::new();
        fmt.format(&self.insn, &mut output);
        output
    }
}

pub trait DisAsmUtil {
    fn disasm(&self, address: usize) -> Option<DisAsmWrapper>;
}

impl DisAsmUtil for Process {
    fn disasm(&self, address: usize) -> Option<DisAsmWrapper> {
        let mut buf = [0 as u8; MAX_INSN_SIZE];
        if self.read_memory(address, &mut buf)?.len() > 0 {
            DisAsmWrapper::new(address, &buf)
        } else { None }
    }
}