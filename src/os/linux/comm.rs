use super::process::Process;
use crate::prelude::*;

impl<T: AsRef<Process>> ReadMemory for T {
    default fn read_memory<'a>(&self, addr: usize, data: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.as_ref().read_memory(addr, data)
    }
}

impl<T: AsRef<Process>> WriteMemory for T {
    default fn write_memory(&self, address: usize, data: &[u8]) -> Option<usize> {
        self.as_ref().write_memory(address, data)
    }
}

impl<T: AsRef<Process>> TargetMemory for T {
    default fn enum_memory<'a>(&'a self) -> UDbgResult<Box<dyn Iterator<Item = MemoryPage> + 'a>> {
        Ok(Box::new(self.as_ref().enum_memory()))
    }

    default fn virtual_query(&self, address: usize) -> Option<MemoryPage> {
        self.as_ref().virtual_query(address as _)
    }

    default fn virtual_alloc(&self, address: usize, size: usize, ty: &str) -> UDbgResult<usize> {
        todo!()
    }

    default fn virtual_free(&self, address: usize) {}

    default fn collect_memory_info(&self) -> Vec<MemoryPageInfo> {}
}

impl<T: AsRef<Process>> TargetControl for T {
    fn detach(&self) -> UDbgResult<()> {
        todo!()
    }

    fn kill(&self) -> UDbgResult<()> {
        todo!()
    }

    fn breakk(&self) -> UDbgResult<()> {
        todo!()
    }

    fn suspend(&self) -> UDbgResult<()> {
        self.as_ref().suspend();
        Ok(())
    }

    fn resume(&self) -> UDbgResult<()> {
        self.as_ref().resume();
        Ok(())
    }
}
