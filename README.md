
# udbg

udbg provides a mass of functions for implementing a binary debugger, and the most of interfaces were designed to be dynamic objects, which is for script-binding friendly.

- 👍 Cross-platform: udbg wraps the details of different debug interface of OS, and provides uniform interfaces for debugging
- 👍 Multiple-target: you can control multiple debug target in most cases
- 👍 Non-invasive: you can only view the information of target, instead of attaching to it

There is default debug engine implements by udbg itself, and a wrapped [dbgeng](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-engine-overview) as same interface as udbg

## Supported features

|    Platform/Target     | Target Info | Debug Symbol | Breakpoint | Watchpoint(HWBP) | Multiple Target |
| ---------------------- | ----------- | ------------ | ---------- | ---------------- | --------------- |
| Windows(x86/x64)       | ✔️          | ✔️ (pdb)     | ✔️         | ✔️               | ✔️              |
| Windows(aarch64)       | ✔️          | ✔️ (pdb)     | ✔️         | ✔️               | ✔️              |
| Linux(x86_64)          | ✔️          | ✔️ (elf)     | ✔️         | ✔️               | ✔️              |
| Linux/Android(aarch64) | ✔️          | ✔️ (elf)     | ✔️         | ✔️               | ✔️              |
| Minidump               | 🚧           | 🚧            | -          | -                | -               |

## Examples

- Write a basic debugger, see `examples/debugger.rs` `src/test.rs`