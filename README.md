
# udbg

[![crates.io](https://img.shields.io/crates/v/udbg.svg)](https://crates.io/crates/udbg)
[![docs.rs](https://docs.rs/udbg/badge.svg)](https://docs.rs/udbg)

Cross-platform library for binary debugging and memory hacking written in Rust.

- 👍 Cross-platform: udbg wraps the details of different interfaces on different platform, and provides uniform interfaces
- 👍 Multiple-target: you can control multiple debug target in most cases
- 👍 Non-invasive: you can only view the information of target, instead of attaching to it
- 👍 Various target types: In addition to process, target can be a [`minidump`](struct@minidump::MiniDumpTarget), a [`PE file`](struct@pe::PETarget), even be the OS-Kernel space with extra extension.

## API Overview

There are two main kinds of interfaces in udbg, target information and debugging interfaces.

Interaces of target information, which abstracted as the [`UDbgTarget`](trait@target::UDbgTarget) trait, represents an observable debugging target, it is an [`active process`](struct@os::ProcessTarget) in most cases, also it can be a [`minidump`](struct@minidump::MiniDumpTarget), a [`PE file`](struct@pe::PETarget), even be the OS-Kernel space with extra extension.

[`UDbgTarget`](trait@target::UDbgTarget) contains these functions, [`memory operation`](trait@memory::TargetMemory) (read/write/enumeration), [`module`](trait@symbol::UDbgModule) enumeration, [`thread`](trait@target::UDbgThread) enumeration, [`handle/FDs`](struct@shell::HandleInfo) enumeration, etc. Based on these functions, we can implement some utililties over the different types of target, such as **[module dump](https://github.com/glmcdona/Process-Dump)**, **memory search**, **hook scanning**, **malicious code scanning**, etc.

Debugging interfaces, which abstracted as the [`UDbgEngine`](trait@target::UDbgEngine) trait, mainly provides the ability of process control. There is a [`default implementation`](struct@os::DefaultEngine), typically it wraps the [Debugging Functions](https://docs.microsoft.com/en-us/windows/win32/debug/debugging-functions) on Windows, and wraps the [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html) interfaces on Linux.

Most of above interfaces were designed to be dynamic objects, which is for script-binding friendly, and udbg provides [`lua bindings`](mod@lua) defaultly.

Current status of target information interfaces

| Platform/Target | Memory operation | Memory List | Thread | Module/Symbol | Handle/FD List |
| --------------- | ---------------- | ----------- | ------ | ------------- | -------------- |
| Windows Process | ✔️               | ✔️          | ✔️     | ✔️            | ✔️             |
| Linux Process   | ✔️               | ✔️          | ✔️     | ✔️            | ✔️             |
| MacOs Process   | ✔️               | ✔️          | ✔️     | ✔️            | ✔️             |
| Minidump        | ✔️ (readonly)    | ✔️          | ✔️     | ✔️            | 🚧              |
| PE File         | ✔️ (readonly)    | ✔️          | -      | -             | -              |

Current status of debugging interfaces

| Platform/Target  | Debug Symbol | Breakpoint | Watchpoint(HWBP) | Multiple Target |
| ---------------- | ------------ | ---------- | ---------------- | --------------- |
| Windows(x86/x64) | ✔️ (pdb)     | ✔️         | ✔️               | ✔️              |
| Windows(aarch64) | ✔️ (pdb)     | ✔️         | ✔️               | ✔️              |
| Linux(x86_64)    | ✔️ (elf)     | ✔️         | ✔️               | ✔️              |
| Linux(aarch64)   | ✔️ (elf)     | ✔️         | ✔️               | ✔️              |

<!-- ### Wrapper of functions in ntdll for windows -->

<!-- ### String utilities -->

## Examples

- Cross-platform interfaces to get target information, see `src/test.rs` `fn target`
- Write a basic debugger, see `src/test.rs` `fn test_debug`
<!-- - Read or write target memory, even any struct -->
<!-- tracing multiple target, and its child -->