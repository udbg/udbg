
udbg-base is the base library of udbg, it provides the API to write externsion for udbg, contains some utilities to write Windows native program, and you can also use it for memory hacking

## Features

- Cross-platform `ReadMemory`/`WriteMemory` trait, you can read the most of data types, by only implementing these trait, see `udbg_base::mem`
- Cross-platform iterator for memory, module, thread, process, etc.
- Implementation for DLL-inject, by creating remote thread or window hook `use udbg_base::inject;`
- Simple inline hook implementation (Windows) `use udbg_base::hook::*;`
- Encoding conversion on Windows `use udbg_base::strutil::*;`
- ...

## Examples

See `examples/`
- `find-handle` like the function 'Find handles or DLLs' in Process Hacker, commonly used to find (pragram) who hold a file (handle)
- `udbg-inject` is a DLL injector
- `detect-process` is used to detect suspicious footprint in a process, such as unsigned module or executable memory not in module

Another example about to write externsion for udbg, see [udbg-ext](https://github.com/udbg/udbg-ext)

## Build & Install

This repo is a library, but it contains several practical example, you can install these examples to use

- Clone this repo to your disk and change the directory
- `cargo install --path . --example *`