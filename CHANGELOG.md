
## v0.3.1

- Fix memory leak in `call_with_timeout`
- Introduce `typed_handle!` macro, and derived `ThreadHandle` `EventHandle`
- Add `pid` for `HandleInfo` struct
- Improve enumeration for all handles

## v0.3.0

- Migrate winapi to windows-rs

## v0.2.3

- Use `ezlua` instead of `llua`
- Upgrade dependencies