use crate::symbol::Symbol;

impl Symbol {
    pub fn undecorate(sym: &str, flags: UFlags) -> Option<String> {
        use cpp_demangle::{DemangleOptions, Symbol};
        Symbol::new(sym).ok().and_then(|s| {
            let mut opts = DemangleOptions::new();
            if flags.contains(UFlags::UNDEC_TYPE) {
                opts = opts.no_params();
            }
            if flags.contains(UFlags::UNDEC_RETN) {
                opts = opts.no_return_type();
            }
            s.demangle(&opts).ok()
        })
    }
}
