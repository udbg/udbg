
use super::output_debug_string;
use log::{Level, Metadata, Record};

pub struct DbgLogger;
pub static DBG_LOGGER: DbgLogger = DbgLogger;

impl log::Log for DbgLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            output_debug_string(format!(
                "{}({}): {} - {}\n",
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.level(),
                record.args()
            ));
        }
    }

    fn flush(&self) {}
}