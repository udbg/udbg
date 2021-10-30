
use alloc::string::String;

use std::path::Path;
use std::fs::File;
use std::io::{self, *};

pub struct LineReader<T: Sized>(BufReader<T>);

impl<T: io::Read> Iterator for LineReader<T> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let mut result = String::new();
        match self.0.read_line(&mut result) {
            Err(_) => None,
            Ok(s) => if s > 0 {
                result.truncate(result.trim_end().len());
                Some(result)
            } else { None }
        }
    }
}

pub fn read_lines(filename: impl AsRef<Path>) -> io::Result<LineReader<File>> {
    let file = File::open(filename)?;
    Ok(LineReader(io::BufReader::new(file)))
}

pub struct LineParser<'a> {
    s: &'a str,
}

impl<'a> LineParser<'a> {
    pub fn new(s: &'a str) -> Self { Self {s} }

    pub fn next(&mut self) -> Option<&'a str> {
        let s = self.s.trim_start();
        let pos = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
        self.s = &s[pos..];
        Some(&s[..pos])
    }

    pub fn till(&mut self, c: char) -> Option<&'a str> {
        let s = self.s.trim_start();
        let pos = s.find(c)?;
        self.s = &self.s[pos..];
        Some(&s[..pos])
    }

    pub fn rest(self) -> &'a str { self.s }

    pub fn skip_count(&mut self, c: usize) { self.s = &self.s[c..]; }
}