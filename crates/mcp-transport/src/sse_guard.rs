use crate::{Error, Limits};

/// Counts raw blocks including comments. CR, LF and CRLF are delimiters.
pub(crate) struct Guard {
    size: usize,
    line: usize,
    blocks: usize,
    cr: bool,
    cr_size: usize,
    limits: Limits,
}
impl Guard {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            size: 0,
            line: 0,
            blocks: 0,
            cr: false,
            cr_size: 0,
            limits,
        }
    }
    pub(crate) fn observe(&mut self, chunk: &[u8]) -> Result<usize, Error> {
        let mut high = self.size;
        for &b in chunk {
            high = high.max(self.byte(b)?);
        }
        Ok(high)
    }
    fn byte(&mut self, b: u8) -> Result<usize, Error> {
        if self.cr && b == b'\n' {
            self.cr = false;
            if self.size != 0 {
                self.size += 1;
            }
            return self.check_size(self.cr_size + 1);
        }
        self.size += 1;
        let size = self.check_size(self.size)?;
        self.cr = b == b'\r';
        self.cr_size = size;
        match b {
            b'\r' | b'\n' => self.newline()?,
            _ => self.line += 1,
        }
        Ok(size)
    }
    fn check_size(&self, size: usize) -> Result<usize, Error> {
        if size > self.limits.event_bytes {
            Err(Error("event_bytes"))
        } else {
            Ok(size)
        }
    }
    fn newline(&mut self) -> Result<(), Error> {
        if self.line == 0 {
            self.blocks += 1;
            self.size = 0;
            if self.blocks > self.limits.events {
                return Err(Error("events"));
            }
        }
        self.line = 0;
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> Result<(), Error> {
        if self.size != 0 {
            Err(Error("sse_truncated"))
        } else {
            Ok(())
        }
    }
}
