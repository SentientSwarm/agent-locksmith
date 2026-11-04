use crate::{Error, Limits};
use rmcp::model::ServerJsonRpcMessage;

/// Conservative work units: every structural delimiter and scalar/string start.
/// No allocation, recursion, schema compiler or remote reference resolution.
pub(crate) fn preflight(bytes: &[u8], limits: Limits) -> Result<usize, Error> {
    let mut state = Scan::default();
    for &b in bytes {
        state.byte(b, limits)?;
    }
    if state.quoted || state.depth != 0 {
        return Err(Error("json_syntax"));
    }
    Ok(state.units)
}
#[derive(Default)]
struct Scan {
    quoted: bool,
    escaped: bool,
    scalar: bool,
    depth: usize,
    units: usize,
}
impl Scan {
    fn byte(&mut self, b: u8, limits: Limits) -> Result<(), Error> {
        if self.quoted {
            self.string_byte(b);
            return Ok(());
        }
        self.token(b)?;
        if self.depth > limits.json_depth {
            return Err(Error("json_depth"));
        }
        if self.units > limits.json_units {
            return Err(Error("json_units"));
        }
        Ok(())
    }
    fn string_byte(&mut self, b: u8) {
        if self.escaped {
            self.escaped = false;
        } else if b == b'\\' {
            self.escaped = true;
        } else if b == b'"' {
            self.quoted = false;
        }
    }
    fn token(&mut self, b: u8) -> Result<(), Error> {
        if b"{[}]:,\"".contains(&b) {
            self.units += 1;
            self.scalar = false;
        }
        match b {
            b'"' => self.quoted = true,
            b'{' | b'[' => self.depth += 1,
            b'}' | b']' => self.depth = self.depth.checked_sub(1).ok_or(Error("json_syntax"))?,
            b',' | b':' => (),
            b' ' | b'\r' | b'\n' | b'\t' => self.scalar = false,
            _ if !self.scalar => {
                self.scalar = true;
                self.units += 1;
            }
            _ => (),
        }
        Ok(())
    }
}
pub(crate) fn decode(bytes: &[u8], limits: Limits) -> Result<ServerJsonRpcMessage, Error> {
    preflight(bytes, limits)?;
    let message = serde_json::from_slice(bytes).map_err(|_| Error("json_syntax"))?;
    if let ServerJsonRpcMessage::Response(response) = &message
        && let rmcp::model::ServerResult::InitializeResult(result) = &response.result
        && result.protocol_version.as_str() != "2025-11-25"
    {
        return Err(Error("protocol_version"));
    }
    Ok(message)
}
