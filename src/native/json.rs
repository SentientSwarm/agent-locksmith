//! Bounded JSON with duplicate object members rejected before SDK decoding.
use serde_json::Value;

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, ()> {
    preflight(bytes)?;
    locksmith_mcp_transport::strict_json::parse(
        bytes,
        locksmith_mcp_transport::Limits {
            json_depth: 32,
            json_units: 8192,
            ..Default::default()
        },
    )
    .map_err(|_| ())
}
fn preflight(bytes: &[u8]) -> Result<(), ()> {
    let (mut depth, mut units, mut quoted, mut escape) = (0usize, 0usize, false, false);
    for &b in bytes {
        if quoted {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                quoted = false;
            }
            continue;
        }
        quoted = outside(b, &mut depth, &mut units)?;
        if depth > 32 || units > 8192 {
            return Err(());
        }
    }
    if quoted || depth != 0 {
        Err(())
    } else {
        Ok(())
    }
}
fn outside(b: u8, depth: &mut usize, units: &mut usize) -> Result<bool, ()> {
    match b {
        b'"' => {
            *units += 1;
        }
        b'{' | b'[' => {
            *depth += 1;
            *units += 1;
        }
        b'}' | b']' => {
            *depth = depth.checked_sub(1).ok_or(())?;
            *units += 1;
        }
        b',' | b':' => *units += 1,
        _ => {}
    }
    Ok(b == b'"')
}
