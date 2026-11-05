use super::{Definition, Error};
pub(super) fn check(d: &Definition) -> Result<(), Error> {
    if !d.id.starts_with("builtin.") {
        return Ok(());
    }
    let bytes = match d.id.as_str() {
        "builtin.linear" => include_str!("../../definitions/linear.json"),
        "builtin.context7" => include_str!("../../definitions/context7.json"),
        "builtin.slack" => include_str!("../../definitions/slack.json"),
        _ => return Err(Error::Invalid),
    };
    let builtin: Definition = super::decode(bytes.as_bytes())?;
    super::validate::definition(&builtin)?;
    if *d == builtin {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}
