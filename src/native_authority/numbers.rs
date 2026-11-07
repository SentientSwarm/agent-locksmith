//! Compare parsed JSON numbers without rounding an integer through f64.
use serde_json::Number;
use std::cmp::Ordering;

pub(super) fn compare(left: &Number, right: &Number) -> Ordering {
    match (integer(left), integer(right)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(a), None) => integer_float(a, right.as_f64().unwrap()),
        (None, Some(b)) => integer_float(b, left.as_f64().unwrap()).reverse(),
        (None, None) => left.as_f64().partial_cmp(&right.as_f64()).unwrap(),
    }
}

fn integer(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

fn integer_float(integer: i128, float: f64) -> Ordering {
    // JSON floats are finite. Saturation outside i128 is safe because every
    // integer here came from i64/u64 and is strictly inside that wider range.
    match integer.cmp(&(float as i128)) {
        Ordering::Equal => 0.0_f64.partial_cmp(&float.fract()).unwrap(),
        order => order,
    }
}
