//! Bounded JSON with duplicate object members rejected before SDK decoding.
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use std::fmt;

pub(super) fn parse(bytes: &[u8]) -> Result<Value, ()> {
    preflight(bytes)?;
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Unique::deserialize(&mut decoder).map_err(|_| ())?.0;
    decoder.end().map_err(|_| ())?;
    Ok(value)
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
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(UniqueVisitor)
    }
}
struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("unique JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(v) = a.next_element::<Unique>()? {
            values.push(v.0);
        }
        Ok(Unique(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
        let mut values = Map::new();
        while let Some(key) = a.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate member"));
            }
            values.insert(key, a.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(values)))
    }
}
