//! Output formatting. `--format table|json|yaml` covers the surface in
//! SPEC §4.7.4. Tables are emitted with the column set defined per
//! command; json/yaml print the raw response document.

use clap::ValueEnum;
use serde_json::Value;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum Format {
    Table,
    Json,
    Yaml,
}

/// Print a JSON value in the chosen format. Table rendering is a thin
/// implementation: when the value is `{"key": [..]}` we render the
/// array; otherwise we print key:value pairs. For one-off agent / token
/// records we delegate to per-command helpers.
pub fn print(value: &Value, format: Format) {
    match format {
        Format::Json => println!(
            "{}",
            serde_json::to_string_pretty(value).expect("json serializes")
        ),
        Format::Yaml => println!("{}", serde_yaml::to_string(value).expect("yaml serializes")),
        Format::Table => print_table(value),
    }
}

fn print_table(value: &Value) {
    match value {
        Value::Object(map) => {
            // Single-record renderer: print as key: value lines.
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for k in keys {
                let v = render_scalar(&map[k]);
                println!("{k}: {v}");
            }
        }
        Value::Array(items) => {
            print_array_table(items);
        }
        other => println!("{}", render_scalar(other)),
    }
}

fn print_array_table(items: &[Value]) {
    if items.is_empty() {
        println!("(no rows)");
        return;
    }
    // Pick column set from the first object's keys (sorted for stable
    // output).
    let mut cols: Vec<String> = Vec::new();
    if let Value::Object(m) = &items[0] {
        let mut k: Vec<_> = m.keys().cloned().collect();
        k.sort();
        cols = k;
    }
    if cols.is_empty() {
        for item in items {
            println!("{}", render_scalar(item));
        }
        return;
    }
    // Compute column widths.
    let mut widths: Vec<usize> = cols.iter().map(|c| c.len()).collect();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            cols.iter()
                .map(|c| match item.get(c) {
                    Some(v) => render_scalar(v),
                    None => "-".to_string(),
                })
                .collect()
        })
        .collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let header: Vec<String> = cols
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
        .collect();
    println!("{}", header.join("  "));
    println!(
        "{}",
        header
            .iter()
            .map(|h| "-".repeat(h.len()))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for row in rows {
        let line: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{:width$}", c, width = widths[i]))
            .collect();
        println!("{}", line.join("  "));
    }
}

fn render_scalar(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(v).unwrap_or_else(|_| String::new())
        }
    }
}
