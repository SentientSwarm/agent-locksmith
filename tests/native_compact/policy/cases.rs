use super::*;
pub(super) fn pages() -> Vec<Vec<Value>> {
    let selected = tools()["tools"].as_array().unwrap()[..4].to_vec();
    let mut first = selected.clone();
    first.push(omitted(0));
    let mut overflow = selected.clone();
    for i in 0..253 {
        overflow.push(omitted(i));
    }
    let mut bad = tools();
    bad["tools"][0]["inputSchema"]["properties"]["key"]["default"] = json!(99);
    vec![
        vec![
            json!({"tools":first,"nextCursor":"next"}),
            json!({"tools":[omitted(0)]}),
        ],
        vec![json!({"tools":selected[..3]})],
        vec![json!({"tools":overflow})],
        five_pages(&selected),
        vec![bad],
    ]
}
fn five_pages(selected: &[Value]) -> Vec<Value> {
    vec![
        json!({"tools":selected,"nextCursor":"p2"}),
        json!({"tools":[omitted(1)],"nextCursor":"p3"}),
        json!({"tools":[omitted(2)],"nextCursor":"p4"}),
        json!({"tools":[omitted(3)],"nextCursor":"p5"}),
        json!({"tools":[omitted(4)]}),
    ]
}
