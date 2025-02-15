use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum SerializationType {
    Int(i64),
    Float(f64),
    Str(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnitValue {
    pub name: String,
    pub value: SerializationType,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Unit {
    pub name: String,
    pub value: Vec<UnitValue>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub units: Vec<Unit>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventError<'a> {
    pub message_code: &'a str,
}

pub fn read_event_data(event_root: &Value) -> Result<Event, EventError> {
    let mut fill_units: Vec<Unit> = Vec::new();
    let mut unit_values: Vec<UnitValue> = Vec::new();
    debug!("!>: go common");
    for val in event_root.as_object().unwrap() {
        let (key, v) = val;
        debug!(">>: {}", key);
        let column_name = key.to_string();

        let mut set_value = SerializationType::Str(String::new());
        if v.is_i64() {
            set_value = SerializationType::Int(v.as_i64().unwrap());
        } else if v.is_f64() {
            set_value = SerializationType::Float(v.as_f64().unwrap());
        } else if v.is_string() {
            set_value = SerializationType::Str(v.as_str().unwrap().to_string());
        }
        unit_values.push(UnitValue {
            name: column_name,
            value: set_value,
        });
    }
    fill_units.push(Unit {
        name: String::new(),
        value: unit_values,
    });

    return Ok(Event { units: fill_units });
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonSchemaProperty {
    #[serde(rename = "type")]
    pub type_: String,

    #[serde(rename = "x-manyevents-ch-type")]
    pub x_manyevents_ch_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ComponentJsonSchema {
    pub properties: HashMap<String, JsonSchemaProperty>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EventJsonSchema {
    #[serde(rename = "x-manyevents-ch-order-by")]
    pub x_manyevents_ch_order_by: String,

    #[serde(rename = "x-manyevents-ch-partition-by")]
    pub x_manyevents_ch_partition_by: String,

    #[serde(rename = "x-manyevents-ch-partition-by-func")]
    pub x_manyevents_ch_partition_by_func: Option<String>,

    pub properties: HashMap<String, JsonSchemaProperty>,
}

impl EventJsonSchema {
    pub fn new() -> EventJsonSchema {
        EventJsonSchema {
            x_manyevents_ch_order_by: String::new(),
            x_manyevents_ch_partition_by: String::new(),
            x_manyevents_ch_partition_by_func: None,
            properties: HashMap::new(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use rstest::rstest;
    use serde_json::json;
    use tracing_test::traced_test;

    #[rstest]
    #[traced_test]
    fn parse_event_json_schema_successfully() {
        let js = json!({
            "type": "object",
            "properties": {
                "base_timestamp": { "type": "integer", "x-manyevents-ch-type": "DateTime64(3)" },
                "base_name": { "type": "string", "x-manyevents-ch-type": "String" },
            },
            "x-manyevents-ch-order-by": "timestamp",
            "x-manyevents-ch-partition-by-func": "toYYYYMMDD",
            "x-manyevents-ch-partition-by": "timestamp",
            "required": ["base_timestamp", "base_name"],
        });

        let event: Result<EventJsonSchema, _> = serde_json::from_value(js);

        assert!(event.is_ok());
        let event = event.unwrap();
        assert_eq!(
            event.properties["base_timestamp"].type_,
            "integer".to_string()
        );
        assert_eq!(
            event.properties["base_timestamp"].x_manyevents_ch_type,
            "DateTime64(3)".to_string()
        );
        assert_eq!(event.properties["base_name"].type_, "string".to_string());
        assert_eq!(
            event.properties["base_name"].x_manyevents_ch_type,
            "String".to_string()
        );
        assert_eq!(event.x_manyevents_ch_order_by, "timestamp".to_string());
        assert_eq!(event.x_manyevents_ch_partition_by, "timestamp".to_string());
        assert_eq!(
            event.x_manyevents_ch_partition_by_func,
            Some("toYYYYMMDD".to_string())
        );
    }

    #[rstest]
    #[traced_test]
    fn parse_component_json_schema_successfully() {
        let js = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "x-manyevents-ch-type": "String" },
            },
        });

        let event: Result<ComponentJsonSchema, _> = serde_json::from_value(js);

        assert!(event.is_ok());
        let event = event.unwrap();
        assert_eq!(event.properties["name"].type_, "string".to_string());
        assert_eq!(
            event.properties["name"].x_manyevents_ch_type,
            "String".to_string(),
        );
    }
}
