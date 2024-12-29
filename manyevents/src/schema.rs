use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

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
    println!("!>: go common");
    for val in event_root.as_object().unwrap() {
        let (key, v) = val;
        println!(">>: {}", key);
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

impl ComponentJsonSchema {
    pub fn new() -> ComponentJsonSchema {
        ComponentJsonSchema {
            properties: HashMap::new(),
        }
    }
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

pub fn validate_json_example() {
    use jsonschema::{Retrieve, Uri};
    use serde_json::{json, Value};
    use std::collections::HashMap;

    struct InMemoryRetriever {
        schemas: HashMap<String, Value>,
    }

    impl Retrieve for InMemoryRetriever {
        fn retrieve(
            &self,
            uri: &Uri<&str>,
        ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
            self.schemas
                .get(uri.as_str())
                .cloned()
                .ok_or_else(|| format!("Schema not found: {uri}").into())
        }
    }

    let mut schemas = HashMap::new();
    schemas.insert(
        "https://example.com/person.json".to_string(),
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "x-manyevents-ch-type": "String" },
                "age": { "type": "integer", "x-manyevents-ch-type": "Int32" }
            },
            "required": ["name", "age"]
        }),
    );

    let retriever = InMemoryRetriever { schemas };

    let schema = json!({
        "$ref": "https://example.com/person.json"
    });

    let validator = jsonschema::options()
        .with_retriever(retriever)
        .build(&schema)
        .unwrap();

    assert!(validator.is_valid(&json!({
        "name": "Alice",
        "age": 30,
    })));

    assert!(!validator.is_valid(&json!({
        "name": "Bob",
    })));
}

#[cfg(test)]
pub mod test {
    use super::*;
    use rstest::{fixture, rstest};

    #[rstest]
    fn test_json_schema() {
        validate_json_example()
    }

    #[rstest]
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
