use serde_json::{json, Value};
use std::collections::HashMap;

use rocket::serde::{Deserialize, Serialize};

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
    let event = event_root.get("event");
    if event.is_none() {
        return Err(EventError {
            message_code: "invalid_event",
        });
    }
    if !event.unwrap().is_object() {
        return Err(EventError {
            message_code: "invalid_event",
        });
    }
    let units = event.unwrap().get("units");
    if units.is_none() {
        return Err(EventError {
            message_code: "invalid_units",
        });
    }
    if !units.unwrap().is_array() {
        return Err(EventError {
            message_code: "invalid_units",
        });
    }
    for unit in units.unwrap().as_array().unwrap() {
        let unit_type = unit.get("type");

        let mut unit_values: Vec<UnitValue> = Vec::new();

        if unit_type.is_none() {
            return Err(EventError {
                message_code: "unit_no_type",
            });
        }
        let type_str = unit_type.unwrap().as_str().unwrap();
        if !unit.is_object() {
            return Err(EventError {
                message_code: "unit_not_object",
            });
        }
        for val in unit.as_object().unwrap() {
            let (key, v) = val;
            println!(">>: {}", key);
            if key == "type" {
                continue;
            }
            let column_name = key.to_string();

            let mut set_value = SerializationType::Str("".to_string());
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
            name: type_str.to_string(),
            value: unit_values,
        });
    }

    return Ok(Event { units: fill_units });
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JsonSchemaProperty {
    #[serde(rename = "type")]
    pub type_: String,

    #[serde(rename = "x-manyevents-ch-type")]
    pub x_manyevents_ch_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JsonSchemaEntity {
    pub properties: HashMap<String, JsonSchemaProperty>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum JsonSchemaPropertyStatus {
    Added(String),
    Changed(String, String),
    Removed(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JsonSchemaPropertyEntryDiff {
    pub name: String,
    pub status: JsonSchemaPropertyStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JsonSchemaPropertyDiff {
    pub name: String,
    pub status: JsonSchemaPropertyStatus,
    pub diff: Vec<JsonSchemaPropertyEntryDiff>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JsonSchemaDiff {
    pub diff: Vec<JsonSchemaPropertyDiff>,
    pub unsupported_change: bool,
}

pub fn diff_schema(from: JsonSchemaEntity, to: JsonSchemaEntity) -> JsonSchemaDiff {
    let mut unsupported_change = false;
    let mut changes: Vec<JsonSchemaPropertyDiff> = vec![];

    for (name, to_property) in &to.properties {
        println!("{name:?} has {to_property:?}");

        let mut has_change = false;
        let mut status = JsonSchemaPropertyStatus::Added("".to_string());
        let mut entry_changes: Vec<JsonSchemaPropertyEntryDiff> = vec![];

        if !from.properties.contains_key(name) {
            has_change = true;
        } else {
            let from_property = from.properties[name].clone();
            // TODO: need to check all fields in JsonSchemaProperty
            if to_property.type_ != from_property.type_ {
                entry_changes.push(JsonSchemaPropertyEntryDiff {
                    name: "type".to_string(),
                    status: JsonSchemaPropertyStatus::Changed(from_property.type_.clone(), to_property.type_.clone()),
                });
                status = JsonSchemaPropertyStatus::Changed("".to_string(), "".to_string());
                has_change = true;
            }

            if to_property.x_manyevents_ch_type != from_property.x_manyevents_ch_type {
                entry_changes.push(JsonSchemaPropertyEntryDiff {
                    name: "x-manyevents-ch-type".to_string(),
                    status: JsonSchemaPropertyStatus::Changed(from_property.x_manyevents_ch_type.clone(), to_property.x_manyevents_ch_type.clone()),
                });
                status = JsonSchemaPropertyStatus::Changed("".to_string(), "".to_string());
                has_change = true;
            }
        }

        if has_change {
            changes.push(JsonSchemaPropertyDiff {
                name: name.to_string(),
                status: status,
                diff: entry_changes,
            })
        }
    }

    JsonSchemaDiff {
        diff: changes,
        unsupported_change,
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use rstest::{fixture, rstest};

    #[rstest]
    fn parse_json_schema_successfully() {
        let js = json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "x-manyevents-ch-type": "String" },
                "age": { "type": "integer", "x-manyevents-ch-type": "Int32" }
            },
            "required": ["name", "age"]
        });

        let entity: Result<JsonSchemaEntity, _> = serde_json::from_value(js);

        assert!(entity.is_ok());
        let entity = entity.unwrap();
        assert_eq!(entity.properties["name"].type_, "string".to_string());
        assert_eq!(
            entity.properties["name"].x_manyevents_ch_type,
            "String".to_string()
        );
        assert_eq!(entity.properties["age"].type_, "integer".to_string());
        assert_eq!(
            entity.properties["age"].x_manyevents_ch_type,
            "Int32".to_string()
        );
    }

    #[rstest]
    fn diff_entities_same_schema() {
        let the_same = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    x_manyevents_ch_type: "String".to_string(),
                },
            )]),
        };

        let diff = diff_schema(the_same.clone(), the_same.clone());
        assert_eq!(diff.unsupported_change, false);
        assert_eq!(diff.diff.len(), 0);
    }

    #[rstest]
    fn diff_entities_new_field() {
        let empty = JsonSchemaEntity {
            properties: HashMap::new(),
        };
        let new = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    x_manyevents_ch_type: "String".to_string(),
                },
            )]),
        };

        let diff = diff_schema(empty, new);
        assert_eq!(diff.unsupported_change, false);
        assert_eq!(diff.diff.len(), 1);
        let status = diff.diff[0].status.clone();
        assert!(match status { JsonSchemaPropertyStatus::Added(_) => true, _ => false });
    }

    #[rstest]
    fn diff_entities_schema_changed_type() {
        let old = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "string".to_string(),
                    x_manyevents_ch_type: "String".to_string(),
                },
            )]),
        };
        let new = JsonSchemaEntity {
            properties: HashMap::from([(
                "name".to_string(),
                JsonSchemaProperty {
                    type_: "integer".to_string(),
                    x_manyevents_ch_type: "Int64".to_string(),
                },
            )]),
        };

        let diff = diff_schema(old, new);
        assert_eq!(diff.unsupported_change, false);
        assert_eq!(diff.diff.len(), 1);
        assert_eq!(diff.diff[0].name, "name".to_string());
        let status = diff.diff[0].status.clone();
        assert!(match status { JsonSchemaPropertyStatus::Changed(_, _) => true, _ => false });
        assert_eq!(diff.diff[0].diff.len(), 2);
    }
}
