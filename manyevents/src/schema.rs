use serde_json::Value;

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
