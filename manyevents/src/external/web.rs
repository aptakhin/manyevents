use jsonschema::{Retrieve, Uri};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendEventResponse {
    ok: bool,
}

pub fn web_transform_event(data: Value) -> Result<(), ()> {
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

    let file = File::open("src/external/schemas/web-input.json").unwrap();
    let reader = BufReader::new(file);
    let value: Value = serde_json::from_reader(reader).unwrap();
    // println!("Generic parse: {}", value);

    let mut schemas = HashMap::new();
    schemas.insert("https://example.com/web.json".to_string(), value);

    let retriever = InMemoryRetriever { schemas };

    let schema = json!({
        "$ref": "https://example.com/web.json"
    });

    let validator = jsonschema::options()
        .with_retriever(retriever)
        .build(&schema)
        .unwrap();

    let valid = validator.is_valid(&data);

    if valid {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use rstest::rstest;
    use tracing_test::traced_test;

    #[rstest]
    #[traced_test]
    fn test_web_event_transform() {
        let js = json!({
            "hostname": "localhost",
            "path": "/assets/test.html",
            "hash": "#hello",
            "queryArgs": [["params", ""]],
            "browser": "Mozilla/5.0",
            "protocol": "http:",
            "origin": "http://localhost:8000",
        });

        let res = web_transform_event(js.clone());

        assert!(res.is_ok(), "{:?}", js)
    }
}
