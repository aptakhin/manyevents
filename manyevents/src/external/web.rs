use jsonschema::{Retrieve, Uri};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendEventResponse {
    ok: bool,
}

pub fn validate_json_by_schema(data: Value, schema: Value) -> Result<(), ()> {
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
    schemas.insert("https://example.com/web.json".to_string(), schema);

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

pub fn web_transform_event(data: Value, ip: SocketAddr) -> Result<Value, ()> {
    let file = File::open("static/schemas/web-input.json").unwrap();
    let reader = BufReader::new(file);
    let schema: Value = serde_json::from_reader(reader).unwrap();

    let result = validate_json_by_schema(data.clone(), schema);

    if result.is_err() {
        return Err(());
    }

    let result = result.unwrap();
    let mut data = data;
    // the best ip -> country conversion
    data["country"] = "earth".into();
    Ok(data)
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

        let res = web_transform_event(
            js.clone(),
            "127.0.0.1:8000".parse().expect("Parse addr failed"),
        );

        assert!(res.is_ok(), "{:?}", js);
        let tjs = res.unwrap();
        assert_eq!(
            tjs,
            json!({
                "country": "earth",
                "hostname": "localhost",
                "path": "/assets/test.html",
                "hash": "#hello",
                "queryArgs": [["params", ""]],
                "browser": "Mozilla/5.0",
                "protocol": "http:",
                "origin": "http://localhost:8000",
            })
        )
    }
}
