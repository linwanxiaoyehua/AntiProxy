use serde_json::Value;

/// Recursively clean JSON Schema to conform to Gemini API requirements
///
/// 1. [New] Expand $ref and $defs: Replace references with actual definitions to resolve Gemini's lack of $ref support
/// 2. Remove unsupported fields: $schema, additionalProperties, format, default, uniqueItems, validation fields
/// 3. Handle union types: ["string", "null"] -> "string"
/// 4. Convert type field values to lowercase (Gemini v1internal requirement)
/// 5. Remove numeric validation fields: multipleOf, exclusiveMinimum, exclusiveMaximum, etc.
pub fn clean_json_schema(value: &mut Value) {
    // 0. Preprocessing: Expand $ref (Schema Flattening)
    if let Value::Object(map) = value {
        let mut defs = serde_json::Map::new();
        // Extract $defs or definitions
        if let Some(Value::Object(d)) = map.remove("$defs") {
            defs.extend(d);
        }
        if let Some(Value::Object(d)) = map.remove("definitions") {
            defs.extend(d);
        }

        if !defs.is_empty() {
            // Recursively replace references
            flatten_refs(map, &defs);
        }
    }

    // Recursive cleaning
    clean_json_schema_recursive(value);
}

/// Recursively expand $ref
fn flatten_refs(map: &mut serde_json::Map<String, Value>, defs: &serde_json::Map<String, Value>) {
    // Check and replace $ref
    if let Some(Value::String(ref_path)) = map.remove("$ref") {
        // Parse reference name (e.g., #/$defs/MyType -> MyType)
        let ref_name = ref_path.split('/').last().unwrap_or(&ref_path);

        if let Some(def_schema) = defs.get(ref_name) {
            // Merge definition content into current map
            if let Value::Object(def_map) = def_schema {
                for (k, v) in def_map {
                    // Only insert if current map doesn't have this key (avoid overwriting)
                    // Typically $ref nodes shouldn't have other properties
                    map.entry(k.clone()).or_insert_with(|| v.clone());
                }

                // Recursively process potential $ref in the merged content
                // Note: This may cause infinite recursion if circular references exist, but tool definitions are usually DAG
                flatten_refs(map, defs);
            }
        }
    }

    // Traverse child nodes
    for (_, v) in map.iter_mut() {
        if let Value::Object(child_map) = v {
            flatten_refs(child_map, defs);
        } else if let Value::Array(arr) = v {
            for item in arr {
                if let Value::Object(item_map) = item {
                    flatten_refs(item_map, defs);
                }
            }
        }
    }
}

fn clean_json_schema_recursive(value: &mut Value) {
    match value {
        Value::Object(map) => {
            // 1. [CRITICAL] Deep recursive processing: Must traverse all field values in current object
            // Handles cleaning of definitions, anyOf, allOf, etc. beyond properties/items
            for v in map.values_mut() {
                clean_json_schema_recursive(v);
            }

            // 2. Collect and process validation fields (Migration logic: Downgrade constraints to hints in description)
            let mut constraints = Vec::new();

            // Constraint blacklist to migrate
            let validation_fields = [
                ("pattern", "pattern"),
                ("minLength", "minLen"),
                ("maxLength", "maxLen"),
                ("minimum", "min"),
                ("maximum", "max"),
                ("minItems", "minItems"),
                ("maxItems", "maxItems"),
                ("exclusiveMinimum", "exclMin"),
                ("exclusiveMaximum", "exclMax"),
                ("multipleOf", "multipleOf"),
                ("format", "format"),
            ];

            for (field, label) in validation_fields {
                if let Some(val) = map.remove(field) {
                    // Only migrate if value is a simple type
                    if val.is_string() || val.is_number() || val.is_boolean() {
                        constraints.push(format!("{}: {}", label, val));
                    } else {
                        // [FIX] If not a simple type (may be a property with same name), put it back
                        map.insert(field.to_string(), val);
                    }
                }
            }

            // 3. Append constraint info to description
            if !constraints.is_empty() {
                let suffix = format!(" [Constraint: {}]", constraints.join(", "));
                let desc_val = map
                    .entry("description".to_string())
                    .or_insert_with(|| Value::String("".to_string()));
                if let Value::String(s) = desc_val {
                    s.push_str(&suffix);
                }
            }

            // 4. Physically remove interfering "hard" blacklist fields (Hard Blacklist)
            let hard_remove_fields = [
                "$schema",
                "$id", // [NEW] JSON Schema identifier
                "additionalProperties",
                "enumCaseInsensitive",
                "enumNormalizeWhitespace",
                "uniqueItems",
                "default",
                "const",
                "examples",
                "propertyNames",
                "anyOf",
                "oneOf",
                "allOf",
                "not",
                "if",
                "then",
                "else",
                "dependencies",
                "dependentSchemas",
                "dependentRequired",
                "cache_control",
                "contentEncoding",  // [NEW] base64 encoding hint
                "contentMediaType", // [NEW] MIME type hint
                "deprecated",       // [NEW] Gemini doesn't understand this
                "readOnly",         // [NEW]
                "writeOnly",        // [NEW]
            ];
            for field in hard_remove_fields {
                map.remove(field);
            }

            // [NEW FIX] Ensure fields in required are present in properties
            // Gemini strict validation: Fields in required that are not defined in properties will throw INVALID_ARGUMENT
            // Refactored to avoid double borrow (mutable map vs immutable get("properties"))
            let valid_prop_keys: Option<std::collections::HashSet<String>> = map
                .get("properties")
                .and_then(|p| p.as_object())
                .map(|obj| obj.keys().cloned().collect());

            if let Some(required_val) = map.get_mut("required") {
                if let Some(req_arr) = required_val.as_array_mut() {
                    if let Some(keys) = &valid_prop_keys {
                        req_arr.retain(|k| {
                            if let Some(k_str) = k.as_str() {
                                keys.contains(k_str)
                            } else {
                                false
                            }
                        });
                    } else {
                        // If no properties exist, required should be empty
                        req_arr.clear();
                    }
                }
            }

            // 5. Handle type field (Gemini requires single string and lowercase)
            if let Some(type_val) = map.get_mut("type") {
                match type_val {
                    Value::String(s) => {
                        *type_val = Value::String(s.to_lowercase());
                    }
                    Value::Array(arr) => {
                        let mut selected_type = "string".to_string();
                        for item in arr {
                            if let Value::String(s) = item {
                                if s != "null" {
                                    selected_type = s.to_lowercase();
                                    break;
                                }
                            }
                        }
                        *type_val = Value::String(selected_type);
                    }
                    _ => {}
                }
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                clean_json_schema_recursive(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_clean_json_schema_draft_2020_12() {
        let mut schema = json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "minLength": 1,
                    "format": "city"
                },
                // Simulate property name conflict: pattern is an Object property, should not be removed
                "pattern": {
                    "type": "object",
                    "properties": {
                        "regex": { "type": "string", "pattern": "^[a-z]+$" }
                    }
                },
                "unit": {
                    "type": ["string", "null"],
                    "default": "celsius"
                }
            },
            "required": ["location"]
        });

        clean_json_schema(&mut schema);

        // 1. Verify type remains lowercase
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["location"]["type"], "string");

        // 2. Verify standard fields are converted and moved to description (Advanced Soft-Remove)
        assert!(schema["properties"]["location"].get("minLength").is_none());
        assert!(schema["properties"]["location"]["description"]
            .as_str()
            .unwrap()
            .contains("minLen: 1"));

        // 3. Verify property named "pattern" was not mistakenly deleted
        assert!(schema["properties"].get("pattern").is_some());
        assert_eq!(schema["properties"]["pattern"]["type"], "object");

        // 4. Verify internal pattern validation field was correctly removed and converted to description
        assert!(schema["properties"]["pattern"]["properties"]["regex"]
            .get("pattern")
            .is_none());
        assert!(
            schema["properties"]["pattern"]["properties"]["regex"]["description"]
                .as_str()
                .unwrap()
                .contains("pattern: \"^[a-z]+$\"")
        );

        // 5. Verify union types are downgraded to single type (Protobuf compatibility)
        assert_eq!(schema["properties"]["unit"]["type"], "string");

        // 6. Verify metadata fields are removed
        assert!(schema.get("$schema").is_none());
    }

    #[test]
    fn test_type_fallback() {
        // Test ["string", "null"] -> "string"
        let mut s1 = json!({"type": ["string", "null"]});
        clean_json_schema(&mut s1);
        assert_eq!(s1["type"], "string");

        // Test ["integer", "null"] -> "integer" (and lowercase check if needed, though usually integer)
        let mut s2 = json!({"type": ["integer", "null"]});
        clean_json_schema(&mut s2);
        assert_eq!(s2["type"], "integer");
    }

    #[test]
    fn test_flatten_refs() {
        let mut schema = json!({
            "$defs": {
                "Address": {
                    "type": "object",
                    "properties": {
                        "city": { "type": "string" }
                    }
                }
            },
            "properties": {
                "home": { "$ref": "#/$defs/Address" }
            }
        });

        clean_json_schema(&mut schema);

        // Verify references are expanded and types are converted to lowercase
        assert_eq!(schema["properties"]["home"]["type"], "object");
        assert_eq!(
            schema["properties"]["home"]["properties"]["city"]["type"],
            "string"
        );
    }

    #[test]
    fn test_clean_json_schema_missing_required() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "existing_prop": { "type": "string" }
            },
            "required": ["existing_prop", "missing_prop"]
        });

        clean_json_schema(&mut schema);

        // Verify missing_prop was removed from required
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0].as_str().unwrap(), "existing_prop");
    }
}
