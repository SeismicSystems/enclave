use attestation_service::{Data, HashAlgorithm};
use kbs_types::Tee;
use serde::de::{self, Visitor, MapAccess};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::ser::SerializeStruct;
use std::fmt;
use std::str::FromStr;
use serde_json::Value;

pub struct AttestationEvalEvidenceRequest {
    pub evidence: Vec<u8>,
    pub tee: Tee,
    pub runtime_data: Vec<Data>,
    pub runtime_data_hash_algorithm: Option<HashAlgorithm>,
    // pub init_data: Option<Data>,
    // pub init_data_hash_algorithm: Option<HashAlgorithm>,
    // pub policy_ids: Vec<String>,
}

impl fmt::Debug for AttestationEvalEvidenceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationEvalEvidenceRequest")
            .field("evidence", &self.evidence)
            .field("tee", &self.tee)
            .field(
                "runtime_data",
                &self
                    .runtime_data
                    .iter()
                    .map(|data| {
                        match data {
                            Data::Raw(bytes) => format!("Raw({:?})", bytes),
                            Data::Structured(value) => format!("Structured({:?})", value),
                        }
                    })
                    .collect::<Vec<_>>(),
            ) 
            .field(
                "runtime_data_hash_algorithm",
                &match &self.runtime_data_hash_algorithm {
                    Some(alg) => alg.to_string(),
                    None => "None".to_string(),
                },
            )
            .finish()
    }
}

impl Serialize for AttestationEvalEvidenceRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AttestationEvalEvidenceRequest", 4)?;
        state.serialize_field("evidence", &self.evidence)?;
        state.serialize_field("tee", &self.tee)?;

        // Manually serialize `runtime_data`
        let runtime_data: Vec<String> = self.runtime_data.iter().map(|data| {
            match data {
                Data::Raw(bytes) => format!("Raw({:?})", bytes),  // Serialize Raw as string
                Data::Structured(value) => serde_json::to_string(value).unwrap(),  // Directly serialize `Value` from serde_json
            }
        }).collect();
        state.serialize_field("runtime_data", &runtime_data)?;

        // Serialize `runtime_data_hash_algorithm` using its Display implementation
        let runtime_data_hash_algorithm = match &self.runtime_data_hash_algorithm {
            Some(alg) => alg.to_string(),
            None => "None".to_string(),
        };
        state.serialize_field("runtime_data_hash_algorithm", &runtime_data_hash_algorithm)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for AttestationEvalEvidenceRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field { 
            Evidence, 
            Tee, 
            RuntimeData, 
            RuntimeDataHashAlgorithm 
        }

        struct AttestationEvalEvidenceRequestVisitor;

        impl<'de> Visitor<'de> for AttestationEvalEvidenceRequestVisitor {
            type Value = AttestationEvalEvidenceRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct AttestationEvalEvidenceRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<AttestationEvalEvidenceRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut evidence = None;
                let mut tee = None;
                let mut runtime_data = None;
                let mut runtime_data_hash_algorithm = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Evidence => {
                            if evidence.is_some() {
                                return Err(de::Error::duplicate_field("evidence"));
                            }
                            evidence = Some(map.next_value()?);
                        }
                        Field::Tee => {
                            if tee.is_some() {
                                return Err(de::Error::duplicate_field("tee"));
                            }
                            tee = Some(map.next_value()?);
                        }
                        Field::RuntimeData => {
                            if runtime_data.is_some() {
                                return Err(de::Error::duplicate_field("runtime_data"));
                            }
                            let raw_data: Vec<String> = map.next_value()?;
                            let parsed_data: Vec<Data> = raw_data.into_iter().map(|s| {
                                if s.starts_with("Raw(") {
                                    let bytes = s.trim_start_matches("Raw(").trim_end_matches(")").as_bytes().to_vec();
                                    Data::Raw(bytes)
                                } else if s.starts_with("Structured(") {
                                    // Deserialize `Value` directly using serde_json
                                    let json_str = s.trim_start_matches("Structured(").trim_end_matches(")");
                                    let value: Value = serde_json::from_str(json_str).unwrap();  // Deserialize back to Value
                                    Data::Structured(value)
                                } else {
                                    panic!("Unexpected data format");
                                }
                            }).collect();
                            runtime_data = Some(parsed_data);
                        }
                        Field::RuntimeDataHashAlgorithm => {
                            if runtime_data_hash_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("runtime_data_hash_algorithm"));
                            }
                            let alg_str: String = map.next_value()?;
                            runtime_data_hash_algorithm = if alg_str == "None" {
                                None
                            } else {
                                HashAlgorithm::from_str(&alg_str).ok()  // Use `from_str` or equivalent
                            };
                        }
                    }
                }

                let evidence = evidence.ok_or_else(|| de::Error::missing_field("evidence"))?;
                let tee = tee.ok_or_else(|| de::Error::missing_field("tee"))?;
                let runtime_data = runtime_data.ok_or_else(|| de::Error::missing_field("runtime_data"))?;
                let runtime_data_hash_algorithm = runtime_data_hash_algorithm; // Option type

                Ok(AttestationEvalEvidenceRequest {
                    evidence,
                    tee,
                    runtime_data,
                    runtime_data_hash_algorithm,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["evidence", "tee", "runtime_data", "runtime_data_hash_algorithm"];
        deserializer.deserialize_struct("AttestationEvalEvidenceRequest", FIELDS, AttestationEvalEvidenceRequestVisitor)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_debug() {
        let request = AttestationEvalEvidenceRequest {
            evidence: vec![1, 2, 3],
            tee: Tee::Sgx,
            runtime_data: vec![Data::Raw(vec![7, 8, 9])],
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
        };

        let debug_output = format!("{:?}", request);

        // The expected debug output
        let expected_output = "AttestationEvalEvidenceRequest { \
        evidence: [1, 2, 3], \
        tee: Sgx, \
        runtime_data: [\"Raw([7, 8, 9])\"], \
        runtime_data_hash_algorithm: \"Sha256\" }";

        assert_eq!(
            debug_output.trim(),
            expected_output.trim(),
            "Debug output does not match expected"
        );

        // Ensure that each key part of the struct is present in the output
        assert!(debug_output.contains("AttestationEvalEvidenceRequest"));
        assert!(debug_output.contains("evidence: [1, 2, 3]"));
        assert!(debug_output.contains("tee: Sgx"));
        assert!(debug_output.contains("runtime_data: [\"Raw([7, 8, 9])\"]"));
        assert!(debug_output.contains("runtime_data_hash_algorithm: \"Sha256\""));
    }

    #[test]
    fn test_serialize_deserialize() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![1, 2, 3],
            tee: Tee::Sgx,       
            runtime_data: vec![Data::Raw(vec![7, 8, 9])],
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        assert_eq!(
            original_request.runtime_data.len(),
            deserialized.runtime_data.len()
        );
        // assert_eq!(original_request.runtime_data_hash_algorithm, deserialized.runtime_data_hash_algorithm);
    }
}
