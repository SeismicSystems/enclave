use attestation_service::{Data, HashAlgorithm};
use kbs_types::Tee;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Map;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

pub struct AttestationEvalEvidenceRequest {
    pub evidence: Vec<u8>,
    pub tee: Tee,
    pub runtime_data: Option<Data>,
    pub runtime_data_hash_algorithm: Option<HashAlgorithm>,
}
// pub init_data: Option<Data>,
// pub init_data_hash_algorithm: Option<HashAlgorithm>,
// pub policy_ids: Vec<String>,

#[derive(Serialize, Deserialize, Debug)]
pub struct ASCoreTokenClaims {
    pub tee: &'static str,
    pub evaluation_reports: Vec<Value>,
    pub tcb_status: Map<String, Value>,
    pub reference_data: HashMap<String, Vec<String>>,
    pub customized_claims: ASCustomizedClaims,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ASCustomizedClaims {
    pub init_value: Value,
    pub runtime_data: Value,
}

impl fmt::Debug for AttestationEvalEvidenceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestationEvalEvidenceRequest")
            .field("evidence", &self.evidence)
            .field("tee", &self.tee)
            .field(
                "runtime_data",
                &match &self.runtime_data {
                    Some(data) => match data {
                        Data::Raw(bytes) => format!("Raw({:?})", bytes),
                        Data::Structured(value) => format!("Structured({:?})", value),
                    },
                    None => "None".to_string(),
                },
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

        match &self.runtime_data {
            Some(Data::Raw(bytes)) => state.serialize_field("runtime_data", bytes)?,
            Some(Data::Structured(value)) => state.serialize_field("runtime_data", value)?,
            None => state.serialize_field("runtime_data", &Option::<()>::None)?,
        };

        // Use Option<String> to properly serialize None as null
        let runtime_data_hash_algorithm = self
            .runtime_data_hash_algorithm
            .as_ref()
            .map(ToString::to_string);
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
            RuntimeDataHashAlgorithm,
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
                            evidence = Some(map.next_value()?);
                        }
                        Field::Tee => {
                            tee = Some(map.next_value()?);
                        }
                        Field::RuntimeData => {
                            // First, check if the value is None (i.e., null in the JSON)
                            let is_none: Option<()> = map.next_value()?;
                            if is_none.is_none() {
                                runtime_data = None;
                            } else {
                                // Attempt to deserialize as a Vec<u8> if it's not None
                                let raw_data: Option<Vec<u8>> = map.next_value()?;
                                if let Some(bytes) = raw_data {
                                    runtime_data = Some(Data::Raw(bytes));
                                } else {
                                    // If Vec<u8> fails, attempt to deserialize as a Value
                                    let structured_data: Option<Value> = map.next_value()?;
                                    if let Some(value) = structured_data {
                                        runtime_data = Some(Data::Structured(value));
                                    }
                                }
                            }
                        }
                        Field::RuntimeDataHashAlgorithm => {
                            // Deserialize as Option<String> and handle conversion
                            let alg_str: Option<String> = map.next_value()?;
                            if alg_str.is_some() {
                                runtime_data_hash_algorithm =
                                    alg_str.and_then(|alg| HashAlgorithm::from_str(&alg).ok());
                            }
                        }
                    }
                }

                let evidence = evidence.ok_or_else(|| de::Error::missing_field("evidence"))?;
                let tee = tee.ok_or_else(|| de::Error::missing_field("tee"))?;

                Ok(AttestationEvalEvidenceRequest {
                    evidence,
                    tee,
                    runtime_data,
                    runtime_data_hash_algorithm,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "evidence",
            "tee",
            "runtime_data",
            "runtime_data_hash_algorithm",
        ];
        deserializer.deserialize_struct(
            "AttestationEvalEvidenceRequest",
            FIELDS,
            AttestationEvalEvidenceRequestVisitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json;

    #[test]
    fn test_debug() {
        let request = AttestationEvalEvidenceRequest {
            evidence: vec![1, 2, 3],
            tee: Tee::Sgx,
            runtime_data: Some(Data::Raw(vec![7, 8, 9])),
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
        };

        let debug_output = format!("{:?}", request);

        // The expected debug output
        let expected_output = "AttestationEvalEvidenceRequest { \
        evidence: [1, 2, 3], \
        tee: Sgx, \
        runtime_data: \"Raw([7, 8, 9])\", \
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
        assert!(debug_output.contains("runtime_data: \"Raw([7, 8, 9])\""));
        assert!(debug_output.contains("runtime_data_hash_algorithm: \"Sha256\""));
    }

    #[test]
    fn test_serialize_some_data() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ],
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())),
            runtime_data_hash_algorithm: Some(HashAlgorithm::Sha256),
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");
        println!("serialized: {:?}", serialized);

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        match (
            &original_request.runtime_data.unwrap(),
            &deserialized.runtime_data.unwrap(),
        ) {
            (Data::Raw(bytes1), Data::Raw(bytes2)) => assert_eq!(bytes1, bytes2),
            (Data::Structured(value1), Data::Structured(value2)) => assert_eq!(value1, value2),
            _ => panic!("Mismatched runtime data types"),
        }
        assert_eq!(
            original_request
                .runtime_data_hash_algorithm
                .unwrap()
                .to_string(),
            deserialized
                .runtime_data_hash_algorithm
                .unwrap()
                .to_string()
        );
    }

    #[test]
    fn test_serialize_none_hash_algorithm() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ],
            tee: Tee::Sample,
            runtime_data: Some(Data::Raw("nonce".as_bytes().to_vec())),
            runtime_data_hash_algorithm: None,
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");
        println!("serialized: {:?}", serialized);

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        match (
            &original_request.runtime_data.unwrap(),
            &deserialized.runtime_data.unwrap(),
        ) {
            (Data::Raw(bytes1), Data::Raw(bytes2)) => assert_eq!(bytes1, bytes2),
            (Data::Structured(value1), Data::Structured(value2)) => assert_eq!(value1, value2),
            _ => panic!("Mismatched runtime data types"),
        }
        assert!(deserialized.runtime_data_hash_algorithm.is_none());
    }

    #[test]
    fn test_serialize_none_data() {
        let original_request = AttestationEvalEvidenceRequest {
            evidence: vec![
                123, 34, 115, 118, 110, 34, 58, 34, 49, 34, 44, 34, 114, 101, 112, 111, 114, 116,
                95, 100, 97, 116, 97, 34, 58, 34, 98, 109, 57, 117, 89, 50, 85, 61, 34, 125,
            ],
            tee: Tee::Sample,
            runtime_data: None,
            runtime_data_hash_algorithm: None,
        };

        // Serialize the request to a JSON string
        let serialized = serde_json::to_string(&original_request).expect("Failed to serialize");
        println!("serialized: {:?}", serialized);

        // Deserialize the JSON string back to a `AttestationEvalEvidenceRequest`
        let deserialized: AttestationEvalEvidenceRequest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Check that the deserialized object is equal to the original
        assert_eq!(original_request.evidence, deserialized.evidence);
        assert_eq!(original_request.tee, deserialized.tee);
        assert!(deserialized.runtime_data.is_none());
        assert!(deserialized.runtime_data_hash_algorithm.is_none());
    }
}
