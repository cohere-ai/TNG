use crate::crypto::{DefaultCrypto, HashAlgo};
use crate::errors::*;
use crate::tee::coco::evidence::{tee_from_str, CocoEvidence};
use crate::tee::{
    serialize_canon_json, wrap_runtime_data_as_structed, GenericAttester, ReportData,
};

pub(crate) mod asr_client;

pub(crate) use asr_client::AsrClient;

/// CoCo attester that fetches evidence via the API Server Rest (ASR) HTTP
/// interface instead of talking to the Attestation Agent over ttrpc.
///
/// Produces the same [`CocoEvidence`] as [`CocoAttester`], so downstream
/// converters and verifiers are unaffected.
pub struct CocoAsrAttester {
    asr: AsrClient,
}

impl CocoAsrAttester {
    pub fn new(asr_addr: &str) -> Result<Self> {
        Ok(Self {
            asr: AsrClient::new(asr_addr)?,
        })
    }
}

#[async_trait::async_trait]
impl GenericAttester for CocoAsrAttester {
    type Evidence = CocoEvidence;

    async fn get_evidence(&self, report_data: &ReportData) -> Result<CocoEvidence> {
        let aa_runtime_data = wrap_runtime_data_as_structed(report_data)?;
        let aa_runtime_data_bytes = serialize_canon_json(&aa_runtime_data)?;
        let aa_runtime_data_hash_algo = HashAlgo::Sha384;

        let aa_runtime_data_hash_value =
            DefaultCrypto::hash(aa_runtime_data_hash_algo, &aa_runtime_data_bytes);

        let evidence = self
            .asr
            .get_evidence(aa_runtime_data_hash_value.clone())
            .await?;

        let tee_type_str = self.asr.get_tee_type().await?;
        let tee_type = tee_from_str(&tee_type_str)?;

        let additional_evidence = self
            .asr
            .get_additional_evidence(aa_runtime_data_hash_value)
            .await;

        Ok(CocoEvidence::new(
            tee_type,
            evidence,
            additional_evidence,
            String::from_utf8(aa_runtime_data_bytes).map_err(Error::InvalidUtf8)?,
            aa_runtime_data_hash_algo,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn primary_and_additional_evidence_use_same_runtime_data_hash() {
        let server = MockServer::start().await;
        let report_data = ReportData::Claims(
            serde_json::from_value(serde_json::json!({"key": "value"})).unwrap(),
        );
        let runtime_data = wrap_runtime_data_as_structed(&report_data).unwrap();
        let runtime_data_bytes = serialize_canon_json(&runtime_data).unwrap();
        let runtime_data_hash = DefaultCrypto::hash(HashAlgo::Sha384, &runtime_data_bytes);
        let runtime_data_hash_b64 = STANDARD.encode(runtime_data_hash);
        let additional_evidence = br#"{"nvidia":{"device_evidence_list":[]}}"#;

        for endpoint in ["/aa/evidence", "/aa/additional_evidence"] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .and(query_param("runtime_data", runtime_data_hash_b64.clone()))
                .and(query_param("encoding", "base64"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(
                    if endpoint == "/aa/evidence" {
                        br#"{"quote":"cpu-evidence"}"#.to_vec()
                    } else {
                        additional_evidence.to_vec()
                    },
                ))
                .expect(1)
                .mount(&server)
                .await;
        }

        Mock::given(method("GET"))
            .and(path("/info"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"tee": "az-snp-vtpm"})),
            )
            .expect(1)
            .mount(&server)
            .await;

        let attester = CocoAsrAttester::new(&server.uri()).unwrap();
        let evidence = attester.get_evidence(&report_data).await.unwrap();

        assert_eq!(
            evidence.aa_additional_evidence_ref().as_deref(),
            Some(additional_evidence.as_slice())
        );
    }
}
