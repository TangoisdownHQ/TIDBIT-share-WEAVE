// src/storage/supabase.rs

use anyhow::{bail, Result};
use reqwest::Client;
use serde::Deserialize;

#[derive(Clone)]
pub struct SupabaseStorage {
    url: String,
    service_key: String,
    bucket: String,
    client: Client,
}

#[derive(Deserialize)]
struct SignedUrlResp {
    #[serde(rename = "signedURL")]
    signed_url: String,
}

impl SupabaseStorage {
    pub fn new(url: String, service_key: String, bucket: String) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            service_key,
            bucket,
            client: Client::new(),
        }
    }

    fn sanitize_path_segment(segment: &str) -> String {
        segment
            .chars()
            .map(|ch| match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
                _ => '_',
            })
            .collect()
    }

    fn object_filename_from_hash(hash_hex: &str) -> String {
        format!("{hash_hex}.bin")
    }

    pub fn expected_object_path(
        document_owner: &str,
        document_id: &str,
        version: i32,
        hash_hex: &str,
    ) -> String {
        let owner = Self::sanitize_path_segment(document_owner);
        let doc_id = Self::sanitize_path_segment(document_id);
        let filename = Self::object_filename_from_hash(hash_hex);

        format!("{owner}/{doc_id}/v{version}/{filename}")
    }

    /// Upload bytes into a stable document/version path inside the bucket.
    pub async fn upload_bytes(
        &self,
        document_owner: &str,
        document_id: &str,
        version: i32,
        bytes: &[u8],
        content_type: &str,
    ) -> anyhow::Result<String> {
        let hash_hex = hex::encode(crate::pqc::sha3::sha3_256_bytes(bytes));
        let path = Self::expected_object_path(document_owner, document_id, version, &hash_hex);
        let url = format!("{}/storage/v1/object/{}/{}", self.url, self.bucket, path);

        let res = self.client
            .put(&url)
            .bearer_auth(&self.service_key)
            .header("Content-Type", content_type)
            .header("x-upsert", "true")   //  REQUIRED
            .body(bytes.to_vec())
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await.unwrap_or_default();

        if !status.is_success() {
        anyhow::bail!("Supabase upload failed ({}): {}", status, body);
        }

        Ok(path)
    }

    pub async fn object_exists(&self, storage_path: &str) -> Result<bool> {
        let url = format!(
            "{}/storage/v1/object/authenticated/{}/{}",
            self.url, self.bucket, storage_path
        );

        let res = self
            .client
            .get(&url)
            .bearer_auth(&self.service_key)
            .send()
            .await?;

        if res.status().is_success() {
            return Ok(true);
        }

        let status = res.status();
        let body = res.text().await.unwrap_or_default();

        if status == reqwest::StatusCode::NOT_FOUND
            || body.contains("\"error\":\"not_found\"")
            || body.contains("\"statusCode\":\"404\"")
            || body.contains("\"message\":\"Object not found\"")
        {
            return Ok(false);
        }

        bail!(
            "Failed to fetch object info for {} ({}): {}",
            storage_path,
            status,
            body
        )
    }

    pub async fn download_bytes(&self, storage_path: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/storage/v1/object/authenticated/{}/{}",
            self.url, self.bucket, storage_path
        );

        let res = self
            .client
            .get(&url)
            .bearer_auth(&self.service_key)
            .send()
            .await?;

        let status = res.status();
        if !status.is_success() {
            bail!(
                "Failed to download object {} ({}): {}",
                storage_path,
                status,
                res.text().await.unwrap_or_default()
            );
        }

        Ok(res.bytes().await?.to_vec())
    }

    pub async fn move_object(&self, source_path: &str, destination_path: &str) -> Result<()> {
        let url = format!("{}/storage/v1/object/move", self.url);

        let res = self
            .client
            .post(&url)
            .bearer_auth(&self.service_key)
            .json(&serde_json::json!({
                "bucketId": self.bucket,
                "sourceKey": source_path,
                "destinationKey": destination_path,
            }))
            .send()
            .await?;

        if !res.status().is_success() {
            bail!(
                "Failed to move object from {} to {} ({}): {}",
                source_path,
                destination_path,
                res.status(),
                res.text().await.unwrap_or_default()
            );
        }

        Ok(())
    }


    /// Generate signed download URL (IMPORTANT: DO NOT URL-ENCODE PATH)
    pub async fn signed_download_url(
        &self,
        storage_path: &str,
        expires_in: i64,
    ) -> Result<String> {
        let url = format!(
            "{}/storage/v1/object/sign/{}/{}",
            self.url, self.bucket, storage_path
        );

        let res = self
            .client
            .post(&url)
            .bearer_auth(&self.service_key)
            .json(&serde_json::json!({ "expiresIn": expires_in }))
            .send()
            .await?;

        if !res.status().is_success() {
            bail!(
                "Failed to sign URL ({}): {}",
                res.status(),
                res.text().await.unwrap_or_default()
            );
        }

        let body: SignedUrlResp = res.json().await?;
        let signed = body.signed_url;

        Ok(if signed.starts_with("http") {
            signed
        } else if signed.starts_with("/object/") {
            format!("{}/storage/v1{}", self.url, signed)
        } else {
            format!("{}{}", self.url, signed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SupabaseStorage;

    #[test]
    fn object_path_is_stable_and_safe() {
        let path = SupabaseStorage::expected_object_path(
            "0xAbC/123",
            "doc 01",
            1,
            "aa807f8803076ea4b0376cd7aa443f7cdaeb76aff936b3b874048e11c8359a0c",
        );

        assert_eq!(
            path,
            "0xAbC_123/doc_01/v1/aa807f8803076ea4b0376cd7aa443f7cdaeb76aff936b3b874048e11c8359a0c.bin"
        );
    }
}
