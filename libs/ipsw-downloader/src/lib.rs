use plist::Value;
use serde::Deserialize;

const IPSW_URL: &str = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version";

#[derive(Debug, Deserialize)]
pub struct IPSW {
    #[serde(rename = "productVersion")]
    pub product_version: String,
    #[serde(rename = "buildId")]
    pub build_id: String,
    #[serde(rename = "firmwareURL")]
    pub firmware_url: String,
    #[serde(rename = "firmwareSHA1")]
    pub firmware_sha1: String,
}

#[derive(Debug, Deserialize)]
pub struct IPSWList {
    #[serde(rename = "MobileDeviceSoftwareVersionsByVersion")]
    pub versions: Value,
}

#[derive(thiserror::Error, Debug)]
pub enum IPSWError {
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Plist parsing error: {0}")]
    Plist(#[from] plist::Error),
}

pub async fn get_ipsw_list() -> Result<IPSWList, IPSWError> {
    let response = reqwest::get(IPSW_URL).await?;
    let bytes = response.bytes().await?;
    let list: IPSWList = plist::from_bytes(&bytes)?;
    Ok(list)
}

pub async fn fetch_firmware_url(device: &str, build: &str) -> Result<Option<String>, IPSWError> {
    let list = get_ipsw_list().await?;
    let Value::Dictionary(root_dict) = list.versions else {
        return Ok(None);
    };

    for (_bucket_key, bucket_val) in root_dict {
        let Value::Dictionary(bucket_dict) = bucket_val else {
            continue;
        };

        if let Some(Value::Dictionary(mobile_versions)) =
            bucket_dict.get("MobileDeviceSoftwareVersions")
            && let Some(Value::Dictionary(device_versions)) = mobile_versions.get(device)
            && let Some(Value::Dictionary(build_info)) = device_versions.get(build)
            && let Some(Value::Dictionary(restore_info)) = build_info.get("Restore")
            && let Some(Value::String(url)) = restore_info.get("FirmwareURL")
        {
            return Ok(Some(url.clone()));
        }
    }

    Ok(None)
}
