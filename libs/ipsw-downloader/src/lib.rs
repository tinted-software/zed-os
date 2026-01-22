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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_ipsw_list() {
        let result = get_ipsw_list().await;
        assert!(result.is_ok());
        let ipsw_list = result.unwrap();
        println!("{:#?}", ipsw_list);
    }
}
