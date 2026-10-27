//! Optional rotated transport credential for explicitly disposable A2 tests.
use cardano_kes_forge::host::{
    client::{AuthenticatedClient, DevelopmentIdentity, Error},
    config::DeviceConfig,
    usb::UsbWire,
};
use kes_core::types::CredentialEpoch;
use std::{env, path::Path};

pub fn open(wire: &mut UsbWire) -> Result<(AuthenticatedClient, DevelopmentIdentity), Error> {
    match env::var_os("KES_A2_MANAGEMENT_CONFIG") {
        Some(path) => {
            let config = DeviceConfig::load(Path::new(&path)).map_err(|_| Error::Security)?;
            AuthenticatedClient::open_a2_development_with_credential(
                wire,
                &config.credential.signing_key,
                CredentialEpoch::new(config.credential.epoch),
            )
        }
        None => AuthenticatedClient::open_a2_development(wire),
    }
}
