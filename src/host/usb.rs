//! Exclusive Linux USB transport for the KES vendor-bulk interface.

use crate::host::client::{DeviceWire, Error as ClientError};
use kes_protocol::{MAX_FRAME_BYTES, ReceiverState};
use nusb::descriptors::TransferType;
use nusb::transfer::{Buffer, Bulk, Direction, In, Out};
use nusb::{DeviceInfo, Endpoint, Interface, MaybeFuture};
use std::fmt;
use std::mem;
use std::time::{Duration, Instant};
#[cfg(feature = "development")]
use zeroize::Zeroize;

/// Vendor-specific interface identity. This prevents KES frames from being sent
/// to unrelated vendor interfaces, including the RP2350 BOOTSEL interface.
pub const KES_USB_CLASS: u8 = 0xff;
pub const KES_USB_SUBCLASS: u8 = 0x4b;
pub const KES_USB_PROTOCOL: u8 = 0x01;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Selector {
    vendor: Option<u16>,
    product: Option<u16>,
    serial: Option<String>,
    bus: Option<u8>,
    address: Option<u8>,
    port: Option<Vec<u8>>,
}

impl Selector {
    fn parse(text: &str) -> Result<Self, OpenError> {
        let mut selector = Self {
            vendor: None,
            product: None,
            serial: None,
            bus: None,
            address: None,
            port: None,
        };
        for field in text.split(',') {
            let (name, value) = field
                .split_once('=')
                .ok_or(OpenError::InvalidSelector("expected key=value fields"))?;
            if name.is_empty() || value.is_empty() {
                return Err(OpenError::InvalidSelector(
                    "selector fields must be nonempty",
                ));
            }
            match name {
                "vid" => set_once(&mut selector.vendor, parse_hex_u16(value)?)?,
                "pid" => set_once(&mut selector.product, parse_hex_u16(value)?)?,
                "serial" => {
                    if value.len() > 128 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
                        return Err(OpenError::InvalidSelector("invalid serial value"));
                    }
                    set_once(&mut selector.serial, value.to_owned())?;
                }
                "bus" => set_once(&mut selector.bus, parse_decimal_u8(value)?)?,
                "address" => set_once(&mut selector.address, parse_decimal_u8(value)?)?,
                "port" => {
                    let mut chain = Vec::new();
                    for component in value.split('.') {
                        chain.push(parse_decimal_u8(component)?);
                    }
                    if chain.is_empty() || chain.len() > 7 {
                        return Err(OpenError::InvalidSelector("invalid USB port chain"));
                    }
                    set_once(&mut selector.port, chain)?;
                }
                _ => return Err(OpenError::InvalidSelector("unknown selector field")),
            }
        }
        let bus_address = selector.bus.is_some() && selector.address.is_some();
        let pinned_identity = selector.vendor.is_some()
            && selector.product.is_some()
            && (selector.serial.is_some() || (selector.bus.is_some() && selector.port.is_some()));
        if !(bus_address || pinned_identity)
            || selector.vendor.is_some() != selector.product.is_some()
            || selector.address.is_some() && selector.bus.is_none()
            || selector.port.is_some() && selector.bus.is_none()
            || selector.address.is_some() && selector.port.is_some()
        {
            return Err(OpenError::InvalidSelector(
                "use bus/address or vid/pid with serial or bus/port",
            ));
        }
        Ok(selector)
    }

    fn matches(&self, device: &DeviceInfo) -> bool {
        self.vendor.is_none_or(|value| device.vendor_id() == value)
            && self
                .product
                .is_none_or(|value| device.product_id() == value)
            && self
                .serial
                .as_deref()
                .is_none_or(|value| device.serial_number() == Some(value))
            && self.bus.is_none_or(|value| device.busnum() == value)
            && self
                .address
                .is_none_or(|value| device.device_address() == value)
            && self
                .port
                .as_deref()
                .is_none_or(|value| device.port_chain() == value)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), OpenError> {
    if slot.replace(value).is_some() {
        Err(OpenError::InvalidSelector("duplicate selector field"))
    } else {
        Ok(())
    }
}

fn parse_hex_u16(value: &str) -> Result<u16, OpenError> {
    if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(OpenError::InvalidSelector(
            "VID and PID require four hexadecimal digits",
        ));
    }
    u16::from_str_radix(value, 16).map_err(|_| OpenError::InvalidSelector("invalid VID or PID"))
}

fn parse_decimal_u8(value: &str) -> Result<u8, OpenError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OpenError::InvalidSelector("invalid decimal selector value"));
    }
    value
        .parse::<u8>()
        .ok()
        .filter(|number| *number != 0)
        .ok_or(OpenError::InvalidSelector("USB numbers must be in 1..=255"))
}

#[derive(Debug)]
pub enum OpenError {
    InvalidSelector(&'static str),
    Enumerate(nusb::Error),
    NotFound,
    Ambiguous,
    Open(nusb::Error),
    MissingInterface,
    Claim(nusb::Error),
}

impl fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSelector(reason) => write!(formatter, "invalid USB selector: {reason}"),
            Self::Enumerate(error) => write!(formatter, "failed to enumerate USB devices: {error}"),
            Self::NotFound => formatter.write_str("selected USB device is not connected"),
            Self::Ambiguous => formatter.write_str("USB selector matches multiple devices"),
            Self::Open(error) => write!(formatter, "failed to open selected USB device: {error}"),
            Self::MissingInterface => formatter.write_str(
                "selected device has no unique KES vendor-bulk interface; BOOTSEL is not application firmware",
            ),
            Self::Claim(error) => write!(formatter, "failed to claim KES USB interface: {error}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// Resolve one explicitly selected USB device without opening or claiming it.
#[cfg(feature = "provisioning")]
pub fn resolve_provisioning_selector(selector: &str) -> Result<(u8, u8), OpenError> {
    let selector = Selector::parse(selector)?;
    let mut matches = nusb::list_devices()
        .wait()
        .map_err(OpenError::Enumerate)?
        .filter(|device| selector.matches(device));
    let selected = matches.next().ok_or(OpenError::NotFound)?;
    if matches.next().is_some() {
        return Err(OpenError::Ambiguous);
    }
    Ok((selected.busnum(), selected.device_address()))
}

pub struct UsbWire {
    _interface: Interface,
    out: Endpoint<Bulk, Out>,
    input: Endpoint<Bulk, In>,
    transmit: Buffer,
    receive: Buffer,
}

impl UsbWire {
    pub fn open(selector: &str) -> Result<Self, OpenError> {
        let selector = Selector::parse(selector)?;
        let mut matches = nusb::list_devices()
            .wait()
            .map_err(OpenError::Enumerate)?
            .filter(|device| selector.matches(device));
        let selected = matches.next().ok_or(OpenError::NotFound)?;
        if matches.next().is_some() {
            return Err(OpenError::Ambiguous);
        }
        let device = selected.open().wait().map_err(OpenError::Open)?;
        let (interface_number, alternate_setting, out_address, in_address) =
            kes_interface(&device).ok_or(OpenError::MissingInterface)?;
        let interface = device
            .claim_interface(interface_number)
            .wait()
            .map_err(OpenError::Claim)?;
        if alternate_setting != interface.get_alt_setting() {
            interface
                .set_alt_setting(alternate_setting)
                .wait()
                .map_err(OpenError::Claim)?;
        }
        let out = interface
            .endpoint::<Bulk, Out>(out_address)
            .map_err(OpenError::Claim)?;
        let input = interface
            .endpoint::<Bulk, In>(in_address)
            .map_err(OpenError::Claim)?;
        let receive = Buffer::new(input.max_packet_size());
        Ok(Self {
            _interface: interface,
            out,
            input,
            transmit: Buffer::new(MAX_FRAME_BYTES + 4),
            receive,
        })
    }
}

fn kes_interface(device: &nusb::Device) -> Option<(u8, u8, u8, u8)> {
    let configuration = device.active_configuration().ok()?;
    let mut found = None;
    for interface in configuration.interface_alt_settings() {
        if interface.class() != KES_USB_CLASS
            || interface.subclass() != KES_USB_SUBCLASS
            || interface.protocol() != KES_USB_PROTOCOL
            || interface.num_endpoints() != 2
        {
            continue;
        }
        let mut out = None;
        let mut input = None;
        for endpoint in interface.endpoints() {
            if endpoint.transfer_type() != TransferType::Bulk {
                continue;
            }
            match endpoint.direction() {
                Direction::Out if out.replace(endpoint.address()).is_none() => {}
                Direction::In if input.replace(endpoint.address()).is_none() => {}
                _ => {
                    out = None;
                    input = None;
                    break;
                }
            }
        }
        let candidate = (
            interface.interface_number(),
            interface.alternate_setting(),
            out?,
            input?,
        );
        if found.replace(candidate).is_some() {
            return None;
        }
    }
    found
}

impl DeviceWire for UsbWire {
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_FRAME_BYTES],
        timeout: Duration,
    ) -> Result<usize, ClientError> {
        if request.is_empty() || request.len() > MAX_FRAME_BYTES || timeout.is_zero() {
            return Err(ClientError::Unavailable);
        }
        let started = Instant::now();
        let mut transmit = mem::replace(&mut self.transmit, Buffer::new(0));
        transmit.clear();
        transmit.extend_from_slice(&(request.len() as u32).to_be_bytes());
        transmit.extend_from_slice(request);
        let expected = transmit.len();
        let completion = self.out.transfer_blocking(transmit, timeout);
        let transferred = completion.actual_len;
        let status = completion.status;
        self.transmit = completion.buffer;
        if status.is_err() || transferred != expected {
            return Err(ClientError::Uncertain);
        }

        let mut receiver = ReceiverState::new();
        loop {
            let remaining = timeout
                .checked_sub(started.elapsed())
                .ok_or(ClientError::Uncertain)?;
            let mut receive = mem::replace(&mut self.receive, Buffer::new(0));
            receive.clear();
            receive.set_requested_len(self.input.max_packet_size());
            let completion = self.input.transfer_blocking(receive, remaining);
            let transferred = completion.actual_len;
            let status = completion.status;
            self.receive = completion.buffer;
            if status.is_err() || transferred == 0 {
                #[cfg(feature = "development")]
                self.receive[..].zeroize();
                return Err(ClientError::Uncertain);
            }
            let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let consumed = receiver.push(response, &self.receive[..transferred], now_ms);
            #[cfg(feature = "development")]
            self.receive[..].zeroize();
            let consumed = consumed.map_err(|_| ClientError::Integrity)?;
            if consumed != transferred {
                return Err(ClientError::Integrity);
            }
            if let Some(body) = receiver.complete(response) {
                return Ok(body.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenError, Selector};

    #[test]
    fn accepts_explicit_and_stable_selector_forms() {
        assert!(Selector::parse("bus=1,address=13").is_ok());
        assert!(Selector::parse("vid=2e8a,pid=000f,serial=development-device").is_ok());
        assert!(Selector::parse("vid=2e8a,pid=000f,bus=1,port=2.3").is_ok());
    }

    #[test]
    fn rejects_ambiguous_or_incomplete_selector_forms() {
        for selector in [
            "",
            "vid=2e8a",
            "vid=2e8a,pid=000f",
            "bus=1",
            "address=13",
            "bus=1,address=13,address=14",
            "vid=2e8a,pid=000f,serial=contains space",
        ] {
            assert!(matches!(
                Selector::parse(selector),
                Err(OpenError::InvalidSelector(_))
            ));
        }
    }
}
