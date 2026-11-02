# Captured USB descriptors

## Source

Captured on the target Apple Silicon Mac (`macOS 26.5.1`, arm64) on 2026-10-15.
The dongle is attached through a GenesysLogic USB hub.

`system_profiler SPUSBDataType` excerpt (serial number value removed):

```
802.11 n WLAN:

  Location ID:      0x01140000
  Connection Type:  Removable
  Manufacturer:     MediaTek
  Serial Number:    1.0
  Link Speed:       480 Mb/s
  USB Vendor ID:    0x148f
  USB Product ID:   0x7601
  USB Product Version: 0x0000
  Power Allocated:  0.8 W (160 mA)
```

Raw descriptor dump from `cargo run -- --diagnose` (serial redacted by the
tool on purpose):

```
148f:7601 bus 1 address 4 (High (480 Mbit/s))
  Manufacturer: MediaTek
  Product:      802.11 n WLAN
  Serial:       <present, redacted>
  Configuration 1: self-powered=false, remote-wakeup=false, max power 320 mA, 1 interface(s)
    Interface 0 alt 0: class 0xff/0xff/0xff, 8 endpoint(s)
      Endpoint 0x84 (IN Bulk), max packet 512, interval 0
      Endpoint 0x85 (IN Bulk), max packet 512, interval 0
      Endpoint 0x08 (OUT Bulk), max packet 512, interval 0
      Endpoint 0x04 (OUT Bulk), max packet 512, interval 0
      Endpoint 0x05 (OUT Bulk), max packet 512, interval 0
      Endpoint 0x06 (OUT Bulk), max packet 512, interval 0
      Endpoint 0x07 (OUT Bulk), max packet 512, interval 0
      Endpoint 0x09 (OUT Bulk), max packet 512, interval 0
```

(The endpoint ordering above is libusb's enumeration order, i.e. the order the
endpoints appear in the configuration descriptor. The Linux driver assigns
`out_eps[]` in exactly this order, so the first bulk OUT — `0x08` on this unit —
is the endpoint it uses as `MT_EP_OUT_INBAND_CMD`. This project resolves that
endpoint at runtime rather than hardcoding `0x08`.)

## Interpretation

* **VID:PID** `148f:7601` — matches the Linux driver device table.
* **Speed** High (480 Mbit/s), consistent with `Link Speed: 480 Mb/s`.
* **Endpoints**: 2 bulk IN + 6 bulk OUT, all 512-byte max packet. This matches
  the Linux driver's `__MT_EP_IN_MAX = 2` / `__MT_EP_OUT_MAX = 6` requirement
  exactly (`mt7601u_assign_pipes()`).
* Interface class `0xff/0xff/0xff` is vendor-specific, i.e. there is no
  standard wireless/usbnet class interface. A user-space driver must speak the
  vendor control protocol directly.
* `Power Allocated 160 mA` (system_profiler) vs `max power 320 mA` (descriptor,
  `bMaxPower * 2mA`). Treat 320 mA as the descriptor upper bound.

## Do not hardcode

Per the master plan, the Rust code reads these values at runtime rather than
baking in endpoint numbers. The numbers above are reference data for the human
reader only.
