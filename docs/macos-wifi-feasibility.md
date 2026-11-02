# macOS Wi-Fi feasibility

Status of the "make macOS treat the dongle as a normal Wi-Fi interface" goal.

## Question

Is there a **supported public API** on macOS that lets a third-party USB Wi-Fi
adapter register as a Wi-Fi interface and integrate with System Settings
scanning/association?

## Findings (to verify against current Apple documentation)

* **NetworkingDriverKit** is Apple's public user-space networking driver
  framework. Its public documentation describes **Ethernet** interfaces as the
  supported networking interface type. An Ethernet DriverKit sample does **not**
  establish that a third-party Wi-Fi interface can be registered or that its
  scan results would appear in System Settings.
* **USBDriverKit** is a USB transport framework, not a Wi-Fi registration API.
* Apple's Wi-Fi stack (`IO80211`, airportd) is not a documented public
  integration point for third-party adapters.
* Entitlements: any DriverKit-based approach requires Apple-granted
  entitlements, which are not guaranteed to be issued for this use case.

## Conclusion

Treat **native macOS Wi-Fi registration as blocked pending evidence**. Before
investing further, obtain a concrete Apple document that describes registering
a third-party **Wi-Fi** (not Ethernet) interface and lists the required
entitlement. Until such a document exists, do not attempt to disguise a `utun`
interface as a Wi-Fi adapter.

## Consequences for this project

* The GUI and USB diagnostics are developed independently of this question.
* The experimental user-space path (Rust station + `utun`) is separate. The
  `utun` interface is a layer-3 IP tunnel and does **not** provide Wi-Fi
  semantics (no scan, no association, no per-SSID device).
* The Linux-backed fallback (Track C in the master plan) remains the practical
  way to get the Mac online through this dongle.

## References

* DriverKit — <https://developer.apple.com/documentation/driverkit>
* USBDriverKit — <https://developer.apple.com/documentation/usbdriverkit>
* NetworkingDriverKit — <https://developer.apple.com/documentation/networkingdriverkit>
