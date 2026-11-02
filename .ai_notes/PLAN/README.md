# PLAN

Planning and feasibility documents for the MT7601U macOS project. These are decision documents, not user documentation — they record what was investigated, what was ruled out, and why.

## Documents

| Document | Status | Date | Covers |
|---|---|---|---|
| [`feasibility-wifi-bt-app.md`](feasibility-wifi-bt-app.md) | Current | 2026-11-02 | One app with a Wi-Fi tab (MT7601U) and a Bluetooth tab (built-in `BCM_4378` or CSR8510). Answers whether the MT7601U can do Bluetooth, what each half can control, and the CSR8510 external-controller path. |

## Reading order

1. **`feasibility-wifi-bt-app.md` §0** — the bottom line, if you only read one page.
2. **§2** — why the MT7601U cannot do Bluetooth (hardware, not driver).
3. **§3** — the capability matrix; note that Wi-Fi is app-private and Bluetooth is system-shared.
4. **§5–6** — the Bluetooth backend and the CSR8510 decision.
5. **§7–9** — architecture, UX, and effort if the app is built.
6. **§10** — the validation plan, starting with a no-code API probe.

## Conventions

- **Status:** `Current`, `Superseded`, or `Draft`.
- Every feasibility claim should name its evidence: a local command, an SDK header, an Apple document, or a datasheet.
- A document that changes scope is replaced, not silently edited. The old file is removed and the new one notes what it replaces.
- Kill criteria are written before work starts, not after it fails.

## Related project documents

- [`../docs/macos-wifi-feasibility.md`](../docs/macos-wifi-feasibility.md) — the original native-Wi-Fi blocker finding.
- [`../docs/usb-descriptors.md`](../docs/usb-descriptors.md) — captured MT7601U descriptors (vendor-specific class, bulk endpoints only).
- [`../masterplan.md`](../masterplan.md) — architecture tracks and the Linux-backed fallback.
- [`../README.md`](../README.md) — current implementation status.
