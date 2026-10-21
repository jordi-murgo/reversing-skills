# Firmware report guidance

Use `assets/firmware-report-template.md` for firmware images, extracted filesystems, services, or
hardware-backed assessment. Distinguish image evidence, emulation, clean-room models, and hardware
observations throughout.

## Scope and identity

Record vendor/product family, model or board revision, firmware version/build, acquisition source,
container and partition layout, signatures, hashes, and update channel. Tie every extracted artifact
to its parent by offset or archive path, extraction method, and hash.

## Firmware evidence

For each finding, identify:

- partition, filesystem path, package, service or init unit, process user, and privileges;
- exposed interface and path from network, local client, update package, or physical access;
- activation and persistence across reboot, factory reset, rollback, and update where tested;
- dependencies on bootloader, secure boot, update verification, NVRAM, hardware devices, or cloud;
- affected models/builds and evidence for fleet-level scope;
- whether evidence came from static inspection, component emulation, full-system emulation,
  clean-room modeling, or real hardware.

Document substitutions and fidelity gaps. Offline sanitizer proof establishes behavior in the model,
not reachability, target memory layout, exploitability, persistence, or fleet infection.

## Malware routing

An unknown binary, high entropy, stripped symbols, hard-coded host, or startup entry is not enough to
classify firmware as malicious. Create a malware triage companion when related lineage, configuration,
delivery, or capability evidence forms a coherent hypothesis. Use the full malware report for
observed unauthorized execution, persistence, C2, exfiltration, destructive behavior, or a verified
implanted component.

The primary firmware report retains model/build scope, component location, startup path, privileges,
reachability, persistence, update/supply-chain implications, fleet impact, and the companion report
identifier. Keep hardware confirmation and emulation/model conclusions separate.
