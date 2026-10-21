# Android rooted emulator lab manifest

## Authorization and scope

| Field | Value |
|---|---|
| Authorization reference | `<written reference>` |
| Approved actions | `<AVD modification / root / instrumentation / concealment boundaries>` |
| In-scope app artifacts | `<IDs and SHA-256; no APKs here>` |
| Package, signer, versions | `<identity>` |
| Assessment window / owner | `<dates / role>` |

## Host and SDK

| Field | Value |
|---|---|
| Host OS / architecture | `<value>` |
| Hypervisor / acceleration check | `<value / result>` |
| Android SDK root | `<sanitized path>` |
| Emulator version | `<exact output>` |
| Platform-tools / build-tools | `<versions>` |
| System-image package / revision | `<package / revision>` |
| Image variant / API / ABI | `<values>` |

## AVD lineage

| Stage | AVD / artifact ID | Parent | SHA-256 | Format/version | External evidence path |
|---|---|---|---|---|---|
| Baseline | `<ID>` | `<system image>` | `<hash or manifest hash>` | `<details>` | `<path>` |
| Stock kernel | `<ID>` | `<system image>` | `<hash>` | `<wrapper / uname>` | `<path>` |
| Patch tools/image | `<IDs>` | `<upstream revisions>` | `<hashes>` | `<versions>` | `<path>` |
| Derived kernel | `<ID>` | `<stock kernel>` | `<hash>` | `<wrapper / KMI>` | `<path>` |
| Root manager/modules | `<IDs>` | `<upstream revisions>` | `<hashes>` | `<versions>` | `<path>` |

## Boot and root controls

| Control | Stock baseline | Derived lab | Evidence |
|---|---|---|---|
| Cold boot completed | `<result>` | `<result>` | `<IDs>` |
| `uname` / KMI / vermagic | `<values>` | `<values>` | `<IDs>` |
| Root identity/context | `<result>` | `<result>` | `<IDs>` |
| SELinux state | `<value>` | `<value>` | `<IDs>` |
| Vendor modules/services | `<result>` | `<result>` | `<IDs>` |
| Reboot stability | `<result>` | `<result>` | `<IDs>` |
| Tombstone/ANR/kernel warnings | `<result>` | `<result>` | `<IDs>` |

## Detection experiments

| Run | Changed cause | Observed source/callsite | Stock result | Lab result | App state reached | Side effects/evidence |
|---|---|---|---|---|---|---|
| `<ID>` | `<one change>` | `<path/property/syscall/etc.>` | `<result>` | `<result>` | `<state>` | `<details / IDs>` |

## Commands and custody

- Exact commands and tool-help captures: `<external evidence reference>`
- Download URLs, revisions, licenses, notices, hashes: `<custody record>`
- Secrets supplied outside shell history/process arguments: `<method, not secret>`
- Failed approaches and errors: `<attempt / evidence / consequence>`
- Recovery and cleanup: `<stock boot / AVD destruction / evidence retention>`
- Residual unknowns: `<question and evidence needed>`
