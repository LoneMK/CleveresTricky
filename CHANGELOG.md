## V2.4.0 — Deep Bug Fix Release

### Critical Fixes
- **Fix AOSP attestation failure**: Replaced hardcoded `system_patch_level` / `vendor_patch_level` (20250205) in Rust COSE with dynamic date computation. Stale dates caused attestation rejection on newer devices.
- **Fix keystore crash on FLAG_ONEWAY transactions**: `BinderInterceptor.onTransact()` used `reply!!` which threw `KotlinNullPointerException` when native layer sent one-way transactions, crashing the entire keystore2 process.
- **Fix BouncyCastle provider race condition**: `buildECKeyPair()` and `buildRSAKeyPair()` both called `Security.removeProvider/addProvider` globally without synchronization, causing `NoSuchProviderException` under concurrent attestation requests. Provider is now registered once at class initialization.
- **Fix algorithm normalization NPE**: `hackCertificateChain()` used raw JCA algorithm name (e.g., "ECDSA") to look up `rotationCounters`, but the map only contained "EC" keys, causing NPE on every ECDSA attestation hack.
- **Fix inject binary ABI-unaware path**: `KeystoreInterceptor` used a flat path `/data/adb/modules/cleverestricky/inject` but the binary is deployed per-ABI under `lib/{abi}/inject`. Now resolves correct ABI path from `Build.SUPPORTED_ABIS`.
- **Fix RKP keyPairCounter thread safety + overflow**: Changed from plain `Int` to `AtomicInteger` with `and 0x7FFFFFFF` overflow mask.
- **Fix `update.json` version mismatch**: Was stuck at V2.3.3 while codebase was at V2.3.5+. Module update detection was broken.

### AOSP Compatibility Fixes
- **Fix `createExtension()` null return NPE chain**: When `createExtension()` returned null (on any Throwable), `certBuilder.addExtension(null)` threw NPE in BouncyCastle, silently failing key generation with no error message.
- **Fix `rootOfTrust` null dereference**: When original TEE sequence had no tag 704, `rootOfTrust` was null but `rootOfTrust.getClass().getName()` was called, replacing the intended error with an NPE.
- **Fix boot key/hash null in `createExtension()`**: `UtilKt.getBootKey()` / `getBootHash()` could return null, causing NPE in `DEROctetString(null)`. Now generates random 32-byte fallback.
- **Fix device properties NPE**: When `brand` was set but `device`/`product`/`manufacturer`/`model` were null, `DEROctetString(null)` crashed. Each field is now guarded individually.
- **Fix missing `ro.oem_unlock_supported`** in comprehensive hide props path (non-Shamiko devices).

### Safety Improvements
- **Fix `KeyCache.values()` concurrent modification**: `RkpInterceptor.resolveDeviceInfo()` iterated over `KeyCache.values()` without protection against concurrent inserts, which could throw `ConcurrentModificationException`.

## Changelog

- Changelog and other stuff Github.

Github:
github.com/tryigit/CleveresTricky
