# Provisioning Workflow & Security Model

This document explains how ZCP devices are provisioned offline (or intermittently online) using the `clonic-identity` primitives: certificates, CRLs, and rotation certificates. All signatures are Ed25519.

## Roles & Artifacts
- **Root**: Long-lived trust anchor, kept offline. Issues server certificates and CRLs.
- **Server**: Online provisioning service. Issues device certificates and CRLs under the root.
- **Device**: Leaf node. Presents its device certificate chain during operations.
- **Certificates**: Compact format (subject role, issuer role, subject pubkey, not_before, not_after, max_depth, signature).
- **CRL**: List of revoked device pubkeys, signed by issuer (root/server).
- **Rotation certificate**: Binds new_device to old_device, signed by issuer.

## Recommended Workflow (root → server → device)
1. **Root setup (offline)**
   - Generate root Ed25519 keypair.
   - Issue server certificate with max_depth ≥ 1 (allows server to issue device certs).
   - Publish root public key to all provisioning servers out-of-band.

2. **Server provisioning (semi-online)**
   - Server holds its signing key in a protected store (TPM/HSM preferred).
   - Server periodically publishes CRLs signed by root (if root delegates CRL issuance) or by itself if root policy allows.

3. **Device onboarding (offline-capable)**
   - Device generates its own Ed25519 keypair locally.
   - Device sends REQUEST (msg_type 0x30) with its public key and desired parameters.
   - Server verifies request policy, then issues a device certificate (subject=device, issuer=server, max_depth=0) and returns chain: [root, server, device].
   - Optionally include latest CRL.

4. **Device validation on receipt**
   - Verify each certificate signature in order (root→server→device).
   - Check `not_before` / `not_after` for each cert.
   - Enforce `max_depth`: each child must have max_depth ≥ parent.max_depth-1.
   - Verify CRL signature and ensure device pubkey not listed.
   - Pin the chain and CRL locally.

5. **Runtime presentation**
   - Device attaches its certificate chain to protocol handshakes; peers validate against root public key and current CRL.

6. **Key rotation**
   - Issue a rotation certificate binding old_device → new_device, signed by the issuer (server or root per policy).
   - Distribute CRL updates if the old key is revoked after rotation.

## Security Model & Considerations
- **Trust anchor**: Root key must remain offline/secured; compromise breaks the system.
- **Validity windows**: Short `not_after` for server certs reduces exposure; device certs can be medium-lived.
- **Depth control**: `max_depth` limits delegation; devices should use 0.
- **Revocation**: Distribute signed CRLs frequently; consumers must check CRL freshness.
- **Replay resistance**: Certificate format is deterministic; freshness is enforced via `not_before`/`not_after` and CRL updates.
- **Storage**: Use the `KeyStore` abstraction to back secrets with filesystem/TPM/secure enclave implementations.
- **Offline support**: All artifacts are self-contained (no OCSP); CRL bundling enables offline validation.

## Serialization Notes
- All integers little-endian in the certificate format used by `cert.rs`.
- Certificate encoding = body || signature (1+1+32+8+8+1 bytes + 64-byte signature).
- CRL encoding = issuer_pubkey || count_le_u16 || revoked_entries*32 || signature.

## Implementation Pointers
- See `identity/src/cert.rs` for encoding, signing, verification, chain checks, CRL, and rotation certs.
- Provisioning message structs are in `identity/src/provisioning.rs`.
- Ed25519 via `ed25519-dalek` (v2).
