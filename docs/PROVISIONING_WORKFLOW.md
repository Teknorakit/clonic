# ZCP Provisioning Workflow Guide

This guide explains the device provisioning process for the Zone Coordination Protocol (ZCP).

## Overview

ZCP provisioning establishes secure device identities and defines the trust relationships between devices in a zone. The process ensures that only authorized devices can communicate within a zone and respects cross-zone data residency requirements.

## Key Concepts

### Device Identity
- **32-byte Ed25519 public key** uniquely identifies each device
- **Device ID**: The public key serves as the device's identifier in ZCP envelopes
- **Key Generation**: Uses cryptographically secure random number generation

### Certificate Chain
- **Root Certificate**: Issued by zone authority, defines zone boundaries
- **Server Certificate**: Issued by root, authorizes servers in the zone
- **Device Certificate**: Issued by server, authorizes specific devices

### Trust Decay
- **Chain Depth**: Maximum delegation depth (root→server→device)
- **Expiration**: Time-based validity for certificates
- **Revocation**: Ability to invalidate compromised certificates

## Provisioning Flow

### Phase 1: Device Registration

1. **Device Generates Key Pair**
   ```rust
   use clonic_identity::HybridSigKeypair;
   
   let device_keypair = HybridSigKeypair::keygen()?;
   let device_id = DeviceIdentity::from_bytes(&device_keypair.ed_public);
   ```

2. **Device Creates Provisioning Request**
   ```rust
   use clonic_identity::ProvisioningMessage;
   
   let request = ProvisioningMessage::request_request(
       device_id,
       Some(device_capabilities), // Optional device metadata
   );
   ```

3. **Device Sends Request to Zone Authority**
   - Uses secure channel (TLS or out-of-band)
   - Includes device metadata and capabilities
   - Signs request with device private key

### Phase 2: Certificate Issuance

1. **Zone Authority Validates Request**
   - Verifies device signature
   - Checks device compliance with zone policies
   - Validates device capabilities

2. **Authority Issues Device Certificate**
   ```rust
   use clonic_identity::Certificate;
   
   let cert = Certificate::sign(
       device_id,           // Subject
       zone_root_public,     // Issuer
       1,                    // Chain depth (device)
       current_time,         // Not before
       expiry_time,          // Not after
       max_depth,            // Max delegation depth
       &zone_root_private,   // Issuer private key
   );
   ```

3. **Authority Returns Certificate**
   - Includes certificate chain (root→server→device)
   - Provides zone configuration and policies
   - Signs response with authority private key

### Phase 3: Certificate Validation

1. **Device Validates Certificate Chain**
   ```rust
   let cert_chain = parse_certificate_chain(response)?;
   
   // Validate each certificate in the chain
   for cert in &cert_chain {
       cert.verify_signature()?;
       cert.validate_expiry(current_time)?;
       cert.validate_trust_depth(max_allowed_depth)?;
   }
   ```

2. **Device Stores Certificate**
   - Stores certificate in secure storage
   - Sets up automatic renewal before expiration
   - Configures zone-specific policies

## Certificate Format

### Wire Format
```
Certificate (146 bytes):
- subject_public_key: [u8; 32]    // Device Ed25519 public key
- issuer_public_key: [u8; 32]     // Issuer Ed25519 public key  
- not_before: u64                   // Unix timestamp (LE)
- not_after: u64                    // Unix timestamp (LE)
- max_depth: u8                    // Maximum delegation depth
- signature: [u8; 64]              // Ed25519 signature over above fields
```

### Trust Decay Rules
- **Root Certificate**: Can issue server certificates (depth 1)
- **Server Certificate**: Can issue device certificates (depth 2)
- **Device Certificate**: Cannot issue further certificates (leaf)

## Security Considerations

### Key Management
- **Secure Storage**: Private keys stored in TPM/secure enclave when available
- **Key Rotation**: Regular rotation of root and server keys
- **Backup**: Secure backup procedures for recovery

### Certificate Validation
- **Signature Verification**: Always verify Ed25519 signatures
- **Expiry Checking**: Reject expired certificates
- **Chain Validation**: Ensure proper delegation chain
- **Revocation Checking**: Check certificate revocation lists

### Network Security
- **TLS Encryption**: Use TLS for provisioning communications
- **Authentication**: Mutual authentication during provisioning
- **Integrity**: Verify message integrity and authenticity

## Implementation Examples

### Device-Side Provisioning

```rust
use clonic_identity::{DeviceIdentity, ProvisioningMessage, HybridSigKeypair};

pub struct DeviceProvisioner {
    keypair: HybridSigKeypair,
    certificate: Option<Certificate>,
    zone_config: ZoneConfig,
}

impl DeviceProvisioner {
    pub fn new() -> Result<Self, Error> {
        let keypair = HybridSigKeypair::keygen()?;
        Ok(Self {
            keypair,
            certificate: None,
            zone_config: ZoneConfig::default(),
        })
    }
    
    pub fn provision_device(&mut self, zone_authority: &str) -> Result<(), Error> {
        // Generate provisioning request
        let device_id = DeviceIdentity::from_bytes(&self.keypair.ed_public);
        let request = ProvisioningMessage::request_request(device_id, None);
        
        // Send request to zone authority
        let response = send_provisioning_request(zone_authority, &request)?;
        
        // Parse and validate certificate
        let cert = Certificate::from_bytes(&response.certificate_data)?;
        cert.verify_signature()?;
        
        // Store certificate
        self.certificate = Some(cert);
        
        Ok(())
    }
    
    pub fn is_provisioned(&self) -> bool {
        self.certificate.is_some()
    }
}
```

### Server-Side Certificate Issuance

```rust
use clonic_identity::{Certificate, DeviceIdentity, HybridSigKeypair};

pub struct ZoneAuthority {
    root_keypair: HybridSigKeypair,
    server_keypair: HybridSigKeypair,
    issued_certificates: Vec<Certificate>,
}

impl ZoneAuthority {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            root_keypair: HybridSigKeypair::keygen()?,
            server_keypair: HybridSigKeypair::keygen()?,
            issued_certificates: Vec::new(),
        })
    }
    
    pub fn issue_device_certificate(
        &mut self,
        device_request: &ProvisioningMessage,
        expiry_days: u64,
    ) -> Result<Certificate, Error> {
        // Validate request
        device_request.verify_signature()?;
        
        // Get device identity
        let device_id = DeviceIdentity::from_bytes(&device_request.sender_device_id);
        
        // Calculate expiry
        let now = current_unix_timestamp();
        let expiry = now + (expiry_days * 24 * 60 * 60);
        
        // Issue certificate
        let cert = Certificate::sign(
            device_id,
            DeviceIdentity::from_bytes(&self.root_keypair.ed_public),
            2, // Device certificate (depth 2)
            now,
            expiry,
            3, // Max depth for devices
            &self.root_keypair.ed_secret,
        );
        
        // Track issued certificate
        self.issued_certificates.push(cert.clone());
        
        Ok(cert)
    }
}
```

## Zone Configuration

### Zone Definition
```rust
#[derive(Debug, Clone)]
pub struct ZoneConfig {
    pub zone_id: u16,
    pub residency_tag: u16,
    pub max_chain_depth: u8,
    pub certificate_expiry_days: u32,
    pub allowed_device_types: Vec<DeviceType>,
    pub cross_zone_policies: Vec<CrossZonePolicy>,
}
```

### Cross-Zone Policies
```rust
#[derive(Debug, Clone)]
pub struct CrossZonePolicy {
    pub target_zone: u16,
    pub allowed_data_types: Vec<DataType>,
    pub require_mutual_auth: bool,
    pub audit_logging: bool,
}
```

## Error Handling

### Common Provisioning Errors
```rust
#[derive(Debug, Clone)]
pub enum ProvisioningError {
    InvalidSignature,
    CertificateExpired,
    ChainDepthExceeded,
    UnauthorizedDevice,
    ZonePolicyViolation,
    NetworkError(String),
    KeyGenerationFailed,
}
```

### Error Recovery
- **Retry Logic**: Exponential backoff for network errors
- **Fallback Procedures**: Alternative provisioning methods
- **Audit Logging**: Record all provisioning attempts and failures

## Testing

### Unit Tests
```rust
#[test]
fn test_certificate_signing() {
    let keypair = HybridSigKeypair::keygen().unwrap();
    let device_id = DeviceIdentity::from_bytes(&keypair.ed_public);
    
    let cert = Certificate::sign(
        device_id,
        device_id, // Self-signed for testing
        1,
        current_time(),
        current_time() + 86400, // 1 day
        2,
        &keypair.ed_secret,
    ).unwrap();
    
    assert!(cert.verify_signature().is_ok());
}
```

### Integration Tests
```rust
#[tokio::test]
async fn test_provisioning_workflow() {
    // Setup zone authority
    let mut authority = ZoneAuthority::new().unwrap();
    
    // Setup device
    let mut device = DeviceProvisioner::new().unwrap();
    
    // Provision device
    device.provision_device("localhost:8080").await.unwrap();
    
    // Verify provisioning
    assert!(device.is_provisioned());
}
```

## Monitoring and Auditing

### Provisioning Metrics
- **Certificate Issuance Rate**: Track certificates issued per time period
- **Provisioning Success Rate**: Monitor successful vs failed provisioning
- **Certificate Expiry**: Alert before certificates expire
- **Revocation Events**: Track certificate revocations

### Audit Trail
```rust
#[derive(Debug, Clone)]
pub struct ProvisioningEvent {
    pub timestamp: u64,
    pub device_id: DeviceIdentity,
    pub event_type: ProvisioningEventType,
    pub details: String,
}

pub enum ProvisioningEventType {
    RequestReceived,
    CertificateIssued,
    CertificateRevoked,
    ProvisioningFailed,
    KeyRotated,
}
```

## Best Practices

### Security
- **Use Hardware Security Modules**: Store private keys in TPM when available
- **Implement Certificate Pinning**: Verify expected certificates
- **Regular Key Rotation**: Rotate keys before they expire
- **Secure Backup**: Maintain secure backup procedures

### Performance
- **Batch Operations**: Process multiple provisioning requests efficiently
- **Caching**: Cache certificate validation results
- **Async Operations**: Use async I/O for network operations
- **Resource Limits**: Implement rate limiting for provisioning requests

### Reliability
- **Retry Logic**: Implement exponential backoff for failures
- **Fallback Methods**: Provide alternative provisioning channels
- **Health Checks**: Monitor provisioning service health
- **Graceful Degradation**: Handle partial failures gracefully

## Troubleshooting

### Common Issues

#### Certificate Validation Failures
- **Check Clock Sync**: Ensure devices have synchronized time
- **Verify Chain**: Validate complete certificate chain
- **Check Revocation**: Verify certificate not revoked

#### Network Connectivity
- **DNS Resolution**: Ensure zone authority reachable
- **TLS Configuration**: Verify TLS settings
- **Firewall Rules**: Check network firewall policies

#### Key Generation Errors
- **Entropy Source**: Ensure sufficient entropy available
- **Memory Constraints**: Check available memory for key operations
- **Hardware Support**: Verify hardware RNG support

### Debug Tools

```rust
// Enable debug logging
env_logger::init();

// Certificate debugging
cert.debug_print();

// Chain validation debugging
let chain_result = cert.validate_chain();
println!("Chain validation: {:?}", chain_result);
```

## References

- [Ed25519 Digital Signatures](https://ed25519.cr.yp.to/)
- [X25519 Key Exchange](https://cr.yp.to/user/ed25519.html)
- [Certificate Formats](https://tools.ietf.org/html/rfc5280)
- [Zone Coordination Protocol Specification](../MANIFESTO.md)
