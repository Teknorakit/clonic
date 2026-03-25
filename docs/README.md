# ZCP Documentation

This directory contains comprehensive documentation for the Zone Coordination Protocol (ZCP).

## 📚 Documentation Structure

### Protocol & Architecture
- **[ZCP_PROTOCOL_SPEC.md](./ZCP_PROTOCOL_SPEC.md)** - Complete RFC-style protocol specification
  - Wire format definition
  - Message types and ranges
  - Cryptographic suites
  - Zone enforcement mechanisms
  - Security considerations

### Implementation Guides
- **[SUITE_SELECTION.md](./SUITE_SELECTION.md)** - Cryptographic suite selection guidelines
  - Performance benchmarks
  - Security recommendations
  - Migration paths
  - Use case recommendations

- **[TRANSPORT_GUIDE.md](./TRANSPORT_GUIDE.md)** - Transport implementation guide
  - Step-by-step implementation
  - Two-phase framing protocol
  - Best practices and examples
  - Testing framework

- **[PROVISIONING_WORKFLOW.md](./PROVISIONING_WORKFLOW.md)** - Device provisioning guide
  - Complete provisioning flow
  - Certificate management
  - Security considerations
  - Implementation examples

### Configuration & Operations
- **[ZONE_CONFIGURATION.md](./ZONE_CONFIGURATION.md)** - Zone configuration cookbook
  - Common zone patterns
  - Cross-zone policies
  - Enforcement mechanisms
  - Real-world examples

- **[WIRESHARK_DISSECTOR.md](./WIRESHARK_DISSECTOR.md)** - Network analysis tool
  - Complete Lua dissector implementation
  - Installation instructions
  - Usage examples and filters
  - Performance analysis

## 🌐 Online Documentation

The latest documentation is automatically published to GitHub Pages:
- **[ZCP Documentation](https://teknorakit.github.io/clonic/)**

## 🔧 Building Documentation Locally

To build the documentation locally:

```bash
# Build Rust API documentation
cargo doc --all-features --no-deps --document-private-items

# View documentation
open target/doc/index.html
```

## 📝 Contributing

When contributing documentation:

1. **Use clear, concise language** - Aim for technical accuracy and readability
2. **Include code examples** - Provide working examples where appropriate
3. **Follow the existing style** - Maintain consistency with existing documentation
4. **Update cross-references** - Ensure all internal links remain valid
5. **Test examples** - Verify all code examples compile and run correctly

## 📋 Documentation Checklist

- [ ] All code examples are tested and working
- [ ] Internal links are valid and up-to-date
- [ ] External links are accessible
- [ ] Tables and formatting render correctly
- [ ] Diagrams and images are properly sized
- [ ] Version information is current
- [ ] Security considerations are documented

## 🔗 Related Resources

- **[GitHub Repository](https://github.com/Teknorakit/clonic)** - Source code and issues
- **[API Documentation](https://teknorakit.github.io/clonic/clonic_core/)** - Rust API docs
- **[Examples](../examples/)** - Code examples and tutorials
- **[CHANGELOG](../CHANGELOG.md)** - Version history and changes
