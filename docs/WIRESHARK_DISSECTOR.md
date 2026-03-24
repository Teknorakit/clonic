# Wireshark Dissector for ZCP

This guide explains how to install and use the Wireshark dissector for the Zone Coordination Protocol (ZCP).

## Overview

The ZCP Wireshark dissector provides:
- **Protocol parsing** of ZCP envelopes
- **Field extraction** for analysis
- **Zone enforcement visualization**
- **Cryptographic suite identification**
- **Message type classification**

## Installation

### Prerequisites

- **Wireshark 3.0+** with Lua support
- **Lua 5.1+** runtime
- **ZCP dissector plugin files**

### Linux Installation

```bash
# Install Wireshark
sudo apt-get install wireshark

# Create plugin directory
mkdir -p ~/.local/lib/wireshark/plugins/

# Copy dissector files
cp zcp_dissector.lua ~/.local/lib/wireshark/plugins/
cp zcp_init.lua ~/.local/lib/wireshark/plugins/

# Restart Wireshark
wireshark
```

### macOS Installation

```bash
# Install Wireshark (via Homebrew)
brew install --cask wireshark

# Create plugin directory
mkdir -p ~/Library/Application\ Support/Wireshark/Plugins/

# Copy dissector files
cp zcp_dissector.lua ~/Library/Application\ Support/Wireshark/Plugins/
cp zcp_init.lua ~/Library/Application\ Support/Wireshark/Plugins/

# Restart Wireshark
open -a Wireshark
```

### Windows Installation

```
# Install Wireshark from https://www.wireshark.org/

# Create plugin directory
mkdir "%APPDATA%\Wireshark\plugins\"

# Copy dissector files
copy zcp_dissector.lua "%APPDATA%\Wireshark\plugins\"
copy zcp_init.lua "%APPDATA%\Wireshark\plugins\"

# Restart Wireshark
```

## Dissector Files

### zcp_init.lua

```lua
-- ZCP dissector initialization
local zcp = {}

-- Register dissector
zcp.dissector = Dissector.get("zcp")

-- Protocol fields
zcp.fields = {
    -- Header fields
    version = ProtoField.uint8("zcp.version", "Version", base.HEX, nil, nil, "Protocol version")
    suite = ProtoField.uint8("zcp.suite", "Crypto Suite", base.HEX, nil, nil, "Cryptographic suite")
    msg_type = ProtoField.uint8("zcp.msg_type", "Message Type", base.HEX, nil, nil, "Message type")
    flags = ProtoField.uint8("zcp.flags", "Flags", base.HEX, nil, nil, "Message flags")

    -- Device identification
    sender_device_id = ProtoField.bytes("zcp.sender_device_id", "Sender Device ID", base.NONE)
    timestamp = ProtoField.absolute_time("zcp.timestamp", "Timestamp", base.UTC)

    -- Payload information
    payload_length = ProtoField.uint32("zcp.payload_length", "Payload Length", base.DEC)
    residency_tag = ProtoField.uint16("zcp.residency_tag", "Residency Tag", base.DEC)

    -- Payload content
    nonce = ProtoField.bytes("zcp.nonce", "Nonce", base.NONE)
    ciphertext = ProtoField.bytes("zcp.ciphertext", "Ciphertext", base.NONE)
    mac = ProtoField.bytes("zcp.mac", "MAC", base.NONE)
}

-- Protocol definition
zcp.proto = Proto("zcp", "Zone Coordination Protocol", "ZCP")

-- Register protocol fields
for name, field in pairs(zcp.fields) do
    zcp.proto.fields[name] = field
end

-- Register dissector table
local udp_table = DissectorTable.get("udp.port")
udp_table:add(8080, zcp.proto)  -- Default ZCP port

return zcp
```

### zcp_dissector.lua

```lua
-- ZCP protocol dissector
local zcp = require("zcp_init")

-- Message type mappings
local msg_types = {
    [0x01] = "Encrypted Application Data",
    [0x02] = "Compressed Data",
    [0x03] = "Fragmented Data",
    [0x10] = "Key Exchange",
    [0x11] = "Key Exchange Response",
    [0x12] = "Node Discovery",
    [0x20] = "Gossip Message",
    [0x21] = "Gossip Response",
    [0x30] = "Provisioning Request",
    [0x31] = "Provisioning Certificate",
    [0x32] = "Certificate Revocation",
    [0x40] = "Heartbeat",
    [0x41] = "Heartbeat Response",
    [0xF0] = "Vendor Extension",
}

-- Crypto suite mappings
local crypto_suites = {
    [0x01] = "Post-Quantum Hybrid",
    [0x02] = "Classical",
}

-- Country code mappings
local country_codes = {
    [360] = "Indonesia",
    [702] = "Singapore",
    [458] = "Malaysia",
    [764] = "Thailand",
    [704] = "Vietnam",
    [840] = "United States",
    [826] = "United Kingdom",
    [250] = "France",
    [276] = "Germany",
    [380] = "Italy",
    [392] = "Japan",
    [156] = "China",
    [344] = "Hong Kong",
    [356] = "India",
}

-- Flag definitions
local flags = {
    [0x01] = "Compressed",
    [0x02] = "Fragmented",
    [0x04] = "Encrypted",
    [0x08] = "Signed",
}

-- Main dissector function
function zcp.dissector.dissector(buffer, pinfo, tree)
    -- Validate minimum packet size
    if buffer:len() < 58 then  -- 42 header + 16 MAC minimum
        return 0
    end

    -- Set protocol column
    pinfo.cols.protocol = "ZCP"

    -- Create protocol tree
    local subtree = tree:add(zcp.proto, buffer())

    -- Parse header
    local header = buffer(0, 42)
    local version = header(0, 1):uint()
    local suite = header(1, 1):uint()
    local msg_type = header(2, 1):uint()
    local msg_flags = header(3, 1):uint()

    -- Add header fields
    subtree:add(zcp.fields.version, version)
    subtree:add(zcp.fields.suite, suite):append_text(" (" .. (crypto_suites[suite] or "Unknown") .. ")")
    subtree:add(zcp.fields.msg_type, msg_type):append_text(" (" .. (msg_types[msg_type] or "Unknown") .. ")")

    -- Parse flags
    local flags_tree = subtree:add(zcp.proto, "Flags", header(3, 1))
    for bit, name in pairs(flags) do
        if bit.band(msg_flags, bit) ~= 0 then
            flags_tree:add(zcp.proto, name, bit)
        end
    end

    -- Parse device ID
    local device_id = header(4, 8)
    subtree:add(zcp.fields.sender_device_id, device_id)

    -- Parse timestamp
    local timestamp_bytes = header(20, 8)
    local timestamp = timestamp_bytes:uint64()
    subtree:add(zcp.fields.timestamp, NSTime(timestamp, 0))

    -- Parse payload length
    local payload_length = header(36, 4):uint()
    subtree:add(zcp.fields.payload_length, payload_length)

    -- Parse residency tag
    local residency_tag = header(40, 2):uint()
    local country_name = country_codes[residency_tag] or "Unknown"
    subtree:add(zcp.fields.residency_tag, residency_tag):append_text(" (" .. country_name .. ")")

    -- Parse payload if present
    if buffer:len() >= 58 then
        local payload_start = 42
        local payload_size = payload_length
        local mac_start = payload_start + payload_size

        if buffer:len() >= mac_start + 16 then
            local payload = buffer(payload_start, payload_size)
            local mac = buffer(mac_start, 16)

            -- Add MAC
            subtree:add(zcp.fields.mac, mac)

            -- Parse payload based on message type
            if msg_type == 0x01 and payload_size >= 12 then
                -- Encrypted application data
                local nonce = payload(0, 12)
                local ciphertext = payload(12, payload_size - 12)

                subtree:add(zcp.fields.nonce, nonce)
                subtree:add(zcp.fields.ciphertext, ciphertext)

                -- Set info column
                pinfo.cols.info = string.format("ZCP %s -> %s (%s)",
                    msg_types[msg_type] or "Unknown",
                    country_name,
                    crypto_suites[suite] or "Unknown"
                )
            elseif msg_type == 0x10 and payload_size >= 32 then
                -- Key exchange
                local ephemeral_pk = payload(0, 32)
                local encapsulated_key = payload(32, payload_size - 32)

                subtree:add(zcp.proto, "Ephemeral Public Key", ephemeral_pk)
                subtree:add(zcp.proto, "Encapsulated Key", encapsulated_key)

                pinfo.cols.info = string.format("ZCP %s (%s)",
                    msg_types[msg_type] or "Unknown",
                    crypto_suites[suite] or "Unknown"
                )
            elseif msg_type == 0x40 and payload_size >= 4 then
                -- Heartbeat
                local sequence = payload(0, 4):uint()
                subtree:add(zcp.proto, "Sequence Number", sequence)

                pinfo.cols.info = string.format("ZCP %s (seq=%d)",
                    msg_types[msg_type] or "Unknown",
                    sequence
                )
            else
                -- Unknown payload type
                subtree:add(zcp.proto, "Payload", payload)

                pinfo.cols.info = string.format("ZCP %s (%s, %d bytes)",
                    msg_types[msg_type] or "Unknown",
                    country_name,
                    payload_size
                )
            end
        end
    end

    return buffer:len()
end

-- Register post-dissector for zone analysis
local post_dissector = PostDissector.get("zcp_zone_analyzer")

function post_dissector.dissector(buffer, pinfo, tree)
    -- Analyze zone compliance
    if pinfo.cols.protocol == "ZCP" then
        local zcp_tree = tree:child("ZCP Zone Analysis")

        -- Extract residency tag from parsed data
        local residency_tag = pinfo.cols.info:match("%((%d+)%s+%w+%)")
        if residency_tag then
            residency_tag = tonumber(residency_tag)
            local country_name = country_codes[residency_tag] or "Unknown"

            zcp_tree:add(zcp.proto, "Source Zone", country_name)
            zcp_tree:add(zcp.proto, "Zone ID", residency_tag)

            -- Check for cross-zone transfers
            -- This would require tracking previous packets
            -- For now, just display the zone information
        end
    end
end

-- Register post-dissector
register_post_dissector(post_dissector)

return zcp.dissector
```

## Usage

### Basic Analysis

1. **Start Wireshark** and capture traffic
2. **Filter ZCP traffic**: `zcp` or `tcp.port == 8080`
3. **View parsed packets**: Click on ZCP packets to see detailed breakdown

### Zone Analysis

1. **Enable zone analysis**: Tools → Analyze → Enable Protocols → ZCP Zone Analyzer
2. **View zone information**: Look for "ZCP Zone Analysis" tree in packet details
3. **Track cross-zone transfers**: Monitor residency tags across packets

### Cryptographic Analysis

1. **Identify suites**: Look at "Crypto Suite" field
2. **Analyze key exchange**: Filter for `zcp.msg_type == 0x10`
3. **Monitor encryption**: Check "Encrypted Application Data" packets

### Performance Analysis

1. **Timestamp analysis**: Use "Timestamp" field for latency measurement
2. **Message size**: Monitor "Payload Length" for bandwidth analysis
3. **Message frequency**: Use IO graphs for traffic patterns

## Filtering Examples

### Basic Filters

```
# All ZCP traffic
zcp

# ZCP on specific port
tcp.port == 8080

# Specific message types
zcp.msg_type == 0x01  # Encrypted data
zcp.msg_type == 0x10  # Key exchange
zcp.msg_type == 0x40  # Heartbeat
```

### Advanced Filters

```
# Cross-zone traffic (Indonesia to Singapore)
zcp.residency_tag == 360 and tcp.dstport == 8080

# Post-quantum hybrid traffic
zcp.suite == 0x01

# Encrypted and compressed messages
zcp.flags == 0x05  # Compressed + Encrypted

# Heartbeat monitoring
zcp.msg_type == 0x40 or zcp.msg_type == 0x41
```

### Statistical Analysis

```
# Message type distribution
frame.protocols == "zcp" && zcp.msg_type

# Zone traffic distribution
zcp.residency_tag

# Crypto suite usage
zcp.suite

# Payload size distribution
zcp.payload_length
```

## Customization

### Adding Message Types

```lua
-- Add to msg_types table
local msg_types = {
    -- Existing types...
    [0x50] = "Custom Vendor Message",
    [0x51] = "Vendor-Specific Data",
}
```

### Adding Country Codes

```lua
-- Add to country_codes table
local country_codes = {
    -- Existing codes...
    [124] = "Canada",
    [554] = "New Zealand",
}
```

### Custom Fields

```lua
-- Add custom field
zcp.fields.custom_field = ProtoField.string("zcp.custom", "Custom Field", base.NONE)
zcp.proto.fields.custom_field = zcp.fields.custom_field
```

## Troubleshooting

### Common Issues

#### Dissector Not Loading
```bash
# Check Lua support
wireshark -v | grep Lua

# Check plugin directory
ls ~/.local/lib/wireshark/plugins/

# Check for syntax errors
lua -c zcp_dissector.lua
```

#### Packets Not Decoded
```bash
# Check port registration
tshark -d tcp.port==8080,zcp -r capture.pcap

# Force protocol decoding
tshark -d tcp.port==8080,zcp -Y "frame.protocols == \"tcp:zcp\""
```

#### Missing Fields
```bash
# Check dissector version
wireshark -v

# Reload plugins
wireshark -r capture.pcap -X lua_script:zcp_init.lua
```

### Debug Mode

```lua
-- Add to dissector for debugging
function zcp.dissector.dissector(buffer, pinfo, tree)
    print(string.format("ZCP packet: %d bytes, type: 0x%02x", buffer:len(), buffer(2, 1):uint()))

    -- Existing dissector code...
end
```

## Performance Considerations

### Large Captures

For large capture files:
1. **Use display filters** to reduce processing
2. **Disable colorization** for faster rendering
3. **Use tshark** for command-line analysis

### Memory Usage

To reduce memory usage:
1. **Limit packet capture** size
2. **Use ring buffers** for live captures
3. **Clear packet list** periodically

## Integration with Other Tools

### tshark Command Line

```bash
# Extract ZCP statistics
tshark -r capture.pcap -Y "zcp" -T fields -e zcp.msg_type -e zcp.residency_tag -e zcp.payload_length

# Export to CSV
tshark -r capture.pcap -Y "zcp" -T fields -E separator=, -e zcp.msg_type -e zcp.residency_tag -e zcp.payload_length > zcp_analysis.csv

# Real-time monitoring
tshark -i eth0 -Y "zcp" -T fields -e zcp.msg_type -e zcp.residency_tag
```

### Python Integration

```python
import pyshark

# Load capture
cap = pyshark.FileCapture('capture.pcap', display_filter='zcp')

# Analyze packets
for packet in cap:
    if hasattr(packet, 'zcp'):
        msg_type = int(packet.zcp.msg_type)
        residency_tag = int(packet.zcp.residency_tag)
        print(f"Message: {msg_type:02x}, Zone: {residency_tag}")
```

## Contributing

### Adding Features

1. **Fork the repository**: https://github.com/Zluidr/clonic-wireshark
2. **Create feature branch**: `git checkout -b feature/new-feature`
3. **Add tests**: Include test captures
4. **Submit pull request**: With description of changes

### Reporting Issues

1. **Bug reports**: https://github.com/Zluidr/clonic-wireshark/issues
2. **Feature requests**: https://github.com/Zluidr/clonic-wireshark/discussions
3. **Security issues**: security@zluidr.com

## References

- [Wireshark Developer Guide](https://www.wireshark.org/docs/wsdg_html_chunked/)
- [Lua API Reference](https://www.wireshark.org/docs/wsdg_html_chunked/ChapterDissection.html)
- [ZCP Protocol Specification](ZCP_PROTOCOL_SPEC.md)
- [Zone Configuration Guide](ZONE_CONFIGURATION.md)
