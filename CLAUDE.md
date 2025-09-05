# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BGPFix is a high-performance, memory-efficient Golang library designed to handle **tens of thousands of BGP sessions on a single node**. Built as pure Go code, it prioritizes speed and efficiency for real-time BGP session manipulation.

The library enables transparent BGP processing, providing the foundation for **bgpipe** - a BGP proxy that can inspect and modify BGP messages in-flight.

### Performance Design Philosophy

BGPFix is engineered for **extreme performance and scalability**:
- **Pure Golang**: No C dependencies, optimized for Go's runtime
- **Memory efficient**: Minimal allocations, designed for high-throughput scenarios
- **Concurrent by design**: Built to handle thousands of simultaneous BGP sessions
- **Zero-copy where possible**: Efficient message parsing and serialization
- **Minimal dependencies**: Lightweight external dependency footprint

### Core Architecture

The library centers on a **Pipe** concept (`pipe/`) enabling bidirectional message flow:
- **L (Left) side**: One BGP peer in the session
- **R (Right) side**: The other BGP peer in the session
- **Messages** (`msg/`) flow through callback chains that can inspect, modify, drop, or synthesize BGP messages
- **Events** provide lifecycle notifications and custom processing hooks

The L/R abstraction allows flexible deployment - either peer could be a router, local BGP speaker, proxy, or any BGP-speaking process.

Key performance-critical components:
- `msg/` - Zero-allocation BGP message parsing and JSON serialization
- `pipe/` - Lock-free message processing pipeline with callback system
- `speaker/` - Efficient BGP speaker implementation for session management
- `attrs/` - Fast BGP path attribute parsing (communities, flowspec, extended communities)
- `filter/` - High-speed message filtering (prefix, AS path, community matching)
- `binary/` - Optimized binary data handling utilities
- `mrt/` - Streaming MRT file format support

### Real-World Usage via bgpipe

BGPFix powers **bgpipe**, demonstrating scalable BGP processing:

**Transparent Proxy Architecture**:
```bash
bgpipe -- connect peer1 -- [processing stages] -- connect peer2
```

**High-Performance Patterns**:
- **Mass BGP Proxy**: Handle thousands of BGP sessions simultaneously
- **Real-time Filtering**: Drop/modify messages at line rate
- **Prefix Flood Protection**: Detect and mitigate BGP prefix flooding attacks
- **Route Validation**: Real-time RPKI and policy validation
- **Session Multiplexing**: Aggregate multiple sessions efficiently

## Key Performance Patterns

### Lock-Free Message Processing
Messages flow through callbacks registered via `pipe.OnMsg()`:
- **Non-blocking**: Callbacks execute without global locks
- **Return semantics**: `true` continues, `false` drops message
- **In-place modification**: Modify messages without copying
- **Batch processing**: Handle message bursts efficiently

### Event-Driven Architecture
Lightweight event system via `pipe.OnEvent()`:
- `EVENT_ESTABLISHED` - Session ready for processing
- `EVENT_DOWN` - Session cleanup
- Custom events for application-specific processing

### Zero-Copy JSON Serialization
Optimized JSON handling for high-throughput scenarios:
```go
jsonData := msg.GetJSON()     // Minimal allocation JSON serialization
msg.FromJSON(jsonData)        // Fast JSON parsing with validation
```

### High-Performance Filtering
The `filter/` package provides line-rate BGP filtering:
- **Compiled filters**: Pre-compiled filter expressions for speed
- **Batch evaluation**: Process multiple messages per filter invocation
- **Memory pooling**: Reuse filter evaluation contexts

## Code Style Philosophy

BGPFix embraces the engineering principles of systems that **work correctly and efficiently**:

### Simplicity and Clarity
- **Do one thing well**: Each package has a clear, focused responsibility
- **Minimal abstraction**: Direct, readable code over clever indirection
- **Self-documenting**: Code structure and naming convey intent
- **Fail fast**: Clear error handling and validation at boundaries

### Performance Through Design
- **Measure, don't guess**: Benchmark-driven optimizations
- **Zero-cost abstractions**: High-level interfaces with no runtime overhead
- **Resource ownership**: Clear lifetime management without leaks
- **Predictable behavior**: Avoid surprising allocations or blocking operations

### Robustness and Reliability
- **Defensive programming**: Validate inputs, handle edge cases gracefully
- **Composable components**: Small, testable units that combine predictably
- **Protocol correctness**: Strict adherence to BGP RFCs and standards
- **Graceful degradation**: Continue operating under adverse conditions

### Engineering Discipline
- **Tests as specification**: Comprehensive test coverage defining expected behavior
- **Documentation in code**: Comments explain why, not what
- **Consistent conventions**: Uniform naming, structure, and patterns throughout
- **Minimal dependencies**: Each dependency justified by clear benefit

This approach follows the tradition of network engineering tools that prioritize **correctness, performance, and maintainability** over complexity.

## Dependencies

Minimal, performance-focused dependencies:
- `github.com/buger/jsonparser` - Fast JSON parsing without reflection
- `github.com/puzpuzpuz/xsync/v4` - Lock-free concurrent data structures
- `github.com/rs/zerolog` - Zero-allocation structured logging
- `github.com/stretchr/testify` - Testing framework (dev only)