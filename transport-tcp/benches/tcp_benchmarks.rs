//! TCP transport benchmarks for throughput and latency.

use clonic_transport_tcp::TcpTransport;
use clonic_transport::config::TcpConfig;
use clonic_transport::Transport;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

/// Benchmark TCP transport throughput.
fn benchmark_throughput() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40125,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40125")).unwrap();

    // Spawn echo server
    rt.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let _ = socket.write_all(&buf[..n]).await;
                }
                Err(_) => break,
            }
        }
    });

    let mut client = TcpTransport::new(cfg);
    client.connect().unwrap();

    // Create test frame (42-byte header + 1KB payload)
    let mut frame = vec![0u8; 42 + 1024];
    let frame_len = frame.len() as u16;
    frame[0] = (frame_len >> 8) as u8;
    frame[1] = frame_len as u8;

    // Benchmark: send 1000 frames
    let start = Instant::now();
    let iterations = 1000;

    for _ in 0..iterations {
        client.send(&frame).unwrap();
        let mut buf = [0u8; 2048];
        let _ = client.recv(&mut buf).unwrap();
    }

    let elapsed = start.elapsed();
    let throughput_mbps = (frame.len() as f64 * iterations as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    let latency_us = elapsed.as_micros() as f64 / iterations as f64;

    println!("Throughput Benchmark Results:");
    println!("  Iterations: {}", iterations);
    println!("  Frame size: {} bytes", frame.len());
    println!("  Total time: {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    println!("  Throughput: {:.2} Mbps", throughput_mbps);
    println!("  Avg latency: {:.2} µs", latency_us);
}

/// Benchmark TCP transport latency.
fn benchmark_latency() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40126,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40126")).unwrap();

    // Spawn echo server
    rt.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let _ = socket.write_all(&buf[..n]).await;
                }
                Err(_) => break,
            }
        }
    });

    let mut client = TcpTransport::new(cfg);
    client.connect().unwrap();

    // Create small test frame (42-byte header + 64 bytes payload)
    let mut frame = vec![0u8; 42 + 64];
    let frame_len = frame.len() as u16;
    frame[0] = (frame_len >> 8) as u8;
    frame[1] = frame_len as u8;

    // Benchmark: measure latency for 100 roundtrips
    let iterations = 100;
    let mut latencies = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        client.send(&frame).unwrap();
        let mut buf = [0u8; 256];
        let _ = client.recv(&mut buf).unwrap();
        latencies.push(start.elapsed().as_micros() as f64);
    }

    let min_latency = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
    let max_latency = latencies.iter().cloned().fold(0.0, f64::max);
    let avg_latency = latencies.iter().sum::<f64>() / latencies.len() as f64;

    println!("Latency Benchmark Results:");
    println!("  Iterations: {}", iterations);
    println!("  Frame size: {} bytes", frame.len());
    println!("  Min latency: {:.2} µs", min_latency);
    println!("  Max latency: {:.2} µs", max_latency);
    println!("  Avg latency: {:.2} µs", avg_latency);
}

/// Benchmark TCP transport with various frame sizes.
fn benchmark_frame_sizes() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40127,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40127")).unwrap();

    // Spawn echo server
    rt.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let _ = socket.write_all(&buf[..n]).await;
                }
                Err(_) => break,
            }
        }
    });

    let mut client = TcpTransport::new(cfg);
    client.connect().unwrap();

    println!("Frame Size Benchmark Results:");
    println!("{:<15} {:<15} {:<15}", "Frame Size", "Throughput", "Latency");
    println!("{:-<45}", "");

    for payload_size in [64, 256, 1024, 4096, 16384].iter() {
        let mut frame = vec![0u8; 42 + payload_size];
        let frame_len = frame.len() as u16;
        frame[0] = (frame_len >> 8) as u8;
        frame[1] = frame_len as u8;

        let iterations = 100;
        let start = Instant::now();

        for _ in 0..iterations {
            client.send(&frame).unwrap();
            let mut buf = vec![0u8; frame.len() + 256];
            let _ = client.recv(&mut buf).unwrap();
        }

        let elapsed = start.elapsed();
        let throughput_mbps = (frame.len() as f64 * iterations as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
        let latency_us = elapsed.as_micros() as f64 / iterations as f64;

        println!("{:<15} {:<15.2} {:<15.2}", format!("{} B", frame.len()), format!("{:.2} Mbps", throughput_mbps), format!("{:.2} µs", latency_us));
    }
}

fn main() {
    println!("=== TCP Transport Benchmarks ===\n");
    benchmark_throughput();
    println!();
    benchmark_latency();
    println!();
    benchmark_frame_sizes();
}
