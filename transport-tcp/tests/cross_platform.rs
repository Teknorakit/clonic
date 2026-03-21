//! Cross-platform TCP transport tests for Linux, macOS, and Windows.

use clonic_transport_tcp::TcpTransport;
use clonic_transport::config::TcpConfig;
use clonic_transport::Transport;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

/// Test TCP transport on localhost (works on all platforms).
#[test]
fn test_tcp_localhost_connection() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40200,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40200")).unwrap();

    rt.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    let mut client = TcpTransport::new(cfg);
    assert!(client.connect().is_ok());

    let mut frame = vec![0u8; 42 + 10];
    let frame_len = frame.len() as u16;
    frame[0] = (frame_len >> 8) as u8;
    frame[1] = frame_len as u8;

    assert!(client.send(&frame).is_ok());
    let mut buf = [0u8; 256];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], &frame[..]);
    assert!(client.disconnect().is_ok());
}

/// Test TCP transport with IPv4 loopback.
#[test]
fn test_tcp_ipv4_loopback() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40201,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40201")).unwrap();

    rt.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        socket.write_all(&buf[..n]).await.unwrap();
    });

    let mut client = TcpTransport::new(cfg);
    client.connect().unwrap();

    let mut frame = vec![0u8; 42 + 20];
    let frame_len = frame.len() as u16;
    frame[0] = (frame_len >> 8) as u8;
    frame[1] = frame_len as u8;

    client.send(&frame).unwrap();
    let mut buf = [0u8; 256];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(n, frame.len());
}

/// Test TCP transport with multiple connections.
#[test]
fn test_tcp_multiple_connections() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40202,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40202")).unwrap();

    rt.spawn(async move {
        for _ in 0..3 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });

    for i in 0..3 {
        let mut client = TcpTransport::new(cfg.clone());
        client.connect().unwrap();

        let mut frame = vec![0u8; 42 + 10 + i];
        let frame_len = frame.len() as u16;
        frame[0] = (frame_len >> 8) as u8;
        frame[1] = frame_len as u8;

        client.send(&frame).unwrap();
        let mut buf = [0u8; 256];
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(n, frame.len());
        client.disconnect().unwrap();
    }
}

/// Test TCP transport with various frame sizes.
#[test]
fn test_tcp_various_frame_sizes() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40203,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40203")).unwrap();

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

    for payload_size in [64, 256, 1024, 4096].iter() {
        let mut frame = vec![0u8; 42 + payload_size];
        let frame_len = frame.len() as u16;
        frame[0] = (frame_len >> 8) as u8;
        frame[1] = frame_len as u8;

        client.send(&frame).unwrap();
        let mut buf = vec![0u8; frame.len() + 256];
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(n, frame.len());
    }

    client.disconnect().unwrap();
}

/// Test TCP transport disconnect and reconnect.
#[test]
fn test_tcp_disconnect_reconnect() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40204,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40204")).unwrap();

    rt.spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });

    let mut client = TcpTransport::new(cfg);

    // First connection
    client.connect().unwrap();
    let mut frame = vec![0u8; 42 + 10];
    let frame_len = frame.len() as u16;
    frame[0] = (frame_len >> 8) as u8;
    frame[1] = frame_len as u8;
    client.send(&frame).unwrap();
    let mut buf = [0u8; 256];
    let _ = client.recv(&mut buf).unwrap();
    client.disconnect().unwrap();

    // Reconnect
    client.connect().unwrap();
    client.send(&frame).unwrap();
    let _ = client.recv(&mut buf).unwrap();
    client.disconnect().unwrap();
}

/// Test TCP transport with rapid send/recv cycles.
#[test]
fn test_tcp_rapid_cycles() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40205,
    };

    let rt = Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:40205")).unwrap();

    rt.spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 1024];
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

    let mut frame = vec![0u8; 42 + 50];
    let frame_len = frame.len() as u16;
    frame[0] = (frame_len >> 8) as u8;
    frame[1] = frame_len as u8;

    // Perform 50 rapid cycles
    for _ in 0..50 {
        client.send(&frame).unwrap();
        let mut buf = [0u8; 256];
        let n = client.recv(&mut buf).unwrap();
        assert_eq!(n, frame.len());
    }

    client.disconnect().unwrap();
}

/// Test TCP transport connection error handling.
#[test]
fn test_tcp_connection_refused() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40999, // Port with no listener
    };

    let mut client = TcpTransport::new(cfg);
    let result = client.connect();
    assert!(result.is_err());
}

/// Test TCP transport send without connection.
#[test]
fn test_tcp_send_without_connection() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40206,
    };

    let mut client = TcpTransport::new(cfg);
    let frame = vec![0u8; 42];
    let result = client.send(&frame);
    assert!(result.is_err());
}

/// Test TCP transport recv without connection.
#[test]
fn test_tcp_recv_without_connection() {
    let cfg = TcpConfig {
        host: "127.0.0.1".into(),
        port: 40207,
    };

    let mut client = TcpTransport::new(cfg);
    let mut buf = [0u8; 256];
    let result = client.recv(&mut buf);
    assert!(result.is_err());
}
