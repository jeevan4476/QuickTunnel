use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qt_mux::flow::SendWindow;
use tokio::runtime::Runtime;

fn bench_flow_control_credit_accounting(c: &mut Criterion) {
    c.bench_function("stream_flow_control_consume_and_replenish", |b| {
        let sw = SendWindow::new(262144);
        b.iter(|| {
            let acquired = sw.try_acquire(black_box(16384));
            sw.grant(black_box(acquired)).unwrap();
            black_box(&sw);
        })
    });
}

fn bench_in_memory_mux_transfer(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("mux_transfer_64k_stream", |b| {
        b.to_async(&rt).iter(|| async {
            let (client_io, server_io) = tokio::io::duplex(65536);
            let (server_session, _server_handle) =
                qt_mux::MuxSession::new(server_io, qt_mux::MuxConfig::server());
            let (client_session, client_handle) =
                qt_mux::MuxSession::new(client_io, qt_mux::MuxConfig::client());

            let s_task = tokio::spawn(async move { server_session.run().await });
            let c_task = tokio::spawn(async move { client_session.run().await });

            let mut stream = client_handle.open_stream().await.unwrap();
            let payload = vec![0xAA; 16384];
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();

            drop(stream);
            drop(client_handle);

            s_task.abort();
            c_task.abort();
        });
    });
}

criterion_group!(
    benches,
    bench_flow_control_credit_accounting,
    bench_in_memory_mux_transfer
);
criterion_main!(benches);
