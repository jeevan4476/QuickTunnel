use bytes::{Bytes, BytesMut};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use qt_proto::frame::{Frame, FrameType, Header};
use qt_proto::util::FrameAssembler;

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encode");

    for size in [64, 1024, 16384] {
        let payload = Bytes::from(vec![0x42u8; size]);
        let frame = Frame::data(1, payload, false).expect("valid frame");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("data_{size}_bytes"), |b| {
            b.iter(|| {
                let mut buf = BytesMut::with_capacity(size + 12);
                black_box(&frame).encode(&mut buf);
                black_box(buf);
            })
        });
    }

    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decode");

    for size in [64, 1024, 16384] {
        let payload = Bytes::from(vec![0x42u8; size]);
        let frame = Frame::data(1, payload, false).expect("valid frame");
        let mut encoded = BytesMut::new();
        frame.encode(&mut encoded);

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("data_{size}_bytes"), |b| {
            b.iter(|| {
                let mut assembler = FrameAssembler::new(65536);
                let decoded = assembler.feed(black_box(&encoded)).unwrap();
                black_box(decoded);
            })
        });
    }

    group.finish();
}

fn bench_header_parse(c: &mut Criterion) {
    let header = Header {
        ty: FrameType::Data,
        flags: 0,
        stream_id: 1,
        len: 16384,
    };
    let mut buf = [0u8; 12];
    header.encode(&mut buf);

    c.bench_function("header_decode_12_bytes", |b| {
        b.iter(|| {
            let parsed = Header::decode(black_box(&buf), 65536).unwrap();
            black_box(parsed);
        })
    });
}

criterion_group!(
    benches,
    bench_frame_encode,
    bench_frame_decode,
    bench_header_parse
);
criterion_main!(benches);
