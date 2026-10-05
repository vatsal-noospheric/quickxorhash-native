#[macro_use]
extern crate bencher;
use quickxorhash_native::*;

use bencher::Bencher;
use std::hint::black_box;

fn bench_small(bench: &mut Bencher) {
    const N: usize = 1024;
    let bytes: [u8; N] = core::array::from_fn(|i| (i * 7) as u8);
    bench.iter(|| {
        let mut qx = QuickXorHash::new();
        qx.update(black_box(&bytes));
        black_box(black_box(&qx).finalise());
    });
    bench.bytes = N as u64;
}

fn bench_large(bench: &mut Bencher) {
    const N: usize = 1024 * 1024;
    let bytes: [u8; N] = core::array::from_fn(|i| (i * 7) as u8);
    bench.iter(|| {
        let mut qx = QuickXorHash::new();
        qx.update(black_box(&bytes));
        black_box(black_box(&qx).finalise());
    });
    bench.bytes = N as u64;
}

/// Test the worst case scenario in terms of optimization.
fn bench_unaligned(bench: &mut Bencher) {
    const N: usize = 1024 * 1024;
    let bytes: [u8; N] = core::array::from_fn(|i| (i * 7) as u8);
    bench.iter(|| {
        let mut qx = QuickXorHash::new();
        for block in bytes[..].chunks(BLOCK_SIZE - 1) {
            qx.update(black_box(block));
        }
        black_box(black_box(&qx).finalise());
    });
    bench.bytes = N as u64;
}

fn bench_finalize(bench: &mut Bencher) {
    let qx = QuickXorHash::new();
    bench.iter(|| {
        black_box(black_box(&qx).finalise());
    });
}

fn bench_combined(bench: &mut Bencher) {
    let bytes = vec![0x5a; 5 * 1024 * 1024];
    bench.iter(|| {
        let mut accumulator = FileHashAccumulator::new();
        accumulator.update(black_box(&bytes));
        black_box(accumulator.finalise());
    });
    bench.bytes = bytes.len() as u64;
}

fn bench_checkpoint(bench: &mut Bencher) {
    let mut accumulator = FileHashAccumulator::new();
    accumulator.update(&vec![0x5a; 5 * 1024 * 1024 + 159]);
    bench.iter(|| {
        let snapshot = black_box(black_box(&accumulator).snapshot());
        let restored = FileHashAccumulator::restore(black_box(&snapshot)).unwrap();
        black_box(restored.finalise());
    });
}

benchmark_group!(
    benches,
    bench_small,
    bench_large,
    bench_unaligned,
    bench_finalize,
    bench_combined,
    bench_checkpoint
);
benchmark_main!(benches);
