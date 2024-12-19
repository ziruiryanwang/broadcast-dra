use broadcast_dra::{
    AuditedNonMalleableCommitment, BulletproofsCommitment, CommitmentScheme,
    NonMalleableShaCommitment, PedersenRistrettoCommitment, RealNonMalleableCommitment,
};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn bench_fischlin_commit(c: &mut Criterion) {
    let scheme = RealNonMalleableCommitment;
    c.bench_function("fischlin_commit", |b| {
        let mut rng = StdRng::seed_from_u64(42);
        b.iter(|| {
            let (commit, opening) = scheme.commit(12.0, &mut rng);
            criterion::black_box((commit, opening));
        });
    });
}

fn bench_fischlin_verify(c: &mut Criterion) {
    let scheme = RealNonMalleableCommitment;
    let mut rng = StdRng::seed_from_u64(7);
    let (commitment, opening) = scheme.commit(17.0, &mut rng);
    c.bench_function("fischlin_verify", |b| {
        b.iter(|| {
            assert!(scheme.verify(&commitment, &opening));
        });
    });
}

fn bench_bulletproofs_commit(c: &mut Criterion) {
    let scheme = BulletproofsCommitment::default();
    c.bench_function("bulletproofs_commit", |b| {
        let mut rng = StdRng::seed_from_u64(77);
        b.iter(|| {
            let (commit, opening) = scheme.commit(11.0, &mut rng);
            criterion::black_box((commit, opening));
        });
    });
}

fn bench_bulletproofs_verify(c: &mut Criterion) {
    let scheme = BulletproofsCommitment::default();
    let mut rng = StdRng::seed_from_u64(101);
    let (commitment, opening) = scheme.commit(9.0, &mut rng);
    c.bench_function("bulletproofs_verify", |b| {
        b.iter(|| {
            assert!(scheme.verify(&commitment, &opening));
        });
    });
}

fn bench_other_backends(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(99);
    let sha = NonMalleableShaCommitment;
    let pedersen = PedersenRistrettoCommitment;
    let audited = AuditedNonMalleableCommitment::default();
    c.bench_function("sha_commit", |b| {
        b.iter(|| {
            let (commit, opening) = sha.commit(5.0, &mut rng);
            criterion::black_box((commit, opening));
        });
    });
    c.bench_function("pedersen_commit", |b| {
        b.iter(|| {
            let (commit, opening) = pedersen.commit(5.0, &mut rng);
            criterion::black_box((commit, opening));
        });
    });
    c.bench_function("audited_commit", |b| {
        let mut local_rng = StdRng::seed_from_u64(55);
        b.iter(|| {
            let (commit, opening) = audited.commit(5.0, &mut local_rng);
            criterion::black_box((commit, opening));
        });
    });
}

criterion_group!(
    commitment_benches,
    bench_fischlin_commit,
    bench_fischlin_verify,
    bench_bulletproofs_commit,
    bench_bulletproofs_verify,
    bench_other_backends
);
criterion_main!(commitment_benches);
