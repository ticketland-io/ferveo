use criterion::criterion_main;

pub mod arkworks;
pub mod tpke;

criterion_main!(arkworks::benches, tpke::benches,);
