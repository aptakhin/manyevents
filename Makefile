run::
	(cd manyevents && cargo run)

runw::
	(cd manyevents && RUST_LOG=debug RUST_BACKTRACE=1 cargo watch -- cargo run)

test::
	(cd manyevents && cargo test)

testw::
	(cd manyevents && RUST_LOG=debug RUST_BACKTRACE=1 cargo watch --clear -- cargo test)

build::
	(cd manyevents && cargo build --locked)

build-release::
	(cd manyevents && cargo build --release --locked)

fmt::
	(cd manyevents && cargo fmt --all)

fix::
	(cd manyevents && cargo fix)

migrate::
	(cd manyevents && cargo run -- migrate)
