run::
	(cd manyevents && cargo run)

test::
	(cd manyevents && cargo test)

testw::
	(cd manyevents && RUST_LOG=debug RUST_BACKTRACE=1 cargo watch -x test)

fmt::
	(cd manyevents && cargo fmt)
