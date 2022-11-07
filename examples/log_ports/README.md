# Port Logger

Log ports used in connection to a file.

### Build and run
```
cargo build --release --bin log_ports
sudo env LD_LIBRARY_PATH=$LD_LIBRARY_PATH RUST_LOG=error ./target/release/log_ports -c <path/to/config.toml>
```
