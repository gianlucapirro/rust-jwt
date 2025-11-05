# ────────────────────────────────────────────────
# Developer commands for the Rust + Diesel API
# ────────────────────────────────────────────────

# Start docker-compose (detached)
up:
    docker compose up -d

# Stop and remove containers
down:
    docker compose down

# Show project tree, excluding junk files & folders
tree:
    tree -I "target|.git|.env|node_modules|__pycache__|*.pyc|*.DS_Store"

# Run app
run:
    cargo run

# Clean build artifacts
clean:
    cargo clean

# Build release
build:
    cargo build --release

watch:
    cargo watch -c -w src -x run