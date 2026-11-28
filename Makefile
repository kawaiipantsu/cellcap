# cellcap: build, install and service helpers.

PREFIX  ?= /usr/local
BIN     := cellcap
SERVICE := cellcap.service
STATE   := /var/lib/cellcap

.PHONY: help build release test check decoder e212-data install uninstall start stop status logs

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-z-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Debug build
	cargo build --locked

release: ## Optimised build
	cargo build --locked --release

test: ## Unit tests (no SDR needed)
	cargo test --locked

check: ## Formatting, lints and tests
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked

decoder: ## Generate the patched decoder from grgsm_decode (needed for 'decode')
	@command -v grgsm_decode >/dev/null || { echo "grgsm_decode not found: apt install gr-gsm"; exit 1; }
	python3 tools/gen-decoder.py $(PREFIX)/bin/cellcap-decode

e212-data: ## Refresh the operator table from mcc-mnc.org (downloads networks.csv)
	@csv=$$(mktemp) && \
	  curl -fsSL -A cellcap -o $$csv https://mcc-mnc.org/downloads/networks.csv && \
	  python3 tools/gen-e212.py $$csv src/e212_generated.rs && \
	  rm -f $$csv && \
	  echo "regenerated src/e212_generated.rs; rebuild to pick it up"

install: ## Install the binary, decoder, service and user (run as root, after 'make release')
	@[ -f target/release/$(BIN) ] || { echo "target/release/$(BIN) not found: run 'make release' first"; exit 1; }
	@command -v grgsm_livemon_headless >/dev/null || echo "warning: gr-gsm is not installed (Debian: apt install gr-gsm)"
	install -D -m 0755 target/release/$(BIN) $(PREFIX)/bin/$(BIN)
	@command -v grgsm_decode >/dev/null && python3 tools/gen-decoder.py $(PREFIX)/bin/cellcap-decode || echo "warning: grgsm_decode not found; 'cellcap decode' will be unavailable until you run 'make decoder'"
	install -D -m 0644 README.md $(PREFIX)/share/doc/$(BIN)/README.md
	install -D -m 0644 systemd/$(SERVICE) /etc/systemd/system/$(SERVICE)
	@[ -f /etc/default/$(BIN) ] || install -D -m 0644 systemd/cellcap.default /etc/default/$(BIN)
	@getent passwd $(BIN) >/dev/null || useradd --system --home-dir $(STATE) --no-create-home --shell /usr/sbin/nologin --groups plugdev $(BIN)
	systemctl daemon-reload
	@echo "installed. Edit /etc/default/$(BIN), then: systemctl enable --now $(SERVICE)"

uninstall: ## Remove the binary and the service; keeps captures, settings and the user
	-systemctl disable --now $(SERVICE)
	rm -f /etc/systemd/system/$(SERVICE) $(PREFIX)/bin/$(BIN) $(PREFIX)/bin/cellcap-decode $(PREFIX)/share/doc/$(BIN)/README.md
	systemctl daemon-reload
	@echo "kept: $(STATE), /etc/default/$(BIN) and the '$(BIN)' user"

start: ## Start the service
	systemctl start $(SERVICE)

stop: ## Stop the service
	systemctl stop $(SERVICE)

status: ## Service status
	systemctl status $(SERVICE) --no-pager

logs: ## Follow the service log
	journalctl -u $(SERVICE) -f
