# dorm-ip helper targets. `make` shows the list.
UV     ?= uv
EDIT   := $${VISUAL:-$${EDITOR:-nano}}

.DEFAULT_GOAL := help
.PHONY: help init setup check-uv deps sync edit-config edit-credentials arp-cap test info scan hunt watch history login

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  make %-18s %s\n", $$1, $$2}'
	@echo "  make info|scan|hunt|watch|history|login   shortcuts for dorm-ip <command>"

init: check-uv deps sync ## First-time setup: dependencies + the guided setup (dorm-ip init)
	$(UV) run dorm-ip init

setup: init ## Alias for init

check-uv:
	@command -v $(UV) >/dev/null 2>&1 || { echo "uv is not installed. Arch: sudo pacman -S uv  |  others: https://docs.astral.sh/uv/"; exit 1; }

deps: ## Install arp-scan if it is missing (Arch: pacman)
	@if command -v arp-scan >/dev/null 2>&1; then echo "arp-scan: found"; \
	elif command -v pacman >/dev/null 2>&1; then echo "arp-scan is missing, installing it (sudo)..."; sudo pacman -S --needed arp-scan; \
	else echo "arp-scan is missing: install it with your package manager."; exit 1; fi

sync: ## Install the Python dependencies (uv sync)
	$(UV) sync

edit-config: ## Open config.toml in your editor ($$VISUAL / $$EDITOR)
	@f="$$($(UV) run --quiet dorm-ip path config)"; \
	[ -f "$$f" ] || { echo "No config yet: run 'make init' first."; exit 1; }; \
	$(EDIT) "$$f"

edit-credentials: ## Open credentials.toml in your editor (created with chmod 600 if missing)
	@f="$$($(UV) run --quiet dorm-ip path credentials)"; \
	mkdir -p "$$(dirname "$$f")"; \
	[ -f "$$f" ] || (umask 077; printf 'username = ""\npassword = ""\n' > "$$f"); \
	chmod 600 "$$f"; $(EDIT) "$$f"; chmod 600 "$$f"

arp-cap: ## Let arp-scan run without sudo (setcap, asks for sudo once)
	sudo setcap cap_net_raw,cap_net_admin=eip "$$(command -v arp-scan)"

test: ## Run the unit tests
	$(UV) run pytest -q

info scan hunt watch history login:
	$(UV) run dorm-ip $@