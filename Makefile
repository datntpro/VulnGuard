# ─────────────────────────────────────────────
# VulnGuard — Makefile shortcuts
# ─────────────────────────────────────────────

.PHONY: help up down build logs scan pull-model clean pentest-images pentest-host-ips

help:
	@echo ""
	@echo "  VulnGuard — DevSecOps Scanner"
	@echo "  ──────────────────────────────────────────"
	@echo "  make up              Khởi động VulnGuard (build lần đầu)"
	@echo "  make down            Tắt tất cả services"
	@echo "  make build           Build lại Docker image"
	@echo "  make logs            Xem logs real-time"
	@echo "  make check-docker    Kiểm tra Docker socket path"
	@echo "  make scan ...        Scan qua CLI (xem ví dụ bên dưới)"
	@echo "  make clean           Xóa containers và volumes"
	@echo ""
	@echo "  Sau khi 'make up': mở http://localhost:8080 → Settings → Pull model"
	@echo ""
	@echo "  Ví dụ scan qua CLI:"
	@echo "  make scan PATH_TARGET=/Users/me/myapp PROJECT=MyApp STACKS=java,terraform"
	@echo ""

up:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "📄 Tạo .env từ .env.example"; \
	fi
	@echo "🔍 Kiểm tra Ollama..."
	@$(MAKE) --no-print-directory check-ollama
	@echo "🐳 Kiểm tra Docker socket..."
	@$(MAKE) --no-print-directory check-docker
	docker compose up -d --build
	@echo ""
	@echo "✅ VulnGuard đang chạy!"
	@echo "   Web UI : http://localhost:$$(grep '^VULNGUARD_PORT' .env 2>/dev/null | cut -d= -f2 || echo 8080)"
	@echo "   API docs: http://localhost:$$(grep '^VULNGUARD_PORT' .env 2>/dev/null | cut -d= -f2 || echo 8080)/docs"

check-ollama:
	@if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then \
		echo "✅ Ollama đang chạy tại localhost:11434"; \
	else \
		echo "⚠️  Ollama chưa chạy — hãy chạy: ollama serve"; \
		echo "   (VulnGuard vẫn khởi động được, nhưng AI analysis sẽ không hoạt động)"; \
	fi

check-docker:
	@if [ -S /var/run/docker.sock ]; then \
		echo "✅ Docker socket: /var/run/docker.sock"; \
	elif [ -S "$$HOME/.docker/run/docker.sock" ]; then \
		echo "⚠️  Dùng socket tại: $$HOME/.docker/run/docker.sock"; \
		echo "   → Thêm vào .env: DOCKER_SOCK=$$HOME/.docker/run/docker.sock"; \
	else \
		echo "⚠️  Không tìm thấy Docker socket — container scan sẽ không hoạt động"; \
	fi

down:
	docker compose down

build:
	docker compose build --no-cache vulnguard

logs:
	docker compose logs -f vulnguard

scan:
	@if [ -z "$(PATH_TARGET)" ]; then \
		echo "Usage: make scan PATH_TARGET=/path/to/code PROJECT=my-project [STACKS=java,terraform]"; \
		exit 1; \
	fi
	SCAN_WORKSPACE=$(PATH_TARGET) docker compose run --rm vulnguard python -m scanner.cli scan \
		--path /workspace \
		--project "$(PROJECT)" \
		--stacks "$(STACKS)"

clean:
	docker compose down -v
	@echo "Cleaned up all containers and volumes"

# P2-1/P2-3: image sandbox (docker/pentest-runner/) + gateway egress (docker/pentest-egress/) cho Pentest Agent
pentest-images:
	./scripts/build_pentest_images.sh --self-test

# P2-5: in IP host (csv /32) cho PENTEST_EGRESS_EXTRA_DENY — bắt buộc trên Docker Desktop khi scope mở dải riêng (xem docs/PENTEST_RUNNER.md)
pentest-host-ips:
	@./scripts/pentest_host_ips.sh
