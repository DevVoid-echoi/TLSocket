.PHONY: test lint type cov cov-gate all

test: ## Chạy toàn bộ test (unit + integration)
	pytest -q

lint: ## Kiểm tra style/lint
	ruff check .

type: ## Kiểm tra type - chỉ scope vào các module đã typing đầy đủ
	mypy src/tlsocket/auth src/tlsocket/security src/tlsocket/log_parser src/tlsocket/protocol.py

cov: ## Coverage toàn bộ package - báo cáo, không gate
	pytest --cov --cov-report=term-missing --cov-report=xml

cov-gate: ## Coverage bắt buộc >=80% cho auth/security/log_parser (không tính main.py CLI)
	pytest tests/unit \
		--cov=tlsocket.auth --cov=tlsocket.security \
		--cov=tlsocket.log_parser.parser --cov=tlsocket.log_parser.analyzer --cov=tlsocket.log_parser.models \
		--cov-report=term-missing --cov-fail-under=80

all: lint type test
