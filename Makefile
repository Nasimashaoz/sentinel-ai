.PHONY: install run test lint docker-up docker-down report clean

install:
	pip install -r requirements.txt

run:
	python sentinel.py

dashboard:
	python dashboard/app.py

test:
	python tests/test_scorer.py
	python tests/test_compliance.py
	python tests/test_report.py
	lint:
	python -m py_compile sentinel.py core/*.py alerts/*.py dashboard/app.py reports/generator.py
	@echo "✅ Syntax OK"

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f sentinel

report:
	python -c "from reports.generator import ReportGenerator; g=ReportGenerator(); p=g.save_html_report(); print(f'Report saved: {p}')"

clean:
	find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null; true
	find . -name '*.pyc' -delete 2>/dev/null; true

help:
	@echo ""
	@echo "🛡️  Sentinel AI — Available Commands"
	@echo ""
	@echo "  make install      Install Python dependencies"
	@echo "  make run          Start the security agent"
	@echo "  make dashboard    Start the web dashboard (localhost:8080)"
	@echo "  make test         Run all unit tests"
	@echo "  make lint         Syntax-check all Python files"
	@echo "  make docker-up    Launch via Docker Compose"
	@echo "  make docker-down  Stop Docker containers"
	@echo "  make report       Generate a 7-day HTML audit report"
	@echo "  make clean        Remove __pycache__ files"
	@echo ""
