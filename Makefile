# Security Testbed - Enhanced Makefile
# Provides comprehensive development and management commands


# Simplified, user-friendly Makefile for Security Testbed
SHELL := /bin/bash
.DEFAULT_GOAL := help

PROJECT_NAME := sec-testbed
VERSION := 1.0
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)
ENV_FILE := .env
ENV_EXAMPLE := .env.example

.PHONY: help init start stop restart status logs clean reset backup update \
		attack attack-interactive attack-automated generate-dataset analyze-traffic show-analysis \
		advanced

##@ Main
help: ## Show this help menu
	@awk 'BEGIN {FS = ":.*##"; print "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

start: init ## Start the security testbed
	@./start_testbed.sh

stop: ## Stop all containers
	@docker compose down

restart: stop start ## Restart the testbed

status: ## Show testbed status
	@./utils/status.sh

logs: ## Show logs for all services
	@docker compose logs -f

clean: ## Clean up containers, networks, and volumes
	@docker compose down --volumes --remove-orphans
	@docker system prune -f

reset: clean ## Reset everything and start fresh
	@rm -rf data/captures/* data/analysis/* data/*_logs/*
	@docker compose down --volumes --remove-orphans
	@docker system prune -a
	@utils/cleanup.sh 0 --force || true

backup: ## Create backup of important data
	@mkdir -p backups
	@tar -czf backups/testbed-backup-$(TIMESTAMP).tar.gz data/ config/ .env docker-compose.yaml

##@ Attacks
attack-interactive: ## Run interactive attack menu
	@docker compose exec -it attacker /attack_scenarios/attack_tools.sh --interactive

attack-automated: ## Run all attacks automatically
	@docker compose exec attacker /attack_scenarios/attack_tools.sh --automated

##@ Data
generate-dataset: ## Generate dataset from captured traffic
	@docker compose exec monitor python3 /scripts/dataset_generator.py

analyze-traffic: ## Analyze captured network traffic
	@docker compose exec monitor python3 /scripts/dataset_generator.py --correlate-attacks

show-analysis: ## Show latest analysis results
	@if [ -d "data/analysis" ]; then \
		ls -la data/analysis/ | tail -10; \
	else \
		echo "No analysis results found. Run 'make generate-dataset' first."; \
	fi
