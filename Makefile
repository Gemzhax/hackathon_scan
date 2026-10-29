# Palmerah RedCheck — Makefile
# Windows (PowerShell) primary; bash targets included for WSL/Linux.

.PHONY: all install redcheck-vuln redcheck-hardened compare test record reset help

PYTHON ?= python
PYTEST ?= pytest
OUT    := out

help:
	@echo "Palmerah RedCheck — harness validasi pertahanan"
	@echo ""
	@echo "  make install           Install deps (pip install -e .)"
	@echo "  make redcheck-vuln     Jalankan semua check vs target MODE=vuln"
	@echo "  make redcheck-hardened Jalankan semua check vs target MODE=hardened"
	@echo "  make compare           Bangun out/compare.html dari dua JSON terakhir"
	@echo "  make all               vuln + hardened + compare"
	@echo "  make test              pytest offline (fixtures, no Docker)"
	@echo "  make record            Rekam sesi demo ke record/redcheck.log"
	@echo "  make reset             Petunjuk reset target (perlu Docker)"
	@echo ""

install:
	$(PYTHON) -m pip install -e ".[dev]" 2>nul || $(PYTHON) -m pip install -e .

redcheck-vuln:
	$(PYTHON) -m redcheck.runner --mode vuln

redcheck-hardened:
	$(PYTHON) -m redcheck.runner --mode hardened

compare:
	$(PYTHON) -m redcheck.report --vuln $(OUT)/redcheck_vuln.json --hardened $(OUT)/redcheck_hardened.json --out $(OUT)/compare.html
	@echo "compare.html written — open in browser."

all: redcheck-vuln redcheck-hardened compare

test:
	$(PYTEST) -v

record:
	powershell -ExecutionPolicy Bypass -File record/record.ps1

reset:
	@echo "Reset target: cd dprdemoweb && make reset"
	@echo "(Requires Docker Desktop)"
