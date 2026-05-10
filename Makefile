.PHONY: test guard-dashboard guard-smoke guard-e2e vomcbench-report vomcbench-generate vomcbench-run vomcbench-validate vomcbench-inspect vomcbench-compare

VOMCBENCH_DIR ?= bench-results
VOMCBENCH_KIND ?= variable-order
VOMCBENCH_SEED ?= 42
VOMCBENCH_ALPHABET ?= 64
VOMCBENCH_SESSIONS ?= 10000
VOMCBENCH_MIN_LEN ?= 5
VOMCBENCH_MAX_LEN ?= 50
VOMCBENCH_MAX_DEPTH ?= 4
VOMCBENCH_MIN_COUNT ?= 2
VOMCBENCH_TRAIN_RATIO ?= 0.8
VOMCBENCH_CORPUS ?= $(VOMCBENCH_DIR)/$(VOMCBENCH_KIND).jsonl
VOMCBENCH_RESULT ?= $(VOMCBENCH_DIR)/$(VOMCBENCH_KIND)_depth$(VOMCBENCH_MAX_DEPTH).json
VOMCBENCH_MODEL ?= $(VOMCBENCH_DIR)/$(VOMCBENCH_KIND)_depth$(VOMCBENCH_MAX_DEPTH)_model.json
VOMCBENCH_REPORT ?= $(VOMCBENCH_DIR)/$(VOMCBENCH_KIND)_depth$(VOMCBENCH_MAX_DEPTH)_report.md
VOMCBENCH_BASE ?= $(VOMCBENCH_DIR)/main.json
VOMCBENCH_HEAD ?= $(VOMCBENCH_RESULT)

test:
	go test ./...

guard-dashboard:
	./scripts/build-guard-dashboard-assets.sh

guard-smoke:
	go run ./cmd/kontext guard smoke-test

guard-e2e:
	./scripts/guard-e2e-local.sh

vomcbench-report:
	mkdir -p $(VOMCBENCH_DIR)
	go run ./cmd/vomcbench report \
		-dir $(VOMCBENCH_DIR) \
		-kind $(VOMCBENCH_KIND) \
		-seed $(VOMCBENCH_SEED) \
		-alphabet $(VOMCBENCH_ALPHABET) \
		-sessions $(VOMCBENCH_SESSIONS) \
		-min-len $(VOMCBENCH_MIN_LEN) \
		-max-len $(VOMCBENCH_MAX_LEN) \
		-max-depth $(VOMCBENCH_MAX_DEPTH) \
		-min-count $(VOMCBENCH_MIN_COUNT) \
		-train-ratio $(VOMCBENCH_TRAIN_RATIO) \
		-out $(VOMCBENCH_REPORT) \
		-result-out $(VOMCBENCH_RESULT) \
		-model-out $(VOMCBENCH_MODEL) \
		-corpus-out $(VOMCBENCH_CORPUS)

vomcbench-generate:
	mkdir -p $(VOMCBENCH_DIR)
	go run ./cmd/vomcbench generate \
		-kind $(VOMCBENCH_KIND) \
		-seed $(VOMCBENCH_SEED) \
		-alphabet $(VOMCBENCH_ALPHABET) \
		-sessions $(VOMCBENCH_SESSIONS) \
		-min-len $(VOMCBENCH_MIN_LEN) \
		-max-len $(VOMCBENCH_MAX_LEN) \
		-out $(VOMCBENCH_CORPUS)

vomcbench-run: vomcbench-generate
	go run ./cmd/vomcbench run \
		-corpus $(VOMCBENCH_CORPUS) \
		-max-depth $(VOMCBENCH_MAX_DEPTH) \
		-min-count $(VOMCBENCH_MIN_COUNT) \
		-train-ratio $(VOMCBENCH_TRAIN_RATIO) \
		-seed $(VOMCBENCH_SEED) \
		-out $(VOMCBENCH_RESULT) \
		-model-out $(VOMCBENCH_MODEL)

vomcbench-validate:
	go run ./cmd/vomcbench validate -result $(VOMCBENCH_RESULT)

vomcbench-inspect:
	go run ./cmd/vomcbench inspect -model $(VOMCBENCH_MODEL) -top 50 -sort precedence

vomcbench-compare:
	go run ./cmd/vomcbench compare -base $(VOMCBENCH_BASE) -head $(VOMCBENCH_HEAD) -fail-on-regression
