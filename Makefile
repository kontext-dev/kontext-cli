.PHONY: test guard-dashboard guard-smoke guard-e2e

test:
	go test ./...

guard-dashboard:
	./scripts/build-guard-dashboard-assets.sh

guard-smoke:
	go run ./cmd/kontext guard smoke-test

guard-e2e:
	./scripts/guard-e2e-local.sh
