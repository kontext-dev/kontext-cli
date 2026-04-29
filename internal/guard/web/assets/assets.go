package assets

import "embed"

// FS contains the prebuilt dashboard used by release binaries.
//
// Refresh with:
//
//	pnpm --dir web/guard-dashboard build
//	rm -rf internal/guard/web/assets/dist
//	cp -R web/guard-dashboard/dist internal/guard/web/assets/dist
//
// The runtime binary must not require pnpm, Node, or a source checkout.
//
//go:embed dist
var FS embed.FS
