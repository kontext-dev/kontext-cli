package guardmodels

import _ "embed"

// CodingAgentV0 is the default local risk model shipped inside release builds.
//
//go:embed coding-agent-v0.json
var CodingAgentV0 []byte
