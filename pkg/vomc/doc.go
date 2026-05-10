// Package vomc implements variable-order Markov chains over symbolic
// sequences.
//
// The package is intentionally domain-neutral. Callers are responsible for
// mapping their own events, records, tokens, or workflow steps into Symbols
// before training or scoring a model.
package vomc
