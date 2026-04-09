package auth

import (
	"reflect"
	"testing"
)

func TestResolveLoginScopesDefaults(t *testing.T) {
	t.Parallel()

	got := resolveLoginScopes(nil)
	want := []string{
		"openid",
		"email",
		"profile",
		"offline_access",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveLoginScopes(nil) = %#v, want %#v", got, want)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(nil)) {
		t.Fatal("resolveLoginScopes(nil) returned a shared slice")
	}
}

func TestResolveLoginScopesCustom(t *testing.T) {
	t.Parallel()

	input := []string{"gateway:access"}
	got := resolveLoginScopes(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("resolveLoginScopes(%#v) = %#v", input, got)
	}

	got[0] = "mutated"
	if reflect.DeepEqual(got, resolveLoginScopes(input)) {
		t.Fatal("resolveLoginScopes(custom) returned a shared slice")
	}
}
