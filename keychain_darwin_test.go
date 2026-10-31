package main

import (
	"strings"
	"testing"
)

func TestLookupKeychainRejectsInvalidUTF8(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service string
		account string
	}{
		{name: "service", service: "\xff", account: "account"},
		{name: "account", service: "service", account: "\xff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := lookupKeychain(tc.service, tc.account)
			if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
				t.Fatalf("expected UTF-8 error, got %v", err)
			}
		})
	}
}
