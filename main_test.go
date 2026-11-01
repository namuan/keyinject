package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunDryRunDoesNotPrintSecret(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{"--env", "FOO", "--dry-run", "--", "printenv", "FOO"}, func(service, account string) ([]byte, error) {
		if service != "keyinject.FOO" {
			t.Fatalf("service = %q", service)
		}
		return []byte("top-secret\n"), nil
	}, nil, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("status = %d, stderr = %s", status, stderr.String())
	}
	if strings.Contains(stdout.String(), "top-secret") || !strings.Contains(stdout.String(), "resolved: FOO") || !strings.Contains(stdout.String(), `argv: ["printenv" "FOO"]`) {
		t.Fatalf("unexpected dry-run output %q", stdout.String())
	}
}

func TestRunAllowsMissingSecret(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var executed bool
	status := run([]string{"--env", "MISSING", "--allow-missing", "--", "true"}, func(string, string) ([]byte, error) {
		return nil, errKeyNotFound
	}, func(path string, argv, env []string) error {
		executed = true
		if !strings.HasSuffix(path, "/true") || !reflect.DeepEqual(argv, []string{"true"}) {
			t.Fatalf("exec path=%q argv=%q", path, argv)
		}
		return nil
	}, &stdout, &stderr)
	if status != 0 || !executed {
		t.Fatalf("status=%d executed=%v stderr=%q", status, executed, stderr.String())
	}
}

func TestRunMissingSecretFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := run([]string{"--env", "MISSING", "--", "true"}, func(string, string) ([]byte, error) {
		return nil, errKeyNotFound
	}, nil, &stdout, &stderr)
	if status != 1 || !strings.Contains(stderr.String(), "MISSING") {
		t.Fatalf("status=%d stderr=%q", status, stderr.String())
	}
}

func TestRunMergesEnvironmentAndExecFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	t.Setenv("KEYINJECT_TEST_VALUE", "old")
	status := run([]string{"--env", "KEYINJECT_TEST_VALUE", "--", "sh", "-c", "exit 42"}, func(string, string) ([]byte, error) {
		return []byte("injected"), nil
	}, func(path string, argv, env []string) error {
		if path == "" || !reflect.DeepEqual(argv, []string{"sh", "-c", "exit 42"}) {
			t.Fatalf("path=%q argv=%q", path, argv)
		}
		found := 0
		for _, entry := range env {
			if strings.HasPrefix(entry, "KEYINJECT_TEST_VALUE=") {
				found++
				if entry != "KEYINJECT_TEST_VALUE=injected" {
					t.Fatalf("unexpected injected entry %q", entry)
				}
			}
		}
		if found != 1 {
			t.Fatalf("found %d entries for injected value", found)
		}
		return errors.New("exec failed")
	}, &stdout, &stderr)
	if status != 1 || !strings.Contains(stderr.String(), "exec failed") {
		t.Fatalf("status=%d stderr=%q", status, stderr.String())
	}
}

func TestMergeEnvironmentOverridesExisting(t *testing.T) {
	got := mergeEnvironment([]string{"FOO=old", "BAR=kept"}, map[string]string{"FOO": "new"})
	if !reflect.DeepEqual(got, []string{"BAR=kept", "FOO=new"}) {
		t.Fatalf("environment = %#v", got)
	}
}

func TestUsageRequiresEnvAndCommand(t *testing.T) {
	for _, args := range [][]string{{"true"}, {"--env", "FOO"}} {
		var stderr bytes.Buffer
		if status := run(args, nil, nil, &bytes.Buffer{}, &stderr); status != 2 {
			t.Fatalf("args=%q status=%d", args, status)
		}
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	requests, err := loadConfig("/nonexistent/.keyinject")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if requests != nil {
		t.Fatalf("expected nil requests, got %v", requests)
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	requests, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) != 0 {
		t.Fatalf("expected no requests, got %v", requests)
	}
}

func TestLoadConfigCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	content := "\n# this is a comment\n   \nOPENAI_API_KEY\n# another comment\nGITHUB_TOKEN\n\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	requests, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d: %v", len(requests), requests)
	}
	if requests[0].name != "OPENAI_API_KEY" || requests[0].service != "" {
		t.Fatalf("unexpected request: %+v", requests[0])
	}
	if requests[1].name != "GITHUB_TOKEN" || requests[1].service != "" {
		t.Fatalf("unexpected request: %+v", requests[1])
	}
}

func TestLoadConfigServiceOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	content := "OPENAI_API_KEY=my.custom.service\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	requests, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	if requests[0].name != "OPENAI_API_KEY" || requests[0].service != "my.custom.service" {
		t.Fatalf("unexpected request: %+v", requests[0])
	}
}

func TestLoadConfigInvalidName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	if err := os.WriteFile(path, []byte("invalid-name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "invalid environment variable name") {
		t.Fatalf("expected invalid name error, got %v", err)
	}
}

func TestLoadConfigEmptyServiceOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	if err := os.WriteFile(path, []byte("FOO=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "empty service override") {
		t.Fatalf("expected empty service override error, got %v", err)
	}
}

func TestRunUsesConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	if err := os.WriteFile(path, []byte("CONFIG_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	var resolved []string
	status := run([]string{"--config", path, "--dry-run", "--", "true"}, func(service, account string) ([]byte, error) {
		resolved = append(resolved, service)
		return []byte("value\n"), nil
	}, nil, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("status=%d stderr=%q", status, stderr.String())
	}
	if len(resolved) != 1 || resolved[0] != "keyinject.CONFIG_KEY" {
		t.Fatalf("expected service keyinject.CONFIG_KEY, got %v", resolved)
	}
	if !strings.Contains(stdout.String(), "resolved: CONFIG_KEY") {
		t.Fatalf("expected resolved: CONFIG_KEY in output, got %q", stdout.String())
	}
}

func TestRunCLIEnvOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	if err := os.WriteFile(path, []byte("SHARED_KEY\nCLI_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	var resolved []string
	status := run([]string{"--config", path, "--env", "SHARED_KEY", "--dry-run", "--", "true"}, func(service, account string) ([]byte, error) {
		resolved = append(resolved, service)
		return []byte("value\n"), nil
	}, nil, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("status=%d stderr=%q", status, stderr.String())
	}
	// SHARED_KEY should appear once (CLI wins, dedup), CLI_KEY once from config
	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolutions, got %d: %v", len(resolved), resolved)
	}
}

func TestRunNoConfigSkipsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".keyinject")
	if err := os.WriteFile(path, []byte("CONFIG_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	status := run([]string{"--config", path, "--no-config", "--dry-run", "--", "true"}, func(string, string) ([]byte, error) {
		return nil, errKeyNotFound
	}, nil, &stdout, &stderr)
	if status != 2 {
		t.Fatalf("expected status 2 (no --env), got %d stderr=%q", status, stderr.String())
	}
	if strings.Contains(stderr.String(), "CONFIG_KEY") {
		t.Fatalf("config file should not be read with --no-config, got %q", stderr.String())
	}
}
