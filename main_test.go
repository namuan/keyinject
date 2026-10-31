package main

import (
	"bytes"
	"errors"
	"os"
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
	oldPath := os.Getenv("PATH")
	status := run([]string{"--env", "KEYINJECT_TEST_VALUE", "--", "sh", "-c", "exit 42"}, func(string, string) ([]byte, error) {
		return []byte("injected"), nil
	}, func(path string, argv, env []string) error {
		if path == "" || !reflect.DeepEqual(argv, []string{"sh", "-c", "exit 42"}) {
			t.Fatalf("path=%q argv=%q", path, argv)
		}
		found := false
		for _, entry := range env {
			if entry == "KEYINJECT_TEST_VALUE=injected" {
				found = true
			}
			if entry == "PATH="+oldPath {
				continue
			}
		}
		if !found {
			t.Fatalf("injected value missing from env %q", env)
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
