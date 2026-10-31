# Spec: `keyinject` — macOS Secret Injector (Go)

## 1. Purpose

A small Go CLI that reads secrets from the macOS Keychain and injects them as environment variables into a target command, then `exec`s into that command. Python scripts (and any other scripts) read them via `os.environ` and remain completely unaware of the mechanism.

**Threat model addressed:** secrets currently `export`ed in `.zshrc` are readable by every process under the user account, at all times. After migration, they exist only in Keychain and only for the lifetime of the target process.

**Explicitly out of scope:** a malicious process that can replace the `keyinject` binary, or that runs as the same user *after* injection has occurred (it can read the child's environment via process inspection). Silent access necessarily widens the trust boundary; the spec accepts "any process that can execute `keyinject` can obtain the secret."

## 2. Non-goals

- Cross-platform support (Linux/Windows). macOS only.
- Secret write/edit UI. Use `security add-generic-password` or Keychain Access.app for provisioning.
- Touch ID / biometric gating. That is Secretive's domain; here we want *silent* access.
- Rotation, versioning, audit logging (v1). Hooks are described in §9.

## 3. CLI Surface

```
keyinject [flags] -- <command> [args...]
keyinject [flags] <command> [args...]
```

The `--` separator is optional but recommended so the target command's own flags aren't parsed by `keyinject`.

### Flags

| Flag | Required | Description |
|---|---|---|
| `--env NAME` | yes (repeatable) | Environment variable name to inject. Resolved from Keychain using the service name from `--service-prefix`. |
| `--service-prefix` | no (default: `keyinject.`) | Keychain generic-password service is `<prefix><NAME>`. Example: `keyinject.OPENAI_API_KEY`. |
| `--account` | no (default: current user) | Keychain account attribute. |
| `--allow-missing` | no | If a secret is absent from Keychain, skip it instead of failing. |
| `--dry-run` | no | Print the resolved env **names only** (never values) and the final argv, then exit 0. |
| `--verbose` | no | Log to stderr: which keys were resolved, execution target. Never log values. |
| `--version` | no | Print version, exit. |

### Exit codes

- `0` — target command exited 0 (or `--dry-run`/`--version` succeeded).
- `1` — resolution error (missing key without `--allow-missing`, Keychain read error).
- `2` — usage error (no `--env`, no command).
- Otherwise, the target process's own exit code (see §5).

## 4. Keychain Read Semantics

Use `SecItemCopyMatching` directly via cgo or a pure-Go binding such as `github.com/lexfrei/keychain`. **Do not shell out to `/usr/bin/security`** — doing so would attribute the Keychain ACL check to `security` and make the secret readable by any process running `security find-generic-password`.

Query dictionary (generic password):

```
kSecClass            = kSecClassGenericPassword
kSecAttrService      = "<service-prefix><NAME>"
kSecAttrAccount      = "<account>"        // default: current user
kSecReturnData       = true
kSecMatchLimit       = kSecMatchLimitOne
```

The result is read as raw bytes and converted to a UTF-8 string. Trailing newlines from `security add-generic-password` inputs are stripped (one trailing `\n` only).

**Keychain ACL note.** The first invocation will trigger a macOS dialog ("keyinject wants to access…"). The user clicks **Always Allow**. From that point, the binary must retain a stable code-signing identity so the dialog doesn't recur (see §7).

## 5. Execution Model

1. Build `env := os.Environ()` plus one `NAME=value` entry per resolved secret, with the injected values overriding any preexisting entry of the same name.
2. Resolve the target executable: if `argv[0]` contains no slash, look it up via `exec.LookPath`; otherwise use it verbatim.
3. On Unix, call:

   ```go
   syscall.Exec(path, argv, env)
   ```

   This *replaces* the `keyinject` process with the target. Consequences:
   - The target's exit code is the exit code observed by the shell — no wrapper indirection.
   - The target owns stdin/stdout/stderr and all signal handling.
   - `keyinject`'s memory is reclaimed by the kernel when the exec transitions; there is no lingering parent process holding secrets.
4. If `syscall.Exec` fails, print the error to stderr and exit `1`.

**A note on Go's `os/exec` vs `syscall.Exec`.** Do **not** use `exec.Command(...).Run()` — that spawns a child and leaves `keyinject` alive, waiting, with secrets still in its memory and the child in its process tree. `syscall.Exec` is the only correct primitive here.

## 6. Provisioning Workflow

The tool reads only; secrets are placed in Keychain out-of-band.

```bash
# One-time per secret. -w with no value prompts (input not echoed, not in shell history).
security add-generic-password \
  -s "keyinject.OPENAI_API_KEY" \
  -a "$USER" \
  -w
```

Verify it was stored:

```bash
security find-generic-password -s "keyinject.OPENAI_API_KEY" >/dev/null && echo ok
```

Remove the old `export OPENAI_API_KEY=...` line from `~/.zshrc`. That is the migration step.

## 7. Code Signing (Critical)

Without this, every `go build` produces a new cdhash and Keychain's "Always Allow" record is invalidated on each rebuild, so the dialog returns.

### Create a self-signed signing certificate (one-time)

1. Keychain Access → Certificate Assistant → Create a Certificate.
2. Name: `keyinject-dev`, Identity Type: Self Signed Root, Certificate Type: **Code Signing**.
3. Create it in the **login** keychain.

### Sign the binary

```bash
go build -o keyinject .
codesign --force --sign "keyinject-dev" --identifier "dev.local.keyinject" ./keyinject
```

The `--identifier` and the signing certificate together form the "designated requirement" macOS uses to recognize the binary across rebuilds. Keep both constant.

### Verify

```bash
codesign -dv --verbose=2 ./keyinject
# Expect: Identifier=dev.local.keyinject, Authority=keyinject-dev
```

If you rebuild with `--identifier` and certificate unchanged, Keychain will continue to recognize the new binary as the authorized one, and no dialog will appear.

### Deployment

Place the signed binary in a path not writable by non-root users, e.g.:

```bash
sudo install -m 0755 -o root -g wheel ./keyinject /usr/local/bin/keyinject
```

Putting it in `~/bin` is acceptable for local use but widens the tamper window: any process that can write to `~/bin` can replace it with a binary that prints secrets. `/usr/local/bin` (root-owned) closes that.

## 8. Example Usage

### 8.1 Migration from `.zshrc`

Before:

```bash
# ~/.zshrc
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GITHUB_TOKEN=ghp_...
```

Move each into Keychain:

```bash
security add-generic-password -s keyinject.OPENAI_API_KEY    -a "$USER" -w
security add-generic-password -s keyinject.ANTHROPIC_API_KEY -a "$USER" -w
security add-generic-password -s keyinject.GITHUB_TOKEN      -a "$USER" -w
```

Remove the three `export` lines from `.zshrc`. `exec zsh`.

### 8.2 Running a Python script

`hello.py`:

```python
import os
import requests

resp = requests.get(
    "https://api.openai.com/v1/models",
    headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}"},
    timeout=10,
)
print(resp.status_code)
```

Run it:

```bash
keyinject --env OPENAI_API_KEY -- python3 hello.py
```

First run: macOS asks "keyinject wants to access keyinject.OPENAI_API_KEY" → click **Always Allow**. Subsequent runs are silent.

The script sees `OPENAI_API_KEY` as a normal environment variable. It knows nothing about Keychain, `keyinject`, or the `--` separator.

### 8.3 Multiple secrets, single invocation

```bash
keyinject \
  --env OPENAI_API_KEY \
  --env ANTHROPIC_API_KEY \
  --env GITHUB_TOKEN \
  -- python3 scripts/sync_docs.py
```

All three are injected into that process's environment; none survive after the process exits.

### 8.4 Passing arguments to the target

```bash
keyinject --env GITHUB_TOKEN -- git push origin main
```

Everything after `--` is argv for `git`. `keyinject` does not parse it.

### 8.5 Dry run (verify what will be injected, without exposing values)

```bash
$ keyinject --env OPENAI_API_KEY --env GITHUB_TOKEN --dry-run -- python3 app.py
resolved: OPENAI_API_KEY
resolved: GITHUB_TOKEN
argv: ["python3" "app.py"]
```

Missing keys show up as `MISSING` under `--dry-run`, or fail the run (exit `1`) without `--allow-missing`.

### 8.6 Tolerating optional secrets

```bash
keyinject --env SENTRY_DSN --env SENTRY_ENV --allow-missing -- ./bin/app
```

If `SENTRY_DSN` is not in Keychain, `keyinject` proceeds with just `SENTRY_ENV`. Any script must handle the absence — this is not a silent default; it's an explicit opt-in.

### 8.7 A shell wrapper for convenience

```bash
# ~/bin/run-openai
#!/bin/sh
exec /usr/local/bin/keyinject --env OPENAI_API_KEY -- "$@"
```

```bash
chmod +x ~/bin/run-openai
run-openai python3 script_that_calls_openai.py
```

The wrapper is not trusted by Keychain — `keyinject` is. The wrapper is just an alias.

### 8.8 A Makefile target

```makefile
test:
	@keyinject --env OPENAI_API_KEY -- python3 -m pytest -q
```

The Makefile contains no secret. Checkout, `make test`, done.

## 9. Extension Hooks (v2, out of scope but reserved)

Reserving namespace so v1 doesn't paint itself into a corner:

- `--stdin NAME=...` to inject a secret over stdin (for secrets you don't want passed as an env at all).
- `--audit-log <path>` to append one line per run: timestamp, requesting process's `pid`/`ppid`, injected key names (never values). This makes "who used what" inspectable.
- `--ttl <duration>` is **not** feasible without a resident agent; if you want it, run an agent (à la `kakusu`) rather than extending `keyinject`.

## 10. Acceptance Criteria

- [ ] `keyinject --env FOO -- printenv FOO` prints the secret and exits `0`.
- [ ] Same command, second invocation, produces **no** Keychain dialog.
- [ ] After a `go build` + `codesign` rebuild, dialog **does not** return.
- [ ] `keyinject --env MISSING -- printenv MISSING` exits `1` with a clear message.
- [ ] `keyinject --env MISSING --allow-missing -- true` exits `0`.
- [ ] `keyinject --dry-run --env FOO -- true` prints `resolved: FOO` and **not** the value.
- [ ] `keyinject --env FOO -- sh -c 'exit 42'` exits `42`.
- [ ] `keyinject --env FOO -- python3 -c 'import os, time; print(os.environ["FOO"]); time.sleep(5)'` — while it sleeps, `ps eww -p $PID` does **not** reveal the secret on the command line (it will appear in the process environment block, which is expected; the point is it isn't in argv).
- [ ] `keyinject` invoked with no `--env` exits `2` with usage.
- [ ] `keyinject` invoked with no command exits `2` with usage.