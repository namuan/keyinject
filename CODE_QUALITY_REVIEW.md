# Code quality and security review

## Scope

Reviewed the current `main` branch implementation, including the cgo Keychain boundary, CLI flow, tests, Makefile, and documentation. The review focuses on correctness, maintainability, and security-sensitive behavior.

## Findings

### Medium: Keychain query construction assumes Core Foundation allocations succeed

`keychain_darwin.go:15-21,34-36` passes `CFStringCreateWithCString` results directly into `CFDictionaryCreate`, then passes the dictionary to `SecItemCopyMatching`; it later releases all three references without checking for `NULL`. The service prefix and explicit account are command-line inputs, and invalid UTF-8 makes `CFStringCreateWithCString` return `NULL`. Allocation failures can also return `NULL`. Passing null values into Core Foundation APIs or releasing null references can turn a bad input or allocation failure into a process crash instead of a controlled resolution error.

Validate service/account strings as UTF-8 before crossing the cgo boundary, and check each Core Foundation creation result before using or releasing it. Return a normal error through `lookupKeychain` on failure. This keeps malformed input and resource failures within the CLI's documented error path.

### Low: Environment test contains a no-op assertion branch

`main_test.go:57,69-71` reads the parent `PATH`, then continues the loop when it finds that entry without recording or asserting anything. The test therefore does not verify the inherited environment as its structure suggests. Remove the dead branch or assert that the expected `PATH` entry is present; ideally also assert that the injected variable replaces an existing value in the `run` path.

## Structural assessment

The CLI orchestration and Keychain adapter have clear ownership boundaries. The direct `SecItemCopyMatching` call and `syscall.Exec` match the security and process model; replacing them with shelling out or a child-process wrapper would weaken that model. The current files are small and no broad restructuring appears warranted.

## Verification and limits

- `make all` passed, including `go test ./...` and the macOS build.
- `make vet` passed.
- This review did not exercise a real Keychain item, authorization prompt, signed rebuild, or deployment. Those require a provisioned Keychain item and signing identity, so this review does not certify the live authorization behavior.
