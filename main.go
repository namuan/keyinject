package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"strings"
	"syscall"
)

var version = "dev"
var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type options struct {
	envs          []string
	servicePrefix string
	account       string
	allowMissing  bool
	dryRun        bool
	verbose       bool
	showVersion   bool
	command       []string
}

type lookupFunc func(service, account string) ([]byte, error)
type execFunc func(path string, argv, env []string) error

func main() {
	os.Exit(run(os.Args[1:], lookupKeychain, syscall.Exec, os.Stdout, os.Stderr))
}

func run(args []string, lookup lookupFunc, execute execFunc, stdout, stderr io.Writer) int {
	opts, err := parseOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "keyinject: %v\n", err)
		printUsage(stderr)
		return 2
	}
	if opts.showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(opts.envs) == 0 {
		fmt.Fprintln(stderr, "keyinject: at least one --env is required")
		printUsage(stderr)
		return 2
	}
	if len(opts.command) == 0 {
		fmt.Fprintln(stderr, "keyinject: a command is required")
		printUsage(stderr)
		return 2
	}
	if opts.account == "" {
		current, err := user.Current()
		if err != nil {
			fmt.Fprintf(stderr, "keyinject: determine current account: %v\n", err)
			return 1
		}
		opts.account = current.Username
	}
	values := make(map[string]string, len(opts.envs))
	missing := make(map[string]bool)
	for _, name := range opts.envs {
		data, err := lookup(opts.servicePrefix+name, opts.account)
		if err != nil {
			if errors.Is(err, errKeyNotFound) {
				missing[name] = true
				if opts.dryRun || opts.allowMissing {
					continue
				}
				fmt.Fprintf(stderr, "keyinject: secret for %s not found in Keychain\n", name)
				return 1
			}
			fmt.Fprintf(stderr, "keyinject: read Keychain item for %s: %v\n", name, err)
			return 1
		}
		values[name] = strings.TrimSuffix(string(data), "\n")
	}
	if opts.dryRun {
		for _, name := range opts.envs {
			if missing[name] {
				fmt.Fprintf(stdout, "MISSING: %s\n", name)
			} else {
				fmt.Fprintf(stdout, "resolved: %s\n", name)
			}
		}
		fmt.Fprintf(stdout, "argv: %q\n", opts.command)
		return 0
	}
	if opts.verbose {
		for _, name := range opts.envs {
			if !missing[name] {
				fmt.Fprintf(stderr, "keyinject: resolved %s\n", name)
			}
		}
	}
	env := mergeEnvironment(os.Environ(), values)
	path := opts.command[0]
	if !strings.Contains(path, "/") {
		path, err = exec.LookPath(path)
		if err != nil {
			fmt.Fprintf(stderr, "keyinject: resolve command %q: %v\n", opts.command[0], err)
			return 1
		}
	}
	if opts.verbose {
		fmt.Fprintf(stderr, "keyinject: executing %q\n", path)
	}
	if err := execute(path, opts.command, env); err != nil {
		fmt.Fprintf(stderr, "keyinject: exec %q: %v\n", path, err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: keyinject [flags] -- <command> [args...]")
}

func parseOptions(args []string) (options, error) {
	var opts options
	var envs stringList
	set := flag.NewFlagSet("keyinject", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Var(&envs, "env", "environment variable name to inject")
	set.StringVar(&opts.servicePrefix, "service-prefix", "keyinject.", "Keychain service prefix")
	set.StringVar(&opts.account, "account", "", "Keychain account")
	set.BoolVar(&opts.allowMissing, "allow-missing", false, "skip missing secrets")
	set.BoolVar(&opts.dryRun, "dry-run", false, "print resolved names and target argv")
	set.BoolVar(&opts.verbose, "verbose", false, "log resolved names and execution target")
	set.BoolVar(&opts.showVersion, "version", false, "print version")
	if err := set.Parse(args); err != nil {
		return opts, err
	}
	opts.envs = envs
	for _, name := range opts.envs {
		if !envNamePattern.MatchString(name) {
			return opts, fmt.Errorf("invalid environment variable name %q", name)
		}
	}
	opts.command = set.Args()
	return opts, nil
}

func mergeEnvironment(base []string, values map[string]string) []string {
	env := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if _, overridden := values[name]; ok && overridden {
			continue
		}
		env = append(env, entry)
	}
	for name, value := range values {
		env = append(env, name+"="+value)
	}
	return env
}

var errKeyNotFound = errors.New("Keychain item not found")
