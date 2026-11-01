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
	config        string
	noConfig      bool
	command       []string
}

type secretRequest struct {
	name    string
	service string
}

type lookupFunc func(service, account string) ([]byte, error)
type execFunc func(path string, argv, env []string) error

func main() {
	os.Exit(run(os.Args[1:], lookupKeychain, syscall.Exec, os.Stdout, os.Stderr))
}

func run(args []string, lookup lookupFunc, execute execFunc, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printHelp(stdout)
			return 0
		}
	}
	opts, err := parseOptions(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printHelp(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "keyinject: %v\n", err)
		printUsage(stderr)
		return 2
	}
	if opts.showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	requests := make([]secretRequest, 0, len(opts.envs))
	seen := make(map[string]bool, len(opts.envs))
	for _, name := range opts.envs {
		requests = append(requests, secretRequest{name: name, service: opts.servicePrefix + name})
		seen[name] = true
	}
	if !opts.noConfig {
		configPath := opts.config
		if configPath == "" {
			configPath = ".keyinject"
		}
		configRequests, err := loadConfig(configPath)
		if err != nil {
			fmt.Fprintf(stderr, "keyinject: read config %s: %v\n", configPath, err)
			return 1
		}
		for _, req := range configRequests {
			if seen[req.name] {
				continue
			}
			service := req.service
			if service == "" {
				service = opts.servicePrefix + req.name
			}
			requests = append(requests, secretRequest{name: req.name, service: service})
			seen[req.name] = true
		}
	}
	if len(requests) == 0 {
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
	values := make(map[string]string, len(requests))
	missing := make(map[string]bool)
	for _, req := range requests {
		data, err := lookup(req.service, opts.account)
		if err != nil {
			if errors.Is(err, errKeyNotFound) {
				missing[req.name] = true
				if opts.dryRun || opts.allowMissing {
					continue
				}
				fmt.Fprintf(stderr, "keyinject: secret for %s not found in Keychain\n", req.name)
				return 1
			}
			fmt.Fprintf(stderr, "keyinject: read Keychain item for %s: %v\n", req.name, err)
			return 1
		}
		values[req.name] = strings.TrimSuffix(string(data), "\n")
	}
	if opts.dryRun {
		for _, req := range requests {
			if missing[req.name] {
				fmt.Fprintf(stdout, "MISSING: %s\n", req.name)
			} else {
				fmt.Fprintf(stdout, "resolved: %s\n", req.name)
			}
		}
		fmt.Fprintf(stdout, "argv: %q\n", opts.command)
		return 0
	}
	if opts.verbose {
		for _, req := range requests {
			if !missing[req.name] {
				fmt.Fprintf(stderr, "keyinject: resolved %s\n", req.name)
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

func printHelp(w io.Writer) {
	fmt.Fprintln(w, "keyinject — inject macOS Keychain secrets into a command's environment")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  keyinject [flags] -- <command> [args...]")
	fmt.Fprintln(w, "  keyinject [flags] <command> [args...]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The -- separator is optional but recommended so the target command's own")
	fmt.Fprintln(w, "flags are not parsed by keyinject.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Flags:")
	fmt.Fprintln(w, "  --env NAME                Required; repeatable. Environment variable name to load from Keychain.")
	fmt.Fprintln(w, "  --service-prefix PREFIX   Keychain service prefix. Default: keyinject.")
	fmt.Fprintln(w, "  --account NAME            Keychain account. Default: current user.")
	fmt.Fprintln(w, "  --allow-missing           Continue without secrets that are absent from Keychain.")
	fmt.Fprintln(w, "  --config FILE             Read env names from FILE (default: .keyinject in the current directory).")
	fmt.Fprintln(w, "  --dry-run                 Print resolved names and target argv, never secret values; does not run the target.")
	fmt.Fprintln(w, "  --no-config               Do not load the .keyinject config file.")
	fmt.Fprintln(w, "  --verbose                 Log resolved names and execution target to stderr; never logs values.")
	fmt.Fprintln(w, "  --version                 Print the build version.")
	fmt.Fprintln(w, "  -h, --help                Show this help message.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Config file (.keyinject):")
	fmt.Fprintln(w, "  Instead of passing --env on every invocation, create a .keyinject file listing one")
	fmt.Fprintln(w, "  environment variable name per line. Blank lines and # comments are ignored.")
	fmt.Fprintln(w, "  Optionally append =<service> to use a custom Keychain service for a name.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  keyinject --env OPENAI_API_KEY -- python3 app.py")
	fmt.Fprintln(w, "  keyinject --env FOO --env BAR -- sh -c 'echo $FOO:$BAR'")
	fmt.Fprintln(w, "  keyinject --dry-run --env FOO -- true")
	fmt.Fprintln(w, "  keyinject --config .keyinject -- python3 app.py")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes:")
	fmt.Fprintln(w, "  0   success (or --dry-run / --version)")
	fmt.Fprintln(w, "  1   resolution error (missing key, Keychain read error, exec failure)")
	fmt.Fprintln(w, "  2   usage error (no --env, no command, invalid flag)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Secrets are provisioned in Keychain with:")
	fmt.Fprintln(w, "  security add-generic-password -s keyinject.NAME -a $USER -w")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "See https://github.com/namuan/keyinject for more.")
}

func parseOptions(args []string) (options, error) {
	var opts options
	var envs stringList
	set := flag.NewFlagSet("keyinject", flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	set.Var(&envs, "env", "environment variable name to inject")
	set.StringVar(&opts.servicePrefix, "service-prefix", "keyinject.", "Keychain service prefix")
	set.StringVar(&opts.account, "account", "", "Keychain account")
	set.BoolVar(&opts.allowMissing, "allow-missing", false, "skip missing secrets")
	set.BoolVar(&opts.dryRun, "dry-run", false, "print resolved names and target argv")
	set.BoolVar(&opts.verbose, "verbose", false, "log resolved names and execution target")
	set.BoolVar(&opts.showVersion, "version", false, "print version")
	set.StringVar(&opts.config, "config", "", "config file with env names (default: .keyinject)")
	set.BoolVar(&opts.noConfig, "no-config", false, "do not load .keyinject config file")
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

func loadConfig(path string) ([]secretRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var requests []secretRequest
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, service, hasOverride := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if !envNamePattern.MatchString(name) {
			return nil, fmt.Errorf("invalid environment variable name %q in %s", name, path)
		}
		if hasOverride {
			service = strings.TrimSpace(service)
			if service == "" {
				return nil, fmt.Errorf("empty service override for %q in %s", name, path)
			}
		}
		requests = append(requests, secretRequest{name: name, service: service})
	}
	return requests, nil
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
