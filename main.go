package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	logger := log.New(os.Stderr, "ldapmemberof: ", 0)
	if err := run(os.Args[1:], os.LookupEnv, os.Stdout); err != nil {
		logger.Fatal(err)
	}
}

func run(args []string, getenv func(string) (string, bool), output *os.File) error {
	flags := flag.NewFlagSet("ldapmemberof", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	ldapUrl := flags.String("url", envOr(getenv, "LDAP_URL", ""), "ldap url, for example ldaps://ldap.example.com:636")
	baseDN := flags.String("base-dn", envOr(getenv, "LDAP_BASE_DN", ""), "directory search base dn (or LDAP_BASE_DN)")
	bindDN := flags.String("bind-dn", envOr(getenv, "LDAP_BIND_DN", ""), "bind dn (or LDAP_BIND_DN)")
	compactPath := flags.Bool("compact-path", false, "format output dns as compact slash paths")
	timeout := flags.Duration("timeout", 10*time.Second, "connection and ldap operation timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *ldapUrl == "" {
		return fmt.Errorf("-url or LDAP_URL is required")
	}
	if *baseDN == "" {
		return fmt.Errorf("-base-dn or LDAP_BASE_DN is required")
	}
	if flags.NArg() != 2 {
		return fmt.Errorf("usage: ldapmemberof [options] <group-cn> <user-cn-or-samaccountname>")
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	password, _ := getenv("LDAP_BIND_PASSWORD")
	conn, err := connectLdap(*ldapUrl, *bindDN, password, *timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	lookup := func(dn string) (Entry, error) {
		return lookupLdap(conn, dn)
	}
	root, err := lookupGroupLdap(conn, *baseDN, flags.Arg(0))
	if err != nil {
		return err
	}
	paths, err := resolveMembershipPaths(lookup, root, flags.Arg(1))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		_, err := fmt.Fprintln(output, "No membership path found.")
		return err
	}
	for _, path := range paths {
		formattedPath := make([]string, len(path))
		for index, dn := range path {
			if *compactPath {
				formattedDN, err := formatCompactPath(dn)
				if err != nil {
					return fmt.Errorf("format DN %q as compact path: %w", dn, err)
				}
				formattedPath[index] = formattedDN
			} else {
				formattedPath[index] = dn
			}
		}
		if _, err := fmt.Fprintln(output, strings.Join(formattedPath, " -> ")); err != nil {
			return err
		}
	}
	return nil
}

func envOr(getenv func(string) (string, bool), name, fallback string) string {
	if value, ok := getenv(name); ok {
		return value
	}
	return fallback
}
