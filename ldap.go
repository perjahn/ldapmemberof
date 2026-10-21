package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func connectLdap(ldapUrl, bindDN, password string, timeout time.Duration) (*ldap.Conn, error) {
	parsedUrl, err := url.Parse(ldapUrl)
	if err != nil || (parsedUrl.Scheme != "ldap" && parsedUrl.Scheme != "ldaps") || parsedUrl.Hostname() == "" {
		return nil, fmt.Errorf("invalid ldap url %q: expected ldap:// or ldaps:// url", ldapUrl)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsedUrl.Hostname()}
	conn, err := ldap.DialURL(ldapUrl,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to ldap server: %w", err)
	}
	conn.SetTimeout(timeout)

	if parsedUrl.Scheme == "ldap" {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("start tls on ldap:// connection: %w", err)
		}
	}
	if bindDN != "" {
		if err := conn.Bind(bindDN, password); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap bind failed: %w", err)
		}
	}
	return conn, nil
}

func lookupLdap(conn *ldap.Conn, dn string) (Entry, error) {
	attributes := []string{"objectClass", "member", "cn", "sAMAccountName"}
	request := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attributes,
		nil,
	)
	result, err := conn.Search(request)
	if err != nil {
		return Entry{}, fmt.Errorf("search %q: %w", dn, err)
	}
	if len(result.Entries) != 1 {
		return Entry{}, fmt.Errorf("lookup %q returned %d entries, expected one", dn, len(result.Entries))
	}
	resultEntry := result.Entries[0]
	return entryFromLdap(resultEntry), nil
}

func lookupGroupLdap(conn *ldap.Conn, baseDN, groupCN string) (Entry, error) {
	attributes := []string{"objectClass", "member", "cn", "sAMAccountName"}
	request := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(&(objectClass=%s)(cn=%s))", "group", ldap.EscapeFilter(groupCN)),
		attributes,
		nil,
	)
	result, err := conn.Search(request)
	if err != nil {
		return Entry{}, fmt.Errorf("search for group cn %q under %q: %w", groupCN, baseDN, err)
	}
	switch len(result.Entries) {
	case 0:
		return Entry{}, fmt.Errorf("no group with cn %q found under %q", groupCN, baseDN)
	case 1:
		fmt.Fprint(os.Stderr, ".")
		return entryFromLdap(result.Entries[0]), nil
	default:
		return Entry{}, fmt.Errorf("group cn %q is ambiguous under %q; narrow the base dn", groupCN, baseDN)
	}
}

func entryFromLdap(resultEntry *ldap.Entry) Entry {
	return Entry{
		DN: resultEntry.DN,
		IsGroup: slices.ContainsFunc(resultEntry.GetAttributeValues("objectClass"), func(objectClass string) bool {
			return strings.EqualFold(objectClass, "group")
		}),
		Members: resultEntry.GetAttributeValues("member"),
		User: User{
			DN:             resultEntry.DN,
			CN:             resultEntry.GetAttributeValue("cn"),
			SAMAccountName: resultEntry.GetAttributeValue("sAMAccountName"),
		},
	}
}

func formatCompactPath(dn string) (string, error) {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil {
		return "", err
	}
	rdns := make([]string, 0, len(parsedDN.RDNs))
	for _, rdn := range slices.Backward(parsedDN.RDNs) {
		values := make([]string, 0, len(rdn.Attributes))
		for _, attribute := range rdn.Attributes {
			if !strings.EqualFold(attribute.Type, "dc") {
				value := strings.NewReplacer(`\`, `\\`, "/", `\/`, "+", `\+`).Replace(attribute.Value)
				values = append(values, value)
			}
		}
		if len(values) > 0 {
			rdns = append(rdns, strings.Join(values, "+"))
		}
	}
	return "/" + strings.Join(rdns, "/"), nil
}
