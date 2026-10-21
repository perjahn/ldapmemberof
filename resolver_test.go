package main

import (
	"errors"
	"strings"
	"testing"
)

type testDirectory map[string]Entry

func (d testDirectory) Lookup(dn string) (Entry, error) {
	entry, ok := d[normalizeDN(dn)]
	if !ok {
		return Entry{}, errors.New("not found")
	}
	return entry, nil
}

func TestResolveMembershipPathsFindsAllRoutesAndHandlesCycles(t *testing.T) {
	rootDN := "cn=Root,ou=Groups,dc=example,dc=com"
	childDN := "cn=Child,ou=Groups,dc=example,dc=com"
	otherDN := "cn=Other,ou=Groups,dc=example,dc=com"
	aliceDN := "uid=alice,ou=People,dc=example,dc=com"

	directory := testDirectory{
		normalizeDN(rootDN):  {DN: rootDN, IsGroup: true, Members: []string{childDN, otherDN, aliceDN}},
		normalizeDN(childDN): {DN: childDN, IsGroup: true, Members: []string{rootDN, aliceDN}},
		normalizeDN(otherDN): {DN: otherDN, IsGroup: true, Members: []string{childDN}},
		normalizeDN(aliceDN): {DN: aliceDN, User: User{DN: aliceDN, CN: "Alice Example", SAMAccountName: "asmith"}},
	}

	paths, err := resolveMembershipPaths(directory.Lookup, directory[normalizeDN(rootDN)], "ASMITH")
	if err != nil {
		t.Fatalf("resolveMembershipPaths() error = %v", err)
	}
	want := [][]string{
		{rootDN, childDN, aliceDN},
		{rootDN, otherDN, childDN, aliceDN},
		{rootDN, aliceDN},
	}
	cnPaths, err := resolveMembershipPaths(directory.Lookup, directory[normalizeDN(rootDN)], "alice example")
	if err != nil {
		t.Fatalf("resolveMembershipPaths() by CN error = %v", err)
	}
	if len(cnPaths) != len(want) {
		t.Fatalf("got %d CN paths, want %d", len(cnPaths), len(want))
	}
	if len(paths) != len(want) {
		t.Fatalf("got %d paths, want %d: %#v", len(paths), len(want), paths)
	}
	for i := range want {
		if strings.Join(paths[i], " -> ") != strings.Join(want[i], " -> ") {
			t.Errorf("path %d = %v, want %v", i, paths[i], want[i])
		}
	}
}

func TestResolveMembershipRejectsNonGroupRoot(t *testing.T) {
	directory := testDirectory{
		"uid=alice,dc=example,dc=com": {DN: "uid=alice,dc=example,dc=com"},
	}
	root := directory["uid=alice,dc=example,dc=com"]
	if _, err := resolveMembershipPaths(directory.Lookup, root, "alice"); err == nil {
		t.Fatal("resolveMembershipPaths() succeeded for a non-group root")
	}
}

func TestResolveMembershipPathsReturnsNoneForNonMember(t *testing.T) {
	groupDN := "cn=Root,dc=example,dc=com"
	aliceDN := "uid=alice,dc=example,dc=com"
	bobDN := "uid=bob,dc=example,dc=com"
	directory := testDirectory{
		normalizeDN(groupDN): {DN: groupDN, IsGroup: true},
		normalizeDN(aliceDN): {DN: aliceDN},
		normalizeDN(bobDN):   {DN: bobDN},
	}
	paths, err := resolveMembershipPaths(directory.Lookup, directory[normalizeDN(groupDN)], "alice")
	if err != nil {
		t.Fatalf("resolveMembershipPaths() error = %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("got paths %v, want none", paths)
	}
}

func TestFormatCompactPath(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{
			name: "omit domain attributes and retain organizational unit values",
			dn:   "cn=Engineering,ou=Groups,dc=example,dc=com",
			want: "/Groups/Engineering",
		},
		{
			name: "escaped comma",
			dn:   `cn=Engineering\, East,ou=Groups,dc=example,dc=com`,
			want: `/Groups/Engineering, East`,
		},
		{
			name: "case-insensitive attribute types",
			dn:   "CN=alice,OU=People,DC=example,DC=com",
			want: "/People/alice",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := formatCompactPath(test.dn)
			if err != nil {
				t.Fatalf("formatCompactPath() error = %v", err)
			}
			if got != test.want {
				t.Errorf("formatCompactPath() = %q, want %q", got, test.want)
			}
		})
	}
}
