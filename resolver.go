package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type Entry struct {
	DN      string
	IsGroup bool
	Members []string
	User    User
}

type User struct {
	DN             string
	CN             string
	SAMAccountName string
}

func resolveMembershipPaths(lookup func(dn string) (Entry, error), root Entry, userIdentifier string) ([][]string, error) {
	resolver := membershipResolver{
		lookup:         lookup,
		entries:        make(map[string]Entry),
		userIdentifier: strings.TrimSpace(userIdentifier),
		activePath:     make(map[string]bool),
	}
	if !root.IsGroup {
		return nil, fmt.Errorf("entry %q is not a group", root.DN)
	}
	resolver.entries[normalizeDN(root.DN)] = root
	defer fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, ".")
	if err := resolver.visitGroup(root, nil); err != nil {
		return nil, err
	}
	sort.Slice(resolver.paths, func(i, j int) bool {
		return strings.ToLower(strings.Join(resolver.paths[i], " -> ")) < strings.ToLower(strings.Join(resolver.paths[j], " -> "))
	})
	return resolver.paths, nil
}

type membershipResolver struct {
	lookup         func(dn string) (Entry, error)
	entries        map[string]Entry
	userIdentifier string
	activePath     map[string]bool
	paths          [][]string
}

func (r *membershipResolver) lookupEntry(dn string) (Entry, error) {
	key := normalizeDN(dn)
	if entry, ok := r.entries[key]; ok {
		return entry, nil
	}
	entry, err := r.lookup(dn)
	if err != nil {
		return Entry{}, err
	}
	if entry.DN == "" {
		entry.DN = dn
	}
	r.entries[key] = entry
	if entry.IsGroup {
		fmt.Fprint(os.Stderr, ".")
	}
	return entry, nil
}

func (r *membershipResolver) visitGroup(group Entry, path []string) error {
	groupKey := normalizeDN(group.DN)
	if r.activePath[groupKey] {
		return nil
	}
	r.activePath[groupKey] = true
	defer delete(r.activePath, groupKey)
	path = append(path, group.DN)

	for _, memberDN := range group.Members {
		member, err := r.lookupEntry(memberDN)
		if err != nil {
			return fmt.Errorf("lookup member %q of group %q: %w", memberDN, group.DN, err)
		}
		if member.IsGroup {
			if err := r.visitGroup(member, path); err != nil {
				return err
			}
			continue
		}
		if strings.EqualFold(member.User.CN, r.userIdentifier) || strings.EqualFold(member.User.SAMAccountName, r.userIdentifier) {
			memberPath := append(append([]string(nil), path...), member.DN)
			r.paths = append(r.paths, memberPath)
		}
	}
	return nil
}

func normalizeDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}
