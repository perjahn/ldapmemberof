# ldapmemberof

`ldapmemberof` prints every membership path from a specified group to a specified user. It follows nested groups in the client by reading each group's `member` attribute; it does not use a server-side transitive-membership rule. TLS is always used: `ldaps://` uses implicit TLS, and `ldap://` is automatically upgraded with StartTLS before binding or searching. If the upgrade fails, the command exits without sending credentials or queries over plaintext.

## Build

```sh
go build -o ldapmemberof .
```

## Run

```sh
export LDAP_URL='ldaps://ldap.example.com:636'
export LDAP_BASE_DN='dc=example,dc=com'
export LDAP_BIND_DN='cn=readonly,ou=service accounts,dc=example,dc=com'
export LDAP_BIND_PASSWORD='...'

./ldapmemberof 'Engineering' 'asmith'
```

The first argument is the group's CN. The second is matched case-insensitively against a member's `cn` or `sAMAccountName`. The command prints each matching route on its own line, with DNs separated by `->`. If the user is not a member, it prints `No membership path found.` For an anonymous bind, omit `LDAP_BIND_DN`. The password is read only from `LDAP_BIND_PASSWORD`, never from a command-line flag.

Options:

- `-url`: LDAP URL (`ldap://` or `ldaps://`); can also be set with `LDAP_URL`.
- `-base-dn`: subtree to search for the group CN; can also be set with `LDAP_BASE_DN`.
- `-bind-dn`: bind DN; can also be set with `LDAP_BIND_DN`.
- `-compact-path`: render each DN as a slash path without `dc=` components or attribute labels. For example, `cn=alice,ou=People,dc=example,dc=com` becomes `/People/alice`.
- `-timeout`: connection and LDAP operation timeout (default `10s`).

TLS certificate verification remains enabled for both connection modes.

The bind account needs permission to read the `member` attribute, object classes, `cn`, and `sAMAccountName` for all traversed entries.