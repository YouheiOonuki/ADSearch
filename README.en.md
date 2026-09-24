# ADSearch

[日本語](README.md) | **English**

A PowerShell library for reading Active Directory information without RSAT.
It uses `System.DirectoryServices` (ADSI/LDAP), so it works on ordinary domain-joined machines as an ordinary domain user.

Project page: https://yorozu-craft.com/ADSearch/en/ / License: MIT (`LICENSE`)

> This is an English translation of `README.md` (v1.4.1). If the two differ, the Japanese README prevails. Error messages, warnings and progress output from the module are in Japanese; the meaning of the common ones is given below.

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 or later |
| OS | A domain-joined Windows machine, or one that can reach a DC over LDAP (389/636) |
| Permissions | Runs as a domain user (some features need administrator rights) |
| RSAT | **Not required** |

---

## Loading

### As a module (recommended)

```powershell
Import-Module \\fileserver\tools\ADSearch\ADSearch.psd1
```

It loads directly from a UNC path. After updating the files, reload with `-Force`.

```powershell
Import-Module \\fileserver\tools\ADSearch\ADSearch.psd1 -Force
```

### Dot-sourcing (inside a script or for one-off use)

```powershell
. \\fileserver\tools\ADSearch\ADSearch.ps1
```

### When the execution policy (RemoteSigned etc.) blocks loading

Under RemoteSigned, `.ps1`/`.psm1` files on a network share must be signed, so both `Import-Module` and `. .\ADSearch.ps1` may be refused. In that case use the bundled `Import-ADSearch.ps1`: it reads the files as text and turns them into ScriptBlocks, so the file execution policy does not apply.

```powershell
# 1. Load the loader itself as a ScriptBlock (once)
. ([scriptblock]::Create((Get-Content '\\fileserver\tools\ADSearch\Import-ADSearch.ps1' -Raw)))
# 2. Load from the folder
Import-ADSearch -Path '\\fileserver\tools\ADSearch'
```

If you can copy the files locally, you can also run `Unblock-File *` on the copy and load it normally.

---

## -Identity behaviour (breaking change)

`-Identity` now follows RSAT. It accepts only **DN / ObjectGUID / SID / sAMAccountName**. The earlier loose matching on `cn`/`name`/`UserPrincipalName`/`mail` has been **removed** to prevent picking up the wrong object. To search by those identifiers, use `-Filter`.

Differences by object type (v1.4.1):

| Command | Accepted `-Identity` forms |
|---|---|
| `Get-ADUser` / `Get-ADGroup` / `Get-ADObject` etc. | DN / ObjectGUID / SID / sAMAccountName |
| `Get-ADComputer` / `Get-ADServiceAccount` | The above, plus the name without the trailing `$` (`Get-ADComputer pc001` finds `pc001$`, as in RSAT) |
| `Get-ADTrust` / `Get-ADReplication*` / Exchange configuration commands (`Get-ExchangeServer` / `Get-AcceptedDomain` / `Get-AddressList` etc.) | DN / ObjectGUID / name (the `name` attribute), because these objects have no sAMAccountName |
| Exchange recipient commands (`Get-Mailbox` etc.) | See "Exchange recipients" below |

Also, when `-Identity` matches nothing, the command now **throws**, as RSAT does (it used to return nothing).

```powershell
# Before: cn/name/UPN/mail also matched loosely -> now: sAMAccountName only
Get-ADUser -Identity yamada@corp.local -Server dc01   # may now fail; use -Filter "mail -eq '...'"

# Not found -> exception
Get-ADUser -Identity nonexistent -Server dc01   # throws "オブジェクトが見つかりません (Identity='nonexistent')" (object not found)
```

## -UseSSL requires -Server

When you use `-UseSSL`, you must also give `-Server` (a serverless bind does not support LDAPS). `-UseSSL` without `-Server` is an error.

## Basic usage

```powershell
# Get a user
Get-ADUser -Identity yamada -Server dc01.corp.local

# Filter
Get-ADUser -Filter "DisplayName -like 'Smith*'" -Server dc01.corp.local

# Group members (recursive)
Get-ADGroupMember -Identity "IT-Staff" -Recursive -Server dc01.corp.local

# Find computers
Get-ADComputer -Filter "OperatingSystem -like '*Server*'" -Server dc01.corp.local

# Check GPO links
Get-ADGpoLink -Target "OU=Tokyo,OU=Corp,DC=corp,DC=local" -Server dc01.corp.local

# DNS records (with IP addresses)
Get-ADDnsRecord -Name pc001 -ComputerName dc01.corp.local

# Limit which DNS partition is searched (e.g. only ForestDnsZones from a child domain)
Get-ADDnsRecord -ComputerName dc01.corp.local -Partition Forest
```

> `Get-ADDnsRecord` searches both DomainDnsZones (under the domain NC) and ForestDnsZones (under the forest root NC). In a child domain their DNs differ (for example `DC=DomainDnsZones,DC=main,DC=forestroot,DC=local` and `DC=ForestDnsZones,DC=forestroot,DC=local`). `-Partition Domain` / `-Partition Forest` limits the search to one of them (the default is `Both`).

### Troubleshooting sign-in problems (account state)

The default output of `Get-ADUser` includes properties for working out why someone can't sign in.

| Property | Meaning | Source |
|---|---|---|
| `Enabled` | Account enabled/disabled | userAccountControl |
| `LockedOut` | Currently locked out | msDS-User-Account-Control-Computed (computed by the DC) |
| `PasswordExpired` | Password expired | Same as above |
| `AccountExpirationDate` | Account expiry date (empty if it never expires) | accountExpires |
| `PasswordExpiryDate` (not in default output) | Password expiry date and time | msDS-UserPasswordExpiryTimeComputed |
| `PasswordNeverExpires` (not in default output) | Password never expires | userAccountControl |

```powershell
# Enabled accounts that are locked out
Get-ADUser -Filter "Enabled -eq '$true'" -Server dc01 | Where-Object LockedOut

# Ask explicitly for the password expiry date
Get-ADUser -Identity yamada -Properties PasswordExpiryDate,PasswordNeverExpires -Server dc01
```

> `LockedOut` / `PasswordExpired` / `PasswordExpiryDate` read constructed attributes computed by the DC, so you don't need to look up the domain policy (lockoutDuration / maxPwdAge) or fine-grained password policies separately. The values are as computed by the DC you queried, at the time you queried it.

### Extra properties supported by -Filter

`-Filter` supports the following properties (case-insensitive).

| Kind | Properties | Operators | Notes |
|---|---|---|---|
| Date (FileTime) | `LastLogonDate` / `PasswordLastSet` / `AccountExpirationDate` / `LastBadPasswordAttempt` / `AccountLockoutTime` | `-eq`/`-ne`/`-ge`/`-le`/`-gt`/`-lt` | Right-hand side: a FileTime int64, or a date string (below) |
| Date (Generalized-Time) | `Created` / `Modified` | Same | Right-hand side: a date string (below) |
| UAC bits | `PasswordNeverExpires` / `PasswordNotRequired` / `SmartcardLogonRequired` / `TrustedForDelegation` | `-eq`/`-ne` (`$true`/`$false` only) | Uses the same extensible match rule as `Enabled` (`:1.2.840.113556.1.4.803:`) |

So that the result does not depend on the PC's language settings, date strings are accepted only in these formats (without a time, midnight; the time zone is the PC's):
`yyyy-MM-dd` / `yyyy/MM/dd`, each optionally followed by ` HH:mm` or ` HH:mm:ss`, and `yyyy-MM-ddTHH:mm:ss`. Month, day and hour may be one digit (`2026/1/5 9:05`). `01/05/2026` and `Jan 5 2026` are errors.

`$true`, `'$true'` and `"$true"` all mean the same (since v1.4.1; up to v1.4.0 the quoted `'$true'` did not match).

```powershell
# Users whose password has not changed for 90 days or more (pass the date as yyyy-MM-dd)
Get-ADUser -Filter "PasswordLastSet -le '$((Get-Date).AddDays(-90).ToString('yyyy-MM-dd'))'" -Server dc01

# Users whose password never expires
Get-ADUser -Filter "PasswordNeverExpires -eq '`$true'" -Server dc01
```

> **Properties that cannot be filtered on the server**: `LockedOut` / `PasswordExpired` / `PasswordExpiryDate` / `MachinePasswordAge` / `IPv4Address` / `IPv6Address` / `LinkedGroupPolicyObjects` are constructed attributes or values computed on the client, so they can't be used in `-Filter` (using them is an error). Filter with `Where-Object` after retrieval.

### Diagnosing computer trust relationships

The default output of `Get-ADComputer` includes `MachinePasswordAge` (days since the machine account password was last changed).

```powershell
# Not changed for 30+ days: the secure channel (trust relationship) may be broken
Get-ADComputer -Filter "OperatingSystem -like '*Windows 1*'" -Server dc01 |
    Where-Object { $_.MachinePasswordAge -gt 30 }
```

> **Replication delay**: the default `LastLogonDate` comes from `lastLogonTimestamp`, which can lag by up to about 14 days. Seeing an old date for someone who signed in yesterday is expected. For an exact last logon you need to collect the non-replicated `lastLogon` attribute from every DC.

### Account inventory (Search-ADAccount)

A compatible subset of RSAT's `Search-ADAccount`. It finds inactive, disabled, expired, password-expired, password-never-expires and locked-out accounts. Both users and computers are searched by default; narrow with `-UsersOnly` / `-ComputersOnly`.

| Switch | Finds |
|---|---|
| `-AccountInactive` (with `-TimeSpan` or `-DaysInactive`) | Accounts with no logon in that period (including accounts that never logged on) |
| `-AccountDisabled` | Disabled accounts |
| `-AccountExpired` | Expired accounts |
| `-PasswordExpired` | Expired passwords |
| `-PasswordNeverExpires` | Passwords set never to expire |
| `-LockedOut` | Currently locked out |

```powershell
# Users with no logon for 90 days or more
Search-ADAccount -AccountInactive -DaysInactive 90 -UsersOnly -Server dc01

# Locked-out users
Search-ADAccount -LockedOut -Server dc01
```

> **Replication delay**: `-AccountInactive` uses `lastLogonTimestamp`, so results can be off by up to about 14 days (RSAT has the same limitation).
> **Client-side filtering**: `-PasswordExpired` / `-LockedOut` use constructed attributes computed by the DC, which cannot be filtered on the server; they are filtered on the client after retrieval. In large environments, narrow the scope with `-SearchBase`.

### Computer health check (Get-ADComputerHealth)

The computer counterpart of `Get-ADUserHealth`. It returns, as one object, what you need for a first look at trust relationship (secure channel) problems.

`-Identity` accepts the computer name with or without the trailing `$` (`sAMAccountName` has the form `PC001$`; without `$` it first searches as given, then retries with `$`).

```powershell
Get-ADComputerHealth -Identity PC001 -Server dc01.corp.local
Get-ADComputerHealth -Identity 'PC001$' -Server dc01.corp.local | Format-List
```

- **`MachinePasswordStale`**: `MachinePasswordAge -gt 30` (the default machine password change interval is 30 days). If `$true`, the PC has been offline for a long time or its secure channel (trust relationship) may be broken. Run `Test-ComputerSecureChannel` on the PC.
- **`DnsRegistered`**: `$true` if `IPv4Address` or `IPv6Address` could be obtained.
- Group membership is taken, as in the non-recursive path of `Get-ADUserHealth`, from the leaf CN of each DN in `MemberOf`.

---

## RSAT-compatible properties

`Get-ADUser` and `Get-ADComputer` can return attributes under the same property names that RSAT's cmdlets of the same name return with `-Properties`, so existing RSAT scripts work as they are.

```powershell
# Personal and organisational details
Get-ADUser yamada -Properties GivenName,Surname,Department,Title,Manager,Office,MobilePhone -Server dc01

# Address and contact details
Get-ADUser yamada -Properties StreetAddress,City,State,PostalCode,Country -Server dc01

# Logon statistics and lockout details
Get-ADUser yamada -Properties LogonCount,BadLogonCount,LastBadPasswordAttempt,AccountLockoutTime -Server dc01

# UAC bit flags
Get-ADUser yamada -Properties PasswordNotRequired,SmartcardLogonRequired,TrustedForDelegation -Server dc01

# Computers
Get-ADComputer pc001 -Properties OperatingSystemVersion,Location,ManagedBy,ServicePrincipalName,IPv6Address -Server dc01
```

### Main additional properties (users)

| Property | LDAP attribute | Notes |
|---|---|---|
| `GivenName` / `Surname` | `givenName` / `sn` | First name, last name |
| `Title` / `Department` / `Company` | `title` / `department` / `company` | Job title, department, company |
| `Manager` / `Office` / `Division` | `manager` / `physicalDeliveryOfficeName` / `division` | DN, office, division |
| `OfficePhone` / `MobilePhone` / `HomePhone` / `Fax` | `telephoneNumber` / `mobile` / `homePhone` / `facsimileTelephoneNumber` | Phone numbers |
| `StreetAddress` / `City` / `State` / `PostalCode` / `Country` / `POBox` | `streetAddress` / `l` / `st` / `postalCode` / `c` / `postOfficeBox` | Address |
| `HomeDirectory` / `HomeDrive` / `ProfilePath` / `ScriptPath` | LDAP attributes of the same name | Profile |
| `EmployeeID` / `EmployeeNumber` | `employeeID` / `employeeNumber` | Employee number |
| `LogonCount` / `BadLogonCount` | `logonCount` / `badPwdCount` | Logon statistics |
| `LastBadPasswordAttempt` / `AccountLockoutTime` | `badPasswordTime` / `lockoutTime` | Converted from FileTime |
| `ProxyAddresses` / `PrimaryGroupID` | `proxyAddresses` / `primaryGroupID` | Exchange, group |
| `PasswordNotRequired` | `userAccountControl` bit 0x20 | PASSWD_NOTREQD flag |
| `SmartcardLogonRequired` | `userAccountControl` bit 0x40000 | SMARTCARD_REQUIRED flag |
| `TrustedForDelegation` | `userAccountControl` bit 0x80000 | TRUSTED_FOR_DELEGATION flag |

### Main additional properties (computers)

| Property | LDAP attribute |
|---|---|
| `OperatingSystemVersion` / `OperatingSystemServicePack` | `operatingSystemVersion` / `operatingSystemServicePack` |
| `Location` / `ManagedBy` | `location` / `managedBy` |
| `ServicePrincipalName` | `servicePrincipalName` |
| `IPv6Address` | Resolves `dNSHostName` in DNS and returns the InterNetworkV6 address |

### Additions to the default output

`SID` and `ObjectGUID` have been added to the default output of `Get-ADUser` (RSAT includes them in its default output).

> **Types of SID / ObjectGUID**: they are returned as the same types as RSAT (`SID` is `[System.Security.Principal.SecurityIdentifier]`, `ObjectGUID` is `[guid]`). To compare them as strings, use `.Value` / `.Guid` or `.ToString()`.

### Deliberate omissions

- **`CannotChangePassword`**: omitted because it needs an ACL-based check and can't be read from a single LDAP attribute.
- **Name resolution of `PrimaryGroup`**: only `PrimaryGroupID` (a number) is provided, because resolving it requires rebuilding the domain SID.
- Any other attribute can be retrieved as is with `-Properties *`.

---

## Coexisting with RSAT

Where RSAT is installed, load ADSearch as a module and use module-qualified names to resolve the name clash.

```powershell
Import-Module ActiveDirectory
Import-Module \\server\ADSearch\ADSearch.psd1

ADSearch\Get-ADUser    -Identity yamada -Server dc01  # uses ADSearch
ActiveDirectory\Get-ADUser -Identity yamada           # uses RSAT
```

---

## Connection check

```powershell
Invoke-ADSearchSelfTest -Server dc01.corp.local
```

---

## Exchange configuration (v1.1)

Reads **configuration only**, as stored in the AD configuration partition, without connecting to an Exchange server (read-only). Dynamic information that is not in AD, such as mail contents, queues or service state, is not available. In an environment without Exchange, it warns and returns nothing.

```powershell
Get-ExchangeServer            -Server dc01.corp.local   # Servers, roles, versions
Get-ReceiveConnector          -Server dc01.corp.local   # Receive connectors
Get-SendConnector             -Server dc01.corp.local   # Send connectors
Get-AcceptedDomain            -Server dc01.corp.local   # Accepted domains
Get-RemoteDomain              -Server dc01.corp.local   # Remote domains
Get-TransportRule             -Server dc01.corp.local   # Transport rules (rule body as raw XML)
Get-MailboxDatabase           -Server dc01.corp.local   # Mailbox database configuration
Get-DatabaseAvailabilityGroup -Server dc01.corp.local   # DAG configuration
```

## Exchange recipients (v1.2)

Reads the AD attributes stamped by Exchange and lists recipient objects. No connection to an Exchange server is needed (LDAP to the domain NC only). In an environment without Exchange, it returns nothing.

> **Note**: attribute values are the snapshot stamped in AD. Some attribute names differ between AD and the Exchange Management Shell (for example EMS's `OrganizationalUnit` is in "domain/OU" form, while this library returns the parent DN string). Dynamic information (mailbox size, queues etc.) is not available. `RecipientFilter` of dynamic distribution groups is returned as the raw OPATH string.

```powershell
Get-Recipient             -Server dc01.corp.local   # All recipients (objects with mailNickname)
Get-Mailbox               -Server dc01.corp.local   # Mailbox users (with homeMDB)
Get-RemoteMailbox         -Server dc01.corp.local   # Remote mailboxes (hybrid)
Get-MailUser              -Server dc01.corp.local   # Mail users (external address, no local mailbox)
Get-MailContact           -Server dc01.corp.local   # Mail contacts (contact objects)
Get-DistributionGroup     -Server dc01.corp.local   # Distribution groups and mail-enabled security groups
Get-DynamicDistributionGroup -Server dc01.corp.local # Dynamic distribution groups
Get-DistributionGroupMember -Identity "All Staff" -Server dc01.corp.local  # Group members (non-recursive)
```

### Additional Exchange configuration commands (v1.2)

```powershell
Get-AddressList           -Server dc01.corp.local   # Address lists
Get-GlobalAddressList     -Server dc01.corp.local   # Global address lists (GAL)
Get-OfflineAddressBook    -Server dc01.corp.local   # Offline address books (OAB)
Get-EmailAddressPolicy    -Server dc01.corp.local   # Email address policies
```

The Identity parameter of the recipient commands accepts a DN, GUID or SID; a value containing `@` is matched against email address, UPN and proxyAddresses, and a value without `@` against alias (mailNickname), sAMAccountName, cn and name (close to how the Exchange Management Shell accepts it; more than one object can match).

### Hybrid / Entra Connect attributes

`Get-Mailbox` / `Get-RemoteMailbox` / `Get-MailUser` also return:

| Property | AD attribute | Use |
|---|---|---|
| `ImmutableId` | `msDS-ConsistencyGuid` (Base64) | Matching the Entra Connect source anchor |
| `ArchiveGuid` | `msExchArchiveGUID` | Checking EXO archive provisioning (not for MailUser) |
| `EmailAddressPolicyEnabled` | `msExchPoliciesExcluded` | Checking exclusion from address policies |

## v1.3 improvements (directory commands)

### Get-ADDefaultDomainPasswordPolicy
Fixed to read the password policy attributes correctly.

| Property | LDAP attribute | Notes |
|---|---|---|
| `DistinguishedName` | `distinguishedName` (domain NC) | |
| `MinPasswordLength` | `minPwdLength` | |
| `PasswordHistoryCount` | `pwdHistoryLength` | |
| `LockoutThreshold` | `lockoutThreshold` | |
| `MaxPasswordAge` | `maxPwdAge` | TimeSpan (converted from a negative 100 ns interval) |
| `MinPasswordAge` | `minPwdAge` | TimeSpan |
| `LockoutDuration` | `lockoutDuration` | TimeSpan |
| `LockoutObservationWindow` | `lockOutObservationWindow` | TimeSpan (the LDAP name has a capital O) |
| `ComplexityEnabled` | `pwdProperties` bit 0x1 | DOMAIN_PASSWORD_COMPLEX |
| `ReversibleEncryptionEnabled` | `pwdProperties` bit 0x10 | DOMAIN_PASSWORD_STORE_CLEARTEXT |

### Get-ADDomain
More domain information.

| Property | Source |
|---|---|
| `DNSRoot` / `DistinguishedName` / `Forest` | Existing |
| `NetBIOSName` | `nETBIOSName` of the crossRef in CN=Partitions,\<Config\> |
| `DomainMode` | `msDS-Behavior-Version` of the domain NC |
| `DomainSID` | `objectSid` of the domain NC |
| `PDCEmulator` | `fSMORoleOwner` of the domain NC → DC host name |
| `RIDMaster` | `fSMORoleOwner` of CN=RID Manager$,CN=System |
| `InfrastructureMaster` | `fSMORoleOwner` of CN=Infrastructure |

### Get-ADForest
More forest information.

| Property | Source |
|---|---|
| `Name` / `RootDomain` / `ForestMode` | Existing |
| `SchemaMaster` | `fSMORoleOwner` of the Schema NC |
| `DomainNamingMaster` | `fSMORoleOwner` of CN=Partitions,\<Config\> |
| `Domains` | `nCName` of the crossRefs in Partitions (those with `nETBIOSName`) → DNS names |
| `UPNSuffixes` | `uPNSuffixes` of CN=Partitions,\<Config\> (multi-valued) |
| `Sites` | Names of the site objects directly under CN=Sites,\<Config\> |

### Get-ADDomainController
Enumerates every nTDSDSA in the Config NC and returns all DCs (the old behaviour is kept under the `-Discover` switch).

| Property | Source |
|---|---|
| `Name` | CN of the server object |
| `HostName` | `dNSHostName` of the server object |
| `Site` | Site CN taken from the DN hierarchy |
| `IsGlobalCatalog` | nTDSDSA `options` bit 0x1 (NTDSDSA_OPT_IS_GC) |
| `IsReadOnly` | objectClass includes `nTDSDSARO` (RODC) |
| `Domain` / `Forest` | From rootDSE |

`-Identity` is a client-side wildcard match on Name/HostName. `-Filter '*'` or no filter returns all. Complex `-Filter` expressions are best effort for now (all DCs are returned).

### Get-ADTrust
Adds trust details.

| Property | Source |
|---|---|
| `DistinguishedName` / `Name` | Existing |
| `Source` | DNS name of the connected domain |
| `Target` | `trustPartner` |
| `Direction` | `trustDirection` (0=Disabled / 1=Inbound / 2=Outbound / 3=Bidirectional) |
| `TrustType` | `trustType` (1=Downlevel / 2=Uplevel / 3=MIT / 4=DCE) |
| `ForestTransitive` | `trustAttributes` bit 0x8 (TRUST_ATTRIBUTE_FOREST_TRANSITIVE) |
| `IntraForest` | `trustAttributes` bit 0x20 (TRUST_ATTRIBUTE_WITHIN_FOREST) |

### Get-ADServiceAccount
Adds the same `-SearchScope` / `-ResultSetSize` / `-Timeout` parameters as the other object commands.

### Get-ADOrganizationalUnit (adds LinkedGroupPolicyObjects)
Adds `LinkedGroupPolicyObjects` to the default output (an array of GPO DNs from the `gPLink` attribute).

---

## Pipeline input

These commands do not bind pipeline input directly to `-Identity`. To pipe objects, receive them in a variable and call the command from `ForEach-Object`.

```powershell
# Correct usage
$members = Get-ADGroupMember "IT-Staff" -Server dc01
$members | ForEach-Object { Get-ADUser $_.SamAccountName -Server dc01 }
```

---

## v1.1 improvements

- **More robust `Get-ADGroupMember -Recursive`**: now uses its own step-by-step recursion, with cycle detection, de-duplication and ranged retrieval for groups with more than 1,500 members, so fewer members are missed.
- **PowerShell-style `-Filter`**: supports grouping with parentheses and nested, mixed `-and`/`-or` (e.g. `"(Title -like '*Manager*' -or Title -like '*Director*') -and Enabled -eq '$true'"`). Raw LDAP filters are passed through unchanged.
- **Load and safety limits**: `-ResultSetSize` (maximum number of results) and `-Timeout` (seconds) on the main commands. Large queries show progress, and a warning is shown when a limit or timeout is reached. Unlimited by default (as before).

### Limitations (recursive members)
Members from other domains and foreign security principals (ForeignSecurityPrincipal) are outside the connected domain and are not expanded or resolved. Only references within a single domain are covered.

### Get-ADGroupMember and primaryGroupID members

Groups such as `Domain Users` / `Domain Computers` have an empty `member` attribute; their members are expressed through the members' `primaryGroupID` attribute. `Get-ADGroupMember` returns these members too, as RSAT does (both non-recursive and `-Recursive`).

## Detailed reference

→ **[ADSearch_Reference.html](ADSearch_Reference.html)** (in Japanese)

---

## Files

```
ADSearch/
  ADSearch.psd1          Module manifest (pass this to Import-Module)
  ADSearch.psm1          Module entry point
  ADSearch.ps1           Entry point for dot-sourcing
  Import-ADSearch.ps1    Loader for RemoteSigned environments
  ADSearch.Core.ps1      ADSI core (connection, search, ranged retrieval, limits/progress)
  ADSearch.Filters.ps1   Filter conversion (PowerShell-style parser)
  ADSearch.Objects.ps1   AD object commands
  ADSearch.Directory.ps1 Domain/forest/replication commands
  ADSearch.Gpo.ps1       GPO commands
  ADSearch.Dns.ps1       DNS commands
  ADSearch.Exchange.ps1           Exchange configuration (AD configuration partition)
  ADSearch.ExchangeRecipients.ps1 Exchange recipients (AD domain NC)
  ADSearch.SelfTest.ps1  Connection test
  forTest/               Test scripts and sample data generation
```

### Testing without AD (offline test)

You can check that the LDAP filters built from `-Filter` / `-Identity` are correct without connecting to a domain (queries to AD are replaced with a fake).

```powershell
powershell -ExecutionPolicy Bypass -File .\forTest\Test-ADSearchOffline.ps1
```

It has passed when the last line says `すべて OK` ("all OK"). The test that connects to AD is `forTest/test_all.ps1` (put the target in `test_all.config.json`).
