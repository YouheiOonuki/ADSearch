# ADSearch

RSAT 不要で Active Directory 情報を取得できる PowerShell ライブラリです。  
`System.DirectoryServices`（ADSI/LDAP）を使用するため、ドメインに参加した一般端末・一般ユーザーで動作します。

紹介ページ: https://yorozu-craft.com/ADSearch/ ／ ライセンス: MIT（`LICENSE`）

---

## 動作環境

| 要件 | 内容 |
|---|---|
| PowerShell | 5.1 以上 |
| OS | ドメイン参加済み Windows 端末、または DC への LDAP（389/636）疎通が取れる端末 |
| 権限 | ドメインユーザーで動作（一部機能は管理者権限が必要） |
| RSAT | **不要** |

---

## 読み込み方法

### モジュールとして（推奨）

```powershell
Import-Module \\fileserver\tools\ADSearch\ADSearch.psd1
```

UNC パスからそのまま読み込めます。更新時は `-Force` を付けて再読み込みします。

```powershell
Import-Module \\fileserver\tools\ADSearch\ADSearch.psd1 -Force
```

### dot-source（スクリプト内・一時利用）

```powershell
. \\fileserver\tools\ADSearch\ADSearch.ps1
```

### 実行ポリシー（RemoteSigned 等）で読み込めない場合

ネットワーク共有上の `.ps1`/`.psm1` は RemoteSigned 環境では署名が必要で、`Import-Module` も `. .\ADSearch.ps1` も弾かれることがあります。その場合は同梱の `Import-ADSearch.ps1` を使うと、ファイルを文字列として読み込み ScriptBlock 化して取り込むため、ファイル実行ポリシーの影響を受けません。

```powershell
# ① ローダー自身も ScriptBlock 化して取り込む（1回だけ）
. ([scriptblock]::Create((Get-Content '\\fileserver\tools\ADSearch\Import-ADSearch.ps1' -Raw)))
# ② フォルダを指定して読み込む
Import-ADSearch -Path '\\fileserver\tools\ADSearch'
```

ローカルにコピーできる環境なら、コピー後に `Unblock-File *` してから通常どおり読み込む方法もあります。

---

## -Identity の仕様（破壊的変更）

`-Identity` は RSAT 準拠になりました。受理する形式は **DN / ObjectGUID / SID / sAMAccountName** のみです。従来対応していた `cn`/`name`/`UserPrincipalName`/`mail` での曖昧一致は、誤オブジェクト取得防止のため**廃止**しました。該当する識別子で検索したい場合は `-Filter` を使用してください。

オブジェクトの種類による違い（v1.4.1）:

| コマンド | `-Identity` で受理する形式 |
|---|---|
| `Get-ADUser` / `Get-ADGroup` / `Get-ADObject` など | DN / ObjectGUID / SID / sAMAccountName |
| `Get-ADComputer` / `Get-ADServiceAccount` | 上に加え、末尾 `$` を省いた名前（`Get-ADComputer pc001` で `pc001$` が見つかる。RSAT と同じ） |
| `Get-ADTrust` / `Get-ADReplication*` / Exchange 構成系（`Get-ExchangeServer` / `Get-AcceptedDomain` / `Get-AddressList` など） | DN / ObjectGUID / 名前（`name` 属性）。sAMAccountName を持たないオブジェクトのため |
| Exchange 受信者系（`Get-Mailbox` など） | 下記「Exchange 受信者（Recipient）系の取得」を参照 |

また、`-Identity` 指定時に対象オブジェクトが見つからない場合、従来は空を返していましたが、RSAT と同様に **throw（例外）** するようになりました。

```powershell
# 従来: cn/name/UPN/mail でも曖昧一致していた → 現在: sAMAccountName のみ一致
Get-ADUser -Identity yamada@corp.local -Server dc01   # 現在はエラーになる可能性あり。-Filter "mail -eq '...'" を使用

# 見つからない場合は例外
Get-ADUser -Identity nonexistent -Server dc01   # throw "オブジェクトが見つかりません (Identity='nonexistent')"
```

## -UseSSL の要件

`-UseSSL` を指定する場合は `-Server` の指定が必須です（serverless バインドは LDAPS 非対応のため）。`-Server` を省略して `-UseSSL` のみ指定するとエラーになります。

## 基本的な使い方

```powershell
# ユーザーを検索
Get-ADUser -Identity yamada -Server dc01.corp.local

# 条件で絞り込み
Get-ADUser -Filter "DisplayName -like '山田*'" -Server dc01.corp.local

# グループメンバーを取得（再帰）
Get-ADGroupMember -Identity "IT-Staff" -Recursive -Server dc01.corp.local

# コンピュータを検索
Get-ADComputer -Filter "OperatingSystem -like '*Server*'" -Server dc01.corp.local

# GPO リンクを確認
Get-ADGpoLink -Target "OU=Tokyo,OU=Corp,DC=corp,DC=local" -Server dc01.corp.local

# DNS レコードを確認（IP アドレス付き）
Get-ADDnsRecord -Name pc001 -ComputerName dc01.corp.local

# DNS の探索先パーティションを限定（子ドメインで ForestDnsZones だけ見たいとき等）
Get-ADDnsRecord -ComputerName dc01.corp.local -Partition Forest
```

> `Get-ADDnsRecord` は DomainDnsZones（ドメイン NC 配下）と ForestDnsZones（フォレストルート NC 配下）の両方を探索します。子ドメイン環境では両者の DN が異なります（例: `DC=DomainDnsZones,DC=main,DC=forestroot,DC=local` と `DC=ForestDnsZones,DC=forestroot,DC=local`）。`-Partition Domain` / `-Partition Forest` で片方に限定できます（既定は `Both`）。

### アカウント状態の切り分け（ログイントラブル）

`Get-ADUser` の既定出力に、ログインできない問い合わせの切り分け用プロパティを含めています。

| プロパティ | 意味 | 取得元 |
|---|---|---|
| `Enabled` | アカウント有効/無効 | userAccountControl |
| `LockedOut` | 現在ロックアウト中か | msDS-User-Account-Control-Computed（DC が計算） |
| `PasswordExpired` | パスワード期限切れか | 同上 |
| `AccountExpirationDate` | アカウント有効期限（無期限は空） | accountExpires |
| `PasswordExpiryDate` ※既定外 | パスワード期限日時 | msDS-UserPasswordExpiryTimeComputed |
| `PasswordNeverExpires` ※既定外 | 無期限パスワードか | userAccountControl |

```powershell
# ロックされている有効アカウントを抽出
Get-ADUser -Filter "Enabled -eq '$true'" -Server dc01 | Where-Object LockedOut

# パスワード期限日も見たい場合は明示指定
Get-ADUser -Identity yamada -Properties PasswordExpiryDate,PasswordNeverExpires -Server dc01
```

> `LockedOut` / `PasswordExpired` / `PasswordExpiryDate` は DC が計算する構築属性を読むため、ドメインポリシー（lockoutDuration / maxPwdAge）や FGPP を別途照会する必要がありません。値は照会した DC が計算した時点のものです。

### -Filter で使用できるプロパティ（拡張）

`-Filter` は以下のプロパティに対応しています（大文字小文字を区別しません）。

| 種別 | プロパティ | 使用可能な演算子 | 備考 |
|---|---|---|---|
| 日時（FileTime） | `LastLogonDate` / `PasswordLastSet` / `AccountExpirationDate` / `LastBadPasswordAttempt` / `AccountLockoutTime` | `-eq`/`-ne`/`-ge`/`-le`/`-gt`/`-lt` | 右辺は FileTime の int64、または日時の文字列（下記） |
| 日時（Generalized-Time） | `Created` / `Modified` | 同上 | 右辺は日時の文字列（下記） |
| UAC ビット | `PasswordNeverExpires` / `PasswordNotRequired` / `SmartcardLogonRequired` / `TrustedForDelegation` | `-eq`/`-ne`（`$true`/`$false`のみ） | `Enabled` と同様の拡張マッチルール（`:1.2.840.113556.1.4.803:`）を使用 |

日時の文字列は、PC の言語設定で解釈が変わらないよう、次の形式だけを受け付けます（時刻を省くと 0 時。タイムゾーンは PC の設定）:
`yyyy-MM-dd` / `yyyy/MM/dd`、それぞれに ` HH:mm` または ` HH:mm:ss`、および `yyyy-MM-ddTHH:mm:ss`。月・日・時は 1 桁でも構いません（`2026/1/5 9:05`）。`01/05/2026` や `Jan 5 2026` はエラーになります。

真偽値は `$true` / `'$true'` / `"$true"` のどれでも同じ意味です（v1.4.1 から。v1.4.0 までは引用符付きの `'$true'` が一致しませんでした）。

```powershell
# 90日以上パスワード未変更のユーザー（日付は yyyy-MM-dd で渡す）
Get-ADUser -Filter "PasswordLastSet -le '$((Get-Date).AddDays(-90).ToString('yyyy-MM-dd'))'" -Server dc01

# パスワード無期限のユーザー
Get-ADUser -Filter "PasswordNeverExpires -eq '`$true'" -Server dc01
```

> **サーバー側フィルター不可のプロパティ**: `LockedOut` / `PasswordExpired` / `PasswordExpiryDate` / `MachinePasswordAge` / `IPv4Address` / `IPv6Address` / `LinkedGroupPolicyObjects` は構築属性・クライアント計算値のため `-Filter` では使用できません（指定するとエラーになります）。取得後に `Where-Object` で絞り込んでください。

### コンピューターの信頼関係診断

`Get-ADComputer` の既定出力に `MachinePasswordAge`（マシンアカウントパスワードの経過日数）を含めています。

```powershell
# パスワードが 30 日以上更新されていない＝セキュアチャネル切れ（信頼関係失敗）の疑い
Get-ADComputer -Filter "OperatingSystem -like '*Windows 1*'" -Server dc01 |
    Where-Object { $_.MachinePasswordAge -gt 30 }
```

> **複製遅延の注意**: 既定の `LastLogonDate` は `lastLogonTimestamp` 由来で、最大約 14 日の複製遅延があります。「昨日ログインしたはずなのに古い」と出るのは正常動作です。正確な最終ログオンが必要な場合は全 DC の `lastLogon`（非複製属性）を集約する必要があります。

### アカウント棚卸し（Search-ADAccount）

RSAT の `Search-ADAccount` のサブセット互換です。非アクティブ・無効・期限切れ・パスワード期限切れ・パスワード無期限・ロックアウト中のアカウントを検索します。既定ではユーザー・コンピューターの両方が対象で、`-UsersOnly` / `-ComputersOnly` で絞り込めます。

| スイッチ | 内容 |
|---|---|
| `-AccountInactive` （`-TimeSpan` または `-DaysInactive` と併用） | 指定期間ログオンのないアカウント（未ログオンも含む） |
| `-AccountDisabled` | 無効化されているアカウント |
| `-AccountExpired` | アカウント有効期限切れ |
| `-PasswordExpired` | パスワード期限切れ |
| `-PasswordNeverExpires` | パスワード無期限設定 |
| `-LockedOut` | 現在ロックアウト中 |

```powershell
# 90日以上ログオンのないユーザー
Search-ADAccount -AccountInactive -DaysInactive 90 -UsersOnly -Server dc01

# ロックアウト中のユーザー
Search-ADAccount -LockedOut -Server dc01
```

> **複製遅延の注意**: `-AccountInactive` は `lastLogonTimestamp` を判定に使うため、最大約 14 日の複製遅延により結果に同程度の誤差を含みます（RSAT も同じ制約）。
> **クライアント側判定の注意**: `-PasswordExpired` / `-LockedOut` は DC が計算する構築属性のためサーバー側フィルターができず、取得後にクライアント側で絞り込みます。大規模環境では `-SearchBase` で対象を絞ることを推奨します。

### コンピュータ健全性診断（Get-ADComputerHealth）

`Get-ADUserHealth` のコンピュータ版です。信頼関係（セキュアチャネル）トラブルの一次切り分けに必要な情報を1オブジェクトで返します。

`-Identity` にはコンピュータ名を末尾 `$` の有無どちらでも指定できます（`sAMAccountName` は `PC001$` 形式のため、`$` 無しで指定した場合は内部でまず `$` 無しで検索し、見つからなければ `$` 付きで再試行します）。

```powershell
Get-ADComputerHealth -Identity PC001 -Server dc01.corp.local
Get-ADComputerHealth -Identity 'PC001$' -Server dc01.corp.local | Format-List
```

- **`MachinePasswordStale`**: `MachinePasswordAge -gt 30`（既定のマシンパスワード更新周期は30日）。`$true` の場合、そのPCが長期間オフラインだったか、セキュアチャネル（信頼関係）が壊れている可能性があります。PC側での `Test-ComputerSecureChannel` 実行を推奨します。
- **`DnsRegistered`**: `IPv4Address` または `IPv6Address` が取得できていれば `$true`。
- グループ所属は `Get-ADUserHealth` の非再帰パスと同様、`MemberOf` の各 DN から葉 CN を抽出します。

---

## RSAT 互換プロパティ

`Get-ADUser` および `Get-ADComputer` は、RSAT の同名コマンドレットが `-Properties` で返すプロパティ名と一致する属性を取得できます。既存の RSAT 向けスクリプトをそのまま利用できます。

```powershell
# 個人情報・組織情報
Get-ADUser yamada -Properties GivenName,Surname,Department,Title,Manager,Office,MobilePhone -Server dc01

# 住所・連絡先
Get-ADUser yamada -Properties StreetAddress,City,State,PostalCode,Country -Server dc01

# ログオン統計・ロック詳細
Get-ADUser yamada -Properties LogonCount,BadLogonCount,LastBadPasswordAttempt,AccountLockoutTime -Server dc01

# UAC ビットフラグ系
Get-ADUser yamada -Properties PasswordNotRequired,SmartcardLogonRequired,TrustedForDelegation -Server dc01

# コンピューター
Get-ADComputer pc001 -Properties OperatingSystemVersion,Location,ManagedBy,ServicePrincipalName,IPv6Address -Server dc01
```

### 主な追加プロパティ（ユーザー）

| プロパティ | LDAP 属性 | 備考 |
|---|---|---|
| `GivenName` / `Surname` | `givenName` / `sn` | 名・姓 |
| `Title` / `Department` / `Company` | `title` / `department` / `company` | 役職・部署・会社 |
| `Manager` / `Office` / `Division` | `manager` / `physicalDeliveryOfficeName` / `division` | DN・事務所・部門 |
| `OfficePhone` / `MobilePhone` / `HomePhone` / `Fax` | `telephoneNumber` / `mobile` / `homePhone` / `facsimileTelephoneNumber` | 電話系 |
| `StreetAddress` / `City` / `State` / `PostalCode` / `Country` / `POBox` | `streetAddress` / `l` / `st` / `postalCode` / `c` / `postOfficeBox` | 住所系 |
| `HomeDirectory` / `HomeDrive` / `ProfilePath` / `ScriptPath` | 同名 LDAP 属性 | プロファイル系 |
| `EmployeeID` / `EmployeeNumber` | `employeeID` / `employeeNumber` | 社員番号 |
| `LogonCount` / `BadLogonCount` | `logonCount` / `badPwdCount` | ログオン統計 |
| `LastBadPasswordAttempt` / `AccountLockoutTime` | `badPasswordTime` / `lockoutTime` | filetime 変換済み |
| `ProxyAddresses` / `PrimaryGroupID` | `proxyAddresses` / `primaryGroupID` | Exchange・グループ |
| `PasswordNotRequired` | `userAccountControl` bit 0x20 | PASSWD_NOTREQD フラグ |
| `SmartcardLogonRequired` | `userAccountControl` bit 0x40000 | SMARTCARD_REQUIRED フラグ |
| `TrustedForDelegation` | `userAccountControl` bit 0x80000 | TRUSTED_FOR_DELEGATION フラグ |

### 主な追加プロパティ（コンピューター）

| プロパティ | LDAP 属性 |
|---|---|
| `OperatingSystemVersion` / `OperatingSystemServicePack` | `operatingSystemVersion` / `operatingSystemServicePack` |
| `Location` / `ManagedBy` | `location` / `managedBy` |
| `ServicePrincipalName` | `servicePrincipalName` |
| `IPv6Address` | `dNSHostName` を DNS 解決して InterNetworkV6 アドレスを返す |

### 既定出力への追加

`Get-ADUser` の既定出力に `SID` と `ObjectGUID` を追加しました（RSAT の既定出力に含まれるため）。

> **SID / ObjectGUID の型**: RSAT と同型のオブジェクトで返します（`SID` は `[System.Security.Principal.SecurityIdentifier]`、`ObjectGUID` は `[guid]`）。文字列比較する場合は `.Value` / `.Guid` または `.ToString()` を使用してください。

### 意図的な省略

- **`CannotChangePassword`**: ACL ベースの判定が必要で単一 LDAP 属性から取得不可のため省略。
- **`PrimaryGroup`** の名前解決: ドメイン SID 再構成が必要なため `PrimaryGroupID`（数値）のみ提供。
- 上記以外の属性は `-Properties *` でそのまま取得できます。

---

## RSAT との共存

RSAT が入っている環境では、モジュールとして読み込むことで関数名の衝突を解決できます。

```powershell
Import-Module ActiveDirectory
Import-Module \\server\ADSearch\ADSearch.psd1

ADSearch\Get-ADUser    -Identity yamada -Server dc01  # ADSearch を使用
ActiveDirectory\Get-ADUser -Identity yamada           # RSAT を使用
```

---

## 接続確認

```powershell
Invoke-ADSearchSelfTest -Server dc01.corp.local
```

---

## Exchange 構成の取得（v1.1）

Exchange サーバーに接続せず、AD の構成パーティションに格納された **構成情報のみ** を取得します（読み取り専用）。メールの中身・キュー・サービス稼働状態など AD に存在しない動的情報は取得できません。Exchange 未導入環境では警告を出して空を返します。

```powershell
Get-ExchangeServer            -Server dc01.corp.local   # サーバー一覧・役割・バージョン
Get-ReceiveConnector          -Server dc01.corp.local   # 受信コネクタ
Get-SendConnector             -Server dc01.corp.local   # 送信コネクタ
Get-AcceptedDomain            -Server dc01.corp.local   # 受理ドメイン
Get-RemoteDomain              -Server dc01.corp.local   # リモートドメイン
Get-TransportRule             -Server dc01.corp.local   # トランスポートルール（本体は生XML）
Get-MailboxDatabase           -Server dc01.corp.local   # メールボックスDB構成
Get-DatabaseAvailabilityGroup -Server dc01.corp.local   # DAG構成
```

## Exchange 受信者（Recipient）系の取得（v1.2）

Exchange がスタンプした AD 属性を読み取り、受信者オブジェクトの一覧を取得します。Exchange サーバーへの接続は不要です（ドメイン NC の LDAP のみ）。Exchange 未導入環境では空を返します。

> **注意**: 属性値は AD にスタンプされたスナップショットです。AD と EMS で属性名が異なる場合があります（例: EMS の `OrganizationalUnit` は "domain/OU" 形式ですが、本ライブラリは親 DN 文字列を返します）。動的情報（メールボックスサイズ・キュー等）は取得不可。動的配布グループの `RecipientFilter` は OPATH 文字列をそのまま返します。

```powershell
Get-Recipient             -Server dc01.corp.local   # 全受信者（mailNickname 持ちオブジェクト）
Get-Mailbox               -Server dc01.corp.local   # メールボックスユーザー（homeMDB 持ち）
Get-RemoteMailbox         -Server dc01.corp.local   # リモートメールボックス（ハイブリッド）
Get-MailUser              -Server dc01.corp.local   # メールユーザー（外部アドレス、ローカルなし）
Get-MailContact           -Server dc01.corp.local   # メール連絡先（contactオブジェクト）
Get-DistributionGroup     -Server dc01.corp.local   # 配布グループ・メール対応セキュリティグループ
Get-DynamicDistributionGroup -Server dc01.corp.local # 動的配布グループ
Get-DistributionGroupMember -Identity "All Staff" -Server dc01.corp.local  # グループメンバー（非再帰）
```

### Exchange 構成パーティション追加コマンド（v1.2）

```powershell
Get-AddressList           -Server dc01.corp.local   # アドレスリスト
Get-GlobalAddressList     -Server dc01.corp.local   # グローバルアドレスリスト（GAL）
Get-OfflineAddressBook    -Server dc01.corp.local   # オフラインアドレス帳（OAB）
Get-EmailAddressPolicy    -Server dc01.corp.local   # 電子メールアドレスポリシー
```

受信者系コマンドの Identity パラメータには DN、GUID、SID のほか、`@` を含む値ならメールアドレス・UPN・proxyAddresses、含まない値なら alias（mailNickname）・sAMAccountName・cn・name が指定できます（Exchange 管理シェルに近い受け付け方。複数一致することがあります）。

### ハイブリッド / Entra Connect 向け属性

`Get-Mailbox` / `Get-RemoteMailbox` / `Get-MailUser` は以下も返します。

| プロパティ | AD 属性 | 用途 |
|---|---|---|
| `ImmutableId` | `msDS-ConsistencyGuid`（Base64） | Entra Connect ソースアンカーの突き合わせ |
| `ArchiveGuid` | `msExchArchiveGUID` | EXO アーカイブのプロビジョニング確認（MailUser を除く） |
| `EmailAddressPolicyEnabled` | `msExchPoliciesExcluded` | アドレスポリシー適用除外の確認 |

## v1.3 の強化点（ディレクトリ系コマンド）

### Get-ADDefaultDomainPasswordPolicy
パスワードポリシー属性を正確に取得するよう修正しました。

| プロパティ | 取得元 LDAP 属性 | 備考 |
|---|---|---|
| `DistinguishedName` | `distinguishedName`（ドメイン NC） | |
| `MinPasswordLength` | `minPwdLength` | |
| `PasswordHistoryCount` | `pwdHistoryLength` | |
| `LockoutThreshold` | `lockoutThreshold` | |
| `MaxPasswordAge` | `maxPwdAge` | TimeSpan（負の 100ns 間隔から変換） |
| `MinPasswordAge` | `minPwdAge` | TimeSpan |
| `LockoutDuration` | `lockoutDuration` | TimeSpan |
| `LockoutObservationWindow` | `lockOutObservationWindow` | TimeSpan（LDAP 名に大文字 O あり） |
| `ComplexityEnabled` | `pwdProperties` bit 0x1 | DOMAIN_PASSWORD_COMPLEX |
| `ReversibleEncryptionEnabled` | `pwdProperties` bit 0x10 | DOMAIN_PASSWORD_STORE_CLEARTEXT |

### Get-ADDomain
ドメイン情報を拡充しました。

| プロパティ | 取得元 |
|---|---|
| `DNSRoot` / `DistinguishedName` / `Forest` | 既存 |
| `NetBIOSName` | CN=Partitions,\<Config\> crossRef の `nETBIOSName` |
| `DomainMode` | ドメイン NC の `msDS-Behavior-Version` |
| `DomainSID` | ドメイン NC の `objectSid` |
| `PDCEmulator` | ドメイン NC の `fSMORoleOwner` → DC のホスト名 |
| `RIDMaster` | CN=RID Manager$,CN=System の `fSMORoleOwner` |
| `InfrastructureMaster` | CN=Infrastructure の `fSMORoleOwner` |

### Get-ADForest
フォレスト情報を拡充しました。

| プロパティ | 取得元 |
|---|---|
| `Name` / `RootDomain` / `ForestMode` | 既存 |
| `SchemaMaster` | Schema NC の `fSMORoleOwner` |
| `DomainNamingMaster` | CN=Partitions,\<Config\> の `fSMORoleOwner` |
| `Domains` | Partitions の crossRef（`nETBIOSName` あり）の `nCName` → DNS 名 |
| `UPNSuffixes` | CN=Partitions,\<Config\> の `uPNSuffixes`（多値） |
| `Sites` | CN=Sites,\<Config\> 直下の site オブジェクト名 |

### Get-ADDomainController
Config NC の nTDSDSA を全件列挙してすべての DC を返します（旧動作は `-Discover` スイッチで維持）。

| プロパティ | 取得元 |
|---|---|
| `Name` | サーバーオブジェクトの CN |
| `HostName` | サーバーオブジェクトの `dNSHostName` |
| `Site` | DN 階層から抽出したサイト CN |
| `IsGlobalCatalog` | nTDSDSA `options` bit 0x1（NTDSDSA_OPT_IS_GC） |
| `IsReadOnly` | objectClass に `nTDSDSARO` を含む場合（RODC） |
| `Domain` / `Forest` | rootDSE から |

`-Identity` はクライアント側で Name/HostName のワイルドカード一致。`-Filter '*'` または省略で全件返す。複雑な `-Filter` は現時点でベストエフォート（全件返す）。

### Get-ADTrust
信頼関係の詳細情報を追加しました。

| プロパティ | 取得元 |
|---|---|
| `DistinguishedName` / `Name` | 既存 |
| `Source` | 接続ドメインの DNS 名 |
| `Target` | `trustPartner` |
| `Direction` | `trustDirection`（0=Disabled / 1=Inbound / 2=Outbound / 3=Bidirectional） |
| `TrustType` | `trustType`（1=Downlevel / 2=Uplevel / 3=MIT / 4=DCE） |
| `ForestTransitive` | `trustAttributes` bit 0x8（TRUST_ATTRIBUTE_FOREST_TRANSITIVE） |
| `IntraForest` | `trustAttributes` bit 0x20（TRUST_ATTRIBUTE_WITHIN_FOREST） |

### Get-ADServiceAccount
他のオブジェクト系コマンドと同じ `-SearchScope` / `-ResultSetSize` / `-Timeout` パラメーターを追加しました。

### Get-ADOrganizationalUnit（LinkedGroupPolicyObjects 追加）
既定出力に `LinkedGroupPolicyObjects` を追加しました（`gPLink` 属性から GPO DN 配列を返す）。

---

## パイプライン入力について

これらのコマンドは `-Identity` にパイプラインからの値を直接バインドしません。パイプラインで渡す場合は変数に受けてから `ForEach-Object` で呼び出してください。

```powershell
# 正しい使い方
$members = Get-ADGroupMember "IT-Staff" -Server dc01
$members | ForEach-Object { Get-ADUser $_.SamAccountName -Server dc01 }
```

---

## v1.1 の強化点

- **`Get-ADGroupMember -Recursive` を堅牢化**：自前の段階的再帰に変更し、循環参照の検出・重複排除・1500件超グループの range 取得に対応。取りこぼしを低減。
- **`-Filter` の PowerShell 風強化**：括弧によるグループ化と `-and`/`-or` の入れ子・混在に対応（例：`"(Title -like '*Manager*' -or Title -like '*Director*') -and Enabled -eq '$true'"`）。生の LDAP フィルターはそのまま素通し。
- **負荷・安全策**：`-ResultSetSize`（件数上限）/`-Timeout`（秒）を主要コマンドに追加。大量取得時は進捗表示、上限・タイムアウト到達時は警告。既定は無制限（従来どおり）。

### 制限事項（再帰メンバー）
別ドメインのメンバーや外部セキュリティプリンシパル（ForeignSecurityPrincipal）は、接続先ドメイン外のため展開・解決されません。単一ドメイン内の参照が対象です。

### Get-ADGroupMember の primaryGroupID メンバー対応

`Domain Users` / `Domain Computers` 等のグループは `member` 属性が空で、メンバーはメンバー側の `primaryGroupID` 属性で表現されます。`Get-ADGroupMember` はこの経路のメンバーも RSAT と同様に返します（非再帰・`-Recursive` の両方に対応）。

## 詳細リファレンス

→ **[ADSearch_Reference.html](ADSearch_Reference.html)**

---

## ファイル構成

```
ADSearch/
  ADSearch.psd1          モジュールマニフェスト（Import-Module で指定）
  ADSearch.psm1          モジュールエントリポイント
  ADSearch.ps1           dot-source 用エントリポイント
  Import-ADSearch.ps1    RemoteSigned 環境用ローダー
  ADSearch.Core.ps1      ADSI コア関数（接続・検索・range取得・上限/進捗）
  ADSearch.Filters.ps1   フィルター変換（PowerShell 風パーサ）
  ADSearch.Objects.ps1   AD オブジェクト取得関数
  ADSearch.Directory.ps1 ドメイン/フォレスト/レプリケーション関数
  ADSearch.Gpo.ps1       GPO 関数
  ADSearch.Dns.ps1       DNS 関数
  ADSearch.Exchange.ps1           Exchange 構成取得（AD 構成パーティション）
  ADSearch.ExchangeRecipients.ps1 Exchange 受信者取得（AD ドメイン NC）
  ADSearch.SelfTest.ps1  接続テスト
  forTest/               テスト用スクリプト・サンプルデータ生成
```

### AD なしで確かめる（オフラインテスト）

`-Filter` / `-Identity` から作る LDAP フィルターが正しいかを、ドメインに接続せずに確かめられます（AD への問い合わせは偽物に差し替えます）。

```powershell
powershell -ExecutionPolicy Bypass -File .\forTest\Test-ADSearchOffline.ps1
```

最後に「すべて OK」と出れば成功です。AD に接続して動作を見るテストは `forTest/test_all.ps1`（`test_all.config.json` に接続先を書く）です。
