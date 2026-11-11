# 検証用クライアント（Windows 11）を Azure に作る手順

ADSearch の前提（ドメイン参加の Windows 11 Enterprise から、Domain Users の権限で使う）を確かめるための、使い捨てのクライアントの作り方です。DC（AD DS を入れた Windows Server）が同じ VNet に既にあることを前提にします。

作って、テストして、消すまでを 1 回の作業にします。置きっぱなしにすると、公開 IP と RDP の口が開いたままになります。

## 0. 値を決める

最初に一度、自分の環境の値を入れます。パスワードは画面に打ち込み、ファイルには書きません。

```powershell
$rg       = '<リソースグループ>'
$vnet     = '<VNet 名>'
$subnet   = 'default'
$dcIp     = '<DC の IP>'            # VNet の DNS にする
$domain   = '<ドメインの DNS 名>'    # 例: corp.example
$vmName   = 'win11-temp'
$location = 'japaneast'
$size     = 'Standard_B2ms'         # 2 vCPU・8 GB。B2s（4 GB）は 2 人がサインインするとメモリが尽きた
$localAdmin = '<ローカル管理者名>'
$localPass  = Read-Host 'ローカル管理者のパスワード' -AsSecureString
$myIp     = (Invoke-RestMethod https://api.ipify.org)   # RDP を自分の IP だけに開ける
```

## 1. イメージを選ぶ（新しい版の Enterprise）

イメージの名前は版ごとに変わるので、決め打ちせずに一覧から一番新しいものを取ります。ADSearch の想定は Enterprise なので `-ent` を選びます（Pro で足りるなら `-pro`）。

```powershell
$skus = az vm image list-skus -l $location -p MicrosoftWindowsDesktop -f windows-11 --query "[].name" -o tsv
$skus | Where-Object { $_ -match '^win11-\d\dh\d-ent$' } | Sort-Object   # 版の一覧を目で確かめる
$sku   = $skus | Where-Object { $_ -match '^win11-\d\dh\d-ent$' } | Sort-Object | Select-Object -Last 1
$image = "MicrosoftWindowsDesktop:windows-11:${sku}:latest"
$image
```

26H2 が一覧に無ければ、まだ Azure に出ていません。一番新しいもの（24H2 など）で進めます。Azure で Windows 11 を動かすには、対象のライセンス（Microsoft 365 E3/E5、Visual Studio サブスクリプションなど）が要ります。

## 2. VNet の DNS を DC にする（初回だけ）

```powershell
az network vnet update -g $rg -n $vnet --dns-servers $dcIp
```

## 3. VM を作る

```powershell
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($localPass))
az vm create `
  --resource-group $rg --name $vmName --location $location `
  --image $image --size $size `
  --admin-username $localAdmin --admin-password $plain `
  --vnet-name $vnet --subnet $subnet `
  --public-ip-sku Standard --security-type TrustedLaunch `
  --os-disk-delete-option Delete --nic-delete-option Delete --nsg-rule NONE
Remove-Variable plain

# RDP は自分の IP からだけ（az vm open-port は世界中に開くので使わない）
$nsg = az network nsg list -g $rg --query "[?contains(name, '$vmName')].name | [0]" -o tsv
az network nsg rule create -g $rg --nsg-name $nsg -n AllowRdpFromMe --priority 1000 `
  --source-address-prefixes "$myIp/32" --destination-port-ranges 3389 --access Allow --protocol Tcp

az vm list-ip-addresses -g $rg -n $vmName -o table
```

## 4. ドメインに参加させる（VM に RDP で入って）

```powershell
ipconfig /all | findstr "DNS"          # DNS サーバーが DC の IP になっているか
nltest /dsgetdc:<ドメインの DNS 名>      # DC が見つかるか
Add-Computer -DomainName <ドメインの DNS 名> -Credential (Get-Credential) -Restart
```

再起動したら、ローカル管理者で入り直して、テストに使う一般ユーザーが RDP で入れるようにします。

```powershell
(Get-CimInstance Win32_ComputerSystem) | Select-Object Name, Domain, PartOfDomain
Add-LocalGroupMember -Group 'Remote Desktop Users' -Member '<NetBIOS 名>\adsearch-reader'
```

## 5. テスト用のユーザーとデータ（DC の管理者の PowerShell で、初回だけ）

```powershell
# Domain Users だけの一般ユーザー
New-ADUser -Name adsearch-reader -SamAccountName adsearch-reader -AccountPassword (Read-Host -AsSecureString 'パスワード') -Enabled $true

# テスト用の OU・ユーザー・グループ・GPO（forTest\Setup-ADSearchTestData.ps1）
.\forTest\Setup-ADSearchTestData.ps1

# test_all で使うグループのメンバーと、OU の下のコンピューター
Add-ADGroupMember adsearch-olgrp -Members adsearch-reader
New-ADComputer adsearch-pc -Path 'OU=ADSearchTest,<ドメインの DN>'
```

## 6. テストを流す（VM に adsearch-reader で入って）

**このクライアントには一般ユーザーだけでサインインします。** 管理者と 2 人で入るとメモリが足りなくなり、PowerShell が OutOfMemory や「ServicePointManager の初期化に失敗」で落ちます。

```powershell
Get-ChildItem -Recurse -File | Unblock-File
# forTest\test_all.config.json を書き換える（Server・SampleUser=adsearch-reader・SampleGroup=adsearch-olgrp・SampleComputer=adsearch-pc・SampleOU）
Start-Transcript C:\Temp\test_all.log
.\forTest\test_all.ps1
Stop-Transcript
```

RSAT と並べて突き合わせるときは `forTest\Compare-ADSearchWithRsat.ps1` を使います（流す場所と使い方は、そのファイルの冒頭）。

## 7. 消す

```powershell
az vm delete -g $rg -n $vmName --yes
az network public-ip list -g $rg -o table   # 残りが無いか
az network nic list -g $rg -o table
az disk list -g $rg -o table
az network nsg list -g $rg -o table         # VM 用に作られた NSG は残るので消す
az network nsg delete -g $rg -n $nsg
```

DC 側でコンピューターのアカウントも消しておきます（`Remove-ADComputer <VM 名>`）。
