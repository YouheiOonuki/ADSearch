@{
    ModuleVersion     = '1.4.0'
    GUID              = '0ab80c38-cafb-4b36-b6be-e34949ab1861'
    RootModule        = 'ADSearch.psm1'

    Author            = ''
    Description       = 'RSAT 不要でドメイン一般ユーザーが AD/Exchange 構成情報を取得できる LDAP ラッパーライブラリ'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Get-ADUser',
        'Get-ADGroup',
        'Get-ADGroupMember',
        'Get-ADComputer',
        'Get-ADOrganizationalUnit',
        'Get-ADObject',
        'Get-ADServiceAccount',
        'Get-ADDomain',
        'Get-ADDomainController',
        'Get-ADForest',
        'Get-ADDefaultDomainPasswordPolicy',
        'Get-ADTrust',
        'Get-ADReplicationSite',
        'Get-ADReplicationSiteLink',
        'Get-ADReplicationSubnet',
        'Get-ADReplicationConnection',
        'Get-ADGpoLink',
        'Get-ADDnsRecord',
        'Get-ExchangeServer',
        'Get-ReceiveConnector',
        'Get-SendConnector',
        'Get-AcceptedDomain',
        'Get-RemoteDomain',
        'Get-TransportRule',
        'Get-MailboxDatabase',
        'Get-DatabaseAvailabilityGroup',
        'Get-AddressList',
        'Get-GlobalAddressList',
        'Get-OfflineAddressBook',
        'Get-EmailAddressPolicy',
        'Get-Recipient',
        'Get-Mailbox',
        'Get-RemoteMailbox',
        'Get-MailUser',
        'Get-MailContact',
        'Get-DistributionGroup',
        'Get-DynamicDistributionGroup',
        'Get-DistributionGroupMember',
        'Invoke-ADSearchSelfTest',
        # 診断
        'Get-ADUserHealth',
        'Search-ADAccount',
        'Get-ADComputerHealth'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
