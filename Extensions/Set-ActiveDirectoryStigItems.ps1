Function Set-ActiveDirectoryStigItems{
    <# 
      .Synopsis 
       Executes all of the Active Directory STIG settings included in the module. 
      .Description 
       The cmdlet runs each audit and configuration setting in the module. 
            .Example 
       Set-ActiveDirectoryStigItems 
       Configures all of the settings in this module 
      .Inputs 
       None 
      .Outputs 
       None 
      .Notes 
       NAME: Set-ActiveDirectoryStigItems 
       AUTHOR: Michael Haken 
       LASTEDIT: 12/5/2015 
      #Requires -Version 2.0 
     #>

    Param(
    [Parameter(Position=0)] 
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty  
    )

    Import-Module ActiveDirectory

    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty){
        if(Test-IsEnterpriseAdmin -UserName $Credential.UserName){
            Invoke-Command -ScriptBlock {
            Set-RIDManagerAuditing
            Set-PolicyContainerAuditing
            Set-MaxConnectionIdleTime
            Set-InfrastructureObjectAuditing
            Set-DsHeuristics
            Set-AdminSDHolderAuditing
            Set-DomainAuditing
            Set-DomainControllersOUAuditing
            Set-NTDSFilePermissions
            } -Credential $Credential
        }
        else{
            Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
            Exit 1
        }
    }
    else {
        if(Test-IsEnterpriseAdmin){
            Set-RIDManagerAuditing
            Set-PolicyContainerAuditing
            Set-MaxConnectionIdleTime
            Set-InfrastructureObjectAuditing
            Set-DsHeuristics
            Set-AdminSDHolderAuditing
            Set-DomainAuditing
            Set-DomainControllersOUAuditing
            Set-NTDSFilePermissions
        } 
    }
}

Function Set-NTDSFilePermissions{
<# 
  .Synopsis 
   Active Directory data files must have proper access control permissions. 
  .Description 
   The Set-NTDSFilePermissions cmdlet sets the required security permissions for the database files and log files. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AD-000001-DC 
  .Rule ID 
   SV-51175r2 
  .Vuln ID 
   V-8316 
  .Severity 
   CAT I 
        .Example 
   Set-NTDSFilePermissions 
         Configures the required permissions for the NTDS database and logs 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-NTDSFilePermissions 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

    Begin
    {
        $BuiltinAdministrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $CreatorOwner = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
        $LocalService = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalServiceSid, $null)

        $AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

        $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $LocalServiceAce = New-Object System.Security.AccessControl.FileSystemAccessRule($LocalService,
            @([System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    }

    Process{
        if (Test-IsEnterpriseAdmin){
            ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains | ForEach-Object {
                $_.DomainControllers | Select-Object -ExpandProperty Name | ForEach-Object {
                    Write-Host ("Reviewing Domain Contoller " + $_)
                    $NTDS = Invoke-Command -ScriptBlock { Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters" } -ComputerName $_
                    $DSA = $NTDS.'DSA Database File'
                    $Logs = $NTDS.'Database log files path'

                    $DSA = "\\$_\\" + $DSA.Replace(":\","$\").Replace("\", "\\")
                    $Logs = "\\$_\\" + $Logs.Replace(":\","$\").Replace("\", "\\")

                    $DSA = $DSA.Substring(0, $DSA.LastIndexOf("\\"))

                    $ACL1 = Get-Acl -Path $DSA

                    foreach ($Rule in $ACL1.Access) {
                        $ACL1.RemoveAccessRule($Rule) | Out-Null
                    }

                    $ACL1.AddAccessRule($AdministratorAce)
                    $ACL1.AddAccessRule($SystemAce)

                    Write-Host "Setting $DSA ACL"

                    Set-Acl -Path $DSA -AclObject $ACL1

                    Get-ChildItem -Path $DSA | ForEach-Object {
                        $Acl = Get-Acl -Path $_.FullName

                        foreach ($Rule in $Acl.Access) {
                            if (-not $Rule.IsInherited) {
                                $Acl.RemoveAccessRule($Rule) | Out-Null
                            }
                        }

                        Set-Acl -Path $_.FullName -AclObject $Acl
                    }

                    $ACL2 = Get-Acl -Path $Logs

                    foreach ($Rule in $ACL2.Access){
                        $ACL2.RemoveAccessRule($Rule) | Out-Null
                    }

                    $ACL2.AddAccessRule($AdministratorAce)
                    $ACL2.AddAccessRule($SystemAce)
                    $ACL2.AddAccessRule($LocalServiceAce)
                    $ACL2.AddAccessRule($CreatorOwnerAce)

                    Write-Host "Setting $Logs ACL"

                    Set-Acl -Path $Logs -AclObject $ACL2

                    Get-ChildItem -Path $Logs | ForEach-Object {
                        $Acl = Get-Acl -Path $_.FullName

                        foreach ($Rule in $Acl.Access) {
                            if (-not $Rule.IsInherited) {
                            $Acl.RemoveAccessRule($Rule) | Out-Null
                            }
                        }

                        Set-Acl -Path $_.FullName -AclObject $Acl
                    }
                }
            }
        }
        else{
            Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
            Exit 1
        }
    }
    End{}
}

Function Set-RIDManagerAuditing{
<# 
  .Synopsis 
   The Active Directory RID Manager$ object must be configured with proper audit settings. 
  .Description 
   The Set-RIDManagerAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AU-000212-DC 
  .Rule ID 
   SV-51174r2 
  .Vuln ID 
   V-39330 
  .Severity 
   CAT II 
        .Example 
   Set-RIDManagerAuditing 
         Configures the required auditing for the RID Manager object. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-RIDManagerAuditing 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
#>
    Begin {}

    Process{
        if (Test-IsEnterpriseAdmin){
            $Domains = Get-ForestDomains
            foreach ($Domain in $Domains){
                [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-RIDManagerAuditRuleSet
                Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=RID Manager$,CN=System"
            }
        }
        else{
            Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
            Exit 1
        }
    }
    End {}
}

Function Set-PolicyContainerAuditing
{
<# 
  .Synopsis 
   Active Directory Group Policy objects must be configured with proper audit settings. 
  .Description 
   The Set-PolicyContainerAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AU-000207-DC 
  .Rule ID 
   SV-51169r4 
  .Vuln ID 
   V-39325 
  .Severity 
   CAT II 
        .Example 
   Set-PolicyContainerAuditing 
         Configures the required auditing for the Group Policy container. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-PolicyContainerAuditing 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
    Begin {}

    Process{
        if (Test-IsEnterpriseAdmin){
            $Domains = Get-ForestDomains
            foreach ($Domain in $Domains){
                [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-PolicyContainerAuditRuleSet
                Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Policies,CN=System"
            }
        }
        else{
            Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
            Exit 1
        }
    }

    End {}
}

Function Set-MaxConnectionIdleTime
{
<# 
  .Synopsis 
   The directory service must be configured to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity. 
  .Description 
   The Set-MaxConnectionIdleTime cmdlet sets the timeout for inactive connections. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AD-000014-DC 
  .Rule ID 
   SV-51188r2 
  .Vuln ID 
   V-14831 
  .Severity 
   CAT III 
        .Example 
   Set-MaxConnectionIdleTime 
         Sets the connection idle time setting to 5 minutes (default). 
   Set-MaxConnectionIdleTime -MaxConnIdleTime 180 
   Sets the connection idle time setting to 3 minutes 
  .Parameter MaxConnIdleTime 
   The timeout for inactive network connections. Defaults to 5 minutes 
  .Parameter Credential 
   The credentials to use to make the change. The command must be run with Enterprise Admin credentials. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-MaxConnectionIdleTime 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
    Param
    (   
    [Parameter(Position=0)]
    [int]$MaxConnIdleTime = 300,
    [Parameter(Position=1)] 
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty  
    )

    Begin {}

    Process{
        $EntAdmin = $false
        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty){
            $EntAdmin = Test-IsEnterpriseAdmin -UserName $Credential.UserName
        }
        else {
            $EntAdmin = Test-IsEnterpriseAdmin
        }

        if ($EntAdmin){
            [string]$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser).RootDomain | Select-Object -ExpandProperty DistinguishedName
            [string]$SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + $DomainDN
            [Microsoft.ActiveDirectory.Management.ADEntity]$Policies = get-adobject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *
            $AdminLimits = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$Policies.lDAPAdminLimits

            for ($i = 0; $i -lt $AdminLimits.Count; $i++){
                if ($AdminLimits[$i] -match "MaxConnIdleTime=*"){
                    break
                }
            }   

            if ($i -lt $AdminLimits.Count){
                $AdminLimits[$i] = "MaxConnIdleTime=" + $MaxConnIdleTime 
            }
            else{
                $AdminLimits.Add("MaxConnIdleTime=" + $MaxConnIdleTime)
            }

            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $Credential -ne $null){
                Set-ADObject -Identity $Policies -Clear lDAPAdminLimits -Credential $Credential

                foreach ($Limit in $AdminLimits){
                    Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit} -Credential $Credential
                }
            }
            else{
                Set-ADObject -Identity $Policies -Clear lDAPAdminLimits

                foreach ($Limit in $AdminLimits){
                    Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit}
                }
            }

            return Get-ADObject -Identity $Policies -Properties * | Select-Object -ExpandProperty lDAPAdminLimits | Where-Object {$_ -match "MaxConnIdleTime=*"}
        }
        else{
            Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
            Exit 1
        }
    }
}

Function Set-InfrastructureObjectAuditing{
<# 
  .Synopsis 
   The Active Directory Infrastructure object must be configured with proper audit settings. 
  .Description 
   The Set-InfrastructureObjectAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AU-000209-DC 
  .Rule ID 
   SV-51171r2 
  .Vuln ID 
   V-39327 
  .Severity 
   CAT II 
        .Example 
   Set-InfrastructureObjectAudting 
         Configures the required auditing for the infrastructure object. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-InfrastructureObjectAudting 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
    Begin {}

    Process{
        if (Test-IsEnterpriseAdmin){
            $Domains = Get-ForestDomains
            foreach ($Domain in $Domains){
                [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-InfrastructureObjectAuditRuleSet
                Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Infrastructure"
            }
        }
        else{
            Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
            Exit 1
        }
    }

    End {}
}

Function Set-DsHeuristics
{
<# 
  .Synopsis 
   The dsHeuristics option can be configured to override the default restriction on anonymous access to AD data above the rootDSE level. Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access. 
  .Description 
   The Set-DsHeuristics cmdlet configures anonymous access to AD data. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Active Directory Forest V2R5 1/23/2015 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   AD.0230 
   WN12-AD-000013-DC 
  .Rule ID 
   SV-9052r2 
   SV-52838r1 
  .Vuln ID 
   V-8555 
   V-1070 
  .Severity 
   CAT II 
        .Example 
   Set-DsHeuristic 
         Removes anonymous access from the AD Forest 
   Set-DsHeuristic -AddAnonymousRead 
   Adds anonymous read access to the AD Forest 
  .Parameter AddAnonymousAccess 
   Adds anonymous read access to the AD Forest 
  .Parameter Credential 
   The credentials to run the command with. These must be an Enterprise Admin 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-DsHeuristics 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
    Param
    (
    [Parameter(Position = 0)]
    [switch]$AddAnonymousRead = $false,
    [Parameter(Position = 1)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin{
        Import-Module ActiveDirectory
    }

    Process{ 
        $DN = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain -Identity (Get-ADForest -Current LocalComputer).RootDomain).DistinguishedName
        $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
        [string]$Heuristic = $DirectoryService.dsHeuristics

        [array]$Array = @()
        if ($AddAnonymousRead){
            if($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty){
                $Array = $Heuristic.ToCharArray()
                if ($Array.Length -lt 7){
                    for ($i = $Array.Length; $i -lt 6; $i++){
                        $Array += "0"
                    }

                    $Array += "2"
                }
                else{
                    $Array[6] = "2"
                }
            }
            else{
                $Array = "0000002"
            }
        }
        else{
            if (($Heuristic -ne $null) -and ($Heuristic -ne [System.String]::Empty) -and ($Heuristic.Length -ge 7)){
                $Array = $Heuristic.ToCharArray()
                $Array[6] = "0";
            }
            else{
                $Array = "0000000"
            }
        }

        [string]$Heuristic = "$Array".Replace(" ", [System.String]::Empty)
        if ($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty){
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $Credential -ne $null){
                Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic} -Credential $Credential
            }
            else{
                Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
            }
        }
    }

    End{
        $Result = Get-ADObject -Identity $DirectoryService -Properties dsHeuristics | Select-Object -ExpandProperty dsHeuristics
        if ($Result -ne $null){
            Write-Host "dsHeuristics: " $Result
        }
        else{
            Write-Warning "dsHeuristics is not set"
            Exit 1
        }
    }
}

Function Set-DomainControllersOUAuditing
{
<# 
  .Synopsis 
   The Active Directory Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings. 
  .Description 
   The Set-DomainControllersOUAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AU-000210-DC 
  .Rule ID 
   SV-51172r2 
  .Vuln ID 
   V-39328 
  .Severity 
   CAT II 
        .Example 
   Set-DomainControllersOUAuditing 
         Configures the required auditing for the domain controller OU. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-InfrastructureObjectAudting 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
Begin {}

Process
{
if (Test-IsEnterpriseAdmin)
{
$Domains = Get-ForestDomains
foreach ($Domain in $Domains)
{
[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainControllersAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "OU=Domain Controllers"
}
}
else
{
Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
Exit 1
}
}

End {}
}

Function Set-DomainAuditing
{
<# 
  .Synopsis 
   The Active Directory Domain object must be configured with proper audit settings. 
  .Description 
   The Set-DomainAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AU-000208-DC 
  .Rule ID 
   SV-51170r2 
  .Vuln ID 
   V-39326 
  .Severity 
   CAT II 
        .Example 
   Set-DomainAudting 
         Configures the required auditing for the domain 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-DomainAuditing 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
Begin {}

Process
{
if (Test-IsEnterpriseAdmin)
{
$Domains = Get-ForestDomains
foreach ($Domain in $Domains)
{
[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainAuditRuleSet -DomainSID (Get-ADDomain -Identity $Domain | Select-Object -ExpandProperty DomainSID)
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN ""
}
}
else
{
Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
Exit 1
}
}

End {}
}

Function Set-AdminSDHolderAuditing
{
<# 
  .Synopsis 
   The Active Directory AdminSDHolder object must be configured with proper audit settings. 
  .Description 
   The Set-AdminSDHolderAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials. 
  .STIG 
   Windows Server 2012 / 2012 R2 Domain Controller V2R3 
  .STIG ID 
   WN12-AU-000211-DC 
  .Rule ID 
   SV-51173r2 
  .Vuln ID 
   V-39329 
  .Severity 
   CAT II 
        .Example 
   Set-AdminSDHolderAuditing 
         Configures the required auditing for the AdminSDHolder object. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-AdminSDHolderAuditing 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
    Begin {}

Process
    {
if (Test-IsEnterpriseAdmin)
{
$Domains = Get-ForestDomains
foreach ($Domain in $Domains)
{
[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-EveryoneAuditRuleSet
Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=AdminSDHolder,CN=System"
}
}
else
{
Write-Warning "Current user is not an Enterprise Admin, run the command again with Enterprise Admin credentials."
Exit 1
}
}

End{} 
}

Function Set-Auditing
{
<# 
  .Synopsis 
   Sets auditing on an Active Directory object. 
  .Description 
   The Set-Auditing cmdlet applies an audit rule set to an AD object. 
  .Parameter Domain 
   The domain to set the auditing in. 
  .Parameter ObjectCN 
   The CN of the object to set auditing on up to the domain part of the DN. This can be an emptry string to set auditing on the domain. 
  .Parameter Rules 
   The array of ActiveDirectoryAuditRule. 
        .Example 
   Set-Auditing -Domain contoso.com -ObjectCN "CN=Policies,CN=System" -Rules $Rules 
         Implements the audit rules. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Set-Auditing 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
    Param 
    (
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Domain,
        [Parameter(Mandatory=$true,Position=2)]
        [AllowEmptyString()]
        [String]$ObjectCN,
        [Parameter(Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]$Rules
    )

    Begin
    {
        $DN = (Get-ADDomain -Identity $Domain).DistinguishedName
        $DC = Get-ADDomainController -DomainName $Domain -Discover
[String[]]$Drives = Get-PSDrive | Select-Object -ExpandProperty Name
    }

    Process
    {
        if ($DC -ne $null)
        {
            if (Test-Connection -ComputerName $DC)
            {
                $TempDrive = "tempdrive"

                if ($Drives.Contains($TempDrive))
                {
                    Write-Host "An existing PSDrive exists with name $TempDrive, temporarily removing" -ForegroundColor Yellow
                    $OldDrive = Get-PSDrive -Name $TempDrive
                    Remove-PSDrive -Name $TempDrive
                }

                $Drive = New-PSDrive -Name $TempDrive -Root "" -PSProvider ActiveDirectory -Server $DC.Name

                if ($ObjectCN -eq "")
                {
                    $ObjectDN = $DN
                }
                else
                {
                    $ObjectDN = $ObjectCN + "," + $DN
                }

                $ObjectToChange = Get-ADObject -Identity $ObjectDN -Server $DC

                $Path = $Drive.Name + ":" + $ObjectToChange.DistinguishedName

                try
                {
                    $Acl = Get-Acl -Path $Path -Audit

                    if ($Acl -ne $null)
                    {
                        foreach ($Rule in $Rules)
                        {
                            $Acl.AddAuditRule($Rule)
                        }

                        Set-Acl -Path $Path -AclObject $Acl

                        Write-Results -Path $Path -Domain $Domain
                    }
                    else
                    {
                        Write-Warning "Could not retrieve the ACL for $Path"
                    }
                }
                catch [System.Exception]
                {
                    Write-Warning $_.ToString()
                }

                Remove-PSDrive $Drive

                if ($OldDrive -ne $null)
                {
                    Write-Host "Recreating original PSDrive" -ForegroundColor Yellow
                    New-PSDrive -Name $OldDrive.Name -PSProvider $OldDrive.Provider -Root $OldDrive.Root | Out-Null
                    $OldDrive = $null
                }
            }
            else
            {
                Write-Host "Could not contact domain controller $DC" -ForegroundColor Red
            }
        }
    }

    End {}
}

Function New-InfrastructureObjectAuditRuleSet
{
<# 
  .Synopsis 
   Creates the audit rule set for auditing the Infrastructure object. 
  .Description 
   The New-InfrastructureObjectAuditRuleSet cmdlet creates the required audit rule set for auditing the Infrastructure object. 
        .Example 
   New-InfrastructureObjectAuditRuleSet 
         Creates the audit rules. 
  .Inputs 
   None 
  .Outputs 
   [System.DirectoryServices.ActiveDirectoryAuditRule[]] 
  .Notes 
   NAME: New-InfrastructureObjectAuditRuleSet 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

Begin
{
$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
}

Process
{
$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
[System.Security.AccessControl.AuditFlags]::Failure, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

#$objectguid = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" #Guid for change infrastructure master extended right if it was needed
$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
[System.Security.AccessControl.AuditFlags]::Success,
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
}

End
{
return $Rules
}
}

Function New-DomainControllersAuditRuleSet
{
<# 
  .Synopsis 
   Creates the audit rule set for auditing the domain controller's OU. 
  .Description 
   The New-DomainControllerAuditRuleSet cmdlet creates the required audit rule set for auditing the Domain Controller's OU. 
        .Example 
   New-DomainControllersAuditRuleSet 
         Creates the audit rules. 
  .Inputs 
   None 
  .Outputs 
   [System.DirectoryServices.ActiveDirectoryAuditRule[]] 
  .Notes 
   NAME: New-DomainControllersAuditRuleSet 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

Begin
{
$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
}

Process
{
$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
[System.Security.AccessControl.AuditFlags]::Failure, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

$EveryoneWriteDaclSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
[System.Security.AccessControl.AuditFlags]::Success, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

$EveryoneWritePropertySuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
[System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
[System.Security.AccessControl.AuditFlags]::Success, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneWriteDaclSuccess, $EveryoneWritePropertySuccess)
}

End
{
return $Rules
}
}

Function New-EveryoneAuditRuleSet
{
<# 
  .Synopsis 
   Creates the audit rule set for Everyone success and failures. 
  .Description 
   The New-EveryoneAuditRuleSet cmdlet creates the an audit rule set for success and failure on Everyone. 
        .Example 
   New-EveryoneAuditRuleSet 
         Creates the audit rules. 
  .Inputs 
   None 
  .Outputs 
   [System.DirectoryServices.ActiveDirectoryAuditRule[]] 
  .Notes 
   NAME: New-EveryoneAuditRuleSet 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

Begin
{
    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
}

Process
{
$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll, 
[System.Security.AccessControl.AuditFlags]::Failure, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
[System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
[System.Security.AccessControl.AuditFlags]::Success, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        
[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
}

End
{
return $Rules
}
}

Function New-DomainAuditRuleSet
{
Param
    (
        [Parameter(Mandatory=$true,Position=0)]
        [System.Security.Principal.SecurityIdentifier]$DomainSID
    )

    $Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
    $DomainUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $domainSID)
    $Administrators = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $domainSID)
    
    $EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AuditFlags]::Failure, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $DomainUsersSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($DomainUsers, 
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $AdministratorsSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Administrators, 
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    $EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
        @([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner), 
        [System.Security.AccessControl.AuditFlags]::Success, 
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

    [System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $DomainUsersSuccess, $AdministratorsSuccess, $EveryoneSuccess)
    return $Rules
}

Function New-PolicyContainerAuditRuleSet
{
<# 
  .Synopsis 
   Creates the audit rule set for the Group Policy container. 
  .Description 
   The New-PolicyContainerAuditRuleSet cmdlet creates the required auditing rule set for group policy objects. 
        .Example 
   New-PolicyContainerAuditRuleSet 
         Creates the audit rules. 
  .Inputs 
   None 
  .Outputs 
   [System.DirectoryServices.ActiveDirectoryAuditRule[]] 
  .Notes 
   NAME: New-PolicyContainerAuditRuleSet 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>
Begin 
{
$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
}

Process 
{
$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
[System.Security.AccessControl.AuditFlags]::Failure, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    
$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl),
[System.Security.AccessControl.AuditFlags]::Success,
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
}

End 
{
return $Rules
}
}

Function New-RIDManagerAuditRuleSet
{
<# 
  .Synopsis 
   Creates the audit rule set for the RID Manager object. 
  .Description 
   The New-RIDManagerAuditRuleSet cmdlet sets the required auditing for the RID Manager object. 
        .Example 
   New-RIDManagerAuditRuleSet 
         Creates the audit rules. 
  .Inputs 
   None 
  .Outputs 
   [System.DirectoryServices.ActiveDirectoryAuditRule[]] 
  .Notes 
   NAME: New-RIDManagerAuditRuleSet 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

Begin
{
$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
}
    
Process
{
$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
[System.Security.AccessControl.AuditFlags]::Failure, 
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
[System.Security.AccessControl.AuditFlags]::Success,
[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)
}

End
{
return $rules
}
}

Function Get-ForestDomains
{
<# 
  .Synopsis 
   Gets all of the domains in the current Active Directory Forest. 
  .Description 
   The Get-ForestDomains cmdlet gets all of the domains in the current Active Directory Forest. 
        .Example 
   Get-ForestDomains 
         Gets all of the domains in the Forest of the logged on user. 
  .Inputs 
   None 
  .Outputs 
   [String[]] 
  .Notes 
   NAME: Get-ForestDomains 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

    Param
    ()

    Begin {}

    Process
    {
try
        {
            $Forest = Get-ADForest -Current LocalComputer
            $ForestDN = (Get-ADDomain -Identity ($Forest.RootDomain)).DistinguishedName
        }
        catch [System.Exception]
        {
            Write-Warning $_.ToString()
            Exit 1
        }
    }

    End 
{
return $Forest.Domains
}
}

function Write-Results
{
<# 
  .Synopsis 
   Writes the ACL configuration output results. 
  .Description 
   The Write-Results cmdlet outputs the modified ACL. 
  .Parameter Path 
   The path of the Active Directory object to get the ACL of. 
  .Parameter Domain 
   The domain the object belongs to. 
        .Example 
   Write-Results -Path "dc=contso,sc=com" -Domain "contoso.com" 
         Writes the current ACL of the domain object. 
  .Inputs 
   None 
  .Outputs 
   None 
  .Notes 
   NAME: Write-Results 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

    Param
    (
        [Parameter(Mandatory=$true)]
        [String]$Path,
        [Parameter(Mandatory=$true)]
        [String]$Domain
    )

    $acl = Get-Acl -Path $Path 
    Write-Host $Domain -ForegroundColor DarkRed -BackgroundColor White
    Write-Host ($Path.Substring($path.IndexOf(":") + 1)) -ForegroundColor DarkRed -BackgroundColor White
    $acl.Access
}

Function Test-IsEnterpriseAdmin
{
<# 
  .Synopsis 
   Tests if a user is a member of the Enterprise Admins group. 
  .Description 
   The Test-IsEnterpriseAdmin returns true if the user is in the group and false otherwise. 
        .Example 
   Test-IsEnterpriseAdmin 
         Determines if the user credentials being used to run the cmdlet have Enterprise Admin privileges 
   Test-IsEnterpriseAdmin -UserName "John Smith" 
   Determines if the user John Smith has Enterprise Admin privileges 
  .Parameter UserName 
   The user to test the group membership on. If no user name is specified, the cmdlet runs against WindowsIdentity Principal. 
  .Inputs 
   [string] 
  .Outputs 
   [bool] 
  .Notes 
   NAME: Test-IsEnterpriseAdmin 
   AUTHOR: Michael Haken 
   LASTEDIT: 12/5/2015 
  #Requires -Version 2.0 
 #>

Param (
[Parameter(Position=0)]
[string]$UserName = [System.String]::Empty
)

Begin {}

Process 
{
if ($UserName -ne [System.String]::Empty)
{
$CurrentUser = $UserName 
}
else
{
$CurrentUser = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
$CurrentUser = $CurrentUser.Substring($CurrentUser.IndexOf("\") + 1)
}

$Groups = Get-ADPrincipalGroupMembership -Identity $CurrentUser | Select-Object -Property Name,SID
$RootDomainSID = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser).RootDomain | Select-Object -ExpandProperty DomainSID
        
[Security.Principal.SecurityIdentifier]$EnterpriseAdminSID = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid, $RootDomainSID)
    
foreach ($Group in $Groups)
{
if ($Group.SID -eq $EnterpriseAdminSID) 
{
return $true;
} 
}

return $false
}

End{}
} 


#https://powershell.org/2013/04/02/get-local-admin-group-members-in-a-new-old-way-3/
Function Get-NetLocalGroup {
    [cmdletbinding()]

    Param(
    [Parameter(Position=0)]
    [ValidateNotNullorEmpty()]
    [object[]]$Computername=$env:computername,
    [ValidateNotNullorEmpty()]
    [string]$Group = "Administrators",
    [switch]$Asjob
    )

    Write-Verbose "Getting members of local group $Group"

    #define the scriptblock
    $sb = {
        Param([string]$Name = "Administrators")
        $members = net localgroup $Name | 
            where {$_ -AND $_ -notmatch "command completed successfully"} | 
            select -skip 4
        New-Object PSObject -Property @{
            Computername = $env:COMPUTERNAME
            Group = $Name
            Members=$members
        }
    } #end scriptblock

    #define a parameter hash table for splatting
    $paramhash = @{
        Scriptblock = $sb
        HideComputername=$True
        ArgumentList=$Group
    }

    if ($Computername[0] -is [management.automation.runspaces.pssession]) {
        $paramhash.Add("Session",$Computername)
    }
    else {
        $paramhash.Add("Computername",$Computername)
    }

    if ($asjob) {
        Write-Verbose "Running as job"
        $paramhash.Add("AsJob",$True)
    }

    #run the command
    Invoke-Command @paramhash | Select * -ExcludeProperty RunspaceID

} #end Get-NetLocalGroup