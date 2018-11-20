#========================================================================
#
#       Title: RemoveSTIGsAndGPOs
#     Created: 2018-02-26
#      Author: Richard tracy
#
#
# GOALS:
# Apply STIGS from Backup
#
#========================================================================
##*===============================================
##* VARIABLE DECLARATION
##*===============================================
## Variables: Domain Membership
[boolean]$IsMachinePartOfDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').PartOfDomain
[string]$envMachineWorkgroup = ''
[string]$envMachineADDomain = ''
[string]$envLogonServer = ''
[string]$MachineDomainController = ''
If ($IsMachinePartOfDomain) {
	[string]$envMachineADDomain = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
	Try {
		[string]$envLogonServer = $env:LOGONSERVER | Where-Object { (($_) -and (-not $_.Contains('\\MicrosoftAccount'))) } | ForEach-Object { $_.TrimStart('\') } | ForEach-Object { ([Net.Dns]::GetHostEntry($_)).HostName }
		# If running in system context, fall back on the logonserver value stored in the registry
		If (-not $envLogonServer) { [string]$envLogonServer = Get-ItemProperty -LiteralPath 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'DCName' -ErrorAction 'SilentlyContinue' }
		[string]$MachineDomainController = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
	}
	Catch { }
}
Else {
	[string]$envMachineWorkgroup = (Get-WmiObject -Class 'Win32_ComputerSystem' -ErrorAction 'SilentlyContinue').Domain | Where-Object { $_ } | ForEach-Object { $_.ToUpper() }
}
[string]$envMachineDNSDomain = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
[string]$envUserDNSDomain = $env:USERDNSDOMAIN | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
Try {
	[string]$envUserDomain = [Environment]::UserDomainName.ToUpper()
}
Catch { }


[psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
[string]$envOSName = $envOS.Caption.Trim()
[string]$envOSServicePack = $envOS.CSDVersion
[version]$envOSVersion = $envOS.Version
[string]$envOSVersionMajor = $envOSVersion.Major
[string]$envOSVersionMinor = $envOSVersion.Minor
[string]$envOSVersionBuild = $envOSVersion.Build
[string]$envOSVersionSimple = "$envOSVersionMajor.$envOSVersionMinor"
[int32]$envOSRoleType = $envOS.ProductType
[string]$enOSVersionRelease = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\" -Name ReleaseID).ReleaseId

$Dated = (Get-Date -Format yyyyMMdd)

## Variables: Script Name and Script Paths
[string]$scriptPath = $MyInvocation.MyCommand.Definition
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
[string]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[string]$scriptRoot = Split-Path -Path $scriptPath -Parent
[string]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName

#Get required folder and File paths
[string]$ExtensionsPath = Join-Path -Path $scriptRoot -ChildPath 'Extensions'
[string]$ModulesPath = Join-Path -Path $scriptRoot -ChildPath 'Modules'
[string]$ToolsPath = Join-Path -Path $scriptRoot -ChildPath 'Tools'
[string]$TempPath = Join-Path -Path $scriptRoot -ChildPath 'Temp'
[string]$LogsPath = Join-Path -Path $scriptRoot -ChildPath 'Logs'


[string]$BackupGPOPath = Join-Path -Path $scriptRoot -ChildPath 'GPO'
[string]$workingLogPath = Join-Path -Path $LogsPath -ChildPath $env:COMPUTERNAME
    New-Item $workingLogPath -ItemType Directory -ErrorAction SilentlyContinue


$extensions = Get-ChildItem -Path $ExtensionsPath -Recurse -Include *.ps1
foreach($extension in $extensions){
    Try{
        Write-Host "Loading extension: $($extension.FullName)" -ForegroundColor Cyan
        Import-Module $extension.FullName -ErrorAction SilentlyContinue
    }
    Catch {
        Write-Host "Unable to import the extensions." $_.Exception.Message -ForegroundColor White -BackgroundColor Red
    }
}

$modules = Get-ChildItem -Path $ModulesPath -Recurse -Include *.psd1
foreach($module in $modules){
    Try{
        Write-Host "Loading module: $($module.FullName)" -ForegroundColor Cyan
        Import-Module $module.FullName -ErrorAction SilentlyContinue -DisableNameChecking -NoClobber
    }
    Catch {
        Write-Host "Unable to import the module." $_.Exception.Message -ForegroundColor White -BackgroundColor Red
    }
}

##*===============================================
##* MAIN ROUTINE
##*===============================================
Write-Host "Removing all GPO security settings...please wait" -ForegroundColor Green
Start-Process "secedit" -ArgumentList "/configure /cfg $env:windir\inf\defltbase.inf /db defltbase.sdb /verbose" -RedirectStandardOutput "$workingLogPath\defltbase.stdout" -RedirectStandardError "$workingLogPath\defltbase.stderr" -Wait -NoNewWindow

Write-Host "Removing all GPO settings...please wait" -ForegroundColor Green
Remove-Item "$env:windir\System32\GroupPolicyUsers" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:windir\System32\GroupPolicy" -Force -Recurse -ErrorAction SilentlyContinue
Start-Process gpupdate -ArgumentList "/force"  -Wait -NoNewWindow

$additionalscripts = 0
$IISversion = Get-IISVersion
If($IISversion){
    Write-Host "Extension: Restoring IIS configurations..." -ForegroundColor Yellow
    Restore-WebConfiguration -Name BeforeIISSTig -ErrorAction SilentlyContinue
    $additionalscripts ++
}

$Pendingreboot = (Get-PendingReboot).RebootPending
# Launch text
write-host ""
write-host "-----------------------------------"
write-host "|      " -NoNewLine
write-host "Remove GPO Settings Summary" -NoNewLine -ForegroundColor Green
write-host "     |"
write-host "-----------------------------------"
write-host ""
If ($Pendingreboot){write-host "Policies Removed...please reboot" -ForegroundColor White -BackgroundColor Red}
Else{write-host "Policies removed..." -ForegroundColor Cyan}