#========================================================================
#
#       Title: ApplySTIGBySCAPs
#     Created: 2018-02-26
#      Author: Richard tracy
#
#
# GOALS:
# Parse ccdf file from STIG
# bind it with latest control tool
# build confguration files for all rules
#
# Inspiration: http://www.entelechyit.com/2017/01/02/powershell-and-disa-nist-stigs-part-1/
#            
#Configuration Settings
# Place semicolon (;) in front for comments
#
# [Validate]   = Section
# Ignore       = True/False
# ScriptBlock  = Powershell scriptblock; end with semicolon. Multiple Scriptblock keys will be combined
# Functon      = Function script must be added in scripts folder. Mutiple function will be ignored; last one ran
# Argument     = 
# ScriptFile   =
#
# [Remediate]  = Section
# Ignore       = True/False
# RunAlways    = True/False
# LGPO         = Uses LGPO.exe; Applies registry settings and updates local GPO
# GPTemplate   = Uses LGPO.exe; Applies security template
# 
#========================================================================
##*===============================================
##* PATH VARIABLE DECLARATION
##*===============================================
## Variables: Script Name and Script Paths
[string]$scriptPath = $MyInvocation.MyCommand.Definition
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)
[string]$scriptFileName = Split-Path -Path $scriptPath -Leaf
[string]$scriptRoot = Split-Path -Path $scriptPath -Parent
[string]$invokingScript = (Get-Variable -Name 'MyInvocation').Value.ScriptName
#  Get the invoking script directory
If ($invokingScript) {
	#  If this script was invoked by another script
	[string]$scriptParentPath = Split-Path -Path $invokingScript -Parent
}
Else {
	#  If this script was not invoked by another script, fall back to the directory one level above this script
	[string]$scriptParentPath = (Get-Item -LiteralPath $scriptRoot).Parent.FullName
}

#Get required folder and File paths
[string]$ExtensionsPath = Join-Path -Path $scriptRoot -ChildPath 'Extensions'
[string]$ModulesPath = Join-Path -Path $scriptRoot -ChildPath 'Modules'
[string]$ToolsPath = Join-Path -Path $scriptRoot -ChildPath 'Tools'
[string]$TempPath = Join-Path -Path $scriptRoot -ChildPath 'Temp'
[string]$LogsPath = Join-Path -Path $scriptRoot -ChildPath 'Logs'
[string]$BackupGPOPath = Join-Path -Path $scriptRoot -ChildPath 'GPO'

[string]$workingLogPath = Join-Path -Path $LogsPath -ChildPath $env:COMPUTERNAME
    New-Item $workingLogPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
[string]$workingTempPath = Join-Path -Path $TempPath -ChildPath $env:COMPUTERNAME
    New-Item $workingTempPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

## Dot source the required Functions
Try {
	[string]$moduleToolkitMain = "$ExtensionsPath\STIGSCAPToolMainExtension.ps1"
	If (-not (Test-Path -Path $moduleToolkitMain -PathType Leaf)) { Throw "Extension script does not exist at the specified location [$moduleToolkitMain]." }
    Else{
        . $moduleToolkitMain 
        Write-Host "Loading main extension:       $moduleToolkitMain" -ForegroundColor Green
    }
}
Catch {
	[int32]$mainExitCode = 60008
	Write-Error -Message "Module [$moduleToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
	Exit $mainExitCode
}

#try to load any additional scripts
$extensions = Get-ChildItem -Path $ExtensionsPath -Recurse -Include *.ps1 -Exclude STIGSCAPToolMainExtension.ps1
foreach($extension in $extensions){
    Try{
        Write-Host "Loading additional extension: $($extension.FullName)" -ForegroundColor Cyan
        Import-Module $extension.FullName -ErrorAction SilentlyContinue
    }
    Catch {
        [int32]$mainExitCode = 60008
        Write-Error -Message "Module [$_] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
    }
}

#try to load any additional modules
$modules = Get-ChildItem -Path $ModulesPath -Recurse -Include *.psd1
foreach($module in $modules){
    Try{
        Write-Host "Loading additional module:    $($module.FullName)" -ForegroundColor Cyan
        Import-Module $module.FullName -ErrorAction SilentlyContinue -DisableNameChecking -NoClobber
    }
    Catch {
        Write-Host "Unable to import the module." $_.Exception.Message -ForegroundColor White -BackgroundColor Red
    }
}

##*===============================================
##* MAIN ROUTINE
##*===============================================

# download and unzip your benchmark from DIA NISTA 
# from: http://iase.disa.mil/stigs/compilations/Pages/index.aspx
$BenchMarkFilePath = "$scriptRoot\STIGS\U_Windows_Server_2016_V1R3_STIG\U_Windows_Server_2016_V1R3_Manual_STIG\U_Windows_Server_2016_STIG_V1R3_Manual-xccdf.xml"

# Download and unzip the latest control list 
# from: http://iase.disa.mil/stigs/cci/Pages/index.aspx
$CCIControlFile = "$scriptRoot\CCI\U_CCI_List.xml"

# This is the NIST Revision we are wanting to reference:
$CCIFilter = 'NIST SP 800-53 Revision 4'

$ToolOption = "Remediate"     #ValidateOnly or Remediate

##*===============================================
##* MAIN
##*===============================================
# Load the content as XML
[xml]$Stigx = Get-Content -Path $BenchMarkFilePath -EA Stop
[xml]$CCIx = Get-Content -Path $CCIControlFile -EA Stop

# start by parsing the xccdf benchmark
if($Stigx){
    $StigCollection = @()
     # loop through the xccdf benchmark collecting data into an object collection
    foreach ($rule in $StigX.Benchmark.Group.Rule){
        # create a new PSObject collecting and stripping out as required.
        $STIG = New-Object -TypeName PSObject -Property ([ordered]@{
            RuleID    = $rule. id
            Version    = $rule.version
            RuleTitle = $rule.title 
            Severity = $rule.severity
            VulnerabilityDetails = $($($($rule.description) -split '</VulnDiscussion>')[0] -replace '<VulnDiscussion>', '')
            Check = $rule.check.'check-content'
            Fix = $rule.fixtext.'#text'
            ControlIdentifier = $rule.ident.'#text'
            Control = $null # control is null as it will be added from the CCI List
        })
        $StigCollection += $STIG
    }# close foreach
}# close if

# loop through the Stig Collection updating the Control information pulled from the U_CCI_List.xml
foreach($StigObj in $StigCollection){
    foreach($CciItem in $CCIX.cci_list.cci_items.cci_item){
        if($CciItem.Id -EQ $StigObj.ControlIdentifier){
            # filter the control version by the title
            if($CciItem.references.reference.title -EQ $CCIFilter){
                $StigObj.Control = $CciItem.references.reference.index
            }
        }
    }
}

$evalcnt = 0
$notevalcnt = 0
$passedeval = 0
$failedeval = 0
$appliedcnt = 0
$missingcnt = 0
$ignoredcnt = 0
$errorcnt = 0
$result = $false

# loop through the Stig Collection to pull Version info; then find the config ini for it
foreach($StigObj in $StigCollection){
    $File = "$scriptRoot\Configs\$($StigObj.Version).ini"
    
    If (Test-Path -Path $File -ErrorAction SilentlyContinue){
        Write-Host "Configuration file was found for: $($StigObj.Version)" -ForegroundColor Cyan
        
        #if File found, parse the validation section
        $ConfigFile = Get-IniContent -filePath $File
        If ($ConfigFile.Validate.Ignore -eq "False"){
            
            #if scriptblock was found
            If ($ConfigFile.Validate.ScriptBlock){
                $scriptBlock = [Scriptblock]::Create($ConfigFile.Validate.ScriptBlock)
                try{
                    $result = Invoke-Command -ScriptBlock $scriptBlock
                    Write-Verbose "    RUNNING COMMAND: Invoke-Command -ScriptBlock $scriptBlock"
                    Write-Verbose $result
                    $evalcnt ++
                }
                Catch {
                    Write-Host "    VALIDATE: ScriptBlock failed to run. Check syntax in file: $File" -ForegroundColor DarkMagenta
                    $notevalcnt ++
                }
            }

            #if function was found
            If ($ConfigFile.Validate.Function){
               $scriptBlock = [Scriptblock]::Create($ConfigFile.Validate.Function)
                try{
                    $result = Invoke-Command -ScriptBlock $scriptBlock
                    Write-Verbose "    RUNNING COMMAND: Invoke-Command -ScriptBlock $scriptBlock"
                    Write-Verbose $result
                    $evalcnt ++
                }
                Catch {
                    Write-Host "    VALIDATE: Function failed to run. Check syntax in file: $File" -ForegroundColor DarkMagenta
                    $notevalcnt ++
                }
            }
            If ($result){
                Write-Host "    VALIDATE: Results passed. Policy already implemented!" -ForegroundColor DarkGreen
                $passedeval ++
            }
            Else{
                Write-Host "    VALIDATE: Results did not pass. Policy is not already implemented" -ForegroundColor DarkYellow
                $failedeval ++
            }
        }
        Else {
            Write-Host "    VALIDATE: Set to be ignored." -ForegroundColor DarkYellow
            $notevalcnt ++
        }
        
        <#
        QUERY: if validation results are TRUE and ignore is TRUE or RunAlways is TRUE. ACTION: run the remediate section
        QUERY: if validation results are FALSE and ignore is FALSE or RunAlways is TRUE. ACTION: run the remediate section
        QUERY: if validation results are TRUE and ignore is FALSE or RunAlways is TRUE. ACTION: run the remediate section
        QUERY: if validation results are FALSE and ignore is TRUE or RunAlways is TRUE. ACTION: run the remediate section
        QUERY: if validation results are FALSE and ignore is FALSE or RunAlways is NULL. ACTION: run the remediate section
        QUERY: if validation results are TRUE and ignore is FALSE or RunAlways is NULL. ACTION: Do Nothing
        QUERY: if validation results are TRUE and ignore is TRUE or RunAlways is NULL. ACTION: Do Nothing
        #>
        $runRemediate = 0
        If ((!$result) -and ($ConfigFile.Remediate.Ignore -eq "False")){$runRemediate ++}
        If($ConfigFile.Remediate.RunAlways -eq "True"){$runRemediate ++}
        
        
        If($runRemediate -gt 0){
            If ($ConfigFile.Remediate.LGPO){
                #build LGPO script file
                $Outfile = "$backupTempPath\$($StigObj.Version)_LGPO.stdOut"
                $ErrorFile = "$backupTempPath\$($StigObj.Version)_LGPO.stdError"
                $ConfigFile.Remediate.LGPO | Out-File $backupTempPath\LGPO.txt -Force
                $result = Start-Process "$ToolsPath\LGPO.exe" -ArgumentList "/t $backupTempPath\LGPO.txt /v" -PassThru -Wait -NoNewWindow -RedirectStandardOutput $Outfile -RedirectStandardError $ErrorFile -Verbose
                If ($result.ExitCode -eq 0){
                    Write-Host "    REMEDIATE: Successfully applied policy: $($StigObj.RuleID)" -ForegroundColor Green
                    $appliedcnt ++
                }
                Else{
                    Write-Host "    REMEDIATE: Unable to apply policy: $($StigObj.RuleID), exit code: $($result.ExitCode)" -ForegroundColor Red
                    Write-Host "               View '$ErrorFile' for more details" -ForegroundColor Red
                    $errorcnt ++
                }
            }

            If ($ConfigFile.Remediate.GPTemplate){
                #build LGPO script file
                $Outfile = "$backupTempPath\$($StigObj.Version)_GPTemplate.stdOut"
                $ErrorFile = "$backupTempPath\$($StigObj.Version)_GPTemplate.stdError"

                "[Unicode]
                Unicode=yes
                [Version]
                signature=`"`$CHICAGO`$`"
                Revision=1" | Out-File | Out-File $backupTempPath\GPTemplate.inf -Force
                $ConfigFile.Remediate.GPTemplate | Out-File $backupTempPath\GPTemplate.inf -Append
                $result = Start-Process "$ToolsPath\LGPO.exe" -ArgumentList "/s $backupTempPath\GPTemplate.inf /v" -PassThru -Wait -NoNewWindow -RedirectStandardOutput $Outfile -RedirectStandardError $ErrorFile -Verbose
                If ($result.ExitCode -eq 0){
                    Write-Host "    REMEDIATE: Successfully applied policy: $($StigObj.RuleID)" -ForegroundColor Green
                    $appliedcnt ++
                }
                Else{
                    Write-Host "    REMEDIATE: Unable to apply policy: $($StigObj.RuleID), exit code: $($result.ExitCode)" -ForegroundColor Red
                    Write-Host "               View '$ErrorFile' for more details" -ForegroundColor Red
                    $errorcnt ++
                }
            }
                
            If ($ConfigFile.Remediate.SecPol){
                #build LGPO script file
                $Outfile = "$backupTempPath\$($StigObj.Version)_SecPol.stdOut"
                $ErrorFile = "$backupTempPath\$($StigObj.Version)_SecPol.stdError"

                #get each SecPol line in INI
                $SecPols = $ConfigFile.Remediate.SecPol
                Foreach ($SecPol in $SecPols){
                    $Part = $SecPol.split(",")
                    $Area = $Part[0]
                    $Key = $Part[1]
                    $Value = $Part[2]
                }
                #backup Security Policy
                $SeceditResults = secedit /export /areas $Area /cfg "$backupTempPath\SecPol.cfg"
                   Copy-Item "$backupTempPath\SecPol.cfg" $backupTempPath\SecPol-backup-$Dated.cfg -Force -ErrorAction SilentlyContinue

                If($Area -eq "SECURITYPOLICY"){$CfgSection = 'System Access'}
                switch($Area){
                    #Includes Account Policies, Audit Policies, Event Log Settings and Security Options.
                    "SECURITYPOLICY" {$CfgSection = 'System Access'}
                    #Includes Restricted Group settings
                    "GROUP_MGMT" {} 
                    #Includes User Rights Assignment
                    "USER_RIGHTS" {} 
                    #Includes Registry Permissions
                    "REGKEYS" {}
                    #Includes File System permissions
                    "FILESTORE" {}
                    #Includes System Service settings
                    "SERVICES" {}
                }
                $currentValue = (Get-IniContent "$backupTempPath\SecPol.cfg").$CfgSection.$key
                (Get-Content "$backupTempPath\SecPol.cfg").replace("$Key = $currentValue", "$Key = $Value") | Out-File "$backupTempPath\SecPol.cfg"

                $result = Start-Process secedit -ArgumentList "/configure /db secedit.sdb /cfg ""$backupTempPath\SecPol.cfg""" -PassThru -Wait -NoNewWindow -RedirectStandardOutput $Outfile -RedirectStandardError $ErrorFile -Verbose
                If ($result.ExitCode -eq 0){
                    Write-Host "    REMEDIATE: Successfully applied policy: $($StigObj.RuleID)" -ForegroundColor Green
                    $appliedcnt ++
                }
                Else{
                    Write-Host "    REMEDIATE: Unable to apply policy: $($StigObj.RuleID), exit code: $($result.ExitCode)" -ForegroundColor Red
                    Write-Host "               View '$ErrorFile' for more details" -ForegroundColor Red
                    $errorcnt ++
                }
            }

        }

        #QUERY: if validation results are FALSE and ignore is TRUE. ACTION: Get reason
        If ($ConfigFile.Remediate.Ignore -eq "True"){
            If (!$result){
                Write-Host "    REMEDIATE: Policy: $($StigObj.RuleID) is configured to be ignored" -ForegroundColor Gray
                If ($ConfigFile.Remediate.Reason){
                    $reason = $ConfigFile.Remediate.Reason
                    Write-Host "        REASON: $reason" -ForegroundColor Gray
                    $ignoredcnt ++
                }
                Else{
                    Write-Host "        REASON: Nothing specified in config, counted as an error" -ForegroundColor Red
                    $errorcnt ++
                }
            }
        }

    } 
    Else{
        Write-Host "No configuration file was found for: $($StigObj.Version)" -ForegroundColor Yellow
        $missingcnt ++
    }
}


# Launch text
write-host ""
write-host "--------------------------------"
write-host "|        " -NoNewLine
write-host "STIG Tool Summary" -NoNewLine -ForegroundColor Green
write-host "     |"
write-host "--------------------------------"
write-host ""
write-host "Total Policies evaluated:     " -NoNewLine
write-host $evalcnt -foregroundcolor green
write-host "Total Policies not evaluated: " -NoNewLine
write-host $notevalcnt -foregroundcolor yellow
write-host "Total Policies already set:   " -NoNewLine
write-host $passedeval -foregroundcolor yellow
write-host "Total Policies not set:       " -NoNewLine
write-host $failedeval -foregroundcolor yellow
write-host "Total Policies applied:       " -NoNewLine
write-host $appliedcnt -foregroundcolor green 
write-host "Total Policies not applied:   " -NoNewLine
write-host $errorcnt -foregroundcolor yellow
write-host "Total Policies missing:       " -NoNewLine
write-host $missingcnt -foregroundcolor red
write-host "Total Policies ignored:       " -NoNewLine
write-host $ignoredcnt -foregroundcolor gray
write-host ""