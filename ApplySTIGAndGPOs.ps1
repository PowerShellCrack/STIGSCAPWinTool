#========================================================================
#
#       Title: ApplySTIGAndGPOs
#     Created: 2018-02-26
#      Author: Richard tracy
#
#
# GOALS:
# Apply STIGS from Backup 
#
# 
#========================================================================
##* VARIABLE DECLARATION
## 
##   Change these variables to meet domain/local workgroup enviroment
##*===============================================
$Breakstuff = $true                     #if $ParseGptTmpl set to true; policies will be applied to system;
$ParseGptTmpl = $true                   #If set to True: As long as tools exist, GptTmpl.inf will be parsed within the GPO backup and
                                        #                builds script for LocalPol.exe,LGPO.exe,Secedit.exe,AUDTIPOL.exe
                                        #If set to False: Just runs LGPO.exe against GPO. This is ideal is GPO backup are off the same domain

$Global:NewAdministratorName = "newAdmin" #if $ParseGptTmpl set to true and found in GptTmpl.inf. Changes value for key: NewAdministratorName
$Global:NewGuestName = "noGuest"         #if $ParseGptTmpl set to true and found in GptTmpl.inf. Changes value for key: NewGuestName


#-------------------- START: DEVIATION LIST --------------------#
# Specified Words in GPO name to be identified as policies to run at the end: Order = 4
[string]$runlastGPONames = ("Deviations|Custom|Specific|Updates")
#--------------------- END: DEVIATION LIST ---------------------#

#-------------------- START: IGNORE POLICIES -----------------------#
# Specified Words in GPO name to be identified as policies to NEVER run: Order = 0
[string]$ignoreGPONames = ("_del_|zArchive|Test")
#--------------------- END: IGNORE POLICIES ------------------------#

#-------------------- START: IGNORE SITES -----------------------#
# Specified Words in GPO name to be identified as policies to NEVER run: Order = 0
[string]$ignoreGPOSites = ("LAB|TEST")
#--------------------- END: IGNORE SITES ------------------------#

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

$LGPOExePath ="$ToolsPath\LGPO.exe"
$localPolExePath = "$ToolsPath\LocalGPO\Security Templates\LocalPol.exe"

[string]$workingLogPath = Join-Path -Path $LogsPath -ChildPath $env:COMPUTERNAME
    New-Item $workingLogPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
[string]$workingTempPath = Join-Path -Path $TempPath -ChildPath $env:COMPUTERNAME
    New-Item $workingTempPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null

#Write-Host $workingLogPath
#Write-Host $workingTempPath

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
        #Write-Error -Message "Module [$_] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
        Write-Host "Module [$_] failed to load: $($_.Exception.Message)" -ForegroundColor White -BackgroundColor Red
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
        Write-Host "Unable to import the module: $($_.Exception.Message)" -ForegroundColor White -BackgroundColor Red
    }
}

##*===============================================
##* MAIN ROUTINE
##*===============================================
Start-Log "$workingLogPath\$scriptName.log"

if (!(Test-IsAdmin -CheckOnly)){
    Write-Log -Message "Script is not currently running under a priviledge Administrator account! `nRerun this script using 'Run as Administrator' selection." -CustomComponent "ADMIN" -ColorLevel 6 -NewLine -HostMsg 
    Exit -1
}
Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}

# Get a list of Features on this machine
$additionalFeatureNames = Build-STIGFeatureList
#-------------------- START: OPERATING SYSTEM NAME AND ROLE --------------------#

#Build OS simple names and roles
Switch ($envOSRoleType) {
	3 { [string]$envOSTrimName = $envOSName.Trim("Microsoft|Enterprise|Standard|Datacenter").Replace("Windows","").Trim()
        [string]$envOSRoleTypeName = ('MS|Member Server') 
        }
	2 { [string]$envOSTrimName = $envOSName.Trim("Microsoft|Enterprise|Standard|Datacenter").Replace("Windows","").Trim()
        [string]$envOSSimpleVersions = 
        [string]$envOSRoleTypeName = ('DC|Domain Controller|Domain Controllers|Domain')
        }
	1 { [string]$envOSTrimName = $envOSName.Trim("Microsoft|Enterprise|Home|Professional").Trim()
        [string]$envOSRoleTypeName = ('Windows|Workstation')
        
        }
	Default { [string]$envOSRoleTypeName = 'Windows' }
}

[string]$envOSSimpleName = $envOSTrimName
If ($envOSRoleType -eq 1){
    #$wksVer = $envOSSimpleName.Split(" ")[1]
    $envOSShort = $envOSSimpleName -replace " ",""
    $envOSShorter = ($envOSSimpleName -replace "Windows","WIN").Replace(' ','') + $enOSVersionRelease
    $envOSShortest = ($envOSSimpleName -replace "Windows","WIN").Replace(' ','')
}
Else{
    $serverYear = $envOSSimpleName.Split(" ")[1]
    $serverYearSimple = $serverYear.Substring(2)
    $envOSShort = $envOSSimpleName -replace $serverYear,$serverYearSimple
    $envOSShorter = ($envOSSimpleName -replace "Server","SVR").Replace(' ','')
    $envOSShortest = ($envOSShort -replace "Server","SVR").Replace(' ','')
}
$envOSSimpleNames = "$envOSSimpleName|$envOSShort|$envOSShorter|$envOSShortest"
#--------------------- END: OPERATING SYSTEM NAME AND ROLE ---------------------#


#grab all policies in GPO folder and build a collection array
Write-Log -Message "Building GPO list, this can take a while...." -CustomComponent "POLICIES" -ColorLevel 5 -NewLine Before -HostMsg
$BackupFolders = Get-ChildItem -Recurse -Include backup.xml -Path $BackupGPOPath -ErrorAction SilentlyContinue | %{Write-Log -Message "Found Policies: $($_.fullname)" -CustomComponent "POLICIES" -ColorLevel 1 -HostMsg;$_}
#$BackupFolders = Get-ChildItem -Recurse -Include backup.xml -Path $BackupGPOPath -ErrorAction SilentlyContinue

#Reset GPO Collecton Counters 
$runcnt = 0
$ignorecnt = 0
$progress = 1
$applyProgess = 1
$additionalscripts = 0
$appliedPolicies = 0
$errorPolicies = 0
$successcnt = 0
$failedcnt = 0
$skippedcnt = 0
$FoundPolicies = $BackupFolders.Count
Write-Log -Message "Found $FoundPolicies GPO policies..." -CustomComponent "POLICIES" -ColorLevel 4 -NewLine Before -HostMsg 
Write-Log -Message "  Parsing Policies for [$($envOSSimpleNames.Replace('|',','))] in the name..." -CustomComponent "POLICIES" -ColorLevel 1 -HostMsg 
Write-Log -Message "  Parsing Policies for [$($envOSRoleTypeName.Replace('|',' or '))] in the name..." -CustomComponent "POLICIES" -ColorLevel 1 -HostMsg 
Write-Log -Message "  Parsing Policies for [$($additionalFeatureNames.Replace('|',','))] in the name..." -CustomComponent "POLICIES" -ColorLevel 1 -HostMsg  

$GPOs = @()
#loop through all policies to see if they are ignored or not based on OS, roles and features, and software installed
ForEach ($Folder in $BackupFolders){
    
    $guid = $Folder.Directory.Name
    $x = [xml](Get-Content -Path $Folder -ErrorAction SilentlyContinue)
    $dn = $x.GroupPolicyBackupScheme.GroupPolicyObject.GroupPolicyCoreSettings.DisplayName.InnerText
    #$results.Add($dn, $guid)
    
    Write-Progress -Activity "Processing GPO policy: $($dn)" -Status "Policy: $progress of $FoundPolicies" -PercentComplete (($progress / $FoundPolicies) * 100)  
      
    If ( ($dn -match $ignoreGPONames) -or ($dn -match $ignoreGPOSites) ){ $RunOrder = 0;$runcnt ++}
    ElseIf (($dn -match $envOSRoleTypeName) -and ($dn -match $envOSSimpleNames) -and ($dn -notmatch $runlastGPONames) -and ($dn -notmatch $additionalFeatureNames)){$RunOrder = 1;$runcnt ++}
    ElseIf ( ($dn -match $additionalFeatureNames) -and ($dn -notmatch $runlastGPONames) ){$RunOrder = 2;$runcnt ++}
    ElseIf ( (($dn -match $envOSRoleTypeName) -or ($dn -match $envOSSimpleNames)) -and ($dn -match $runlastGPONames) ){$RunOrder = 3;$runcnt ++}
    ElseIf ( (($dn -match $additionalFeatureNames) ) -and ($dn -match $runlastGPONames) ){$RunOrder = 4;$runcnt ++}
    Else { $RunOrder = 0;$ignorecnt ++}
        
    #build a object tbale to determine which order to run policies
    $GPOTable = New-Object -TypeName PSObject -Property ([ordered]@{
        Path    = $Folder.DirectoryName
        GUID    = "$guid"
        Name    = "$dn"
        Order   = $RunOrder
            
    })
    $GPOs += $GPOTable
    $progress++ 
}# close foreach

Write-Log -Message "$ignorecnt policies are being filtered" -CustomComponent "POLICIES" -ColorLevel 9 -NewLine Before -HostMsg
Write-Log -Message "$runcnt policies will be parsed and applied to local system" -CustomComponent "POLICIES" -ColorLevel 9 -NewLine None -HostMsg 
#Start-Sleep 30
    

#applying GPO to Proper OS in order
Foreach ($GPO in $GPOs | Sort-Object Order){
    #run first
    switch($GPO.Order){
        0 {$orderLabel = "Not Applicable"}
        1 {$orderLabel = "as first group"}
        2 {$orderLabel = "as second group"}
        3 {$orderLabel = "as third group"}
        4 {$orderLabel = "as fourth group"}
    }
    
    $relativeGPOpath = ($GPO.Path).TrimStart("$BackupGPOPath")
    Write-Progress -Activity "Parsing GPO Policy: $($GPO.name)" -Status "Policy: $applyProgess of $($GPOs.Count)" -PercentComplete (($applyProgess / $GPOs.Count) * 100)

    If($GPO.Order -ne 0){
        If($ParseGptTmpl -and (Test-Path $LGPOExePath) -and (Test-Path $localPolExePath)){
            $GptTmplPath = $GPO.Path + "\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
            $MachineRegPOLPath = $GPO.Path + "\DomainSysvol\GPO\Machine\registry.pol"
            $UserRegPOLPath = $GPO.Path + "\DomainSysvol\GPO\User\registry.pol"
            $AuditCsvPath = $GPO.Path + "\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\Audit.csv"
            $xmlRegPrefPath = $GPO.Path + "\DomainSysvol\GPO\Machine\Preferences\Registry\Registry.xml"
        
            Write-Log -Message "Parsing GPO Policy: [$($GPO.name)]. Configured to apply the policy individually $orderLabel" -CustomComponent "POLICIES" -ColorLevel 4 -NewLine None -HostMsg
            Write-Host "------------------------------------------------------------------------------------" -ForegroundColor Cyan

            $env:SEE_MASK_NOZONECHECKS = 1
            If(Test-Path $GptTmplPath){
                #parses the GptTmpl.inf for registry values and builds a text file for LGPO to run later

                # Grab GPO backup security configuration file and parse registry keys and build in a format that LGPO can use
                Build-LGPOTemplate -InfPath $GptTmplPath -OutputPath $workingTempPath -OutputName "$($GPO.name)"
                 
                Write-Log -Message "RUNNING COMMAND: '\Tools\LGPO.exe' /t '$workingTempPath\$($GPO.name).lgpo'" -CustomComponent "COMMAND" -ColorLevel 8 -NewLine None -HostMsg
                If($Breakstuff){
                    $result = Start-Process "$ToolsPath\LGPO.exe" -ArgumentList "/t ""$workingTempPath\$($GPO.name).lgpo""" -RedirectStandardError "$workingLogPath\$($GPO.name).lgpo.stderr.log" -Wait -NoNewWindow -PassThru 
                    If($result.ExitCode -eq 0){
                        Write-Log -Message "LGPO command succesfully ran. View [$workingLogPath\$($GPO.name).lgpo.stderr.log] for details" -CustomComponent "LGPO" -ColorLevel 5 -NewLine After -HostMsg
                        $successcnt ++
                    }
                    Else{
                        #Import failed for some reason
                        Write-Log -Message "LGPO command failed. View [$workingLogPath\$($GPO.name).lgpo.stderr.log] for details" -CustomComponent "LGPO" -ColorLevel 3 -NewLine After -HostMsg 
                        $failedcnt ++
                    }
                } 
                Else{
                     Write-Log -Message "TEST MODE: RUNNING COMMAND did not run! Variable Breakstuff is set to false" -CustomComponent "TEST" -ColorLevel 2 -NewLine None -HostMsg
                     Write-Log -Message "           View [$workingTempPath\$($GPO.name).lgpo] for LGPO script details" -CustomComponent "TEST" -ColorLevel 8 -NewLine After -HostMsg
                     $skippedcnt ++
                }

                If($Breakstuff){
                    # Grab GPO backup security configuration file and parse it for invalid SID associations and rebuild it for import
                    Build-SeceditFile -InfPath $GptTmplPath -OutputPath $workingTempPath -OutputName "$($GPO.name).seceditapply.inf" -LogFolderPath $workingLogPath

                     Write-Log -Message "RUNNING COMMAND: SECEDIT /configure /db secedit.sdb /cfg '$workingTempPath\$($GPO.name).seceditapply.inf' /overwrite /log '$workingLogPath\$($GPO.name).seceditapply.log' /quiet" -CustomComponent "COMMAND" -ColorLevel 8 -NewLine None -HostMsg
                    #Start-Process SECEDIT -ArgumentList " /configure /db secedit.sdb /cfg ""$workingTempPath\$($GPO.name).seceditapply.inf"" /overwrite /quiet" -RedirectStandardOutput "$workingLogPath\$($GPO.name).secedit.stdout.log" -RedirectStandardError "$workingLogPath\$($GPO.name).secedit.stderr.log" -Wait -NoNewWindow
                    $SeceditApplyResults = ECHO y| SECEDIT /configure /db secedit.sdb /cfg "$workingTempPath\$($GPO.name).seceditapply.inf" /overwrite /log "$workingLogPath\$($GPO.name).seceditapply.log"

                    #Verify that update was successful (string reading, blegh.)
                    if($SeceditApplyResults[$SeceditApplyResults.Count-2] -eq "The task has completed successfully."){
                        Write-Log -Message "SECEDIT Command ran successfully. See log [$workingLogPath\$($GPO.name).seceditapply.log] for detail info" -CustomComponent "SECEDIT" -ColorLevel 5 -NewLine After -HostMsg
                        $successcnt ++
                    }
                    Else{
                        #Import failed for some reason
                        $SeceditApplyResults | Out-File "$workingLogPath\$($GPO.name).seceditcmd.log"
                        Write-Log -Message ("SECEDIT Command errored while importing from [$workingTempPath\$($GPO.name).seceditapply.inf]. See log [$workingLogPath\$($GPO.name).seceditapply.log] for detail info.`nError message:") -Output $SeceditApplyResults -CustomComponent "SECEDIT" -ColorLevel 3 -NewLine After -HostMsg 
                        $failedcnt ++
                    }
                } 
                Else{
                     Write-Log -Message "TEST MODE: RUNNING COMMAND did not run! Variable Breakstuff is set to false" -CustomComponent "TEST" -ColorLevel 2 -NewLine None -HostMsg
                     Write-Log -Message "           View [$workingTempPath\$($GPO.name).seceditapply.inf] for SECEDIT script details" -CustomComponent "TEST" -ColorLevel 8 -NewLine After -HostMsg
                     $skippedcnt ++
                }
            }
            Else{
                $skippedcnt ++
            }
        
            If(Test-Path $MachineRegPOLPath){
                # Command Example: LocalPol.exe -m -v -f [path]\registry.pol
                 Write-Log -Message "RUNNING COMMAND: '\Tools\LocalGPO\Security Templates\LocalPol.exe' -m -f '$MachineRegPOLPath'" -CustomComponent "COMMAND" -ColorLevel 8 -NewLine None -HostMsg
                If($Breakstuff){
                    $result = Start-Process "$ToolsPath\LocalGPO\Security Templates\LocalPol.exe" -ArgumentList "-m -f ""$MachineRegPOLPath""" -RedirectStandardOutput "$workingLogPath\$($GPO.name).localpol.machine.stdout.log" -Wait -NoNewWindow -PassThru
                    If($result.ExitCode -eq 0){
                        Write-Log -Message "LOCALPOL Command ran successfully. See log [$workingLogPath\$($GPO.name).localpol.machine.stdout.log] for detail info" -CustomComponent "LOCALPOL" -ColorLevel 5 -NewLine After -HostMsg
                        $successcnt ++
                    }
                    Else{
                        #Import failed for some reason
                        Write-Log -Message "LOCALPOL Command failed to run. See log [$workingLogPath\$($GPO.name).localpol.machine.stdout.log] for detail info" -CustomComponent "LOCALPOL" -ColorLevel 3 -NewLine After -HostMsg 
                        $failedcnt ++
                    }
                } 
                Else{
                     Write-Log -Message "TEST MODE: RUNNING COMMAND did not run! Variable Breakstuff is set to false" -CustomComponent "TEST" -ColorLevel 2 -NewLine None -HostMsg
                     Write-Log -Message "           View [$MachineRegPOLPath] for LOCALPOL details" -CustomComponent "TEST" -ColorLevel 8 -NewLine After -HostMsg
                     $skippedcnt ++
                }
            }
            Else{
                $skippedcnt ++
            }

            If(Test-Path $UserRegPOLPath){
                # Command Example: LocalPol.EXE -u -v -f [path]\registry.pol
                 Write-Log -Message "RUNNING COMMAND: '\Tools\LocalGPO\Security Templates\LocalPol.exe' -u -f '$UserRegPOLPath'" -CustomComponent "COMMAND" -ColorLevel 8 -NewLine None -HostMsg
                If($Breakstuff){
                    $result = Start-Process "$ToolsPath\LocalGPO\Security Templates\LocalPol.exe" -ArgumentList "-u -f ""$UserRegPOLPath""" -RedirectStandardOutput "$workingLogPath\$($GPO.name).localpol.user.stdout.log" -Wait -NoNewWindow -PassThru
                    If($result.ExitCode -eq 0){
                        Write-Log -Message "LOCALPOL Command ran successfully. See log [$workingLogPath\$($GPO.name).localpol.user.stdout.log] for detail info" -CustomComponent "LOCALPOL" -ColorLevel 5 -NewLine After -HostMsg
                        $successcnt ++
                    }
                    Else{
                        #Import failed for some reason
                        Write-Log -Message "LOCALPOL Command failed to run. See log [$workingLogPath\$($GPO.name).localpol.user.stdout.log] for detail info" -CustomComponent "LOCALPOL" -ColorLevel 3 -NewLine After -HostMsg 
                        $failedcnt ++
                    }
                } 
                Else{
                     Write-Log -Message "TEST MODE: RUNNING COMMAND did not run! Variable Breakstuff is set to false" -CustomComponent "TEST" -ColorLevel 2 -NewLine None -HostMsg
                     Write-Log -Message "           View [$UserRegPOLPath] for LOCALPOL details" -CustomComponent "TEST" -ColorLevel 8 -NewLine After -HostMsg
                     $skippedcnt ++
                }
            }
            Else{
                $skippedcnt ++
            }

            If(Test-Path $AuditCsvPath){
                # Command Example: AUDITPOL /restore /file:[path]\Audit.csv    
                 Write-Log -Message "RUNNING COMMAND: AUDITPOL.EXE /restore /file:'$AuditCsvPath'" -CustomComponent "COMMAND" -ColorLevel 8 -NewLine None -HostMsg
                If($Breakstuff){
                    $result = Start-Process AUDITPOL.EXE -ArgumentList "/restore /file:""$AuditCsvPath""" -RedirectStandardOutput "$workingLogPath\$($GPO.name).auditpol.stdout.log" -Wait -NoNewWindow -PassThru
                    If($result.ExitCode -eq 0){
                        Write-Log -Message "AUDITPOL Command ran successfully. See log [$workingLogPath\$($GPO.name).auditpol.stdout.log] for detail info" -CustomComponent "AUDITPOL" -ColorLevel 5 -NewLine After -HostMsg
                        $successcnt ++
                    }
                    Else{
                        #Import failed for some reason
                        Write-Log -Message "AUDITPOL Command failed to run. See log [$workingLogPath\$($GPO.name).auditpol.stdout.log] for detail info" -CustomComponent "AUDITPOL" -ColorLevel 3 -NewLine After -HostMsg 
                        $failedcnt ++
                    }
                } 
                Else{
                     Write-Log -Message "TEST MODE: RUNNING COMMAND did not run! Variable Breakstuff is set to false" -CustomComponent "TEST" -ColorLevel 2 -NewLine None -HostMsg
                     Write-Log -Message "           View [$AuditCsvPath] for AUDITPOL details" -CustomComponent "TEST" -ColorLevel 8 -NewLine After -HostMsg
                     $skippedcnt ++
                }
            }
            Else{
                $skippedcnt ++
            }


            #build collective counter status for all policy items
            #if any status has failed concider whole policy is failed
            <#
            If ($failedcnt -gt 0){
                $errorPolicies ++
            }
            Else{
                $appliedPolicies ++
            }
            #>
            $failedcnt = $errorPolicies
            $appliedPolicies = $successcnt
        }

        ElseIf(Test-Path "$ToolsPath\LGPO.exe"){
            Write-Log -Message "Parsing GPO Policy: [$($GPO.name)]. Configured to apply the policy combined $orderLabel" -CustomComponent "POLICIES" -ColorLevel 4 -NewLine None -HostMsg
            Write-Host "------------------------------------------------------------------------------------" -ForegroundColor Cyan

            If($Breakstuff){
                Try{
                    #Start-Process "$env:windir\system32\cscript.exe" -ArgumentList "//NOLOGO ""$ToolsPath\LocalGPO\LocalGPO.wsf"" /Path:""$($GPO.Path)"" /Validate /NoOverwrite" -RedirectStandardOutput "$workingTempPath\$($GPO.name).gpo.log" -Wait -NoNewWindow
                     Write-Log -Message "    RUNNING COMMAND: '\Tools\LGPO.exe' /q /v /g '$($GPO.Path)' >> '$workingLogPath\$($GPO.name).stdout.log'" -CustomComponent "COMMAND" -ColorLevel 1 -NewLine None -HostMsg 
                    Start-Process "$ToolsPath\LGPO.exe" -ArgumentList "/q /v /g ""$($GPO.Path)""" -RedirectStandardOutput "$workingLogPath\$($GPO.name).allgpo.stdout.log" -RedirectStandardError "$workingLogPath\$($GPO.name).allgpo.stderr.log" -Wait -NoNewWindow -PassThru
                    $appliedPolicies ++
                }
                Catch{
                    Write-Log -Message "Unable to Apply [$($GPO.name)] policy, see [$workingTempPath\$($GPO.name)_lgpo.stderr.log] for details" -CustomComponent "LGPO" -ColorLevel 2 -NewLine None -HostMsg 
                    $errorPolicies ++
                }
            } 
            Else{
                Write-Log -Message "TEST MODE: RUNNING COMMAND did not run! Variable Breakstuff is set to false" -CustomComponent "TEST" -ColorLevel 2 -NewLine After -HostMsg
                $skippedcnt ++
            }
        }

        Else{
           Write-Log -Message "Unable to Apply [$($GPO.name)] policy, [LGPO.exe] and [localPol.exe] in tools directory are missing" -CustomComponent "LGPO" -ColorLevel 3 -NewLine After -HostMsg
           $errorPolicies ++
        }
        $env:SEE_MASK_NOZONECHECKS = 0
    }
    Else{
        Write-Log -Message "  Ignoring [$($GPO.name)] from [$relativeGPOpath] because it's [$orderLabel]..." -CustomComponent $orderLabel -ColorLevel 8 -NewLine After -HostMsg 
    }
    $applyProgess++
} # end loop


Write-Log -Message "Determining if additonal configuration needs to be done based on installed software, roles and features" -CustomComponent "MODULES" -ColorLevel 4 -NewLine Before -HostMsg 

If($envOSRoleType -eq 2){
    If($Breakstuff){
        Write-Log -Message "Extension: Applying STIG'd items for AD..." -CustomComponent "AD" -ColorLevel 8 -NewLine None -HostMsg
        Set-ActiveDirectoryStigItems  | Out-File -FilePath "$workingLogPath\ADSTIGS.log"
        $additionalscripts ++
    } 
    Else{
        Write-Log -Message "TEST MODE: Active Directory Stig items would have been applied" -CustomComponent "TEST" -ColorLevel 2 -NewLine After -HostMsg
        $skippedcnt ++
    }
} #end loop


If(($additionalFeatureNames -match "IIS") -and ($envOSRoleType -ne 1)){
    If($Breakstuff){
        Write-Log -Message "Extension: Applying STIG'd items for IIS..." -CustomComponent "IIS" -ColorLevel 8 -NewLine None -HostMsg 
        # Get CSV files for IIS 7 Web Site STIGs
        # Change to your own files if you do not want to use the default files
        If(Get-WebConfigurationBackup -Name BeforeIISSTig){
            Remove-WebConfigurationBackup -Name BeforeIISSTig
        }
        Backup-WebConfiguration -Name BeforeIISSTig | Out-Null
        $moduleBase = (Get-Module IIS7STIGs).ModuleBase
        . "$moduleBase\ApplyIIS7STIGs.ps1" | Out-File -FilePath "$workingLogPath\IIS7STIGS.log"
        $additionalscripts ++
    } 
    Else{
        Write-Log -Message "TEST MODE: IIS Stig items would have been applied" -CustomComponent "TEST" -ColorLevel 2 -NewLine After -HostMsg
        $skippedcnt ++
    }
}

$Pendingreboot = (Get-PendingReboot).RebootPending
# Launch text
write-host ""
write-host "-----------------------------------"
write-host "|      " -NoNewLine
write-host "Apply GPO Tool Summary" -NoNewLine -ForegroundColor Green
write-host "     |"
write-host "-----------------------------------"
write-host ""
write-host "Total Policies evaluated:  " -NoNewLine
write-host $FoundPolicies -foregroundcolor Cyan
write-host "Total Policies ignored:    " -NoNewLine
write-host $ignorecnt -foregroundcolor yellow
write-host "Total Policies applied:    " -NoNewLine
write-host $appliedPolicies -foregroundcolor green 
write-host "Total Policies errors:     " -NoNewLine
write-host $errorPolicies -foregroundcolor red
write-host "Total Scripts applied:     " -NoNewLine
write-host $additionalscripts -foregroundcolor green
If($Breakstuff){
     
    If ($Pendingreboot){write-host "Policies applied! A reboot is required to take affect..." -ForegroundColor White -BackgroundColor Red}
    Else{write-host "Policies applied!" -ForegroundColor Cyan}
}
Else{
    write-host "Total Scripts skipped:     " -NoNewLine
    write-host $skippedcnt -foregroundcolor DarkYellow
}