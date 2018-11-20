##*=============================================
##* VARIABLE DECLARATION
##*=============================================
#region VariableDeclaration
## Variables: Datetime and Culture
[datetime]$currentDateTime = Get-Date
[string]$currentTime = Get-Date -Date $currentDateTime -UFormat '%T'
[string]$currentDate = Get-Date -Date $currentDateTime -UFormat '%d-%m-%Y'
[timespan]$currentTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now)
[Globalization.CultureInfo]$culture = Get-Culture
[string]$currentLanguage = $culture.TwoLetterISOLanguageName.ToUpper()

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

## OS Variables
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


##*=============================================
##* FUNCTION LISTINGS
##*=============================================
Function Start-Log{
    param (
        [string]$FilePath
    )
 
    try{
        if (!(Test-Path $FilePath))
        {
             ## Create the log file
             New-Item (Split-Path $FilePath -Parent) -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
             New-Item $FilePath -Type File | Out-Null
        }
 
        ## Set the global variable to be used as the FilePath for all subsequent Write-Log
        ## calls in this session
        $global:ScriptLogFilePath = $FilePath
    }
    catch{
        Write-Error $_.Exception.Message
    }
}

Function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        $Output,
        [string]$CustomComponent,

        [Parameter()]
        [ValidateSet(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)]
        [int]$ColorLevel = 1,
        [switch]$HostMsg,

        [ValidateSet("None","Before","After","Both")]
        [string]$NewLine

    )

    Begin{
        #set log level based on colorlevel integer
        Switch ($ColorLevel)
            {
                0 {$LogLevel = 1}
                1 {$LogLevel = 1}
                2 {$LogLevel = 2}
                3 {$LogLevel = 3}
                4 {$LogLevel = 1}
                5 {$LogLevel = 1}
                6 {$LogLevel = 2}
                7 {$LogLevel = 3}
                8 {$LogLevel = 1}
                9 {$LogLevel = 1}
                default {$LogLevel = 1}
            }
    }
    Process{
        $TimeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
        $Line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
        If ($CustomComponent){
            $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$CustomComponent".toupper().Replace(" ","_"), $LogLevel
        }
        Else{
            $LineFormat = $Message, $TimeGenerated, (Get-Date -Format MM-dd-yyyy), "$($MyInvocation.ScriptName | Split-Path -Leaf):$($MyInvocation.ScriptLineNumber)", $LogLevel
        }
        $Line = $Line -f $LineFormat
        Add-Content -Value $Line -Path $ScriptLogFilePath -ErrorAction SilentlyContinue
    }
    End{
       If ($HostMsg){
            If($NewLine){
                Switch($NewLine){
                    "Before" {$FullMessage = "`n" + $Message}
                    "After"  {$FullMessage = $Message + "`n"}
                    "Both"   {$FullMessage = "`n" + $Message + "`n"}
                    "None"   {$FullMessage = $Message}
                    default  {$FullMessage = $Message}
                }
            }
            Else{
                $FullMessage = $Message
            }
            
            $bgcolor = $null
            Switch ($ColorLevel)
            {
                0 {$fgcolor = 'White';Write-Host $FullMessage -ForegroundColor $fgcolor}
                1 {$fgcolor = 'Gray';Write-Host $FullMessage -ForegroundColor $fgcolor}
                2 {$fgcolor = 'Yellow';Write-Host $FullMessage -ForegroundColor $fgcolor}
                3 {$fgcolor = 'White';$bgcolor = 'Red';Write-Host $FullMessage -ForegroundColor $fgcolor -BackgroundColor $bgcolor}
                4 {$fgcolor = 'Cyan';Write-Host $FullMessage -ForegroundColor $fgcolor}
                5 {$fgcolor = 'Green';Write-Host $FullMessage -ForegroundColor $fgcolor}
                6 {$fgcolor = 'Orange';Write-Warning $Message}
                7 {$fgcolor = 'Red';Write-Error $Message}
                8 {$fgcolor = 'DarkYellow';Write-Host $FullMessage -ForegroundColor $fgcolor}
                9 {$fgcolor = 'Magenta';Write-Host $FullMessage -ForegroundColor $fgcolor}
                default {$fgcolor = 'White';Write-Host $FullMessage}
            }

            If($output){
                #save current color
                $fg = $host.UI.RawUI.ForegroundColor
                $bg = $host.UI.RawUI.BackgroundColor
                #set color
                $host.UI.RawUI.ForegroundColor = $fgcolor
                $host.UI.RawUI.BackgroundColor = $bgcolor
                Write-output $Output
                #reset color
                $host.UI.RawUI.ForegroundColor = $fg
                $host.UI.RawUI.BackgroundColor = $bg

            }
        }
    }
}


function Get-IniContent{
    <#
    $value = $iniContent[“386Enh"][“EGA80WOA.FON"]
    $iniContent[“386Enh"].Keys | %{$iniContent["386Enh"][$_]}
    #>
    [CmdletBinding()]  
    Param(  
        [ValidateNotNullOrEmpty()]  
        [Parameter(Mandatory=$True)]  
        [string]$FilePath
    )
    Begin{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"
        $ini = @{}
    }
    Process{
        switch -regex -file $FilePath
        {
            "^\[(.+)\]" # Section
            {
                $section = $matches[1]
                $ini[$section] = @{}
                $CommentCount = 0
            }
            "^(;.*)$" # Comment
            {
                $value = $matches[1]
                $CommentCount = $CommentCount + 1
                $name = "Comment" + $CommentCount
                $ini[$section][$name] = $value
            } 
            "(.+?)\s*=(.*)" # Key
            {
                $name,$value = $matches[1..2]
                $ini[$section][$name] = $value
            }
        }
       return $ini
    }
    End{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
    } 
}



function Set-IniContent{
    [CmdletBinding()]  
    Param(  
        [switch]$Append,
        [ValidateSet("Unicode","UTF7","UTF8","UTF32","ASCII","BigEndianUnicode","Default","OEM")]
        [Parameter()]
        [string]$Encoding = "Unicode",
        [ValidateNotNullOrEmpty()]  
        [Parameter(Mandatory=$True)]  
        [string]$FilePath,  
        [switch]$Force,
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [Hashtable]$InputObject,
        [switch]$Passthru,
        [switch]$NewLine
    )      
    Begin{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function started"
    }     
    Process{ 
        if ($append) {$outfile = Get-Item $FilePath}  
        else {$outFile = New-Item -ItemType file -Path $Filepath -Force:$Force -ErrorAction SilentlyContinue}  
        if (!($outFile)) {Throw "Could not create File"}  
        foreach ($i in $InputObject.keys){
            if (!($($InputObject[$i].GetType().Name) -eq "Hashtable")){
                #No Sections
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $i"
                Add-Content -Path $outFile -Value "$i=$($InputObject[$i])" -NoNewline -Encoding $Encoding

            } 
            else {
                #Sections
                Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing Section: [$i]" 
                $fullList = Get-IniContent $FilePath
                $sectionFound = $fullList[$i]

                #if section [] was not found add it
                If(!$sectionFound){
                    #Add-Content -Path $outFile -Value "" -Encoding $Encoding
                    Add-Content -Path $outFile -Value "[$i]" -Encoding $Encoding
                    }

                Foreach ($j in ($InputObject[$i].keys | Sort-Object)){
                    if ($j -match "^Comment[\d]+") {
                        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing comment: $j" 
                        Add-Content -Path $outFile -Value "$($InputObject[$i][$j])" -NoNewline -Encoding $Encoding 
                    } 
                    else {
                        Write-Verbose "$($MyInvocation.MyCommand.Name):: Writing key: $j" 
                        Add-Content -Path $outFile -Value "$j=$($InputObject[$i][$j])" -NoNewline -Encoding $Encoding 
                    }
                }
                If($NewLine){Add-Content -Path $outFile -Value "" -Encoding $Encoding}
            }
        }
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Finished Writing to file: $path"
        If($PassThru){Return $outFile}
    }
    End{
        Write-Verbose "$($MyInvocation.MyCommand.Name):: Function ended"
    } 
}

function Remove-IniContent{
    <#
    .SYNOPSIS
    Removes an entry/line/setting from an INI file.

    .DESCRIPTION
    A configuration file consists of sections, led by a `[section]` header and followed by `name = value` entries.  This function removes an entry in an INI file.  Something like this:

        [ui]
        username = Regina Spektor <regina@reginaspektor.com>

        [extensions]
        share = 
        extdiff =

    Names are not allowed to contains the equal sign, `=`.  Values can contain any character.  The INI file is parsed using `Split-IniContent`.  [See its documentation for more examples.](Split-IniContent.html)

    If the entry doesn't exist, does nothing.
    Be default, operates on the INI file case-insensitively. If your INI is case-sensitive, use the `-CaseSensitive` switch.

    .LINK
    Set-IniEntry

    .LINK
    Split-IniContent

    .EXAMPLE
    Remove-IniEntry -Path C:\Projects\Carbon\StupidStupid.ini -Section rat -Name tails

    Removes the `tails` item in the `[rat]` section of the `C:\Projects\Carbon\StupidStupid.ini` file.

    .EXAMPLE
    Remove-IniEntry -Path C:\Users\me\npmrc -Name 'prefix' -CaseSensitive

    Demonstrates how to remove an INI entry in an INI file that is case-sensitive.
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the INI file.
        $Path,
        [string]
        # The name of the INI entry to remove.
        $Name,
        [string]
        # The section of the INI where the entry should be set.
        $Section,
        [Switch]
        # Removes INI entries in a case-sensitive manner.
        $CaseSensitive
    )

    $settings = @{ }

    if( Test-Path $Path -PathType Leaf ){
        $settings = Split-IniContent -Path $Path -AsHashtable -CaseSensitive:$CaseSensitive
    }
    else{
       Write-Error ('INI file {0} not found.' -f $Path)
        return
    }

    $key = $Name
    if( $Section ){
        $key = '{0}.{1}' -f $Section,$Name
    }

    if( $settings.ContainsKey( $key ) )
    {
        $lines = New-Object 'Collections.ArrayList'
        Get-Content -Path $Path | ForEach-Object { [void] $lines.Add( $_ ) }
        $null = $lines.RemoveAt( ($settings[$key].LineNumber - 1) )
        if( $PSCmdlet.ShouldProcess( $Path, ('remove INI entry {0}' -f $key) ) )
        {
            if( $lines ){
                $lines | Set-Content -Path $Path
            }
            else{
                Clear-Content -Path $Path
            }
        }
    }
}


function Split-IniContent{
    <#
    .SYNOPSIS
    Reads an INI file and returns its contents.
    
    .DESCRIPTION
    A configuration file consists of sections, led by a "[section]" header and followed by "name = value" entries:
        
        [spam]
        eggs=ham
        green=
            eggs

        [stars]
        sneetches = belly

    By default, the INI file will be returned as `Carbon.Ini.IniNode` objects for each name/value pair.  For example, given the INI file above, the following will be returned:

        Line FullName        Section Name      Value
        ---- --------        ------- ----      -----
           2 spam.eggs       spam    eggs      ham
           3 spam.green      spam    green     eggs
           7 stars.sneetches stars   sneetches belly

    It is sometimes useful to get a hashtable back of the name/values.  The `AsHashtable` switch will return a hashtable where the keys are the full names of the name/value pairs.  For example, given the INI file above, the following hashtable is returned:

        Name            Value
        ----            -----
        spam.eggs       Carbon.Ini.IniNode;
        spam.green      Carbon.Ini.IniNode;
        stars.sneetches Carbon.Ini.IniNode;
        }

    Each line of an INI file contains one entry. If the lines that follow are indented, they are treated as continuations of that entry. Leading whitespace is removed from values. Empty lines are skipped. Lines beginning with "#" or ";" are ignored and may be used to provide comments.
    Configuration keys can be set multiple times, in which case Split-IniContent will use the value that was configured last. As an example:

        [spam]
        eggs=large
        ham=serrano
        eggs=small

    This would set the configuration key named "eggs" to "small".
    It is also possible to define a section multiple times. For example:

        [foo]
        eggs=large
        ham=serrano
        eggs=small

        [bar]
        eggs=ham
        green=
           eggs

        [foo]
        ham=prosciutto
        eggs=medium
        bread=toasted

    This would set the "eggs", "ham", and "bread" configuration keys of the "foo" section to "medium", "prosciutto", and "toasted", respectively. As you can see, the only thing that matters is the last value that was set for each of the configuration keys,
    Be default, operates on the INI file case-insensitively. If your INI is case-sensitive, use the `-CaseSensitive` switch.
    .LINK
    Set-IniEntry

    .LINK
    Remove-IniEntry

    .EXAMPLE
    Split-IniContent -Path C:\Users\rspektor\mercurial.ini 

    Given this INI file:
        [ui]
        username = Regina Spektor <regina@reginaspektor.com>

        [extensions]
        share = 
        extdiff =

    `Split-IniContent` returns the following objects to the pipeline:

        Line FullName           Section    Name     Value
        ---- --------           -------    ----     -----
           2 ui.username        ui         username Regina Spektor <regina@reginaspektor.com>
           5 extensions.share   extensions share    
           6 extensions.extdiff extensions extdiff  

    .EXAMPLE
    Split-IniContent -Path C:\Users\rspektor\mercurial.ini -AsHashtable

    Given this INI file:

        [ui]
        username = Regina Spektor <regina@reginaspektor.com>

        [extensions]
        share = 
        extdiff =

    `Split-IniContent` returns the following hashtable:

        @{
            ui.username = Carbon.Ini.IniNode (
                                FullName = 'ui.username';
                                Section = "ui";
                                Name = "username";
                                Value = "Regina Spektor <regina@reginaspektor.com>";
                                LineNumber = 2;
                            );
           extensions.share = Carbon.Ini.IniNode (
                                    FullName = 'extensions.share';
                                    Section = "extensions";
                                    Name = "share"
                                    Value = "";
                                    LineNumber = 5;
                                )
            extensions.extdiff = Carbon.Ini.IniNode (
                                       FullName = 'extensions.extdiff';
                                       Section = "extensions";
                                       Name = "extdiff";
                                       Value = "";
                                       LineNumber = 6;
                                  )
        }

    .EXAMPLE
    Split-IniContent -Path C:\Users\rspektor\mercurial.ini -AsHashtable -CaseSensitive

    Demonstrates how to parse a case-sensitive INI file.

        Given this INI file:

        [ui]
        username = user@example.com
        USERNAME = user2example.com

        [UI]
        username = user3@example.com

    `Split-IniContent -CaseSensitive` returns the following hashtable:

        @{
            ui.username = Carbon.Ini.IniNode (
                                FullName = 'ui.username';
                                Section = "ui";
                                Name = "username";
                                Value = "user@example.com";
                                LineNumber = 2;
                            );
            ui.USERNAME = Carbon.Ini.IniNode (
                                FullName = 'ui.USERNAME';
                                Section = "ui";
                                Name = "USERNAME";
                                Value = "user2@example.com";
                                LineNumber = 3;
                            );

            UI.username = Carbon.Ini.IniNode (
                                FullName = 'UI.username';
                                Section = "UI";
                                Name = "username";
                                Value = "user3@example.com";
                                LineNumber = 6;
                            );
        }
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='ByPath')]
        [string]
        # The path to the mercurial INI file to read.
        $Path,
        [Switch]
        # Pass each parsed setting down the pipeline instead of collecting them all into a hashtable.
        $AsHashtable,
        [Switch]
        # Parses the INI file in a case-sensitive manner.
        $CaseSensitive
    )

    if( -not (Test-Path $Path -PathType Leaf) ){
        Write-Error ("INI file '{0}' not found." -f $Path)
        return
    }

    $sectionName = ''
    $lineNum = 0
    $lastSetting = $null
    $settings = @{ }
    if( $CaseSensitive ){
        $settings = New-Object 'Collections.Hashtable'
    }

    Get-Content -Path $Path | ForEach-Object {
        $lineNum += 1

        if( -not $_ -or $_ -match '^[;#]' ){
            if( -not $AsHashtable -and $lastSetting ){
                $lastSetting
            }
            $lastSetting = $null
            return
        }

        if( $_ -match '^\[([^\]]+)\]' ){
            if( -not $AsHashtable -and $lastSetting ){
                $lastSetting
            }
            $lastSetting = $null
            $sectionName = $matches[1]
            Write-Debug "Parsed section [$sectionName]"
            return
        }

        if( $_ -match '^\s+(.*)$' -and $lastSetting ){
            $lastSetting.Value += "`n" + $matches[1]
            return
        }

        if( $_ -match '^([^=]*) ?= ?(.*)$' ){
            if( -not $AsHashtable -and $lastSetting ){
                $lastSetting
            }                       

            $name = $matches[1]
            $value = $matches[2]            

            $name = $name.Trim()
            $value = $value.TrimStart()   

            $setting = [pscustomobject]@{Section = $sectionName; Name = $name; Value = $value;LineNumber = $lineNum}
            #$setting = New-Object Carbon.Ini.IniNode $sectionName,$name,$value,$lineNum
            $settings[$setting.Section] = $setting
            $lastSetting = $setting
            Write-Debug "Parsed setting '$($setting.Section)'"
        }
    }

    if( $AsHashtable ){
        return $settings
    }
    else{
        if( $lastSetting ){
            $lastSetting
        }
    }
}

Function Call-IniContent{
[CmdletBinding()]
    PARAM(
        # _Manual-xccdf.xml file path
        [Parameter(Mandatory=$true,
                   Position=0)]
        [xml]$Content,
        [ValidateSet('Validate', 'Remediate')]
        $Section,
        [ValidateSet('ScriptBlock', 'ScriptFile', 'Function', 'LGPO','GPTemplate')]
        $key,
        [string[]]$args,
        $results
    )
    If ($Content.$Section.$key){
        $scriptBlock = [Scriptblock]::Create($Content.$Section.$key)
        
        try{
            If($key -eq 'ScriptBlock'){$result = Invoke-Command -ScriptBlock $key }
            If($key -eq 'Function' -and $args -eq $null){$result = Invoke-Command -ScriptBlock $key}
            If($key -eq 'Function' -and $args){$result = Invoke-Command -ScriptBlock $key -ArgumentList $args}
            If($key -eq 'ScriptFile'){
                If (Test-Path "\Scripts\$key" -ErrorAction SilentlyContinue){
                    $result = . "\Scripts\$key" $args
                }
            }
            If($key -eq 'LGPO'){
                $Outfile = "$env:Temp\$($Content.Version)_LGPO.stdOut"
                $ErrorFile = "$env:Temp\$($Content.Version)_LGPO.stdError"
                $Config.$Section.LGPO | Out-File $env:Temp\LGPO.txt -Force
                $result = Start-Process .\LGPO.exe -ArgumentList "/t $env:Temp\LGPO.txt /v" -PassThru -Wait -NoNewWindow -RedirectStandardOutput $Outfile -RedirectStandardError $ErrorFile -Verbose
            }
            If($key -eq 'GPTemplate'){}

        }
        Catch {
            Write-Host "$Section $key failed to run. Check syntax " -ForegroundColor red
        }
    }

}

Function Check-WindowsDefender {
<#
    .SYNOPSIS

    .DESCRIPTION

    .PARAMETER $return
        
    .EXAMPLE

    .SOURCE https://gallery.technet.microsoft.com/scriptcenter/PowerShell-to-Check-if-811b83bc

    #>
    param(
        [switch]
        $return
        )

    Try { 
        $defenderOptions = Get-MpComputerStatus 
        if([string]::IsNullOrEmpty($defenderOptions)) { 
            If(!$return){Write-host "Windows Defender was not found running on the Server:" $env:computername -foregroundcolor "Green"}
        } 
        else { 
            If(!$return){
                Write-host "Windows Defender was found on the Server:" $env:computername -foregroundcolor "Cyan" 
                Write-host "   Is Windows Defender Enabled?" $defenderOptions.AntivirusEnabled 
                Write-host "   Is Windows Defender Service Enabled?" $defenderOptions.AMServiceEnabled 
                Write-host "   Is Windows Defender Antispyware Enabled?" $defenderOptions.AntispywareEnabled 
                Write-host "   Is Windows Defender OnAccessProtection Enabled?"$defenderOptions.OnAccessProtectionEnabled 
                Write-host "   Is Windows Defender RealTimeProtection Enabled?"$defenderOptions.RealTimeProtectionEnabled
            }
            Else{
                If ( 
                ($defenderOptions.AntivirusEnabled) -or 
                ($defenderOptions.AMServiceEnabled) -or 
                ($defenderOptions.AntispywareEnabled) -or 
                ($defenderOptions.OnAccessProtectionEnabled) -or 
                ($defenderOptions.RealTimeProtectionEnabled) 
                ){return $true}
            }
        } 
    } 
    Catch 
    { 
        If(!$return){Write-host "Windows Defender was not found running on the Server:" $env:computername -foregroundcolor "Green"}
        Else{return $false}
    }
}


Function Check-FirewallState{
    $Compliance = 'Non-Compliant'
    $CheckDomain = Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Domain' -and $_.Enabled -eq 'True'}
    $CheckPublic = Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Public' -and $_.Enabled -eq 'True'}
    $CheckPrivate = Get-NetFirewallProfile | Where-Object {$_.Name -eq 'Private' -and $_.Enabled -eq 'True'}
    if ( ($CheckDomain) -and ($CheckPublic) -and ($CheckPrivate) ) {$Compliance = 'Compliant'}
    $Compliance
}

Function Get-BitlockerStatus{
<#
    .SOURCE https://blogs.technet.microsoft.com/heyscriptingguy/2015/05/26/powershell-and-bitlocker-part-2/
    #>
    $ProtectionState = Get-WmiObject -Namespace ROOT\CIMV2\Security\Microsoftvolumeencryption -Class Win32_encryptablevolume -Filter "DriveLetter = '$env:SystemDrive'" -ErrorAction SilentlyContinue
    If($ProtectionState){
            switch ($ProtectionState.GetProtectionStatus().protectionStatus){
                ("0"){$return = "Unprotected"}
                ("1"){$return = "Protected"}
                ("2"){$return = "Uknowned"}
                default {$return = "NoReturn"}
            }
    }
    Else{
        $return = "Disabled"
    }
    return $return
}

Function Get-CredGuardStatus{
<#
    .SOURCE https://blogs.technet.microsoft.com/poshchap/2016/09/23/security-focus-check-credential-guard-status-with-powershell/
    #>
    $DevGuard = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    #if ($DevGuard.SecurityServicesConfigured -contains 1) {"Credential Guard configured"}
    #if ($DevGuard.SecurityServicesRunning -contains 1) {"Credential Guard running"}
    if ( ($DevGuard.SecurityServicesConfigured -contains 1) ) {return 'Enabled'}
    Else{return 'Disabled'}

}

Function Get-IISVersion{
    $IISversion = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\ -ErrorAction SilentlyContinue).MajorVersion
    $IISrunning = Get-WmiObject Win32_Service -Filter "name='W3SVC'"
    if($IISrunning.State -eq "Running"){return $IISversion}
}


Function Check-HyperVStatus ($OSRole){
    # Get the Hyper-V feature and store it in $hyperv
    if (Test-IsAdmin -CheckOnly){
        Switch ($OSRole) {
	        3 { $hyperv = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).Installed
                }
	        2 { $hyperv = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).Installed
                }
	        1 { $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online -ErrorAction SilentlyContinue
                }
	        Default { }
        }

        If($hyperv){
            # Check if Hyper-V is already enabled.
            if($hyperv.State -eq "Enabled") {
                $state = 'Enabled'
            } else {
                $state = 'Disabled'
            }
        } else {
                $state = 'Not Installed'
        }
        return $state
    }
    Else{
        return 
    }
}


Function Check-SharepointVersion{
    # https://blogs.technet.microsoft.com/stefan_gossner/2015/04/20/powershell-script-to-display-version-info-for-installed-sharepoint-product-and-language-packs/

    Param(
      # decide on whether all the sub-components belonging to the product should be shown as well
      [switch]$ShowComponents
    )

    # location in registry to get info about installed software

    $RegLoc = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall

    # Get SharePoint Products and language packs
    $Programs = $RegLoc | 
	    where-object { $_.PsPath -like "*\Office*" } | 
	    foreach {Get-ItemProperty $_.PsPath} 
    $Components = $RegLoc | 
	    where-object { $_.PsPath -like "*1000-0000000FF1CE}" } | 
	    foreach {Get-ItemProperty $_.PsPath} 

    # output either just the info about Products and Language Packs
    # or also for sub components

    if ($ShowComponents.IsPresent)
    {
	    $Programs | foreach { 
		    $_ | fl  DisplayName, DisplayVersion; 

		    $productCodes = $_.ProductCodes;
		    $Comp = @() + ($Components | 
			    where-object { $_.PSChildName -in $productCodes } | 
			    foreach {Get-ItemProperty $_.PsPath});
		    $Comp | Sort-Object DisplayName | ft DisplayName, DisplayVersion -Autosize
	    }
    }
    else
    {
	    $Programs | fl DisplayName, DisplayVersion
    }
    Return $Programs
}


Function Check-SQLVersion{
    $server = $env:COMPUTERNAME
    try {
        # Define SQL instance registry keys
        $type = [Microsoft.Win32.RegistryHive]::LocalMachine;
        $regconnection = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($type, $server) ;
        $instancekey = "SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL";
 
        try {
            # Open SQL instance registry key
            $openinstancekey = $regconnection.opensubkey($instancekey);
        }
        catch { $out = $server + ",No SQL registry keys found"; }
 
        # Get installed SQL instance names
        $instances = $openinstancekey.getvaluenames();
 
        # Loop through each instance found
        foreach ($instance in $instances) {
 
            # Define SQL setup registry keys
            $instancename = $openinstancekey.getvalue($instance);
            $instancesetupkey = "SOFTWARE\Microsoft\Microsoft SQL Server\" + $instancename + "\Setup"; 
 
            # Open SQL setup registry key
            $openinstancesetupkey = $regconnection.opensubkey($instancesetupkey);
 
            $edition = $openinstancesetupkey.getvalue("Edition")
 
            # Get version and convert to readable text
            $version = $openinstancesetupkey.getvalue("Version");
 
            switch -wildcard ($version) {
                "13*" {$versionname = "SQL Server 2016";}
                "12*" {$versionname = "SQL Server 2014";}
                "11*" {$versionname = "SQL Server 2012";}
                "10.5*" {$versionname = "SQL Server 2008 R2";}
                "10.4*" {$versionname = "SQL Server 2008";}
                "10.3*" {$versionname = "SQL Server 2008";}
                "10.2*" {$versionname = "SQL Server 2008";}
                "10.1*" {$versionname = "SQL Server 2008";}
                "10.0*" {$versionname = "SQL Server 2008";}
                default {$versionname = $version;}
            }

            # Output results to CSV
            $out =  $server + "," + $instancename + "," + $edition + "," + $versionname; 
            return $versionname
        }
 
    }
    catch { $out = $server + ",Could not open registry"; }  

}

Function Check-MBAMInstalled{
    if (-not (Test-Path variable:local:MbamWmiNamespace))
    {
        Try{
            Set-Variable MbamWmiNamespace -Option ReadOnly -Scope local "root\Microsoft\MBAM"
            return "Installed"
        }
        Catch{
            return "Not Installed"
        }
    }

}

Function Get-OfficeVersion{
    $version = 0
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME)
    $reg.OpenSubKey('software\Microsoft\Office').GetSubKeyNames() |% {
        if ($_ -match '(\d+)\.') {
            if ([int]$matches[1] -gt $version) {
                $version = $matches[1]
            }
        }
    }
    switch($version){
        16 {return "Office 2016"}
        15 {return "Office 2013"}
        14 {return "Office 2010"}
        default {return}
    }

}


Function Get-UserToSid{
    [CmdletBinding()]
    param(
        [parameter(
        Mandatory=$true, 
        Position=0,
        ParameterSetName="Domain")]
        [string] $Domain,

        [parameter(
        Mandatory=$true, 
        Position=1,
        ParameterSetName="Domain"
                    )]
        [string] $User,

        [parameter(
        Mandatory=$true, 
        Position=0,
        ParameterSetName="Local",
        ValueFromPipeline= $true
                    )]
        [string] $LocalAccount
    )
    
    #Determine which parameter set was used
    switch ($PsCmdlet.ParameterSetName){
        "Local"   {$objUser = New-Object System.Security.Principal.NTAccount("$LocalAccount")}
        "Domain"  {$objUser = New-Object System.Security.Principal.NTAccount("$Domain", "$user")}
    }

    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier]) 
    $strSID.Value
}


Function Get-SidtoUser($sidString)
{
 $sid = new-object System.Security.Principal.SecurityIdentifier($sidString)
 $user = $sid.Translate([System.Security.Principal.NTAccount])
 $user.value
}

Function Build-STIGFeatureList{
    #BUILD LIST FOR:
    #-------------------- START: ROLES AND FEATURES --------------------#
    #Detection for Workstation and ServerFeature STIGs
    $arrayFeatureNames = @()

    # Always check these:
    $arrayFeatureNames += "Default" #<-- Default domain controller policy
    $arrayFeatureNames += "PowerShell"
    $arrayFeatureNames += "Applocker"

    If(Check-WindowsDefender -return){$arrayFeatureNames += "Defender"}
    If(Check-FirewallState -eq 'Compliant'){$arrayFeatureNames += "Firewall"}
    If(Get-CredGuardStatus -eq 'Enabled'){
        $arrayFeatureNames += "Credential Guard","Cred Guard","Device Guard"}
    If(Check-MBAMInstalled -eq 'Installed'){$arrayFeatureNames += "MBAM"}

    #dynamically add IE if installed to array
    [version]$IEVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer').SvcVersion
    If($IEVersion){
        [string]$IESimpleName = "Internet Explorer $($IEVersion.Major)"
        $arrayFeatureNames += "Internet Explorer",$IESimpleName,"IE","IE$($IEVersion.Major)"
    }

    #Check for Web Server IIS
    $IISState = Get-IISVersion
    If($IISState){
        $arrayFeatureNames += "IIS"
        $arrayFeatureNames += "IIS $IISState"
        $arrayFeatureNames += "Web Server"
    }

    # Check for Hyper-V
    $HyperVRole = Check-HyperVStatus ($envOSRoleType)
    If($HyperVRole -eq "Enabled"){
        $arrayFeatureNames += "Hyper-V"
        $arrayFeatureNames += "HyperV"
    }
    #NetFrameworkFeature

    #Check for SMBv1
    switch([string]$envOSVersionSimple){
       "10.0" {$SMB1Enabled = (Get-SmbServerConfiguration | Select EnableSMB1Protocol).EnableSMB1Protocol}
        default {$SMB1Enabled = (Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath -ErrorAction SilentlyContinue}).SMB1}
    }
    If ( ($SMB1Enabled) -or ($SMB1Enabled -eq 1) ){$arrayFeatureNames += "SMBv1"}

    # rebuild array with pipe delminated to be parsed
    #--------------------- END: ROLES AND FEATURES ---------------------#

    #-------------------- START: WORKSTATION PRODUCTS --------------------#
    #Detection for Workstation Product STIGs
    $officeInstalled = Get-OfficeVersion
    If ($officeInstalled -eq "Office 13"){
        $arrayFeatureNames += "Office 13","Office System 2013","Excel 2013","Project 2013","Outlook 2013",
                                "PowerPoint 2013","Word 2013","Publisher 2013","Infopath 2013","Visio 2013",
                                "Lync 2013"
    }
    If ($officeInstalled -eq "Office 16"){
        $arrayFeatureNames += "Office 16","Office System 2016","Excel 2016","Project 2016","Outlook 2016",
                                "PowerPoint 2016","Word 2016","Publisher 2016","Infopath 2016","Visio 2016",
                                "Skype for Business 2016","OneDrive for Business 2016","Skype","OneDrive","OneNote 2016"
    }

    $chromeInstalled = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(Default)'
    If($chromeInstalled){
        $chromeversion = (Get-Item $chromeInstalled -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
        $arrayFeatureNames += "Chrome"
    }

    #$javaInstalled
    #$adobeInstalled
    #--------------------- END: WORKSTATION PRODUCTS ---------------------#

    #-------------------- START: SERVER PRODUCTS --------------------#
    #Detection for Server Products STIGs
    $serverProductNames = @()
    
    #exchange server
    $exchangeProduct = $env:ExchangeInstallPath + "\bin\ExSetup.exe"
    If(Test-Path $exchangeProduct){
        $productProperty =  Get-ItemProperty -Path $exchangeProduct
        $productversion = $productProperty.VersionInfo.ProductVersion.Major
        $arrayFeatureNames += "Exchange","Exchange $productversion"
    }

    #$sharepointProduct
    $sharepointInstalled = Check-SharepointVersion
    If ($sharepointInstalled){
        [Version]$SPSVersion = $sharepointInstalled.DisplayVersion
        If($SPSVersion.Major -eq 15){$arrayFeatureNames += "SharePoint 2013"}
        If($SPSVersion.Major -eq 16){$arrayFeatureNames += "SharePoint 2016"}   
    }

    #$hbssProduct

    #SQLProduct

    $SQLInstalled = Check-SQLVersion
    If ($SQLInstalled){
        $sqlYear = $SQLInstalled.Split(" ")[2]
        $sqlYearSimple = $sqlYear.Substring(2)
        $sqlSvrShort = $SQLInstalled -replace $sqlYear,$sqlYearSimple
        $sqlSvrShorter = ($SQLInstalled -replace "Server","SVR").Replace(' ','')
        $sqlSvrShortest = ($sqlSvrShort -replace "Server","SVR").Replace(' ','')
        $sqlShort = ($SQLInstalled -replace "Server","").Replace('  ',' ')
        $sqlShorter = ($SQLInstalled -replace "Server","").Replace(' ','')
        $sqlShortest = ($sqlSvrShort -replace "Server","").Replace(' ','')

        $arrayFeatureNames += $SQLInstalled,$sqlSvrShort,$sqlSvrShorter,$sqlSvrShortest,$sqlShort,$sqlShorter,$sqlShortest 
    }


    #--------------------- END: SERVER PRODUCTS ---------------------#

    #COMBINED LIST
    [string]$list = $arrayFeatureNames -join '|'
    return $list
}

Function Build-LGPOTemplate{
    <#

    Test Examples
    $GPO = 'DoD Windows Server 2016 MS and DC v1r3\GPOs\{19859FE3-6E1B-41E7-BDF6-E8ADE5548FD9}'
    $GptTmplPath = $GPO + "\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
    $MachineRegPOLPath = $GPO + "\DomainSysvol\GPO\Machine\registry.pol"
    $UserRegPOLPath = $GPO + "\DomainSysvol\GPO\User\registry.pol"
    $AuditCsvPath = $GPO + "\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\Audit.csv"
    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true,
                   Position=0)]
        $InfPath,
        [Parameter(Mandatory=$true,
                   Position=1)]
        $OutputPath,
        [Parameter(Mandatory=$true,
                   Position=2)]
        $OutputName,
        $Run
    )

    Begin
    {
        If(!(Test-Path $InfPath)){
            Write-Log -Message "[$InfPath] not specified or does not exist. Unable to build LGPO Template." -CustomComponent "Template" -ColorLevel 6 -NewLine -HostMsg 
            exit -1
        }
        #$lgpoout = $null
        $lgpoout = "; ----------------------------------------------------------------------`r`n"
        $lgpoout += "; PROCESSING POLICY`r`n"
        $lgpoout += "; Source file:`r`n"
        $lgpoout += "`r`n"
    }

    Process
    {
        $GptTmplContent = Split-IniContent -Path $InfPath
        If (($GptTmplContent.Section -eq 'Registry Values').count -gt 0){
            Write-Log -Message "'Registry Values' section found in [$InfPath], building template..." -CustomComponent "Template" -ColorLevel 6 -HostMsg 

            $RegValueList = $GptTmplContent | Where {$_.section -eq 'Registry Values'}
            Foreach ($RegKey in $RegValueList){
                $RegKeyHive = ($RegKey.Name).Split('\')[0]
                $RegKeyPath = Split-Path ($RegKey.Name).Split('\',2)[1] -Parent
                $RegName = Split-Path $RegKey.Name -Leaf

                #The -split operator supports specifying the maximum number of sub-strings to return.
                #Some values may have additional commas in them that we don't want to split (eg. LegalNoticeText)
                [String]$RegTypeInt,[String]$RegValue = $RegKey.Value -split ',',2

                Switch($RegKeyHive){
                    MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                    USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                }

                #https://www.motobit.com/help/RegEdit/cl72.htm
                Switch($RegTypeInt){
                    0 {$RegType = 'NONE'}
                    1 {$RegType = 'SZ'}
                    2 {$RegType = 'EXPAND_SZ'}
                    3 {$RegType = 'BINARY'}
                    4 {$RegType = 'DWORD'}
                    5 {$RegType = 'DWORD_BIG_ENDIAN'}
                    6 {$RegType = 'LINK'}
                    7 {$RegType = 'SZ'}
                }

                <#
                If(Test-Path $RegProperty\$RegKeyPath){
                    Set-ItemProperty $RegProperty\$RegKeyPath -Name $RegName -Value $RegValue -Force | Out-Null
                }
                Else{
                    New-Item -Path $RegProperty\$RegKeyPath -Force | Out-Null
                    New-ItemProperty $RegProperty\$RegKeyPath -Name $RegName -Value $RegValue -PropertyType $RegType -Force | Out-Null
                }
                #>
                Write-host "   Adding Registry: $RegProperty\$RegKeyPath\$RegName" -ForegroundColor Gray
                $lgpoout += "$LGPOHive`r`n"
                $lgpoout += "$RegKeyPath`r`n"
                $lgpoout += "$RegName`r`n"
                $lgpoout += "$($RegType):$RegValue`r`n"
                $lgpoout += "`r`n"
            }
        }
        Else{
            Write-host "'Registry Value' section was not found in [$InfPath], skipping..." -ForegroundColor Gray
        }
    }
    End {
        $lgpoout | Out-File "$OutputPath\$OutputName.lgpo"
    }
}

Function Build-SeceditFile{
    <#


    #>
    [CmdletBinding()]
    PARAM(
        [Parameter(Mandatory=$true,
                   Position=0)]
        $InfPath,
        
        [Parameter(Mandatory=$true,
                   Position=1)]
        $OutputPath,

        [Parameter(Mandatory=$true,
                   Position=2)]
        $OutputName,

        [parameter(Mandatory=$false)]
        [string] $LogFolderPath
    )

    Begin
    {
        If(!(Test-Path $InfPath)){
            Write-Log -Message "[$InfPath] not specified or does not exist. Unable to build LGPO Template." -CustomComponent "Template" -ColorLevel 6 -NewLine -HostMsg 
            exit -1
        }Else{
            #build array with content
            $GptTmplContent = Split-IniContent -Path $InfPath
        }

        $backupSeceditFile = "secedit.backup.sdb"
        If(!(Test-Path "$OutputPath\$backupSeceditFile")){
            If ($LogFolderPath){
                $SeceditResults = secedit /export /cfg "$OutputPath\$backupSeceditFile" /log "$LogFolderPath\$backupSeceditFile.log"
            }
            Else{
                $SeceditResults = secedit /export /cfg "$OutputPath\$backupSeceditFile"
            }
        }
    }

    Process
    {       
        $secedit = $null
        $continue = $false
        If ( (($GptTmplContent.Section -eq 'System Access').count -gt 0) -or (($GptTmplContent.Section -eq 'Privilege Rights').count -gt 0) ){
            $continue = $true
        }
        If($continue){
            #generate start of file
            $secedit =  "[Unicode]`r`n"
            $secedit += "Unicode=yes`r`n"
            $secedit += "[Version]`r`n"
            $secedit += "signature=`"`$CHICAGO`$`"`r`n"
            $secedit += "Revision=1`r`n"
        
            #get system access section
            If (($GptTmplContent.Section -eq 'System Access').count -gt 0){
                $SystemAccessFound = $true
                Write-host "'System Access' section found in [$InfPath], building list...." -ForegroundColor Cyan
                $secedit += "[System Access]`r`n"

                $AccessValueList = $GptTmplContent | Where {$_.section -eq 'System Access'}
                Foreach ($AccessKey in $AccessValueList){
                    $AccessName = $AccessKey.Name
                    $AccessValue = $AccessKey.Value
                    If ($AccessName -eq "NewAdministratorName"){
                        $AccessValue = $AccessValue -replace $AccessKey.Value, "$Global:NewAdministratorName"
                    }
                    If ($AccessName -eq "NewGuestName"){
                        $AccessValue = $AccessValue -replace $AccessKey.Value, "$Global:NewGuestName"
                    }
                    $secedit += "$AccessName = $AccessValue`r`n"
                    #$secedit += "$PrivilegeValue" 
                }
            }
            Else{
                $SystemAccessFound = $false
                Write-host "'System Access' section was not found in [$InfPath], skipping..." -ForegroundColor Gray
            }
        
            #next get Privilege Rights section
            If (($GptTmplContent.Section -eq 'Privilege Rights').count -gt 0){
                $PrivilegeRightsFound = $true
                Write-host "'Privilege Rights' section found in [$InfPath], building list...." -ForegroundColor Cyan
                $secedit += "[Privilege Rights]`r`n"

                $PrivilegeValueList = $GptTmplContent | Where {$_.section -eq 'Privilege Rights'}
                Foreach ($PrivilegeKey in $PrivilegeValueList){
                    $PrivilegeName = $PrivilegeKey.Name
                    $PrivilegeValue = $PrivilegeKey.Value

                    If ($PrivilegeValue -match "ADD YOUR ENTERPRISE ADMINS|ADD YOUR DOMAIN ADMINS|S-1-5-21"){
                       
                        If($IsMachinePartOfDomain){
                            $EA_SID = Get-UserToSid -Domain $envMachineDNSDomain -User "Enterprise Admins"
                            $DA_SID = Get-UserToSid -Domain $envMachineDNSDomain -User "Domain Admins"
                            $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR ENTERPRISE ADMINS",$EA_SID
                            $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR DOMAIN ADMINS",$DA_SID
                        }
                        Else{
                            $ADMIN_SID = Get-UserToSid -LocalAccount 'Administrators'
                            $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR ENTERPRISE ADMINS",$ADMIN_SID
                            $PrivilegeValue = $PrivilegeValue -replace "ADD YOUR DOMAIN ADMINS",$ADMIN_SID
                            $PrivilegeValue = $PrivilegeValue -replace "S-1-5-21-[0-9-]+",$ADMIN_SID
                        }
                    }
                    #split up values, get only unique values and make it a comma deliminated list again
                    $temp = $PrivilegeValue -split ","
                    $PrivilegeValue = $($temp | Get-Unique) -join "," 


                    $secedit += "$PrivilegeName = $PrivilegeValue`r`n"
                    #$secedit += "$PrivilegeValue" 
                }
            }
            Else{
                $PrivilegeRightsFound = $false
                Write-host "'Privilege Rights' was not found in [$InfPath], skipping..." -ForegroundColor Gray
            }
        }

    }
    End {
        If($secedit){
            $secedit | Out-File "$OutputPath\$OutputName" -Force
            Write-host "Saved file to [$OutputPath\$OutputName]" -ForegroundColor Gray
        }
    }
}
