## WORK-IN-PROGRESS: 
I need help creating all the configuration files for each STIG item. 

## GOAL: 
The idea is to take each STIG rule and build configuration files (ini) with the appropriate actions for each rule. 
There are over 270 items just for Server 2016 stig and each item would have to be created. 
This will would allow easy maintaince and organization in named by the STIG version id (eg. WN16-00-000040.ini). 

PowerShell will parse the file then translate it into a ScriptBlock

## Example:

    STIG SV-87877r1_rule with ID of WN16-00-000040 says the ESC must be enabled for admins on Windows Servers. 

The registry keys are:
 
    HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073
    HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073

then create a file named: WN16-00-000040.ini. it needs to be validated, then if not compliant, remediate it. 

WN16-00-000040.ini:
    
    ;RuleID : SV-87877r1_rule
    ;Severity : high
    ;Fix : Establish a policy, at minimum, to prohibit administrative accounts 
    from using applications that access the Internet, such as web browsers, 
    or with potential Internet sources, such as email. 

    [Validate]
    Ignore=False
    Scriptblock=$ESCfoAdmins = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -ErrorAction SilentlyContinue
    Scriptblock=$ESCfoUsers = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -ErrorAction SilentlyContinue
    Scriptblock=If ($ESCfoAdmins.IsInstalled -and $ESCfoUsers.IsInstalled){return $true}Else{return $false}

    [Remediate]
    Ignore=False

    LGPO=Computer
    LGPO=SOFTWARE\Microsoft\Active Setup\Installed Components\A509B1A7-37EF-4b3f-8CFC-4F3A74704073
    LGPO=IsInstalled
    LGPO=DWORD:1

    LGPO=Computer
    LGPO=SOFTWARE\Microsoft\Active Setup\Installed Components\A509B1A8-37EF-4b3f-8CFC-4F3A74704073
    LGPO=IsInstalled
    LGPO=DWORD:1

## Breakdown INI file
Ignore and starting semicolon for the commented section. Parse the Validate section and if ignore is set to false, turn ScriptBlock key values into one Powershell ScriptBlock; the example should run like this within the calling Powershell parser 

    $scriptBlock = {
        $ESCfoAdmins = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -ErrorAction SilentlyContinue
        $ESCfoUsers = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -ErrorAction SilentlyContinue
        If ($ESCfoAdmins.IsInstalled -and $ESCfoUsers.IsInstalled){return $true}Else{return $false}
    }
    Invoke-Command -ScriptBlock $scriptBlock

Build this from the text file using the parser and calling it like this:

    $ConfigFile = Get-IniContent -filePath $File
    If ($ConfigFile.Validate.Ignore -eq "False"){
        $scriptBlock = [Scriptblock]::Create($ConfigFile.Validate.ScriptBlock)
        Invoke-Command -ScriptBlock $scriptBlock       
        } 
    }
    
  Instead of just applying the keys to the system, I want to make sure the policy is configured as well. thats where the LGPO tool comes into play. 

LGPO uses script files like this: 

    Computer
    SOFTWARE\Microsoft\Active Setup\Installed Components\A509B1A8-37EF-4b3f-8CFC-4F3A74704073
    IsInstalled
    DWORD:1
    
 So add it to the remediate side like this:
 
    [Remediate]
    Ignore=False

    LGPO=Computer
    LGPO=SOFTWARE\Microsoft\Active Setup\Installed Components\A509B1A7-37EF-4b3f-8CFC-4F3A74704073
    LGPO=IsInstalled
    LGPO=DWORD:1

    LGPO=Computer
    LGPO=SOFTWARE\Microsoft\Active Setup\Installed Components\A509B1A8-37EF-4b3f-8CFC-4F3A74704073
    LGPO=IsInstalled
    LGPO=DWORD:1

Powershell will then loop all LGPO key names and build and array and then call it via scriptblock.

Settings are now applied. Run GPEDIT.msc to verify. 

Repeat this same process about a few hundread times to get all STIGS
