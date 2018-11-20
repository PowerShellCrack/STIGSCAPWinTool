function Get-RegistryHive {
  PARAM([string]$RegHive)
  [string]$key = switch -wildcard ($RegHive) { 
     "*HKEY_LOCAL_MACHINE" {"HKLM:"} 
     "*HKEY_CURRENT_USER" {"HKCU:"} 
  }
    write-output $key
}# close Get-RegistryHive


function  Get-RegTypeValue {
  PARAM([string]$Type)
    [string]$ValueType = switch -wildcard ($Type) { 
      "*REG_DWORD*" {"DWORD"} 
      "*REG_SZ" {"String"}
      "*REG_BINARY" {"Binary"}
    }
    write-output $ValueType

}# close Get-RegTypeValue


function Sanitize-String {
  PARAM([Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true)]
            [string]$String
         )

  $Sanitized = ($String -replace "'", "" -replace '"', '').TrimEnd();
  Write-Output $Sanitized;
}# close Sanitize-String


function Get-StigHelperFunctions {
  $StigCheckPrefix = @'

function Test-RegistryValue {
  PARAM($LiteralPath, $Name, $Value)
  $key = Get-ItemProperty -LiteralPath $LiteralPath -Name $Name -ErrorAction SilentlyContinue
  if($key){
    if($key.$Name -EQ $Value){
      $true
    }
    else{
     $false
    }
  }
  else { 
    $false
  }
}#end Test-RegistryValue


function New-STIGResult {
  PARAM(
    [string]$ComputerName,
    [string]$RuleSeverity,
    [string]$RuleTitle,
    [string]$RuleID,
    [string]$RuleDescription,
    [string]$Fix,
    [bool]$IsApplied,
    [DateTime]$DateScanned
    )

  $object = New-Object –TypeName PSObject
  $object | Add-Member –MemberType NoteProperty –Name ComputerName –Value $ComputerName
  $object | Add-Member –MemberType NoteProperty –Name RuleSeverity –Value $RuleSeverity
  $object | Add-Member –MemberType NoteProperty –Name RuleDescription –Value $RuleDescription
  $object | Add-Member –MemberType NoteProperty –Name RuleTitle –Value $RuleTitle
  $object | Add-Member –MemberType NoteProperty –Name RuleID –Value $RuleID
  $object | Add-Member –MemberType NoteProperty –Name Fix –Value $Fix
  $object | Add-Member –MemberType NoteProperty –Name IsApplied –Value $IsApplied
  $object | Add-Member –MemberType NoteProperty –Name DateScanned –Value $DateScanned
  $object
}# close New-STIGResult

# collection to hold results of STIG
$Collection = @()

'@

  $StigCheckPrefix

}# close Get-StigHelperFunctions



function New-XccdfAuditTool {
<#
.Synopsis
  Create a PowerShell-based STIG auditing tool from
  the windows Xccdf file
.DESCRIPTION
  Convert an windows xccdf file into a simple
  auditing tool that leverages PowerShell to
  check for registry values determing if security
  is in place. 

.NOTES
  Download and unzip your benchmark from DISA from
  http://iase.disa.mil/stigs/compilations/Pages/index.aspx
  and download the cci list from the following
  http://iase.disa.mil/stigs/cci/Pages/index.aspx

.EXAMPLE
  New-XccdfAuditTool -xccdf '~\Documents\U_Windows_2012_and_2012_R2_MS_STIG_V2R6_Manual-xccdf.xml' `
    -outFile ~\Desktop\Windows2012RegistryChecks.ps1

#>
  [CmdletBinding()]
  PARAM(
    # _Manual-xccdf.xml file path
    [Parameter(Mandatory=$true,
               Position=0)]
    [ValidateScript({Test-Path $_ })]
    [string]
    $xccdf,
    # Location to save the STIG auditing file
    [Parameter(Mandatory=$false,
               Position=1)]

    [string]
    $outFile
  )

  BEGIN{
    # Load the content as XML
    try{ 
      [xml]$Stigx = Get-Content -Path $xccdf -EA Stop
    }
    catch {
      write-warning "Failure converting XML for the XCCDF file."
      Write-Error $_ -ErrorAction Stop
    }

    ## Create the Stig Audit script variable
    $StigAuditScript = "# New STIG Audit Tool Generated on $(Get-Date) `n"
    $StigAuditScript += Get-StigHelperFunctions
    ## This are rules that are not parsing properly and for sake of time have been excluded
    $Exceptions = @('SV-52867r2_rule','SV-52845r2_rule','SV-52883r2_rule','SV-52887r1_rule','SV-52931r2_rule','SV-71859r2_rule')
  }# close BEGIN

  PROCESS{
    if($Stigx){
      $StigCollection = @()
      ## loop through the xccdf benchmark collecting data into an object collection

      foreach ($rule in $StigX.Benchmark.Group.Rule){
        ## create a new PSObject collecting and stripping out as required.
        $STIG = New-Object -TypeName PSObject -Property ([ordered]@{
          RuleID    = $rule. id
          RuleTitle = $rule.title 
          Severity = $rule.severity
          VulnerabilityDetails = $($($($rule.description) -split '</VulnDiscussion>')[0] -replace '<VulnDiscussion>', '')
          Check = $rule.check.'check-content'
          Fix = $rule.fixtext.'#text'
          ControlIdentifier = $rule.ident.'#text'
        })

        ## A majority of the simple registry checks start with the Registry Hive string
        ## which we use to create a Get-ItemProperty script checking for existence natively in PS
        ## todo: split the logic out into a separate function
        
        if(($STIG.Check -LIKE "*If the following registry value does not exist or is not configured as specified, this is a finding:*") -AND ($STIG.RuleID -notin $Exceptions)){
          $Lines = $($STIG.Check).Split("`n")
          ## loop through each line of the the CheckContent
          foreach($line in $Lines){
            ## eliminate any leading or trailing spaces
            [string]$strLine = $line.Trim()
            ## find the registry root
            if($strLine -LIKE "Registry Hive: HK*"){
              if($strLine -LIKE "Registry Hive: HKEY_LOCAL_MACHINE"){$Hive = "HKLM:"}
              if($strLine -LIKE "Registry Hive: HKEY_CURRENT_USER"){$Hive = "HKCU:"}
              Write-Debug "The identified Hive for $($STIG.id) : $Hive"
            }
            ## find the registry path and put together with hive
            elseif ($strLine -LIKE "Registry Path: *"){
              $Path = ($strLine -replace "Registry Path: ", "").Trim()
              Write-Debug "The identified registry path for $($STIG.id) : $Path"
              $Key = $Hive + $Path
              Write-Debug "The identified registry key for $($STIG.id) : $Key"
            }

            ## find the -ValueName portion of our audit
            elseif($strLine -LIKE "Value Name: *"){
              $ValueName = ($strLine -replace "Value Name: ", "").Trim()  
              Write-Debug "The identified value name for $($STIG.id) : $ValueName" 
            }

            ## find the -ValueType portion of our audit
            elseif($strLine -LIKE "*Type: *"){
              $ValueTypeParse = $($strLine -replace "Type: ", "")  -replace "Value ", ""
              $ValueType = Get-RegTypeValue $ValueTypeParse.Trim()
              Write-Debug "The identified value type for $($STIG.id) : $ValueType"  
            }

            ## find the -ValueData  portion of our audit
            elseif($strLine -LIKE "Value: *"){
              $ValueData = ($strLine -replace "Value: ", "" -replace "\(or less\)" -replace  "\(or greater\)" -replace "\(Enabled\)").Trim()
              switch  ($ValueData) {
                '0x000000ff (255)' {$ValueData = '255'}
                '0x0000000f (15)' {$ValueData = '15'}
                '0x0000000f (15)' {$ValueData = '15'}
                '(blank)' {$ValueData = ''}
                '0x20080000 (537395200)' {$ValueData = '537395200'}
                '0x0000ea60 (60000)' {$ValueData = '60000'}
                '0x20080000 (537395200)' {$ValueData = '53739520'}
                '0x00008000 (32768) (or greater)' {$ValueData = '32768'}
                '0x00030000 (196608) (or greater)' {$ValueData = '196608'}
                '0x00008000 (32768) (or greater)' {$ValueData = '32768'}
                '0x00000002 (2)' {$ValueData = '2'}
                '0x00000384 (900)' {$ValueData = '900'}
                Default {}
              }
              Write-Debug "The identified value data for $($STIG.id) : $ValueData"
            }
          }#end foreach line
          ## remove any escaping characters for the comments and description, not important to maintain
          $FixComment = "$($STIG.RuleID) : The regsitry $key needs to have the value name $valueName with the value of $ValueData of type $ValueType " 
          $VulnsDetailsSanitized = $STIG.VulnerabilityDetails | Sanitize-String
          $FixSanitized =  $STIG.Fix | Sanitize-String  
          ## Create the Test Rule Check
          $CreateSTIGCheck = '#region '+ $($STIG.RuleID) + "`n"
          $CreateSTIGCheck += '  ## '+ $FixComment + "`n"
          $CreateSTIGCheck += '  $StigDescription = ' + "'$VulnsDetailsSanitized' `n"
          $CreateSTIGCheck += '  $StigTest = Test-RegistryValue -LiteralPath ' + "'$Key' -Name '$ValueName' -Value '$ValueData'" + "`n"
          $CreateSTIGCheck += '  $Collection += New-STIGResult -ComputerName $env:COMPUTERNAME -RuleSeverity' +" '$($STIG.Severity)'" + ' -RuleDescription $StigDescription' + ' -IsApplied $StigTest -RuleTitle' + " '$($STIG.RuleTitle)' -RuleID '$($STIG.RuleID)' -Fix '$FixSanitized' -DateScanned " + ' $(Get-Date)' + "`n"
          $CreateSTIGCheck += '#endregion '+ $($STIG.RuleID) + "`n`n"
          $StigAuditScript += $CreateSTIGCheck
        }# close if
      }# close foreach
    }# close if
  }# close process
  END{
    if($outFile){
      try{
        $StigAuditScript | Out-File $outFile
      }
      catch {
        Write-Error "Failed to write to $OutFile. Check user permissions and if destination exists"
      }
    }
    else {
      $StigAuditScript
    }
  }# close END
} # close New-XccdfAuditTool