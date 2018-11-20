#Windows STIG & SCAP Toolkit

## WHAT IS IT: 	
A PowerShell script that will take a GPO backup or SCAP XCCDF file and generate STIGs settings
Then apply them to a Windows OS using Microsoft's LGPO.exe tool from their Security Compliance Manager Toolkit

## HOW TO USE IT:
  **ApplySTIGAndGPOs.ps1**	This is a more dynamic PowerShell script. This will detect roles,
				            and features and even software and install the appropriate GPO backup.
				
  **ApplySTIGBySCAPs.ps1**	STILL DEVELOPING: This is the most advanced PowerShell script. This script will be a lot
				            like Linux's OpenSCAP, it will parse the XCCDF file from DISA and build a dataset
				            of all STIG components and one by one it will apply the STIG based on the configuration files.
				            Configuration files still need to be created, check out the [README.md](Configs/README.md)
				
  **RemoveSTIGAndGPOs.ps1**	This script just removes the group policy folders and clear the security database.
  

## REQUIREMENTS:		
 - Modules need to be downloaded. Follow [README.md](Modules/README.md) instructions in modules folder
 - STIG Naming conventions is required for STIG Tools. Follow [README.md](GPO/README.md)  instructions in GPO folder
 - CCI required for SCAP Tools. Follow [README.md](CCI/README.md)  instructions in CCI folder
 - SCAP Benchmarks required for SCAP Tools. Follow [README.md](SCAP/README.md)  instructions in SCAP folder
 - LGPO executable required for all tools. Follow [README.md](Tools/README.md)  instructions in Tools folder

## WHAT IT DOES: 	
   **ApplySTIGAndGPOs.ps1**: The script will read into the GPO's backup.xml inside each GUID and identify the name of the policy. Using that information it will determine if the name matches identified system information, roles, features and install products and apply them locally using Microsoft's Security Compliance Manager tool LGPO. This ultimately read the GPO settings, and builds a file with all the registry and security settings, then applies those settings within the local gpo. These settings can then be viewed using the systems gpedit.msc. All keys and settings are backed up in the temp folder and logged in log folder.

## FOLDERS:

    CCI\U_CCI_List.xml <-- Used with ApplySTIGBySCAPs.ps1. Control Correlation Identifier (CCI) provides a standard identifier and description for each of the singular, actionable statements that comprise an IA control or IA best practice			
    Configs\	   <-- Used with ApplySTIGBySCAPs.ps1. Configuration files for each STIG ID. These are ini like files with commands for validation and remediation steps.			
    Extensions\	   <-- Used with ApplySTIGBySCAPs.ps1. PowerShell extension folder provides additional PowerShell functions
    Modules\	   <-- Additional PowerShell modules found in PowerShell Gallery and elsewhere
    GPO\		   <-- Used with ApplySTIGAndGPOs.ps1. Follow [README.md](GPO/README.md) instructions in folder
    Logs\		   <-- Output logs for LGPO and advanced logging (Use CMTRACE)
    SCAP\		   <-- SCAP Benchmark files. Follow [README.md](SCAP/README.md) instructions in folder
    Temp\		   <-- Store generated LGPO config and pol files
    Tools\		   <-- Tools used in scripts, such as LGPO 


## SOURCES:		
 - https://github.com/CyberSecDef/STIG
 - http://www.entelechyit.com/2017/01/02/powershell-and-disa-nist-stigs-part-1/
 - http://iase.disa.mil/stigs/compilations/Pages/index.aspx
 - https://www.powershellgallery.com/profiles/michael.haken/
 - https://github.com/alulsh/SharePoint-2013-STIGs
 - https://blogs.technet.microsoft.com/matt_hinsons_manageability_blog/2016/01/29/gpo-packs-in-mdt-2013-u1-for-windows-10/
 - https://www.microsoft.com/en-us/download/confirmation.aspx?id=55319
 - https://github.com/search?l=PowerShell&q=STIG&type=Repositories&utf8=%E2%9C%93
 - https://github.com/mwrlabs/gists/blob/master/PowerView-with-RemoteAccessPolicyEnumeration.ps1
