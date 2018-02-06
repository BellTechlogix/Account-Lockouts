<#

Account_LockoutFind.ps1
Version:  1.0
Created:  {31Jan18}
Created by {Kristopher Roy - BellTechlogix}
Summary:  {script to allow elevated password resets and account unlocks} 
Usage:
Example:
    
Updates:

#>

# Custom Functions that you create

#Function to import AD Module
Function ImportModule([string]$ModuleName) 
{ 
    # Imports a module if it is not loaded in the current session 
    # Usage: 
    #     ImportModule "<modulename>" 
    # Example: 
    #     ImportModule "activedirectory" 
    # 
     
    [bool]$ModuleIsLoaded = $False 
    $LoadedModules = Get-Module | Select Name 
    If ($LoadedModules -is [object]) 
    { 
        #One or more modules are loaded 
        ForEach ($Module in $LoadedModules) 
        { 
            $ModuleLower = $Module.Name.ToLower() 
            If ($ModuleLower -eq $ModuleName) 
            { 
                #The module we are searching for is already imported. Create flag. 
                $ModuleIsLoaded = $True 
            } 
        } 
        If ($ModuleIsLoaded -eq $False) 
        { 
            #Some modules currently imported but not $ModuleName. Let's import it. 
            Import-Module $ModuleName 
	    Write-output "Imported Module"  |out-string
        } 
    } 
    else 
    { 
        #No modules currently imported. Let's import it. 
        Import-Module $ModuleName 
	Write-output "Imported Module"  |out-string
    } 
} 



#This the arguments needed to pass, up to 4 can be passed

#User account to be modified
$USERNAME=$args[0]



# Always use Try to capture errors within the script, this helps to having process hung and troubleshoot better.

try
{


# Setup your Environment by adding Modules or PSSnapins
       
	# Imports Module if needed
        ImportModule "activedirectory"

     # Adds PS Snapin
	    #Example:: if ( (Get-PSSnapin -Name "VMware.VimAutomation.Core" -ErrorAction SilentlyContinue) -eq $null ) { Add-PsSnapin "VMware.VimAutomation.Core" }

# Adding Help, it's great to have a help to provide more information to your users
    
 If ($USERNAME -eq "?") {
    write-output "Parameter 1 - This is the field that you input the end user account name in"
    exit
    }



# MAIN ROUTINE
    
    # Peform your actions

    [array]$grps=Get-ADUser $username -Property memberOf | Select -ExpandProperty memberOf | Get-ADGroup | Select Name

    $ADUser = Get-ADUser $USERNAME -properties *
    $NAGroups = 'Enterprise Admins','Domain Admins','Account Operators','Desktop Support','Exchange Organization Administrators'
    FOREACH($grp in $grps)
    {IF($grp.name -in $NAGroups){Write-output ("$USERNAME is in a group that your permissions are restricted from modifying, "+$grp.name)
        EXIT
        }
    }
    $usrchk= Get-ADUser $USERNAME | ? { ($_.distinguishedname -like "*OU=Accounts,OU=Network Services*") }
    if ($usrchk) {write-output "You are in restricted OU Group"
    EXIT
    }  

    
    #action to find locked account

$DomainName = $env:USERDOMAIN
[datetime]$StartTime = (Get-Date).AddDays(-3)
Invoke-Command -ComputerName (
    [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain((
        New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $DomainName))
    ).PdcRoleOwner.name
) {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740;StartTime=$Using:StartTime} |
    Where-Object {$_.Properties[0].Value -like "$Using:UserName"} |
    Select-Object -Property TimeCreated,
        @{Label='UserName';Expression={$_.Properties[0].Value}},
        @{Label='ClientName';Expression={$_.Properties[1].Value}}
} #-Credential (Get-Credential -credential tony.johnson ) |

Select-Object -Property TimeCreated, UserName, ClientName|Out-String
	
	    # to return your data use |out-string with your cmdlts to be return via script

        #Examples: Search-ADAccount –LockedOut |out-string
        #Examples: Get-VMHostService | where {$_.key -eq 'sfcbd-watchdog' } | out-string

    # for Console type output use: write-output "Some Information" 

        #Examples: write-output "This is my action"



# Cleanup (Optional)
    #Remove-Module "module name"
    #Remove-PSSnapin "snapin name"



}
catch
{
        # Captures errors
        write-output "Exception Message: $($_.Exception.Message)" 
}

