<#

ParseNetLogon-StandAlone.ps1
Version:  1.7
Created:  {31Jan18}
Modified:  {06Feb18}
Created by {Kristopher Roy - BellTechlogix}
Summary:  {script to parse netlogon logs and find account unlocks} 
#>

#Function to import Module
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

ImportModule ActiveDirectory

$USERNAME = Read-Host -Prompt "Input Locked UserName"

$serverlist = (Get-ADComputer -LDAPFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))").DNSHostName
#$serverlist = "JAXWDC01"
#$server = "CROWLEYPDC"

#set temp dir
$TEMPDIR = "C:\Temp"
if(!(Test-Path -Path $TEMPDIR )){
   New-Item -ItemType directory -Path $TEMPDIR
}

#deffinitions for Error Codes
$codelookup = @{"0xC000005E"="No Logon Servers";"0xC0000022"="Access Denied";"0x00000005"="Access Denied";"0x5"="Access Denied";
"0xC0000064"="No Such User";"0xC000018A"="No Trust LSA Secret";"0xC000006D"="Logon Failure";"0xC000009A"="Insufficient Resources";
"0xC0020050"="RPC NT Call Cancelled";"0xC0000017"="No Memory";"0xC000006E"="Account Restriction";"0xC000006"="Password Restriction";
"0xC0000070"="Invalid Workstation";"0xC000006A"="Wrong Password";"0xC0000193"="Account Expired";"0xC0000192"="NetLogon Not Started";
"0xC0000071"="Password Expired";"0xC000006F"="Invalid Logon Hours";"0xC0000234"="Account Locked Out";"0xC0000072"="Account Disabled";
"0xC00000DC"="Invalid Server State";"0xC0000224"="Password Must Change";"0x0"="Logon Failed"}

#Create netlogondoc array to store data
$netlogondoc = @()
write-host $serverlist.count "Servers listed as DC's"
$statuscount = 0

#loop through each server and gather log details on account listed in input
FOREACH($server in $serverlist)
{
    $statuscount++
	Write-Progress -Activity ("Gathering Logs..."+$server) -Status "collected $statuscount of $($serverlist.count)" -PercentComplete ($statuscount/$serverlist.count*100)
	#Get OS
    $OS = try{Get-ADComputer -Identity $server.split(".")[0] -Properties OperatingSystem|select OperatingSystem}catch{$OS=$NULL}
    IF($OS.OperatingSystem -ne $NULL -and $OS.OperatingSystem -ne "")
    {
        #Get Remote WinDir
        $netlogon = GI \\$Server\admin$\debug\netlogon.log
        #If file get fails, try a different way
        IF($netlogon -eq $null -or $netlogon -eq "")
        {
            $remotewindir = (wmic.exe /NODE:$Server OS GET WindowsDirectory).split(":")
            $netlogon = GI ("\\"+$Server+"\"+$remotewindir[2]+"$"+$remotewindir[3].trim("")+"\debug\netlogon.log")
        }
        IF($netlogon -eq $null -or $netlogon -eq "")
        {
            $netlogon = GI \\$Server\C$\WINNT\debug\netlogon.log
        }
        copy $netlogon.FullName $TEMPDIR
        $netlogonlocal = GI ($TEMPDIR+"\"+$netlogon.name)
        $logerrors = (Import-Csv $netlogonlocal -Header "Dump","UserName","TimeStamp","LoggedAt","Win32Err","Win32ErrCode","Message","From","Code"|Where-Object{$_ -like "*$username*"})
        IF($logerrors -ne $null)
        {
            IF($OS.OperatingSystem -like "*2008*" -or $OS.OperatingSystem -like "*2012*" -or $OS.OperatingSystem -like "*2016*" -or $OS.OperatingSystem -like "*2008" -or $OS.OperatingSystem -like "*2012" -or $OS.OperatingSystem -like "*2016")
            {
                FOREACH($logerror in $logerrors)
                {
                    $alldetails = $logerror.Dump
                    $logerror.UserName = (($alldetails.Split("\")[1]) -split("from"))[0]
                    $TimeStamp = ($alldetails.Split("[")[0]).trim()
                    $logerror.TimeStamp = [datetime](($TimeStamp).split(' ')[0]+"/"+(get-date -Format yyyy)+" "+($TimeStamp).split(' ')[1])
                    $logerror.LoggedAt = $server
                    $logerror.Win32Err = $alldetails.Split("[")[1].Split("]")[0]
                    $logerror.Win32ErrCode = $alldetails.Split("[")[2].Split("]")[0]
                    $logerror.Message = $alldetails.Split("]")[2]
                    IF($alldetails -like "*Returns*")
                    {
                        $logerror.From = ((($alldetails -Split("From"))[1]) -split("Returns"))[0]
                        $logerror.Code = $codelookup[(($alldetails -split("Returns"))[1]).trim("")]
                    }
                    ELSEIF($alldetails -inotlike "*Returns*")
                    {
                       $logerror.From = (($alldetails -Split("From"))[1]) 
                    }
                    $netlogondoc += $logerror|select UserName,TimeStamp,LoggedAt,Win32Err,Win32ErrCode,Message,From,Code
                    $Timestamp = $null
                    $logerror = $null
                }
            }
            IF($OS.OperatingSystem -like "*2003*" -or $OS.OperatingSystem -like "*2003")
            {
                FOREACH($logerror in $logerrors)
                {
                    $alldetails = $logerror.Dump
                    $logerror.UserName = (($alldetails.Split("\")[1]) -split("from"))[0]
                    $TimeStamp = ($alldetails.Split("[")[0]).trim()
                    $logerror.TimeStamp = [datetime](($TimeStamp).split(' ')[0]+"/"+(get-date -Format yyyy)+" "+($TimeStamp).split(' ')[1])
                    $logerror.LoggedAt = $server
                    $logerror.Win32Err = $alldetails.Split("[")[1].Split("]")[0]
                    $logerror.Win32ErrCode = ""
                    $logerror.Message = $alldetails.Split("]")[1]
                    IF($alldetails -like "*Returns*")
                    {
                        $logerror.From = ((($alldetails -Split("From"))[1]) -split("Returns"))[0]
                        $logerror.Code = try{$codelookup[(($alldetails -split("Returns"))[1]).trim("")]}catch{""}
                    }
                    ELSEIF($alldetails -inotlike "*Returns*")
                    {
                       $logerror.From = (($alldetails -Split("From"))[1]) 
                    }
                    $netlogondoc += $logerror|select UserName,TimeStamp,LoggedAt,Win32Err,Win32ErrCode,Message,From,Code
                    $Timestamp = $null
                    $logerror = $null
                }
            }
        }
        $server = $null
        $netlogon = $null
        $netlogonlocal = $null
        $remotewindir = $null
        $logerrors = $null
    }
}

#output details to screen
$netlogondoc|where-object{$_.UserName -like "$Username*"}|Select Timestamp,From,Code|sort TimeStamp -Descending|ft
#output csv of details to c:\temp
$netlogondoc|where-object{$_.UserName -like "$Username*"}|sort TimeStamp -Descending|export-csv ("C:\Temp\"+$username+"Locklogsexport.csv") -NoTypeInformation