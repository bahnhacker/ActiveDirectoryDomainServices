## this script uses PowerShell to automate the collection of information as outlined in the TechNet article, Active 
## Directory Domain Discovery Checklist. the information is then output into a csv to be utilized accordingly.
## https://social.technet.microsoft.com/wiki/contents/articles/38512.active-directory-domain-discovery-checklist.aspx
##
## note: not ALL of the information will be collected. lines will be created for the missing data to be filled in.
##
## variables: set via prompts during execution
##
##
## created/modified: 201905
## https://ms.bahnhacker.us | https://github.bahnhacker.us
## contact: https://twitter.com/bahnhacker | https://www.linkedin.com/in/bpstephenson
########################################################################################################################
########################################################################################################################

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

## Self-elevate the script if required
<#
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] $env:USERNAME)) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
#>


########################################################################################################################

Function Select-FolderDialog  ## Gets the path in which to save the report
{
    param([string]$Description="Select a location in which the dump file will be created:",[string]$RootFolder="Desktop")

 [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") |
     Out-Null     

   $objForm = New-Object System.Windows.Forms.FolderBrowserDialog
        $objForm.Rootfolder = $RootFolder
        $objForm.Description = $Description
        $Show = $objForm.ShowDialog()
        If ($Show -eq "OK")
        {
            Return $objForm.SelectedPath
        }
        Else
        {
            Write-Error "Operation cancelled by user."
        }
    }
$SelectedPath = Select-FolderDialog


########################################################################################################################

$Date = Get-Date -f yyyyMMddhhmm

Import-Module ActiveDirectory

$ForestInfo = Get-ADForest $env:USERDNSDOMAIN
$ForestFQDN = $ForestInfo.Name
$DomainPDC = $ForestInfo.SchemaMaster
$DomainInfo = Get-ADDomain $env:USERDNSDOMAIN
$DomainDN = $DomainInfo.Name

## Output folder
New-Item -Path "$SelectedPath" -Name "$DomainDN-AD_Domain_Discovery-$Date" -ItemType "directory"
$wshshell = New-Object -ComObject WScript.Shell
$desktop = [System.Environment]::GetFolderPath('Desktop')
  $lnk = $wshshell.CreateShortcut($desktop+"\tmp.lnk")
  $lnk.TargetPath = "$SelectedPath\$DomainDN-AD_Domain_Discovery-$Date"
  $lnk.Save() 
$Path = "$SelectedPath\$DomainDN-AD_Domain_Discovery-$Date"

## Output text file
$ExportPath = "$Path\$DomainDN-AD_Domain_Discovery.csv"
"The information below is the output of the AD_Domain_Discovery.ps1. This script uses PowerShell toautomate the" | Out-File -Append -Filepath "$ExportPath"
"collection of information as outlined in the TechNet article, Active Directory Domain Discovery Checklist." | Out-File -Append -Filepath "$ExportPath"
"https://social.technet.microsoft.com/wiki/contents/articles/38512.active-directory-domain-discovery-checklist.aspx" | Out-File -Append -Filepath "$ExportPath"
"Created: $Date" | Out-File -Append -Filepath "$ExportPath"
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## Domain Name
"Fully Qualified Domain Name (FQDN): $env:USERDNSDOMAIN" | Out-File -Append -Filepath "$ExportPath"

#### Forest Functional Level
$ForestFunctionalLevel = $ForestInfo.ForestMode
"Forest Functional Level: $ForestFunctionalLevel" | Out-File -Append -Filepath "$ExportPath"

#### Forest Architecture
$ForestDomains = $ForestInfo.Domains
$ForestCount = $ForestDomains.Count
$ChildDomains = $DomainInfo.ChildDomains
$ChildCount = $ChildDomains.Count
"Domains within Forest: <$ForestCount>" | Out-File -Append -Filepath "$ExportPath"
"Parent Domain: $ForestFQDN" | Out-File -Append -Filepath "$ExportPath"
"Child Domain(s): <$ChildCount> $ChildDomains" | Out-File -Append -Filepath "$ExportPath"
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## Domain Trust(s)
Function Set-TrustAttributes
{
[cmdletbinding()]
Param(
[parameter(Mandatory=$false,ValueFromPipeline=$True)]
[int32]$Value
)
If ($value){
$input = $value
}
[String[]]$TrustAttributes=@() 
Foreach ($key in $input){

                if([int32]$key -band 0x00000001){$TrustAttributes+="Non Transitive"} 
                if([int32]$key -band 0x00000002){$TrustAttributes+="UpLevel"} 
                if([int32]$key -band 0x00000004){$TrustAttributes+="Quarantaine (SID Filtering enabled)"} #SID Filtering 
                if([int32]$key -band 0x00000008){$TrustAttributes+="Forest Transitive"} 
                if([int32]$key -band 0x00000010){$TrustAttributes+="Cross Organization (Selective Authentication enabled)"} #Selective Auth 
                if([int32]$key -band 0x00000020){$TrustAttributes+="Within Forest"} 
                if([int32]$key -band 0x00000040){$TrustAttributes+="Treat as External"} 
                if([int32]$key -band 0x00000080){$TrustAttributes+="Uses RC4 Encryption"}
                        } 
return $trustattributes
}
Try{$TrustQuery = gwmi -Class Microsoft_DomainTrustStatus -Namespace root\microsoftactivedirectory -ComputerName $DomainPDC -ErrorAction SilentlyContinue}
Catch {$_}
If ($TrustQuery){
$TrustOutput = $TrustQuery | Select-Object -Property @{L="Trusted Domain";e={$_.TrustedDomain}},@{L="Trusts Direction";e={switch ($_.TrustDirection)
{
    "1" {"Inbound"}
    "2" {"Outbound"}
    "3" {"Bi-directional"}
    Default {"N/A"}
}}},@{L="Trusts Attributes";e={($_.TrustAttributes | Set-TrustAttributes)}}
} $TrustOutput | Out-File -Append -Filepath $ExportPath
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## Sites
$Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
$SitesSubnets = @()
foreach ($Site in $Sites)
{
	foreach ($Subnet in $Site.Subnets){
	   $SitesTemp = New-Object PSCustomObject -Property @{
	   'Site' = $Site.Name
	   'Subnet' = $Subnet; }
	    $SitesSubnets += $SitesTemp
	}
} $SitesSubnets | Out-File -Append -Filepath $ExportPath
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## Domain Controller(s)
"Domain Controller(s):" | Out-File -Append -Filepath "$ExportPath"
Get-ADDomainController -Filter * | Select Name, ipv4Address, OperatingSystem, site | Sort-Object -Property Name | Out-File -Append -Filepath $ExportPath
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## FSMO Role Holder(s)
"SchemaMaster: $DomainPDC" | Out-File -Append -Filepath $ExportPath
"FSMO Role Holder(s):" | Out-File -Append -Filepath "$ExportPath"
Get-ADDomain | Select-Object InfrastructureMaster,PDCEmulator,RIDMaster | Out-File -Append -Filepath $ExportPath
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## OU Structure
"OU Structure:" | Out-File -Append -Filepath "$ExportPath"
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | Format-Table Name, DistinguishedName -A | Out-File -Append -Filepath $ExportPath
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## AD Objects
"ADObjects" | Out-File -Append -Filepath "$ExportPath"

#### AD Users
$UserCount = (Get-ADUser -Filter *).count
"Users (all): <$UserCount>" | Out-File -Append -Filepath "$ExportPath"
"Users information has been exported to: $DomainDN-Users.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADUser -Filter * -Properties * | Select Name,CanonicalName,Description,DistinguishedName,EmailAddress,LastLogon,PasswordNeverExpires,ObjectGUID,ObjectSID,PasswordExpired,PasswordLastSet,WhenCreated | Out-File -FilePath "$Path\$DomainDN-Users.csv"
" " | Out-File -Append -Filepath "$ExportPath"

#### AD Groups
$GroupCount = (Get-ADGroup -Filter *).count
"Groups: <$GroupCount>" | Out-File -Append -Filepath "$ExportPath"
"Groups information has been exported to: $DomainDN-Groups.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADGroup -Filter * -Properties * | Select-Object Name,CanonicalName,Description,DistinguishedName,EmailAddress,GroupCategory,GroupScope,ManagedBy,ObjectGUID,ObjectSID,WhenCreated | Out-File -FilePath "$Path\$DomainDN-Groups.csv"

#### Privileged Groups
$PrivilegedGroupsCount = (Get-ADGroup -Filter 'AdminCount -eq 1').count
"Privileged Groups: <$PrivilegedGroupsCount>"
"Privileged Groups information has been exported to: $DomainDN-PrivilegedGroups.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADGroup -Filter 'AdminCount -eq 1' -Properties * | Select-Object Name,CanonicalName,DistinguishedName,MemberOf,Members,ObjectGUID,ObjectSID | Out-File -FilePath "$Path\$DomainDN-PrivilegedGroups.csv"

#### Domain Admins
$DomainAdminCount = (Get-ADGroupMember -Identity "Domain Admins").count
"Domain Admins: <$DomainAdminCount>" | Out-File -Append -Filepath "$ExportPath"
"Domain Admin Group Members has been exported to: $DomainDN-DomainAdmins.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADGroupMember -Identity "Domain Admins"  | Out-File -FilePath "$Path\$DomainDN-DomainAdmins.csv"
" " | Out-File -Append -Filepath "$ExportPath"

#### AD Computer Objects
$ComputerCount = (Get-ADComputer -Filter *).count
"Computer Objects: <$ComputerCount>" | Out-File -Append -Filepath "$ExportPath"
"Computer Objects information has been exported to: $DomainDN-Computers.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADComputer -Filter * -Properties * | Select-Object Name,CanonicalName,Description,DestinguishedName,DNSHostName,ObjectGUID,ObjectSID,OperatingSystem,OperatingSystemVersion,PrimaryGroup | Out-File -FilePath "$Path\$DomainDN-Computers.csv"
" " | Out-File -Append -Filepath "$ExportPath"

#### AD Service Accounts - User
$ServiceUserCount = (Get-ADUser -Filter {(Name -like "*svc*") -or (Name -like "*service*")}).count
"Service Accounts (User, filtered for svc or service in name): <$ServiceUserCount>" | Out-File -Append -Filepath "$ExportPath"
"Service Accounts (User) information has been exported to: $DomainDN-ServiceAccount_User.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADUser -Filter {(Name -like "*svc*") -or (Name -like "*service*")} -Properties * | Select Name,CanonicalName,Description,DistinguishedName,EmailAddress,LastLogon,PasswordNeverExpires,ObjectGUID,ObjectSID,PasswordExpired,PasswordLastSet,WhenCreated | Out-File -FilePath "$Path\$DomainDN-ServiceAccount_User.csv"

#### AD Service Accounts - gMSA
"Service Accounts (gMSA) information has been exported to: $DomainDN-ServiceAccount_gMSA.csv" | Out-File -Append -Filepath "$ExportPath"
Get-ADServiceAccount -Filter * -Properties * | Select Name,CanonicalName,Description,DistinguishedName,PrimaryGroup,PrincipalsAllowedToRetrieveManagedPassword,ObjectGUID,ObjectSID,WhenCreated | Out-File -FilePath "$Path\$DomainDN-ServiceAccount_gMSA.csv"
" " | Out-File -Append -Filepath "$ExportPath"
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## GPOs
$GPOCount = (Get-GPO -All).Count
"Group Policy Objects: <$GPOCount>" | Out-File -Append -Filepath "$ExportPath"
"GPOs have been backed up to the folder: $DomainDN-GroupPolicies" | Out-File -Append -Filepath "$ExportPath"
New-Item -Force -Path "$Path\$DomainDN-GroupPolicies\" -ItemType Directory
Backup-Gpo -All -Path "$Path\$DomainDN-GroupPolicies\"
Get-GPO -All -Domain $ForestFQDN -InformationVariable * | Sort DisplayName | Select-Object DisplayName,Id,Owner,GpoStatus | Out-File -Append -Filepath "$ExportPath"
Get-GPOReport -Domain $ForestFQDN -All -ReportType Html -Path "$Path\$DomainDN-GroupPolicies\FullGPOReport.html"
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## Password Security Objects
$PSOCount = (Get-ADFineGrainedPasswordPolicy -Filter *).count
"Password Security Objects (PSOs): <$PSOCount>" | Out-File -Append -Filepath "$ExportPath"
Get-ADFineGrainedPasswordPolicy -Filter * -Properties * | Select-Object Name,Description,DistinguishedName,ObjectGUID,AppliesTo,Precedence,ComplexityEnabled,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled | Out-File -Append -Filepath "$ExportPath"
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## Active Directory Features
"Active Directory Features:" | Out-File -Append -Filepath "$ExportPath"
Get-ADOptionalFeature -Filter * -Properties * | Select-Object Name,EnabledScopes | Out-File -Append -Filepath "$ExportPath"
" " | Out-File -Append -Filepath "$ExportPath"
"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"

## DNS
"DNS Information" | Out-File -Append -Filepath "$ExportPath"
"DNS Forwarders:" | Out-File -Append -Filepath "$ExportPath"
Get-DnsServerForwarder -InformationVariable * | Select-Object IPAddress | Out-File -Append -Filepath "$ExportPath"

#### DNS A Records
$DNSRecordCount = (Get-DnsServerResourceRecord -ZoneName $ForestFQDN -RRType "A").Count
"DNS A Records: <$DNSRecordCount>" | Out-File -Append -Filepath "$ExportPath"
"Information has been exported to: $DomainDN-DNS_A_Records.csv" | Out-File -Append -Filepath "$ExportPath"
Get-DnsServerResourceRecord -ZoneName $ForestFQDN -RRType "A" | Out-File -Append -Filepath "$Path\$DomainDN-DNS_A_Records.csv"
" " | Out-File -Append -Filepath "$ExportPath"

#### DNS ServerZones
$DNSZoneCount = (Get-DnsServerZone -InformationVariable *).Count
"DNS Zones: <$DNSZoneCount>" | Out-File -Append -Filepath "$ExportPath"
Get-DnsServerZone -InformationVariable * | Out-File -Append -Filepath "$ExportPath"
" " | Out-File -Append -Filepath "$ExportPath"

#### DNS Scavenging
"DNS Scavenging:" | Out-File -Append -Filepath "$ExportPath"
Get-DnsServerZoneAging -Name $ForestFQDN | Out-File -Append -Filepath "$ExportPath"
" " | Out-File -Append -Filepath "$ExportPath"


"########################################################################################################################" | Out-File -Append -Filepath "$ExportPath"
"######### End of file ######### End of file ######### End of file ######### End of file ######### End of file ##########" | Out-File -Append -Filepath "$ExportPath"
"#####################################################################################################################bps" | Out-File -Append -Filepath "$ExportPath"


#Compress/Zip Output File
$destination = "$SelectedPath\$DomainDN-AD_Domain_Discovery-$Date.zip"
If(Test-path $destination) {Remove-item $destination}
Add-Type -assembly "system.io.compression.filesystem"
[io.compression.zipfile]::CreateFromDirectory($Path, $destination) 


########################################################################################################################
###### End of script ######## End of script ######## End of script ######## End of script ######## End of script #######
########################################################################################################################
########################################### Disclaimer for custom scripts ##############################################
###### The sample scripts are not supported under any ANY standard support program or service. The sample scripts ######
###### are provided AS IS without warranty of any kind. The author further disclaims all implied warranties       ######
###### including, without limitation, any implied warranties of merchantability or of fitness for a particular    ######
###### purpose. The entire risk arising out of the use or performance of the sample scripts and documentation     ######
###### remains with you. In no event shall the author, its authors, or anyone else involved in the creation,      ######
###### production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation,######
###### damages for loss of business profits, business interruption, loss of business information, or other        ######
###### pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if ######
###### the author has been advised of the possibility of such damages.                                            ######
########################################### Disclaimer for custom scripts ##############################################
#####################################################################################################################bps