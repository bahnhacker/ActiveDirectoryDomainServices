## script creates the administrative groups commonly required in an environment. 
##
## variables: modify variables accordingly
##
##
## created/modified: 201802
## https://ms.bahnhacker.us | https://github.bahnhacker.us
## contact: https://twitter.com/bahnhacker | https://www.linkedin.com/in/bpstephenson
########################################################################################################################
########################################################################################################################

Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

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

## Custom Variables
$GroupScope = "Global" ## select Global, DomainLocal, or Universal.
$GroupDN = “OU=AdminTst,OU=Domain Groups,OU=MGMT” ## update for the OU where the groups are to be created in.


########################################################################################################################

Import-Module ActiveDirectory

$DomainFQDN = Get-ADDomain | select -ExpandProperty DistinguishedName
$wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
$SrceDN = $wmiDomain.DomainName
$Date = Get-Date -f yyyyMMddhhmm


## Infrastructure Support Groups
NEW-ADGroup –name "$SrceDN-MGMT-Infra" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Infrastructure services. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Infrastructure servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Infra-DBA" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Infrastructure Databases. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Infrastructure servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Infra-NET" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Infrastructure Network. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Infrastructure servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Infra-Unix" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Infrastructure Unix systems. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Infrastructure servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Infra-Wintel" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Infrastructure Wintel systems. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Infrastructure servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”

NEW-ADGroup –name "$SrceDN-MGMT-Infra-DBA-SVR" –groupscope $GroupScope -Description "Group intended for all Infrastructure Database Servers. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for all Infrastructure Database Servers within the domain."} –path “$GroupDN,$DomainFQDN”


## Client Support Groups
NEW-ADGroup –name "$SrceDN-MGMT-Client" –groupscope $GroupScope -Description "Group intended for all User Groups that support ALL of the Client services. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Client servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Client-DBA" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Client's Databases. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Client servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Client-NET" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Client's Network. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Client servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Client-Unix" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Client's Unix systems. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Client servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-Client-Wintel" –groupscope $GroupScope -Description "Group intended for all User Groups that support the Client's Wintel systems. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for Client servies/systems within the domain."} –path “$GroupDN,$DomainFQDN”

NEW-ADGroup –name "$SrceDN-MGMT-Client-DBA-SVR" –groupscope $GroupScope -Description "Group intended for all Client Database Servers. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for all Client Database Servers within the domain."} –path “$GroupDN,$DomainFQDN”


## MGMT Applications and Services Groups
NEW-ADGroup –name "$SrceDN-MGMT-Arch " –groupscope $GroupScope -Description "Group intended for User Groups that contain members of the Architect team. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for members of the Architect team within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-BAK" –groupscope $GroupScope -Description "Group intended for all User Groups that contain members of the Backup team. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for members of the Backup team within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-OPS" –groupscope $GroupScope -Description "Group intended for all User Groups that contain members of the Operations or Helpdesk teams. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for members of the Operations or Helpdesk teams within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-STO" –groupscope $GroupScope -Description "Group intended for all User Groups that contain members of the Storage team. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for members of the Storage team within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-TA" –groupscope $GroupScope -Description "Group intended for all User Groups that contain members of the Tools and Automation teams. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for members of the Tools and Automation teams within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-VI" –groupscope $GroupScope -Description "Group intended for all User Groups that contain members of the Virtual Infrastructure team. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for members of the Virtual Infrastructure team within the domain."} –path “$GroupDN,$DomainFQDN”

NEW-ADGroup –name "$SrceDN-MGMT-BAK-SVR" –groupscope $GroupScope -Description "Group intended for all Backup Management Servers. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for all Backup Management Servers within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-STO-SVR" –groupscope $GroupScope -Description "Group intended for all Storage Management Servers. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for all Storage Management Servers within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-TA-SVR" –groupscope $GroupScope -Description "Group intended for all Tools/Automation Management Servers. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions for all Tools/Automation Management Servers within the domain."} –path “$GroupDN,$DomainFQDN”
NEW-ADGroup –name "$SrceDN-MGMT-VI-SVR" –groupscope $GroupScope -Description "Group intended for all Virtual Management Servers. **NOTES**" -OtherAttributes @{Info = "This Domain Group is used to configure rights/permissions forall Virtual Management Servers within the domain."} –path “$GroupDN,$DomainFQDN”


## Adds Wintel Groups to AD DS Builtin Groups
Add-ADGroupMember -Identity "DnsAdmins" -Members "$SrceDN-MGMT-Infra-Wintel", "$SrceDN-MGMT-Client-Wintel"
Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members "$SrceDN-MGMT-Infra-Wintel", "$SrceDN-MGMT-Client-Wintel"


## Adds Support Groups to parent team group
Add-ADGroupMember -Identity "$SrceDN-MGMT-Client" -Members "$SrceDN-MGMT-Client-DBA", "$SrceDN-MGMT-Client-NET", "$SrceDN-MGMT-Client-Unix", "$SrceDN-MGMT-Client-Wintel"
Add-ADGroupMember -Identity "$SrceDN-MGMT-Infra" -Members "$SrceDN-MGMT-Infra-DBA", "$SrceDN-MGMT-Infra-NET", "$SrceDN-MGMT-Infra-Unix", "$SrceDN-MGMT-Infra-Wintel"


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