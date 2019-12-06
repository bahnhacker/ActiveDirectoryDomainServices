## Script grants support groups permissions to view ms-mcs-admpwd attribute of Computer Object.
##
## variables: modify variables accordingly
##
##
## created/modified: 201801
## https://ms.bahnhacker.us | https://github.bahnhacker.us
## contact: https://twitter.com/bahnhacker | https://www.linkedin.com/in/bpstephenson
########################################################################################################################
########################################################################################################################

## Variables 
$MGMTOU = "MGMT" ## edit for the desired OU
$ClientOU = "Client" ## edit for the desired OU
$DevTst = "Dev" ## edit for the desired OU

$InfrastructureTeam = "SupportInfra" ## edit for the desired group
$ClientSupportTeam = "SupportClient" ## edit for the desired group
$Operations = "SupportOps" ## edit for the desired group

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

Import-Module ActiveDirectory
Import-Module AdmPwd.PS

Update-AdmPwdADSchema

Set-AdmPwdReadPasswordPermission -Identity $MGMTOU -AllowedPrincipals $InfrastructureTeam,$ClientSupportTeam,$Operations
Set-AdmPwdReadPasswordPermission -Identity $ClientOU -AllowedPrincipals $InfrastructureTeam,$ClientSupportTeam,$Operations
Set-AdmPwdReadPasswordPermission -Identity $DevTst -AllowedPrincipals $InfrastructureTeam,$ClientSupportTeam,$Operations



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