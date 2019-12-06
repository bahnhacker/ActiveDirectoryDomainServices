## Script performs the necessary tasks to configure LAPS after it has been installed on the Domain Controller.
##
##
## created/modified: 201804
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

Import-Module ActiveDirectory

$wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
$SrceDN = $wmiDomain.DomainName
$DomainDN = Get-ADDomain | select -ExpandProperty DistinguishedName   
$Date = Get-Date -f yyyyMMddhhmm


gpupdate /force

Import-Module AdmPwd.PS
Update-AdmPwdADSchema
Find-AdmPwdExtendedRights -Identity Client
Find-AdmPwdExtendedRights -Identity MGMT
Set-AdmPwdReadPasswordPermission -Identity Client -AllowedPrincipals Client_ADM
Set-AdmPwdReadPasswordPermission -Identity MGMT -AllowedPrincipals MGMT_ADM
Set-AdmPwdComputerSelfPermission -Identity Client
Set-AdmPwdComputerSelfPermission -Identity MGMT


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