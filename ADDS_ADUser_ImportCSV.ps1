## script imports users from csv to active directory
##
## variables: modify variables accordingly
##
##
## created/modified: 201908
## https://ms.bahnhacker.us | https://github.bahnhacker.us
## contact: https://twitter.com/bahnhacker | https://www.linkedin.com/in/bpstephenson
########################################################################################################################
########################################################################################################################

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

## self-elevate the script if required
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
$Path = "C:\tmp" ## udpate file location
$UserOUPath = "OU=Users,OU=AdminTst,OU=Domain Groups,OU=MGMT” ## update for the OU where the users are to be created in.
$AcctPass = "Password" ## update with the desired password


########################################################################################################################

$Date = Get-Date -f yyyyMMdd

Import-Module ActiveDirectory

Import-Csv -Path $Path | foreach {
 
$GivenName = $_.name.split()[0] 
$Surname = $_.name.split()[1]

New-ADUser -Name $_.account -UserPrincipalName $_.email –givenName $GivenName –surname $Surname -DisplayName $_.name -AccountPassword (ConvertTo-SecureString -AsPlainText $AcctPass -Force) -Path $UserOUPath -ChangePasswordAtLogon 0 -EmailAddress $_.email -Enabled 1

}



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