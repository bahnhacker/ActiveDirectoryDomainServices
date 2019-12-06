## script creates Active Directory Password Security Objects, PSOs. 
## creates 3 PSOs:
## 1. PSO_desNOTexp; to which a domain group containing all user service accounts are added.
## 2. PSO_IncSec; to which Privileged Groups are added.
## 3. PSO_BasicSec; to which Domain Users are added.
##
## variables: set via prompts during execution
##
##
## created/modified: 20180126
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

$DomainGroupServiceAccts = Read-Host -Prompt "Input the name of the domain group to which all service accounts are a member"


########################################################################################################################

Import-Module ActiveDirectory

## Creates a PSO for accounts whose password does not expire, ie. service accounts
New-ADFineGrainedPasswordPolicy -Name PSO_desNOTexp -Precedence 1 -ComplexityEnabled $true -Description "PSO for accounts whose password does NOT expire" -DisplayName PSO_desNOTexp -LockoutDuration "0.00:30:00" -LockoutObservationWindow "0.00:30:00" -LockoutThreshold 3 -MinPasswordAge "1.00:00:00" -MinPasswordLength 14 -PasswordHistoryCount 24 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $true 
Write-Host "----New Password Policy 'PSO_desNOTexp' createted----"
Add-ADFineGrainedPasswordPolicySubject PSO_desNOTexp -Subjects $DomainGroupServiceAccts
Get-ADFineGrainedPasswordPolicy PSO_doesNOTexp | ft AppliesTo -A

## Creates a PSO for accounts that require a more strict password, ie. domain admins
New-ADFineGrainedPasswordPolicy -Name PSO_IncSec -Precedence 5 -ComplexityEnabled $true -Description "PSO for accounts that require a more strict password" -DisplayName PSO_IncSec -LockoutDuration "0.00:30:00" -LockoutObservationWindow "0.00:30:00" -LockoutThreshold 3 -MaxPasswordAge "30.00:00:00" -MinPasswordAge "1.00:00:00" -MinPasswordLength 20 -PasswordHistoryCount 24 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $true 
Write-Host "----New Password Policy 'PSO_IncSec' createted----"
Add-ADFineGrainedPasswordPolicySubject PSO_IncSec -Subjects "Domain Admins","Enterprise Admins","Schema Admins"
Get-ADFineGrainedPasswordPolicy PSO_IncSec | ft AppliesTo -A

## Creates a PSO for basic user accounts, ie. domain users
New-ADFineGrainedPasswordPolicy -Name PSO_BasicSec -Precedence 10 -ComplexityEnabled $true -Description "PSO for basic user accounts" -DisplayName PSO_BasicSec -LockoutDuration "0.00:30:00" -LockoutObservationWindow "0.00:30:00" -LockoutThreshold 3 -MaxPasswordAge "60.00:00:00" -MinPasswordAge "1.00:00:00" -MinPasswordLength 14 -PasswordHistoryCount 24 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $true 
Write-Host "----New Password Policy 'PSO_BasicSec' createted----"
Add-ADFineGrainedPasswordPolicySubject PSO_BasicSec -Subjects "Domain Users"
Get-ADFineGrainedPasswordPolicy PSO_BasicSec | ft AppliesTo -A


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