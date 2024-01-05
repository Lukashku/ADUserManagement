## Basic Overview
A basic powershell module that lets me perform my most common Active Directory tasks easily from my desktop. I no longer need to log into the domain controllers for all the various domains.

## Getting Started
Import the module 
```
> Import-Module .\ActiveDirectoryManagement.psm1
```
Then create your domain(s) credential(s)
```
> $ExampleDomainCredential=Get-Credential
```

## Example Uses
Getting a basic summary of a user
```
> Get-ADUserInfo -User jdoe -Server test.org -Credential $ExampleDomainCredential 
############################
#   Password Information   #
############################
Password Expired: No

######################
#   Account-Status   #
######################
Account Disabled: No
Account Locked: No
Account Expired: No, Expires on: 01/01/2025 00:00:00

###########################
#   Account Information   #
###########################
Name: Doe, John
Description: Test Account
Sam Account: jdoe
Title: Test Account
```

Resetting a users password.
```
> Set-ADUserInfo -User jdoe -Server test.org -Credential $ExampleDomainCredential -ResetPassword
Password for jdoe has been reset to TempPassword123!.
```
