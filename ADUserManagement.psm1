<#
.SYNOPSIS
    Retrieves information about an Active Directory user account.

.DESCRIPTION
    The Get-ADUserInfo function retrieves information about the specified Active Directory user account.

.PARAMETER User
    Specifies the username of the Active Directory user account.

.PARAMETER Server
    Specifies the Active Directory server to connect to.

.PARAMETER Credential
    Specifies the credentials to use for connecting to the Active Directory server.

.EXAMPLE
    Get-ADUserInfo -User "JohnDoe" -Server "ADServer01" -Credential (Get-Credential)
    Retrieves information about the user account "JohnDoe" from the Active Directory server "ADServer01" using the specified credentials.

.NOTES
    This function requires the Active Directory module to be installed. You can install it by running the following command:
    Install-WindowsFeature RSAT-AD-PowerShell
#>

function Get-ADUserInfo {
    # Use the provided or entered credentials to connect to Active Directory
    param(
        [string]$User,
        [string]$Server,
        [PSCredential]$Credential,
        [switch]$AllProperties
    )

    $ADUser = Get-ADUser $User -Properties * -Server $Server -Credential $Credential

    if ($AllProperties) {
        Write-Host "######################"
        Write-Host "#   All Properties   #"
        Write-Host "######################"
        $ADUser | Format-List *
        return
    }
    # Password Information
    Write-Host "############################"
    Write-Host "#   Password Information   #"
    Write-Host "############################"

    if ($ADUser.PasswordExpired -eq $true) {
        Write-Host "Password Expired: Yes*"
        Write-Host "Password was last set: $($ADUser.PasswordLastSet)"
    } else {
        Write-Host "Password Expired: No"
    }

    if ($ADUser.PasswordNeverExpires -eq $true) {
        Write-Host "Password is set to never expire."
    }

    if ($ADUser.PasswordNotRequired -eq $true) {
        Write-Host "$User has PasswordNotRequired set to True."
    }

    # Account status
    Write-Host ""
    Write-Host "######################"
    Write-Host "#   Account-Status   #"
    Write-Host "######################"

    if ($ADUser.Enabled -eq $false) {
        Write-Host "Account Disabled: Yes*"
    } elseif ($ADUser.Enabled -eq $true) {
        Write-Host "Account Disabled: No"
    } else {
        Write-Host "Property: 'Enabled' not found."
    }

    if ($ADUser.LockedOut -eq $true) {
        Write-Host "Account Locked: Yes*"
    } elseif ($ADUser.LockedOut -eq $false) {
        # Account is not locked out
        Write-Host "Account Locked: No"
    } else {
        Write-Host "Property: 'LockedOut' not Found"
    }

    if ($ADUser.AccountExpires -ne 0 -and $ADUser.AccountExpires -ne [Int64]::MaxValue) {
        $expirationDate = [datetime]::FromFileTime($ADUser.AccountExpires)

        if ($expirationDate -gt (Get-Date)) {
            Write-Host "Account Expired: No, Expires on: $expirationDate"
        } else {
            Write-Host "Account Expired: Yes, Expired on: $expirationDate*"
        }
    } elseif ($ADUser.AccountExpires -eq [Int64]::MaxValue) {
        Write-Host "Account does not have an expiration date (set to never expire)."
    } else {
        Write-Host "Account does not have an expiration date."
    }

    # Account information
    Write-Host ""
    Write-Host "###########################"
    Write-Host "#   Account Information   #"
    Write-Host "###########################"

    if ($ADUser.Name) {
        Write-Host "Name:" $ADUser.Name
    }

    if ($ADUser.Description) {
        Write-Host "Description:" $ADUser.Description
    }

    if ($ADUser.EmailAddress) {
        Write-Host "Email Address:" $ADUser.EmailAddress
    }

    if ($ADUser.SamAccountName) {
        Write-Host "Sam Account:" $ADUser.SamAccountName
    }

    if ($ADUser.Title) {
        Write-Host "Title:" $ADUser.Title
    }
}
<#
.SYNOPSIS
    Modifies Active Directory user information.

.DESCRIPTION
    The Set-ADUserInfo function is used to modify various attributes of an Active Directory user account. It provides options to reset the password, change the password, unlock the account, enable/disable the account, and add/remove the user from a group.

.PARAMETER User
    Specifies the username of the Active Directory user account.

.PARAMETER Server
    Specifies the Active Directory server to connect to.

.PARAMETER Credential
    Specifies the credentials to use for authentication.

.PARAMETER AddToGroup
    Specifies the group to add the user to.

.PARAMETER RemoveFromGroup
    Specifies the group to remove the user from.

.PARAMETER ChangePassword
    Indicates whether to change the user's password.

.PARAMETER ResetPassword
    Indicates whether to reset the user's password and force a password change at next logon.

.PARAMETER UnlockAccount
    Indicates whether to unlock the user's account.

.PARAMETER EnableAccount
    Indicates whether to enable the user's account.

.PARAMETER DisableAccount
    Indicates whether to disable the user's account.

.EXAMPLE
    Set-ADUserInfo -User "JohnDoe" -Server "DC01" -Credential $cred -ChangePassword
    Changes the password for the user "JohnDoe" using the specified server and credentials.

.EXAMPLE
    Set-ADUserInfo -User "JaneSmith" -Server "DC01" -Credential $cred -ResetPassword
    Resets the password for the user "JaneSmith" and forces a password change at next logon.

#>
function Set-ADUserInfo {
    param(
    [string]$User,
    [string]$Server,
    [PSCredential]$Credential,
    [string]$AddToGroup,
    [string]$RemoveFromGroup,
    [switch]$ChangePassword,
    [switch]$ResetPassword,
    [switch]$UnlockAccount,
    [switch]$EnableAccount,
    [switch]$DisableAccount
    )

    #Reset password and force user to change password at next logon
    if ($ResetPassword) {
        $NewPassword = "TempPassword123!"

        Set-ADAccountPassword -Identity $User -NewPassword (ConvertTo-SecureString -String $NewPassword -AsPlainText -Force) -Reset -Server $Server -Credential $Credential
        Write-Host "Password for $User has been reset to $NewPassword."

        # Force user to change password at next logon
        Set-ADUser -Identity $User -ChangePasswordAtLogon $true -Server $Server -Credential $Credential
    }
    
    # Change a users password
    elseif ($ChangePassword) {
        $NewPassword = Read-Host -Prompt "Enter the new password for $User"
        Set-ADAccountPassword -Identity $User -NewPassword (ConvertTo-SecureString -String $NewPassword -AsPlainText -Force) -Reset -Server $Server -Credential $Credential
        Write-Host "Password for $User has been changed."
    }

    elseif ($UnlockAccount) {
        # Unlock the account
        Unlock-ADAccount -Identity $User -Server $Server -Credential $Credential
        Write-Host "Account for $User has been unlocked."
    }
    elseif ($EnableAccount) {
        # Enable the account
        Enable-ADAccount -Identity $User -Server $Server -Credential $Credential
        Write-Host "Account for $User has been enabled."
    }
    elseif ($DisableAccount) {
        # Disable the account
        Disable-ADAccount -Identity $User -Server $Server -Credential $Credential
        Write-Host "Account for $User has been disabled."
    }
    if ($AddToGroup) {
        Add-ADGroupMember -Identity $AddToGroup -Members $User -Server $Server -Credential $Credential
        Write-Host "$User has been added to $AddToGroup."
    }
    if ($RemoveFromGroup) {
        Remove-ADGroupMember -Identity $RemoveFromGroup -Members $User -Server $Server -Credential $Credential
        Write-Host "$User has been removed from $RemoveFromGroup."
    }

}

Export-ModuleMember -Function Get-ADUserInfo, Set-ADUserInfo
