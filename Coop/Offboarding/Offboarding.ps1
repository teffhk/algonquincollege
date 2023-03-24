# Offboarding.ps1 
# Created by: Cody So
# Email: cso@investottawa.ca

# Connect to Microsoft Graph Powershell
Write-Host "Connecting to Microsoft Graph..."
Write-Host ""

Try
{
Connect-Graph -Scopes User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All -ErrorAction Stop
}
Catch [Exception]
{
Write-Warning "!!!!!!! Exception !!!!!!!" 
Write-Output ""
Write-Output $_ 
Write-Output ""
Write-Warning "The username or password is incorrect. Please verify and try again."
Write-Output ""
Exit
}

# Connect to Exchange Online Powershell
Write-Host ""
Write-Host "Connecting to Exchange Online..."
Write-Host ""

Try
{
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -ShowBanner:$false
}
Catch [Exception]
{
Write-Warning "!!!!!!! Exception !!!!!!!" 
Write-Output ""
Write-Output $_ 
Write-Output ""
Write-Warning "The username or password is incorrect. Please verify and try again."
Write-Output ""
Exit
}
Write-Host "Connect to Exchange Online successfully!"

# Set exit program state varible
$exitprogram = 0
$ErrorActionPreference = "SilentlyContinue"

# Function to retrieve the user account information from LocalAD and AzureAD
function Retrieve_UserInfo {

    # Retrieve the user object from Local AD
    $user = Get-ADUser -Identity $username -Properties Name, EmailAddress, Title, Manager, extensionAttribute1
    
    # Assign the user account properties to the varibles
    $Name = $user.Name
    $email = $user.EmailAddress
    $jobTitle = $user.Title
    $managerName = (Get-ADUser $user.Manager).Name
    $extensionAttribute = $user.extensionAttribute1

    if ($user.Enabled -eq $false) {
        $status = "Disabled"
    }
    else{
        $status = "Enabled"
    }

    # Output the user properties from the variables
    Write-Host `n
    Write-Host "User details for username `"$username`""
    Write-Host ------------------------------------
    Write-Host "Name: $Name"
    Write-Host "Email address: $email"
    Write-Host "Job Title: $jobTitle"
    Write-Host "Manager Name: $managerName"
    Write-Host "Extension Attribute: $extensionAttribute"
    Write-Host "Local AD Account status: $status"
    Write-Host `n
    Write-Host "Checking the account on Office 365..."

    # Check if the user account exists in the Microsoft 365
    if ($null -ne $(Get-MgUser -UserId $email -ErrorAction SilentlyContinue)){  

    # Get the O365 account status, mailbox type and licenses assigned to the user from MG Powershell
    $O365user = Get-MgUser -UserId $email -Property AccountEnabled
    $Mailbox = Get-EXOMailbox -Identity $email
    $LicensedUser  =  Get-MgUserLicenseDetail -UserId $email

        if ($O365user.AccountEnabled -eq $false) {
            $O365status = "Disabled"
        }
        else{
            $O365status = "Enabled"
        }

        if ($Mailbox.RecipientTypeDetails -eq "UserMailbox") {
            $Mailboxtype = "UserMailbox"
        }
        elseif ($Mailbox.RecipientTypeDetails -eq "SharedMailbox") {
            $Mailboxtype = "SharedMailbox"
        }

        Write-Host ""
        Write-Host "Office 365 account details"
        Write-Host ------------------------------------
        Write-Host "Office 365 Account status: $O365status"
        Write-Host "Office 365 Account mailbox type: $Mailboxtype"
        
        $skus = $LicensedUser.SkuPartNumber
        $skucount = $skus.count

        Write-Output ""
        Write-Output "$Name has $skucount total licenses assignments: "
        Write-Output -------------------------------------------------
        Write-Output $skus
        
    }
    else {
        Write-Host `n
        Write-Host "ERROR: $username user account doesn't exists on Office 365!"
    }  
}

# Function to disable the user account
function Disable_User {

    # Get the user object and set the reset password
    $user = Get-ADUser -Identity $username -Properties MemberOf, EmailAddress, Manager

    # Check if the user account is already disabled 
    if ($user.Enabled -eq $false) {
        
        Write-Host ""
        Write-Host "ERROR: $username user account is already disabled!"
    }

    else {      
        # Specify the target OU to move the user account to
        $ouPath = "OU=Disabled Accounts,OU=Users,OU=OCRI,DC=RESEARCH,DC=PRV"
        
        $email = $user.EmailAddress
        $managerName = (Get-ADUser $user.Manager).Name
        $managerEmail = (Get-ADUser $user.Manager -Properties EmailAddress).EmailAddress
        $newPassword = ConvertTo-SecureString "Can*1234" -AsPlainText -Force

        # Disable the user account in the local AD
        Disable-ADAccount -Identity $user
        
        # Confirm completion
        Write-Host ""
        Write-Host "$username local AD user account has been disabled."

        # Reset the user account password
        Set-ADAccountPassword -Identity $user -NewPassword $newPassword -Reset

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account password has been reset."

        # Remove the job title, manager, extensionAttribute1 attribute
        Set-ADUser -Identity $username -Clear title, manager, extensionAttribute1

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account title, manager and extension attribute has been cleared."
        Write-Host ""

        # Remove user from all groups except "All Users"
        foreach ($group in $user.MemberOf) {
        if ((Get-ADGroup $group).Name -ne "Domain Users" -and (Get-ADGroup $group).Name -ne "O365-USERS") {
            Write-Host "Removing user from Group ""$((Get-ADGroup $group).Name)""..."
            Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
        }
        }

        # Confirm completion
        Write-Host ""
        Write-Host "All Local AD groups except 'Domain Users' and 'O365-USERS' have been removed from user $username."

        # Set AD attribute to hide the user’s account from Global Address List
        Get-ADuser -Identity $user -property msExchHideFromAddressLists | Set-ADObject -Replace @{msExchHideFromAddressLists=$true}

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account has been hidden from the Global Address List."

        # Move the user account to the target OU
        Move-ADObject -Identity $user -TargetPath $ouPath

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account have been moved to 'Disabled Accounts' OU."
        
        Write-Host ""
        Write-Host ----------------------------------------------------------------
        Write-Host "Now connecting to Microsoft 365 to disable the user account..."
        Start-Sleep -Seconds 3
        Write-Host "Disabling $username Microsoft 365 user account..."

        # Check if the user account exists in the Microsoft 365
        If ($null -ne $(Get-MgUser -UserId $email -ErrorAction SilentlyContinue)) {
            
        $O365user = Get-MgUser -UserId $email -Property id
        $Mailbox = Get-EXOMailbox -Identity $email
        $LicensedUser  =  Get-MgUserLicenseDetail -UserId $email
        
        # Disable the user account in the Microsoft 365
        Update-MgUser -UserId $email -AccountEnabled:$false

        # Confirm completion
        Write-Host ""
        Write-Host "$username Microsoft 365 user account has been disabled."

        # Check if the user mailbox is a shared mailbox already
        if ($Mailboxtype -ne "SharedMailbox") {
            # Convert user mailbox to shared mailbox
            Set-Mailbox -Identity $email -Type Shared

            # Confirm completion
            Write-Host ""
            Write-Host "$email mailbox has been coverted to shared mailbox."
            Write-Host ""
        }
        else {

            Write-Host ""
            Write-Host "$email mailbox is a shared mailbox already!"
            Write-Host ""
        }

        # Remove user from all the Office365 groups and distribution groups
        $O365Groups = Get-EXORecipient -Filter "Members -eq '$($Mailbox.DistinguishedName)'" -ErrorAction SilentlyContinue | Select-Object DisplayName,ExternalDirectoryObjectId,RecipientTypeDetails

        foreach ($O365Group in $O365Groups) {
                        
            #handle Microsoft 365 Groups
            if ($O365Group.RecipientTypeDetails -eq "GroupMailbox") {
                    Write-Host "Removing user from Microsoft 365 Group ""$($O365Group.DisplayName)"" ..."
                    Remove-UnifiedGroupLinks -Identity $O365Group.ExternalDirectoryObjectId -Links $Mailbox.DistinguishedName -LinkType Member -Confirm:$false -ErrorAction SilentlyContinue
            }
            #handle "regular" groups
            elseif ($O365Group.RecipientTypeDetails -eq "MailUniversalDistributionGroup" -or $O365Group.RecipientTypeDetails -eq "MailUniversalSecurityGroup") { 
                    Write-Host "Removing user from Distribution Group ""$($O365Group.DisplayName)"" ..."
                    Remove-DistributionGroupMember -Identity $O365Group.ExternalDirectoryObjectId -Member $Mailbox.DistinguishedName -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction SilentlyContinue 
            }
        }
        
        $AzureGroups = Get-MgUserMemberOf -UserId $email -All -ConsistencyLevel eventual -Property id,displayName,mailEnabled,securityEnabled,membershipRule,mail,isAssignableToRole,groupTypes

        #Handle Azure AD security groups
        foreach ($AzureGroup in $AzureGroups) {
            #skip groups with dynamic membership
            if ($AzureGroup.AdditionalProperties.groupTypes -eq "DynamicMembership") {
                Write-Host "Skipping group ""$($AzureGroup.AdditionalProperties.displayName)"" as it uses dynamic membership."; continue
            }

            if ($AzureGroup.AdditionalProperties.securityEnabled -eq "True" -and $AzureGroup.AdditionalProperties.mailEnabled -ne "True"){
            Write-Host "Removing user from Azure AD group ""$($AzureGroup.AdditionalProperties.displayName)""..."
            Remove-MgGroupMemberByRef -GroupId $AzureGroup.id -DirectoryObjectId $O365user.id -ErrorAction SilentlyContinue -Confirm:$false
            }        
        }

        # Confirm completion
        Write-Host ""
        Write-Host "All Microsoft 365, Distribution and Azure AD groups have been removed."

        # Delegate mailbox access to the user’s manager 
        Add-MailboxPermission -identity $email -User $managerEmail -AccessRights FullAccess -Confirm:$false | Out-Null

        # Confirm completion
        Write-Host ""
        Write-Host "$email mailbox access has been delegrated to their manager $managerName."

        # Setting Automatic replies for the user mailbox
        $internalmessage = "Thank you for your e-mail. Please note that I am no longer working with Invest Ottawa. For ongoing support and/or any questions, please contact $managerName at $managerEmail. `nThank you for reaching out to Invest Ottawa."
        $externalmessage = "Thank you for your e-mail. Please note that I am no longer working with Invest Ottawa. For ongoing support and/or any questions, please contact $managerName at $managerEmail. `nThank you for reaching out to Invest Ottawa."

        Set-MailboxAutoReplyConfiguration -Identity $email -AutoReplyState Enabled -InternalMessage $internalmessage -ExternalMessage $externalmessage -ExternalAudience All

        # Confirm completion
        Write-Host ""
        Write-Host "Automatic out of office replies has been set for $email mailbox."

        # Remove all the licenses from the user
        Set-MgUserLicense -UserId $email -RemoveLicenses @($LicensedUser.SkuId) -AddLicenses @() -Confirm:$false | Out-Null

        # Confirm completion
        Write-Host ""
        Write-Host "Following licenses have been removed from the user account $email."
        $LicensedUser.SkuPartNumber

        }
        else {
            Write-Host ""
            Write-Host "ERROR: $username user account doesn't exists on Microsoft 365!"
        }  
    
    }
}

#Main script block, keep running until user quits

#While loop block for main query to ask for the username
while($exitprogram -eq 0 ) {
    Write-Host `n
    Write-Host User Offboarding Script:
    Write-Host -------------------------------------

Write-Host "Please enter the username OR enter q to quit: " -NoNewline

# Read the username input
$username = Read-Host

If ($username -eq "Q" -or $username -eq "q" ) {
    Write-Host ""
    Write-Host "Exiting Program.... " 
    $exitprogram = 1
} 

else {
    If ($null -ne $(Get-ADUser -Identity $username)) {

    # Call fucntion 'Retrieve_UserInfo' to retrieve user account inofrmation
    Retrieve_UserInfo

    # Ask for confirmation for disabling user account
    Write-Host `n
    $confirm = ""
    $confirm = Read-Host "*** PLEASE CONFIRM TO DISABLE THE USERNAME $username. Type 'YES' to confirm. ***"
        
        If ($confirm.ToUpper() -eq "YES") {
            
            Write-Host "Disabling $username user account..."

            # Call fucntion 'Disable_User' to disable the user account
            try
            {Disable_User}

            # Catch if there is error or exception while disabling the account
            catch
            {
                Write-Warning "An Error has occurred when disabling the account: $($_.Exception.Message)"
                Start-Sleep -Seconds 10
            }
        }
        else {
            Write-Host ""
            Write-Host "$username user account is not disabled."
        } 
    }

    # Check if the username doesnt exist
    else {
        Write-Host `n
        Write-Host "ERROR: Username $username doesn't exists!"
    }      
}


}

