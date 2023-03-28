# Offboarding.ps1 
# Created by: Cody So
# Email: cso@investottawa.ca

# Connect to Microsoft Graph Powershell
Write-Host "Connecting to Microsoft Graph..."
Write-Host ""

# Connect with Graph permission scopes of User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, DeviceManagementManagedDevices.ReadWrite.All
Try
{
Connect-Graph -Scopes User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, DeviceManagementManagedDevices.ReadWrite.All -ErrorAction Stop
}
# Script ends if the Graph autherication does not succeed
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
# Script ends if the ExchangeOnline autherication does not succeed
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

# Function to retrieve the user account information from Local AD and Microsoft 365
function Retrieve_UserInfo {

    # Retrieve the user object from Local AD
    $user = Get-ADUser -Identity $username -Properties Name, EmailAddress, Title, Manager, extensionAttribute1, Telephonenumber
    
    # Assign the user account properties
    $Name = $user.Name
    $email = $user.EmailAddress
    $jobTitle = $user.Title
    $managerName = (Get-ADUser $user.Manager).Name
    $extensionAttribute = $user.extensionAttribute1
    $phone = $user.Telephonenumber

    if ($user.Enabled -eq $false) {
        $status = "Disabled"
    }
    else{
        $status = "Enabled"
    }

    # Output the user properties from Local AD
    Write-Host `n
    Write-Host "User details for username `"$username`""
    Write-Host ------------------------------------
    Write-Host "Name: $Name"
    Write-Host "Email address: $email"
    Write-Host "Job Title: $jobTitle"
    Write-Host "Manager Name: $managerName"
    Write-Host "Extension Attribute: $extensionAttribute"
    Write-Host "Telephone Number: $phone"
    Write-Host "Local AD Account status: $status"
    Write-Host `n
    Write-Host "Checking the account on Microsoft 365..."

    # Check if the user account exists in the Microsoft 365
    if ($null -ne $(Get-MgUser -UserId $email -ErrorAction SilentlyContinue)){  

    # Get the M365 account status, mailbox type, licenses assigned to and Intune managed devices of the user with ExchangeOnlinea and Graph Powershell
    $M365user = Get-MgUser -UserId $email -Property AccountEnabled
    $Mailbox = Get-EXOMailbox -Identity $email
    $LicensedUser  =  Get-MgUserLicenseDetail -UserId $email
    $Registereddevice = Get-MgUserManagedDevice -userId $email -ErrorAction SilentlyContinue

        # Checked the account enable status
        if ($M365user.AccountEnabled -eq $false) {
            $M365status = "Disabled"
        }
        else{
            $M365status = "Enabled"
        }

        # Checked the user mailbox type
        if ($Mailbox.RecipientTypeDetails -eq "UserMailbox") {
            $Mailboxtype = "UserMailbox"
        }
        elseif ($Mailbox.RecipientTypeDetails -eq "SharedMailbox") {
            $Mailboxtype = "SharedMailbox"
        }

        # Checked if the user has Intune manged devices
        if (!$Registereddevice.DeviceName) {
            $Devicename = "None"
        }
        else{
            $Devicename = $Registereddevice.DeviceName
        }

        # Output the user Microsoft 365 account details
        Write-Host ""
        Write-Host "Microsoft 365 account details"
        Write-Host ------------------------------------
        Write-Host "Microsoft 365 Account status: $M365status"
        Write-Host "Microsoft 365 Account mailbox type: $Mailboxtype"
        Write-Host "Intune managed device of the user: $Devicename"
        
        $skus = $LicensedUser.SkuPartNumber
        $skucount = $skus.count

        Write-Output ""
        Write-Output "$Name has $skucount total licenses assignments: "
        Write-Output -------------------------------------------------
        Write-Output $skus
        
    }
    # Output user account does not exist on Microsoft 365
    else {
        Write-Host `n
        Write-Host "ERROR: $username user account doesn't exists on Microsoft 365!"
    }  
}

# Function to disable the user account on Local AD and Microsoft 365
function Disable_User {

    # Get the user object from the Local AD
    $user = Get-ADUser -Identity $username -Properties MemberOf, EmailAddress, Manager

    # Check if the user account is already disabled 
    if ($user.Enabled -eq $false) {
        
        Write-Host ""
        Write-Host "ERROR: $username user account is already disabled!"
    }

    else {      
        # Specify the OU to move the user account to
        $ouPath = "OU=Disabled Accounts,OU=Users,OU=OCRI,DC=RESEARCH,DC=PRV"
        
        # Get the user properties from the user object and set the reset password
        $email = $user.EmailAddress
        $managerName = (Get-ADUser $user.Manager).Name
        $managerEmail = (Get-ADUser $user.Manager -Properties EmailAddress).EmailAddress
        $newPassword = ConvertTo-SecureString "Can*1234" -AsPlainText -Force

        # Disable the user account in the Local AD
        Disable-ADAccount -Identity $user
        
        # Confirm completion
        Write-Host ""
        Write-Host "$username local AD user account has been disabled."

        # Reset the user account password
        Set-ADAccountPassword -Identity $user -NewPassword $newPassword -Reset

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account password has been reset."

        # Remove the job title, manager, telephone number and extensionAttribute1 attribute
        Set-ADUser -Identity $username -Clear title, manager, Telephonenumber, extensionAttribute1

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account title, manager, telephone number and extension attribute has been cleared."
        Write-Host ""

        # Remove user from all AD groups except "Domain Users" and "O365-USERS" groups
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
            
        # Get the Microsoft 365 account details with ExchangeOnline and Graph Powershell
        $M365user = Get-MgUser -UserId $email -Property id
        $Mailbox = Get-EXOMailbox -Identity $email
        $LicensedUser  =  Get-MgUserLicenseDetail -UserId $email
        
        # Disable the user account in the Microsoft 365 with Graph Powershell
        Update-MgUser -UserId $email -AccountEnabled:$false

        # Confirm completion
        Write-Host ""
        Write-Host "$username Microsoft 365 user account has been disabled."

        # Check if the user mailbox is already a shared mailbox 
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


        # Remove user from all the Microsoft 365 groups and distribution groups
        # Get all the Microsoft 365 and dsitribution groups with Exchange Online Powershell
        $M365Groups = Get-EXORecipient -Filter "Members -eq '$($Mailbox.DistinguishedName)'" -ErrorAction SilentlyContinue | Select-Object DisplayName,ExternalDirectoryObjectId,RecipientTypeDetails

        foreach ($M365Group in $M365Groups) {
                        
            # Handle Microsoft 365 Groups with ExchangeOnline Powershell
            if ($M365Group.RecipientTypeDetails -eq "GroupMailbox") {
                    Write-Host "Removing user from Microsoft 365 Group ""$($M365Group.DisplayName)"" ..."
                    Remove-UnifiedGroupLinks -Identity $M365Group.ExternalDirectoryObjectId -Links $Mailbox.DistinguishedName -LinkType Member -Confirm:$false -ErrorAction SilentlyContinue
            }
            # Handle "regular" groups with ExchangeOnline Powershell
            elseif ($M365Group.RecipientTypeDetails -eq "MailUniversalDistributionGroup" -or $M365Group.RecipientTypeDetails -eq "MailUniversalSecurityGroup") { 
                    Write-Host "Removing user from Distribution Group ""$($M365Group.DisplayName)"" ..."
                    Remove-DistributionGroupMember -Identity $M365Group.ExternalDirectoryObjectId -Member $Mailbox.DistinguishedName -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction SilentlyContinue 
            }
        }
        
        # Get all the Azure security groups with Graph Powershell
        $AzureGroups = Get-MgUserMemberOf -UserId $email -All -ConsistencyLevel eventual -Property id,displayName,mailEnabled,securityEnabled,membershipRule,mail,isAssignableToRole,groupTypes

        foreach ($AzureGroup in $AzureGroups) {
            # Skip groups with dynamic membership which cannot be removed manaully. They will be removed by clearing the user AD extensionAttribute.
            if ($AzureGroup.AdditionalProperties.groupTypes -eq "DynamicMembership") {
                Write-Host "Skipping group ""$($AzureGroup.AdditionalProperties.displayName)"" as it uses dynamic membership. They will be removed by clearing the extensionAttribute."; continue
            }

            # Handle Azure AD security groups with Graph Powershell
            if ($AzureGroup.AdditionalProperties.securityEnabled -eq "True" -and $AzureGroup.AdditionalProperties.mailEnabled -ne "True"){
            Write-Host "Removing user from Azure AD group ""$($AzureGroup.AdditionalProperties.displayName)""..."
            Remove-MgGroupMemberByRef -GroupId $AzureGroup.id -DirectoryObjectId $M365user.id -ErrorAction SilentlyContinue -Confirm:$false
            }        
        }

        # Confirm completion
        Write-Host ""
        Write-Host "All Microsoft 365, Distribution and Azure AD groups have been removed."

        # Delegate mailbox access to the user’s manager with ExchangeOnline Powershell
        Add-MailboxPermission -identity $email -User $managerEmail -AccessRights FullAccess -Confirm:$false | Out-Null

        # Confirm completion
        Write-Host ""
        Write-Host "$email mailbox access has been delegrated to their manager $managerName."

        # Setting Automatic replies for the user mailbox with ExchangeOnline Powershell
        $internalmessage = "Thank you for your e-mail. Please note that I am no longer working with Invest Ottawa. For ongoing support and/or any questions, please contact $managerName at $managerEmail. `nThank you for reaching out to Invest Ottawa."
        $externalmessage = "Thank you for your e-mail. Please note that I am no longer working with Invest Ottawa. For ongoing support and/or any questions, please contact $managerName at $managerEmail. `nThank you for reaching out to Invest Ottawa."

        Set-MailboxAutoReplyConfiguration -Identity $email -AutoReplyState Enabled -InternalMessage $internalmessage -ExternalMessage $externalmessage -ExternalAudience All

        # Confirm completion
        Write-Host ""
        Write-Host "Automatic out of office replies has been set for $email mailbox."

        # Remove all the licenses from the user with Graph Powershell
        Set-MgUserLicense -UserId $email -RemoveLicenses @($LicensedUser.SkuId) -AddLicenses @() -Confirm:$false | Out-Null

        # Confirm completion
        Write-Host ""
        Write-Host "Following licenses have been removed from the user account $email."
        $LicensedUser.SkuPartNumber

        }
        # Output the user account does not exist on Microsoft 365
        else {
            Write-Host ""
            Write-Host "ERROR: $username user account doesn't exists on Microsoft 365!"
        }  
    
    }
}

# Function to check and remove the Intune managed devices of the user
function Remove_device {
    # Get the user object from local AD
    $user = Get-ADUser -Identity $username -Properties Name, EmailAddress
    $Name = $user.Name
    $email = $user.EmailAddress
    
    # Check if the user has any Intune managed devices
    If ($null -ne $(Get-MgUserManagedDevice -userId $email -ErrorAction SilentlyContinue)) {
        
        # Get all the Intune managed devices object of the user with Graph Powershell
        $Registereddevices = Get-MgUserManagedDevice -userId $email
        
        $Devicename = $Registereddevices.DeviceName
        $devicecount = $Devicename.count

        # Output the Intune managed device details
        Write-Output ""
        Write-Output "$Name has $devicecount total Intune managed devices: "
        Write-Output -------------------------------------------------
        Write-Output $Devicename

        # Ask for confirmation for removing ALL devices or SINGLE devicefrom Intune
        Write-Host ""
        Write-Host "*** Please confirm to remove ALL or SINGLE Intune managed devices of $username. ***"
        Write-Host "Type 'ALL' to remove all or 'SINGLE' to remove individual device. Type 'NO' to exit:"  -NoNewline

        $removedevice = Read-Host

        # Remove all Intune managed devices with Graph Powershell
        If ($removedevice.ToUpper() -eq "ALL") {
            
            foreach ($Registereddevice in $Registereddevices){

                Write-Host "Removing the Intune device"$Registereddevice.DeviceName"..."
                Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $Registereddevice.id -ErrorAction Continue
            } 
        }
        # Remove individual Intune managed device with Graph Powershell
        elseif ($removedevice.ToUpper() -eq "SINGLE") {

                # Get the Intune device name to remove
                Write-Host "Please enter the Intune device name to remove individually: " -NoNewline
                $individualdevice = Read-Host
                $Deleted = $false

                # Go through all the retrieved Intune device objects to remove the specified device with Graph Powershell
                foreach ($Registereddevice in $Registereddevices){
                    if ($Registereddevice.DeviceName -eq $individualdevice){

                        Write-Host "Removing the Intune device"$Registereddevice.DeviceName"..."
                        Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $Registereddevice.id -ErrorAction Continue
                        Write-Host ""
                        Write-Host "Intune device"$Registereddevice.DeviceName" has been removed successfully!"
                        $Deleted = $true
                        break
                    }  
                }
                # Output if the device name is not found or not belongs to the user
                if (!$Deleted){
                    Write-Host ""
                    Write-Host "ERROR: $individualdevice doesn't exist or not belongs to user $Name!"
                }
            } 
        else {
            Write-Host ""
            Write-Host "Intune devices of $username user account has not been removed."
        } 
    }
    # Output user has no managed devices on Intune
    else{
        Write-Host `n
        Write-Host "ERROR: User $username has no Intune managed devices!"
    }
}

#Main script block, keep running until user quits

#While loop block for main query to ask for the username input
while($exitprogram -eq 0 ) {
    Write-Host `n
    Write-Host User Offboarding Script:
    Write-Host -------------------------------------

Write-Host "Please enter the username OR enter q to quit: " -NoNewline

# Read the username input
$username = Read-Host

# Quit the script if user input 'q'
If ($username -eq "Q" -or $username -eq "q" ) {
    Write-Host ""
    Write-Host "Exiting Program.... " 
    $exitprogram = 1
} 

else {
    # Check if the username exists in the local AD
    If ($null -ne $(Get-ADUser -Identity $username)) {

    # Call fucntion 'Retrieve_UserInfo' to retrieve user account inofrmation from local AD and Microsoft 365
    Retrieve_UserInfo

    # Ask for confirmation for disabling user account in local AD and Microsoft 365
    Write-Host `n
    $confirm = ""
    $confirm = Read-Host "*** PLEASE CONFIRM TO DISABLE THE USERNAME $username. Type 'YES' to confirm. ***"
        
        If ($confirm.ToUpper() -eq "YES") {
            
            Write-Host "Disabling $username user account..."

            # Call function 'Disable_User' to disable the user account
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

    # Ask if continue to manage the Intune managed devices of the user
    Write-Host ""
    $deviceconfirm = ""
    $deviceconfirm = Read-Host "Do you want to check the Intune device of $username ? (Y/N)"

    If ($deviceconfirm.ToUpper() -eq "Y") {
            
            Write-Host "Getting $username devices from Intune..."

            # Call fucntion 'Remove_device' to remove Intune devices
            try
            {Remove_device}

            # Catch if there is error or exception while removing the devices from Intune
            catch
            {
                Write-Warning "An Error has occurred when removing the devices: $($_.Exception.Message)"
                Start-Sleep -Seconds 10
            }
        }
        
    }

    # Output username does not exist in Local AD
    else {
        Write-Host `n
        Write-Host "ERROR: Username $username doesn't exists!"
    }      
}

}

