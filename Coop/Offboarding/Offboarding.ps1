# Offboarding.ps1 
# Author: Cody So
# Contact: teffhk@gmail.com
# Test 29/06/2023

#Requires -RunAsAdministrator
#Requires -Modules ExchangeOnlineManagement

#Start logging
$Date = Get-Date -Format "yyyyMMdd"

# Connect to Microsoft Graph Powershell
Write-Host "Connecting to Microsoft Graph..."
Write-Host ""

# Connect with Graph permission scopes of User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, DeviceManagementManagedDevices.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.AccessAsUser.All
Try
{
Connect-Graph -Scopes User.ReadWrite.All, Group.ReadWrite.All, Organization.Read.All, DeviceManagementManagedDevices.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Directory.AccessAsUser.All -ErrorAction Stop
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
    $ErrorActionPreference = "SilentlyContinue"

    # Retrieve the user object from Local AD
    $user = Get-ADUser -Identity $username -Properties Name, EmailAddress, Title, Manager, extensionAttribute1, extensionAttribute3, Telephonenumber
    
    # Assign the user account properties
    $Name = $user.Name
    $email = $user.EmailAddress
    $jobTitle = $user.Title
    $extensionAttribute1 = $user.extensionAttribute1
    $extensionAttribute3 = $user.extensionAttribute3
    $phone = $user.Telephonenumber

    if ($null -ne $user.Manager) {
        $managerName = (Get-ADUser $user.Manager).Name
    }
    else {
        $managerName = $null
    }

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
    Write-Host "Extension Attribute 1: $extensionAttribute1"
    Write-Host "Extension Attribute 3: $extensionAttribute3"
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
        Write-Warning "$username user account doesn't exists on Microsoft 365!"
    }  
}

# Function to disable the user account on Local AD and Microsoft 365
function Disable_User {
    $ErrorActionPreference = "SilentlyContinue"

    # Get the user object from the Local AD
    $user = Get-ADUser -Identity $username -Properties MemberOf, EmailAddress, Manager

    # Check if the user account is already disabled 
    if ($user.Enabled -eq $false) {
        
        Write-Host ""
        Write-Warning "$username user account is already disabled!"
    }

    else {      
        # Specify the OU to move the user account to
        $ouPath = "OU=Disabled Accounts,OU=Users,OU=OCRI,DC=RESEARCH,DC=PRV"
        
        # Get the user properties from the user object and set the reset password
        $email = $user.EmailAddress
        $newPassword = ConvertTo-SecureString "" -AsPlainText -Force

        # Check if the user has manager assigned, if not default to Invest Ottawa email
        if ($null -ne $user.Manager) {
            $managerName = (Get-ADUser $user.Manager).Name 
            $managerEmail = (Get-ADUser $user.Manager -Properties EmailAddress).EmailAddress
        }
        else {
            $managerName = "Invest Ottawa"
            $managerEmail = "clientservices@investottawa.ca"
        }

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
        Set-ADUser -Identity $username -Clear title, manager, Telephonenumber, extensionAttribute1, extensionAttribute3

        # Confirm completion
        Write-Host ""
        Write-Host "$username user account title, manager, telephone number and extension attributes have been cleared."
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
        $AssignedApps  = Get-MgUserAppRoleAssignment -UserId $email
        
        # Disable the user account in the Microsoft 365 with Graph Powershell
        Update-MgUser -UserId $email -AccountEnabled:$false

        # Confirm completion
        Write-Host ""
        Write-Host "$username Microsoft 365 user account has been disabled."

        # Check if the user mailbox is already a shared mailbox 
        if ($Mailbox.RecipientTypeDetails -ne "SharedMailbox") {
            # Convert user mailbox to shared mailbox
            Set-Mailbox -Identity $email -Type Shared

            # Confirm completion
            Write-Host ""
            Write-Host "$email mailbox has been converted to shared mailbox."
            Write-Host ""
        }
        else {
            Write-Host ""
            Write-Host "$email mailbox is a shared mailbox already!" -ForegroundColor DarkCyan
            Write-Host ""
        }


        # Remove user from all the Microsoft 365 groups and distribution groups
        # Get all the Microsoft 365 and dsitribution groups with Exchange Online Powershell
        $M365Groups = Get-EXORecipient -Filter "Members -eq '$($Mailbox.DistinguishedName)'" -ErrorAction SilentlyContinue | Select-Object DisplayName,ExternalDirectoryObjectId,RecipientTypeDetails

        foreach ($M365Group in $M365Groups) {
                        
            # Handle Microsoft 365 Groups with ExchangeOnline Powershell
            if ($M365Group.RecipientTypeDetails -eq "GroupMailbox") {
                    Write-Host "Removing user from Microsoft 365 Group ""$($M365Group.DisplayName)""..."
                    Remove-UnifiedGroupLinks -Identity $M365Group.ExternalDirectoryObjectId -Links $Mailbox.DistinguishedName -LinkType Member -Confirm:$false -ErrorAction SilentlyContinue
            }
            # Handle "regular" groups with ExchangeOnline Powershell and check if the distribution group is synced from on-premises AD
            elseif ($M365Group.RecipientTypeDetails -eq "MailUniversalDistributionGroup" -or $M365Group.RecipientTypeDetails -eq "MailUniversalSecurityGroup") { 
                    if ($(Get-DistributionGroup -Identity $M365Group.ExternalDirectoryObjectId).IsDirSynced -eq $False ) {
                        Write-Host "Removing user from Distribution Group ""$($M365Group.DisplayName)""..."
                        Remove-DistributionGroupMember -Identity $M365Group.ExternalDirectoryObjectId -Member $Mailbox.DistinguishedName -BypassSecurityGroupManagerCheck -Confirm:$false -ErrorAction SilentlyContinue 
                    }
                    else {
                        # Skip groups which are being synchronized from on-premises AD. They were removed by removing the groups from user in the local AD.
                        Write-Host "Skipping group ""$($M365Group.DisplayName)"" as it is synced from on-premises AD. It will be removed by removing the group in local AD." -ForegroundColor DarkCyan; 
                    }
            }
        }
        
        # Get all the Azure security groups with Graph Powershell
        $AzureGroups = Get-MgUserMemberOf -UserId $email -All -ConsistencyLevel eventual -Property id,displayName,mailEnabled,securityEnabled,membershipRule,mail,isAssignableToRole,groupTypes

        foreach ($AzureGroup in $AzureGroups) {
            # Skip groups with dynamic membership which cannot be removed manaully. They will be removed by clearing the user AD extensionAttribute.
            if ($AzureGroup.AdditionalProperties.groupTypes -eq "DynamicMembership") {
                Write-Host "Skipping group ""$($AzureGroup.AdditionalProperties.displayName)"" as it uses dynamic membership. They will be removed by clearing the extensionAttribute." -ForegroundColor DarkCyan; continue
            }

            # Handle Azure AD security groups with Graph Powershell
            if ($AzureGroup.AdditionalProperties.securityEnabled -eq "True" -and $AzureGroup.AdditionalProperties.mailEnabled -ne "True"){
            Write-Host "Removing user from Azure AD group ""$($AzureGroup.AdditionalProperties.displayName)""..."
            Remove-MgGroupMemberByRef -GroupId $AzureGroup.id -DirectoryObjectId $M365user.id -Confirm:$false -ErrorAction SilentlyContinue 
            }        
        }

        # Confirm completion
        Write-Host ""
        Write-Host "All Microsoft 365, Distribution and Azure AD groups have been removed."
        

        if ($null -ne $user.Manager) {
            # Delegate mailbox access to the user’s manager with ExchangeOnline Powershell
            Add-MailboxPermission -identity $email -User $managerEmail -AccessRights FullAccess -Confirm:$false -WarningAction SilentlyContinue | Out-Null

            # Confirm completion
            Write-Host ""
            Write-Host "$email mailbox access has been delegrated to their manager $managerName."
        }

        # Setting Automatic replies for the user mailbox with ExchangeOnline Powershell
        $internalmessage = "Thank you for your e-mail. Please note that I am no longer working with Invest Ottawa. For ongoing support and/or any questions, please contact $managerName at $managerEmail. `nThank you for reaching out to Invest Ottawa."
        $externalmessage = "Thank you for your e-mail. Please note that I am no longer working with Invest Ottawa. For ongoing support and/or any questions, please contact $managerName at $managerEmail. `nThank you for reaching out to Invest Ottawa."

        Set-MailboxAutoReplyConfiguration -Identity $email -AutoReplyState Enabled -InternalMessage $internalmessage -ExternalMessage $externalmessage -ExternalAudience All

        # Confirm completion
        Write-Host ""
        Write-Host "Automatic out of office replies has been set for $email mailbox."
        Write-Host ""

        # Remove user from assigned Azure enterprise applications 
        if ($null -ne $AssignedApps) {
            # Set the check list for applications that will be removed (LastPass, Certify, Mural)
            # ADD THE APPLICTION NAMES HERE IF YOU WANT TO REMOVE ADDITIONAL APPLICATIONS
            $CheckApplist = @('LastPass', 'Certify', 'Mural')

            #List of user assigned applications that match the check list 
            $AssignedApplist = @()

            foreach ($AssignedApp in $AssignedApps) {
                # Check to remove only the matched applications from user assigned Enterprise applications. 
                if ($AssignedApp.ResourceDisplayName -in $CheckApplist) {
                    Write-Host "Removing user from Enterprise application ""$($AssignedApp.ResourceDisplayName)""..."
                    Remove-MgServicePrincipalAppRoleAssignedTo -AppRoleAssignmentId $AssignedApp.Id -ServicePrincipalId $AssignedApp.ResourceId -Confirm:$false -ErrorAction SilentlyContinue
                    
                    $AssignedApplist += $AssignedApp.ResourceDisplayName
                }
            }
            # Confirm completion
            if ($null -ne $AssignedApplist) {
                Write-Host ""
                Write-Host "Enterprise applications"$($AssignedApplist -join ", ")"have been removed from the user account $email."
            }
            else {
                Write-Host "User account $email doesn't have"$($CheckApplist -join ", ")"assigned." -ForegroundColor DarkCyan
            }
        }
        else {
            Write-Host "User account $email doesn't have any enterprise applications assigned." -ForegroundColor DarkCyan
        }

        # Check if the user has license assigned
        if (!$LicensedUser.SkuId) {
            Write-Host ""
            Write-Host "User account $email doesn't have any license assigned." -ForegroundColor DarkCyan
        }
        else {
            # Remove all the licenses from the user with Graph Powershell
            Set-MgUserLicense -UserId $email -RemoveLicenses @($LicensedUser.SkuId) -AddLicenses @() -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

            # Confirm completion
            Write-Host ""
            Write-Host "Following licenses have been removed from the user account $email."
            $LicensedUser.SkuPartNumber
        }
        }
        # Output the user account does not exist on Microsoft 365
        else {
            Write-Host ""
            Write-Warning "$username user account doesn't exists on Microsoft 365!"
        }  
    
    }
}

# Function to check and remove the Intune managed devices of the user
function Remove_device {
    $ErrorActionPreference = "SilentlyContinue"

    # Get the user object from local AD
    $user = Get-ADUser -Identity $username -Properties Name, EmailAddress
    $Name = $user.Name
    $email = $user.EmailAddress

    # Get all the Intune managed devices object of the user with Graph Powershell
    $Registereddevices = Get-MgUserManagedDevice -userId $email -ErrorAction SilentlyContinue
    
    # Check if the user has any Intune managed devices
    If ($null -ne $Registereddevices) {
        
        $Devicename = $Registereddevices.DeviceName
        $devicecount = $Devicename.count

        # Output the Intune managed device details
        Write-Output ""
        Write-Output "$Name has $devicecount total Intune managed devices: "
        Write-Output -------------------------------------------------
        Write-Output $Devicename

        # list for local AD devices that matches the Intune device names
        $localADdevicelist = @()

        # Check for the user Intune devices that exist on local AD as well
        foreach ($Registereddevice in $Registereddevices){
            If ($null -ne $(Get-ADComputer -filter {Name -eq $Registereddevice.DeviceName} -ErrorAction SilentlyContinue)) {
                
                $localADdevicelist += $(Get-ADComputer -Identity $Registereddevice.DeviceName).Name
            }
        }

        $localADdevicecount = $localADdevicelist.count

        # Output the local AD managed device details
        Write-Output ""
        Write-Output "$Name has $localADdevicecount total local AD managed devices: "
        Write-Output -------------------------------------------------
        Write-Output $localADdevicelist

        # Ask for confirmation for removing ALL devices or SINGLE device from Intune, Azure AD and local AD
        Write-Host ""
        Write-Host "*** Please confirm to remove ALL or SINGLE managed devices of $username from Intune, Azure AD and local AD. ***" -ForegroundColor DarkYellow
        Write-Host "Type 'ALL' to remove all or 'SINGLE' to remove individual device. Type 'NO' to exit: "  -ForegroundColor Green -NoNewline

        $removedevice = Read-Host

        # Remove all Intune managed devices with Graph Powershell
        If ($removedevice.ToUpper() -eq "ALL") {
            
            foreach ($Registereddevice in $Registereddevices){

                Write-Host "Removing the Intune device"$Registereddevice.DeviceName"..."
                Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $Registereddevice.id -Confirm:$False -ErrorAction Continue
                Write-Host ""
                Write-Host "Intune device"$Registereddevice.DeviceName"has been removed successfully!"

                # Search for the device object of the Intune device on Azure AD which belongs to the user
                $AzureADdevice = Get-MgDevice -Search "DeviceId:$($Registereddevice.AzureAdDeviceId)" -ConsistencyLevel eventual -ErrorAction SilentlyContinue

                # Remove the device object on the Azure AD as well
                if ($null -ne $AzureADdevice) {

                    Write-Host ""
                    Write-Host "Removing the Azure AD device object of"$Registereddevice.DeviceName"..."
                    Remove-MgDevice -DeviceId $AzureADdevice.id -Confirm:$False -ErrorAction Continue
                    Write-Host ""
                    Write-Host "Azure AD device object of"$Registereddevice.DeviceName"has been removed successfully!"
                }   
            }

            # Remove all the found devices on the local AD as well
            foreach ($localADdevice in $localADdevicelist){
                
                Write-Host ""
                Write-Host "Removing the local AD device"$localADdevice"..."
                Remove-ADComputer -Identity $localADdevice -Confirm:$False -ErrorAction Continue
                Write-Host ""
                Write-Host "Local AD device"$localADdevice" has been removed successfully!"
            } 
        }
        # Remove individual Intune managed device with Graph Powershell
        elseif ($removedevice.ToUpper() -eq "SINGLE") {

                # Get the device name to remove
                Write-Host "Please enter the device name to remove individually: " -ForegroundColor Green -NoNewline
                $individualdevice = Read-Host
                $Deleted = $false
                $DeletedAD = $false

                # Go through all the retrieved Intune device objects to remove the specified device with Graph Powershell
                foreach ($Registereddevice in $Registereddevices){
                    if ($Registereddevice.DeviceName -eq $individualdevice){

                        Write-Host "Removing the Intune device"$Registereddevice.DeviceName"..."
                        Remove-MgDeviceManagementManagedDevice -ManagedDeviceId $Registereddevice.id -Confirm:$False -ErrorAction Continue
                        Write-Host ""
                        Write-Host "Intune device"$Registereddevice.DeviceName"has been removed successfully!"

                        # Search for the device object of the Intune device on Azure AD which belongs to the user
                        $AzureADdevice = Get-MgDevice -Search "DeviceId:$($Registereddevice.AzureAdDeviceId)" -ConsistencyLevel eventual -ErrorAction SilentlyContinue
                        
                        # Remove the device object on the Azure AD as well
                        if ($null -ne $AzureADdevice) {

                            Write-Host ""
                            Write-Host "Removing the Azure AD device object of"$Registereddevice.DeviceName"..."
                            Remove-MgDevice -DeviceId $AzureADdevice.id -Confirm:$False -ErrorAction Continue
                            Write-Host ""
                            Write-Host "Azure AD device object of"$Registereddevice.DeviceName"has been removed successfully!"
                        }
                        $Deleted = $true
                        break
                    }
                }
                # Output if the device name is not found or not belongs to the user on Intune
                if (!$Deleted){
                    Write-Host ""
                    Write-Warning "$individualdevice doesn't exist or not belongs to user $Name on Intune!"
                }

                # Go through all the retrieved local AD device objects to remove the specified device from local AD
                foreach ($localADdevice in $localADdevicelist){
                    if ($localADdevice -eq $individualdevice){
                        
                        Write-Host ""
                        Write-Host "Removing the Local AD device"$localADdevice"..."
                        Remove-ADComputer -Identity $localADdevice -Confirm:$False -ErrorAction Continue
                        Write-Host ""
                        Write-Host "Local AD device"$localADdevice" has been removed successfully!"
                        $DeletedAD = $true
                        break
                    }
                }
                # Output if the device name is not found or not belongs to the user on local AD
                if (!$DeletedAD){
                    Write-Host ""
                    Write-Warning "$individualdevice doesn't exist or not belongs to user $Name on Local AD!"
                }
            } 
        else {
            Write-Host ""
            Write-Host "Managed devices of $username user account has not been removed."
        } 
    }
    # Output user has no managed devices
    else{
        Write-Host `n
        Write-Warning "User $username has no managed devices!"
    }
}

#Main script block, keep running until user quits

#While loop block for main query to ask for the username input
while($exitprogram -eq 0 ) {
    Write-Host `n
    Write-Host User Offboarding Script:
    Write-Host -------------------------------------

Write-Host "Please enter the username OR enter q to quit: " -NoNewline -ForegroundColor Green

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
    # Start the log transcript when the user is found
    Start-Transcript -Path "C:\Scripts\Offboarding\Logs\Offboarding_$Date`_$username.txt" -Append -Force | Out-Null

    # Call function 'Retrieve_UserInfo' to retrieve user account information from local AD and Microsoft 365
    Retrieve_UserInfo

    # Ask if continue to manage the Local AD and Intune managed devices of the user
    Write-Host ""
    Write-Host "Do you want to check the managed devices of $username ? (Y/N) " -ForegroundColor Green -NoNewline

    $deviceconfirm = Read-Host

    If ($deviceconfirm.ToUpper() -eq "Y") {
            
            Write-Host "Getting $username devices from Local AD and Intune..."

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

    # Ask for confirmation for disabling user account in local AD and Microsoft 365
    Write-Host `n
    Write-Host "*** PLEASE CONFIRM TO DISABLE THE USERNAME $username. Type 'YES' to confirm. *** " -NoNewline -ForegroundColor DarkYellow

    $confirm = Read-Host
        
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
            # Stop logging
            Stop-Transcript | Out-Null
        }
        else {
            Write-Host ""
            Write-Host "$username user account is not disabled."
           
            # Stop logging
            Stop-Transcript | Out-Null
        } 
        
    }

    # Output username does not exist in Local AD
    else {
        Write-Host `n
        Write-Warning "Username $username doesn't exists!"
    }      
}

}
