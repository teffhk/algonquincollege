# Offboarding.ps1 
# Created by: Cody So
# Email: cso@investottawa.ca

# Set exit program state varible
$exitprogram = 0

# Connect to Exchangeonline, deprecate soon
Connect-MsolService 

$ErrorActionPreference= 'SilentlyContinue'

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
    Write-Host --------------------------------------
    Write-Host "Name: $Name"
    Write-Host "Email address: $email"
    Write-Host "Job Title: $jobTitle"
    Write-Host "Manager Name: $managerName"
    Write-Host "Extension Attribute: $extensionAttribute"
    Write-Host "Account status: $status"

    # Get the licenses assigned to the user from ExchangeOline
    $O365user =  Get-MsolUser -UserPrincipalName $email
    IF ($O365user){
        IF (!($O365user.Licenses)){
            $LicensedUser = $null
            Write-Output ""
            Write-Output "Licenses is null for $($O365user.UserPrincipalName)"
            Write-Output "IsLicensed is $($O365user.IsLicensed)"
            Write-Output ""
            }
            Else
            {
            $LicensedUser = $O365user
            }
          }
          Else
          {
          Write-Error "Get-MsolUser : User Not Found" 
          }
      
    #get skus and services for user
    IF($LicensedUser){
    Foreach ($Userdetails in $LicensedUser){
        $skus = $Userdetails.Licenses.AccountSkuId
        $dname = $Userdetails.DisplayName
        $skucount = $skus.count
        $skusname = $skus -replace "reseller-account:",""

        Write-Output ""
        Write-Output "$dname has $skucount total licenses assignments: "
        Write-Output -------------------------------------------------
        Write-Output $skusname
            
        }
    }
}

# Function to disable the user account
function Disable_User {

    # Get the user object and set the reset password
    $user = Get-ADUser -Identity $username -Properties MemberOf
    $newPassword = ConvertTo-SecureString "Can*1234" -AsPlainText -Force

    # Specify the target OU to move the user account to
    $ouPath = "OU=Disabled Accounts,OU=Users,OU=OCRI,DC=RESEARCH,DC=PRV"

    # Check if the user account is already disabled 
    if ($user.Enabled -eq $false) {

        Write-Host `n
        Write-Host "$username user account is already disabled!"
    }
    else {      

        # Disable the user account
        Disable-ADAccount -Identity $user
        
        # Confirm completion
        Write-Host "$username user account has been disabled."

        # Reset the user account password
        Set-ADAccountPassword -Identity $user -NewPassword $newPassword -Reset

        # Confirm completion
        Write-Host "$username user account password has been reset."

        # Remove the job title, manager, extensionAttribute1 attribute
        Set-ADUser -Identity $username -Clear title, manager, extensionAttribute1

        # Confirm completion
        Write-Host "$username user account title, manager and extension attribute has been cleared."

        # Remove user from all groups except "All Users"
        foreach ($group in $user.MemberOf) {
        if ($group -ne "Domain Users" -or $group -ne "O365-USERS") {
            Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
        }
        }

        # Confirm completion
        Write-Host "All groups except 'Domain Users' and 'O365-USERS' have been removed from user $username."

        # Move the user account to the target OU
        Move-ADObject -Identity $user -TargetPath $ouPath

         # Confirm completion
         Write-Host "$username user account have been moved to 'Disabled Accounts' OU."

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
    $confirm = Read-Host "*** PLEASE CONFIRM TO DISABLE the USERNAME $username (Y/N) ***"
        
        If ($confirm.ToUpper() -eq "Y") {
            
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