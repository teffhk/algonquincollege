# Offboarding.ps1 
# Created by: Cody So
# Email: cso@investottawa.ca

$exitprogram = 0

Connect-MsolService 

$ErrorActionPreference= 'SilentlyContinue'

function Retrieve_UserInfo {

    $user = Get-ADUser -Identity $username -Properties Name, EmailAddress, Title, Manager, extensionAttribute1
    
    $Name = $user.Name
    $email = $user.EmailAddress
    $jobTitle = $user.Title
    $managerName = (Get-ADUser $user.Manager).Name
    $extensionAttribute = $user.extensionAttribute1

    Write-Host `n
    Write-Host "User details for username `"$username`""
    Write-Host --------------------------------------
    Write-Host "Name: $Name"
    Write-Host "Email address: $email"
    Write-Host "Job Title: $jobTitle"
    Write-Host "Manager Name: $managerName"
    Write-Host "Extension Attribute: $extensionAttribute"

    # Get the licenses assigned to the user
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
function Disable_User {

    $newPassword = Can*1234

    # Specify the target OU to move the user account to
    $ouPath = "OU=Disabled Accounts,OU=Users,OU=OCRI,DC=RESEARCH,DC=PRV"

    # Disable the user account
    Disable-ADAccount -Identity $username

    # Reset the user account password
    Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset

    # Move the user account to the target OU
    Move-ADObject -Identity $username -TargetPath $ouPath
}

#While loop block for the main menu
while($exitprogram -eq 0 ) {
    Write-Host `n
    Write-Host User Offboarding Script:
    Write-Host -------------------------------------

Write-Host "Please enter the username OR enter q to quit: " -NoNewline

$username = Read-Host

If ($username.ToUpper() -eq "Q" ) {
    Write-Host "Exiting Program.... " 
    $exitprogram = 1
} 

else {
    If ($null -ne $(Get-ADUser -Identity $username)) {

    {Retrieve_UserInfo}

    $confirm = ""
    $confirm = Read-Host "*** PLEASE CONFIRM TO DISABLE the USERNAME $username (Y/N) ***"
        
        If ($confirm.ToUpper() -eq "Y") {
            
            Write-Host "Disabling $username user account..."

            try
            {Disable_User}

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
    else {
        Write-Host `n
        Write-Host "ERROR: Username $username doesn't exists!"
    }      
}
}