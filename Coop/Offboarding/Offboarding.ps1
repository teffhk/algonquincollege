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

<#
function Remove_User {                                                                         #Function block for option 2 removing an user

    Write-Host ----------------------------------------
    Write-Host Remove a user, existng UserIDs as follow
    Get-LocalUser | select name | Format-table
    Write-Host "Please select and enter the UserID to remove: " -NoNewline
    
    $delete_user = Read-Host
    
    If ($null -ne $(get-localuser -Name $delete_user))
    
        {   Remove-localuser -Name $delete_user
            Write-Host `n
            Write-Host "UserID $delete_user has been removed successfully!"
            Write-Host `n        
            Write-Host "Do you want to delete the User Home Directory and contents as well? (Y/N):" -NoNewline
            $remove_home = Read-Host
    
            If ($remove_home -eq "Y")
                {try
                    { $RemoveHomeFolder = "C:\users\" + $delete_user
                      Remove-Item -Path $RemoveHomeFolder -Recurse -Force -ErrorAction stop
                      Write-Host `n
                      Write-Host "User Home Directory and contents have been deleted successfully!"}
                 catch
                    { Write-Host `n
                      Write-Host "Error removing directory $RemoveHomeFolder! Please check manually."}
                 }
            else
                { Write-Host `n
                  Write-Host "User Home Directory and contents are not deleted."}       
          } 
    
       else
         {  Write-Host `n
            Write-Host "ERROR: UserID $delete_user doesn't exists!"}
    }
#>

while($exitprogram -eq 0 )                                                                   #While loop block for the main menu
{
    Write-Host `n
    Write-Host User Offboarding Script:
    Write-Host -------------------------------------

Write-Host "Please enter the username OR enter q to quit: " -NoNewline

$username = Read-Host

If ($username -eq "q" -or $username -eq "Q" ) {
    Write-Host "Exiting Program.... " 
    $exitprogram = 1
} 

else {
    If ($null -ne $(Get-ADUser -Identity $username))
    {Retrieve_UserInfo}

    else
     {  Write-Host `n
        Write-Host "ERROR: UserID $username doesn't exists!"}
}

}