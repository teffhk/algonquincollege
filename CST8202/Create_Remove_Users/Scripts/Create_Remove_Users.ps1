# Lab7.ps1 
# Created by: Ka Wing So
# Email: so000022@algonquinlive.com
# Logs location: C:\logs\Lab7_logs.txt


$null = Start-Transcript -Path "C:\logs\Lab7_logs.txt" -Append                               #Start logging        
$exitprogram = 0
 
$ErrorActionPreference= 'SilentlyContinue'                                                   #Suppress errors   

function New_User {                                                                          #Function block for option 1 adding a new user
Write-Host -----------------
Write-Host Create a new user
Write-Host "Please enter the UserID to create: " -NoNewline

$new_user = Read-Host

if (!$new_user) {Write-Host `n "ERROR: UserID is empty!"}

elseif ($null -ne $(get-localuser -Name $new_user))

    { Write-Host `n
      Write-Host "ERROR: UserID $new_user already exists!"} 

    else
    { 
      Write-Host "Please enter secure password for the new user: " -NoNewline
      $Password = Read-Host

      if (!$Password) {Write-Host `n "ERROR: Password is empty!"}

      else
      {
        $Securepass = convertto-securestring -String $Password -AsPlainText -Force

        New-LocalUser -Name $new_user -Description "User created at $(get-date) by $env:USERNAME" -Password $Securepass | add-localgroupmember -group Users | Out-Null
        Write-Host `n
        Write-Host "UserID $new_user has been created successfully!"

        Write-Host `n
        Write-Host "Please enter a custom group name to add the new user(Left blank if don't need): " -NoNewline
        $NewGroup = Read-Host

        if (!$NewGroup) {Write-Host `n "No custom group is added for $new_user."}

            elseIf ( $null -ne $(Get-LocalGroup -Name $NewGroup))

                   { add-localgroupmember -group $NewGroup -member $new_user | Out-Null
                     Write-Host `n
                     Write-Host "$new_user has been added into the group $NewGroup successfully!"}
                else
                   { Write-Host `n
                     Write-Host "Group $NewGroup doesn't exist, creating new group..."
                     new-localgroup $NewGroup | Out-Null
                     add-localgroupmember -group $NewGroup -member $new_user | Out-Null
                     Write-Host "$new_user has been added into the new group $NewGroup successfully!"}
       }
     }

}


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


function create100user {                                                                        #Function block for option 3 creating User00-User99

Write-Host -------------------------------
Write-Host Create 100 Users, User00-User99
Write-Host `n

#If ($null -ne $(get-localuser -Name User00))

for ( $i = 0; $i -le 9; $i++) 
    { for ($j =0 ; $j -le 9; $j++)
        { $new100user = "User$i$j"
        
          If ($null -ne $(get-localuser -Name $new100user))
             { Write-Host "ERROR: UserID $new100user already exists!"} 

          else
            { 
               $Securepass = convertto-securestring -String P@ssw0rd -AsPlainText -Force

               New-LocalUser -Name $new100user -Description "User created at $(get-date) by $env:USERNAME" -Password $Securepass | add-localgroupmember -group Users | net user $new100user /logonpasswordchg:yes | Out-Null
               Write-Host "UserID $new100user has been created successfully!"}
        }
    }  
}


function createuserfromfile {                                                                    #Function block for option 4 creating users from a csv file
Write-Host --------------------------
Write-Host Create Users from CSV file
Write-Host "Please enter the full path of CSV file to import: " -NoNewline

$filepath = Read-Host
Write-Host `n

try
{ Import-Csv $filepath -ErrorAction Stop | ForEach-Object {

      $group1 = $_.Group
      $group2 = $_.Group2
      $userid = $_.Uname

      If (($null -eq $(Get-LocalGroup -Name $group1)) -and ($null -eq $(Get-LocalGroup -Name $group2)))
         { 
           Write-Host "Group $group1 doesn't exist, creating new group..."
           new-localgroup $group1 | Out-Null
           Write-Host "Group $group2 doesn't exist, creating new group..."
           new-localgroup $group2 | Out-Null}

        elseif ( $null -eq $(Get-LocalGroup -Name $group1))
             { Write-Host "Group $group1 doesn't exist, creating new group..."
               new-localgroup $group1 | Out-Null }

               elseif ( $null -eq $(Get-LocalGroup -Name $group2) )
                     { Write-Host "Group $group2 doesn't exist, creating new group..."
                       new-localgroup $group2 | Out-Null}

     try
      { New-LocalUser `
        -Name $userid `
        -Password $(convertto-securestring -String P@ssw0rd -AsPlainText -Force) `
        -FullName $($_.First + " " + $_.Last) `
        -Description "User created at $(get-date) by $env:USERNAME" -ErrorAction Stop | add-localgroupmember -group Users | net user $userid /logonpasswordchg:yes | Out-Null

         add-localgroupmember -group $group1 -Member $userid | Out-Null
         add-localgroupmember -group $group2 -Member $userid | Out-Null
         
         Write-Host "UserID $userid has been created, added into group $group1 and $group2 successfully!"}
        
      catch
       { Write-Host "UserID $userid already exists..."}
  }
}

catch
 {  
    Write-Host "ERROR: Invalid file path/format!"}
 
}


while($exitprogram -eq 0)                                                                   #While loop block for the main menu
{
    Write-Host `n
    Write-Host Program Menu Options:
    Write-Host ---------------------
    Write-Host 1. Create a new user
    Write-Host 2. Remove a user
    Write-Host 3. Create 100 Users
    Write-Host 4. Create Users from File
    Write-Host 5. Exit
    Write-Host `n

Write-Host "Please select an option (1-5): " -NoNewline

$Selection = Read-Host

    switch -exact ($Selection) {
    
    1 { New_User }

    2 { Remove_User }

    3 { create100user }

    4 { createuserfromfile }

    5 { Write-Host "Exiting Program.... " 
        $exitprogram = 1 }

    Default {
     Write-Host "Invalid input, program exited."
     $exitprogram = 1 }

    }
}

$null = Stop-Transcript                                                                      #Stop logging