# Written by Umit Gunaydin on November 29/2021
# Powershell Script Lab 7 - CST8202 sections 014/015
# Log saved as C:\PowerShell_Lab7_Log.txt


function CreateUser 
{
   $logline = "Calling function CreateUser: " + $username
   $logline | out-file $logfile -Append
   if(get-localuser | where-object {$_.Name -eq $Username}) 
   {
       echo "Warning! User Already Exists!"
       $logline = "User already exists" 
       $logline | out-file $LogFile -append 
   } else 
   {
       $myPassword = convertto-securestring -String $mySecurePass -AsPlainText -Force
       $mydescription = "Account created on " + $(get-date) + " by " + $env:USERNAME
       new-localuser $UserName -Password $myPassword -Description $mydescription | Out-Null
       echo "User has been created successfully!"
       $logline = "User created" 
       $logline | out-file $LogFile -append 
   }
}


function RemoveUser 
{
  $logline = "Calling function RemoveUser: " + $username
  $logline | out-file $logfile -Append
  if(get-localuser | where-object {$_.Name -eq $Username}) 
   {
       get-localuser $username | remove-localuser
       echo "Removed user $username"
       $logline = "Removed User" 
       $logline | out-file $LogFile -append 
   } else 
   {
       echo "User doesn't exist!"
       $logline = "User doesn't exist" 
       $logline | out-file $LogFile -append 
   }
   
   $RemoveFolderPrompt = ""
   $RemoveFolder = "C:\users\" + $username
   while ($RemoveFolderPrompt -ne "Y" -and $RemoveFolderPrompt -ne "N")
   {
      $RemoveFolderPrompt = Read-Host -Prompt "Do you want to remove the user folder in C:\Users? (Y/N):"
      if($RemoveFolderPrompt -match "^\D$")
      {
         if($RemoveFolderPrompt.ToUpper() -eq "Y")
         {
            $logline = "`r`nAttempting to remove folder: " + $RemoveFolder
            $logline
            try
            {
               $logline = "Attempting to remove home folder " + $RemoveFolder
               $logline | out-file $LogFile -append 
               Remove-Item -Path $RemoveFolder -Recurse -Force -ErrorAction stop
               $logline = "Folder path removed " + $RemoveFolder
               $logline | out-file $LogFile -append 
            }
            catch
            {
               Write-Warning "An Error has occurred when removing folder: $($_.Exception.Message)"
               $logline = "Error Removing Folder: " + $($_.Exception.Message)
               $logline | out-file $LogFile -append 
               Start-Sleep -Seconds 10
            }
         }
         elseif ($RemoveFolderPrompt.ToUpper() -eq "N") 
         {
            $logline = "Folder path not removed " + $RemoveFolder
            $logline | out-file $LogFile -append 
         }
      }
   }

}


function CreateGroup 
{
   $logline = "Calling function CreateGroup: " + $GroupName
   $logline | out-file $logfile -Append
   if(get-localgroup | where-object {$_.Name -eq $GroupName}) 
   {
       echo "Warning! Group Already Exists!"
       $logline = "Group already exist"
       $logline | out-file $LogFile -append 
   }else 
   {
       new-localgroup $GroupName | Out-Null
       echo "Group has been created successfully!"
       $logline = "Group created"
       $logline | out-file $LogFile -append 
   }
}


function Create100Users
{
    $logline = "Calling function Create100Users"
    $logline | out-file $logfile -Append
    for($mycounter=0; $mycounter -lt 100; $mycounter++)
    {
       $mycount = '{0:d2}' -f $mycounter
       $myUser = $username + $mycount
       echo "`r`n"
       echo $myuser
       $myPassword = convertto-securestring -String "P@ssw0rd" -AsPlainText -Force
       try
       {
          new-localuser $myUser -Password $myPassword -ErrorAction Stop | Out-Null
          echo "User created..."
          $logline = "User " + $myuser + " created"
          $logline | out-file $LogFile -append 
       }
       catch
       {
          echo "User already exists..."
          $logline = "User " + $myuser + " already exists"
          $logline | out-file $LogFile -append 
       }
       $ChangePwd = Get-LocalUser -Name $myUser
       $UserPwd = [adsi]"WinNT://localhost/$($ChangePwd.Name)"
       $UserPwd.PasswordExpired = 1
       $UserPwd.SetInfo()
       $logline = "Setting $myUser password has expired flag"
       $logline | out-file $logfile -append
       try
       {
          add-localgroupmember -group Users -member $myUser -ErrorAction Stop | Out-Null
          echo "Added to Users group..."
          $logline = "User " + $myuser + " added to Users Group"
          $logline | out-file $LogFile -append 
       }
       catch
       {
          echo "User already part of group..."
          $logline = "User " + $myuser + " already part of Users Group"
          $logline | out-file $LogFile -append 
       }
    }
}


function AddUsersFromFile
{
   $logline = "Calling function AddUsersFromFile"
   $logline | out-file $logfile -Append 

   $myfile = import-csv $CSVfilename 
   foreach($line in $myfile)
   {
      $firstname = $line.First
      $lastname = $line.Last
      $fullname = $firstname + " " + $lastname
      $username = $line.Uname
      $Group1 = $line.Group
      $Group2 = $line.Group2
      echo "`r`n"
      $username
      $myPassword = convertto-securestring -String "P@ssw0rd" -AsPlainText -Force
      try
      {
         new-localuser $username -Password $myPassword -FullName $fullname -ErrorAction Stop | Out-Null
         $logline = "User " + $username + " created"
         $logline | out-file $LogFile -append 
         $ChangePwd = Get-LocalUser -Name $username
         $UserPwd = [adsi]"WinNT://localhost/$($ChangePwd.Name)"
         $UserPwd.PasswordExpired = 1
         $UserPwd.SetInfo()
         echo "User created..."
         $logline = "Setting $username password has expired flag"
         $logline | out-file $logfile -append

         add-localgroupmember -group "Users" -member $username | Out-Null

         if(get-localgroup | where-object {$_.Name -eq $Group1}) 
         {
            add-localgroupmember -group $Group1 -member $username | Out-Null
            $logline = "Added to group " + $group1
            $logline | out-file $logfile -append
         }
         else
         {
            new-localgroup $Group1 | Out-Null
            add-localgroupmember -group $Group1 -member $username | Out-Null
            $logline = "Created and added to group " + $group1
            $logline | out-file $logfile -append
         }

         if(get-localgroup | where-object {$_.Name -eq $Group2}) 
         {
            add-localgroupmember -group $Group2 -member $username | Out-Null
            $logline = "Added to group " + $group2
            $logline | out-file $logfile -append
         }
         else
         {
            new-localgroup $Group2 | Out-Null
            add-localgroupmember -group $Group2 -member $username | Out-Null
            $logline = "Created and added to group " + $group2
            $logline | out-file $logfile -append
         }

      }
      catch
      {
         echo "User already exists..."
         $logline = "User " + $myuser + " already exists"
         $logline | out-file $LogFile -append 
      }
   }
}


function AddUserToGroup
{
   $logline = "Calling function AddUserToGroup"
   $logline | out-file $logfile -Append 
   if(get-localgroupmember $GroupName | where-object {$_.Name -eq $env:computername + '\' + $UserName})
   {
       echo "Warning! User is already part of group"
       $logline = "User already part of group"
       $logline | out-file $LogFile -append 
   }
   else
   {
       add-localgroupmember -group $GroupName -member $UserName | Out-Null
       echo "User has been added to group!"
       $logline = "User added to group"
       $logline | out-file $LogFile -append 
   }  
}


$logfile = "C:\PowerShell_Lab7_Log.txt"
$logline = "Starting Program - " + $(get-date)
$logline | out-file $logfile -append 
$exitprogram = 0

while($exitprogram -eq 0)
{
   clear-host
   $logline = "Displaying Menu"
   $logline | out-file $logfile -append 
   echo "Welcome to Umit's menu"
   echo "`r`n`r`n"
   echo "[1] Create User"
   echo "[2] Remove User"
   echo "[3] Create 100 users"
   echo "[4] Create users from file"
   echo "[5] Quit program"
   echo "`r`n`r`n"
   $myinput = Read-Host -Prompt 'Enter Menu Item: '
   if($myinput -match "^\d$")
   {
      $logline = "Menu option: " + $myinput
      $logline | out-file $logfile -Append
      if(($myinput -eq 1) -or ($myinput -eq 2)  -or ($myinput -eq 3)  -or ($myinput -eq 4)  -or ($myinput -eq 5))
      {
         if($myinput -eq 1) 
         {
            echo "`r`n`r`n"
            $UserName = Read-Host -Prompt 'Enter Username: '
            echo "`r`n`r`n"
            $mySecurePass = Read-Host -Prompt 'Enter Secure Password: '
            echo "`r`n"
            $GroupName = Read-Host -Prompt 'Enter Group name: '
            echo "`r`n"
            createuser
            CreateGroup
            AddUserToGroup
         }
         elseif ($myinput -eq 2) 
         {
            echo "`r`n`r`n"
            $myusers = net user 
            $myusers.replace("The command completed successfully.","")
            $UserName = Read-Host -Prompt "Select username to delete:"
            echo "`r`n"
            RemoveUser
         }
         elseif ($myinput -eq 3) 
         {
            echo "`r`n`r`n"
            $UserName = Read-Host -Prompt 'Enter Username: '
            echo "`r`n"
            Create100Users
         }
         elseif ($myinput -eq 4)
         {
            # https://4sysops.com/archives/how-to-create-an-open-file-folder-dialog-box-with-powershell/
            echo "`r`n`r`n Select CSV input file from lab"
            $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
            InitialDirectory = [Environment]::GetFolderPath('Desktop') 
            Filter = 'CSV File (*.csv)|*.csv' }
            $null = $FileBrowser.ShowDialog()
            $CSVfilename = $FileBrowser.FileName
            if($FileBrowser.Path -ne $null)
            { 
               $logline = "CSV File: " + $FileBrowser.FileName
               $logline | out-file $LogFile -append
               addusersfromfile
            }
            else
            {
               echo "`r`n`r`nUser clicked CANCEL"
            }
            echo "`r`n"
        }
        elseif ($myinput -eq 5) 
        {
           $exitprogram=1
           $logline = "Exiting Program - " + $(get-date)
           $logline | out-file $LogFile -append 
        }

        echo "`r`n`r`nPausing for 5 seconds..."
        Start-Sleep -Seconds 5
      }
   }
   else
   {
      $exitprogram = 0
   }
}


