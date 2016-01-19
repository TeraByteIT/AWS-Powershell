<#
#
# This PowerShell script will go through all regions (unless specified) and check Security Groups for any entries that 
# contain 0.0.0.0/0 in the ACL and report the entries
# Before running this script, ensure that the execution policy has been set to RemoteSigned -> Set-ExecutionPolicy RemoteSigned
#
# TeraByte IT accepts no responsility in running this code.
#
#>

function Set-AWS-Profile
{
   [cmdletbinding()]
   param  ($AccessKey, $SecretKey, $ProfileName, $Region, $ListProfile, $RemoveProfile) 

   if ($AccessKey -eq "" -or $SecretKey -eq "")  # Verify that we have a value in the AWS credentials
   {
     Write-Host "ERROR: Please enter a AWS AccessKey and Secret Key to continue." -ForegroundColor Red
     Exit
   }
   if ($ProfileName -eq "") # Save the credentials into a profile
   {
      Write-Host "Please enter a profile name to save your credentials." -ForegroundColor Red
      Exit
   }
   if ($ListProfile -eq $true)
   {
      $AWSProfiles = Get-AWSCredentials -ListStoredCredentials
      ForEach-Object $Profile in $AWSProfiles
      { 
         Write-Host $Profile 
      }
   }
   if ($RemoveProfile -eq $true)
   { 
      Clear-AWSCredentials -StoredCredentials $ProfileName 
   }
   else 
   { 
      Set-AWSCredentials -AccessKey $AccessKey -SecretKey $SecretKey -StoreAs $ProfileName  
   }
}

function Get-AWS-SecurityGroups
{
   [cmdletbinding()]
   param  ($Region, $ProfileName) 

   if ($Region -eq "") { $Region = (Get-AWSRegion).Region }
   $x = 1
   foreach ($AWSRegion in $Region) # Loop through all the available regions which are available to us
   {
      $SecurityGroup = (Get-EC2SecurityGroup -Region $AWSRegion -ProfileName $ProfileName) # Get all the security groups for the current region
      Foreach ($SG in $SecurityGroup) # Loop through all the security groups).
      {
         if ($SG.IpPermissions.IpRanges -eq "0.0.0.0/0")
         {
            if ($x -eq 1)
            {
               Write-Host "Checking Region: " $AWSRegion -ForegroundColor Cyan
               $x++
            }
            Write-Host   $SG.GroupName "["$SG.GroupId"] (" $SG.GroupDescription ")" -ForegroundColor DarkCyan
            Write-Host "    Protocol   Port Range    Source"
            foreach ($Permission in $SG.IpPermissions){ # Loop through all the permissions in the current security group
               $FromPort = $Permission.FromPort.ToString()
               $ToPort   = $Permission.ToPort.ToString()
               if ($FromPort -eq "-1") 
               { 
                  $FromPort = "N/A" 
               }
               if ($ToPort -eq "-1") 
               {
                  $ToPort = "N/A" 
               }
               if ($Permission.IpRanges.Count -eq 0)
               {
                  Write-host "   " ($Permission.IpProtocol).PadRight(10," ") $FromPort.PadRight(5," ") $ToPort.PadRight(7," ") $Permission.UserIdGroupPair.GroupId
               }
               else 
               { 
                  Write-Host "   " ($Permission.IpProtocol).PadRight(10," ") $FromPort.PadRight(5," ") $ToPort.PadRight(7," ") $Permission.IpRanges 
               }
               If ($Permission.Protocol -ne $null) 
               { 
                  Write-Host "   " $Permission.Protocol 
               }
            }            
            Write-Host "" #Stick a blank line in
         }
      }
      $x=1
   }
}

## Main code block ##

If (!(Test-Path "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"))
{ 
   Write-Host "ERROR: It looks like you don't have the AWS PowerShell tools installed - http://aws.amazon.com/powershell" -ForegroundColor Red 
}
else 
{ 
   Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1" 
}

Set-AWS-Profile -AccessKey "xxxxxxx" -SecretKey "xxxxxxx" -ProfileName  "DevelopmentAccount"
Get-AWS-SecurityGroups -Region "eu-west-1" -ProfileName "DevelopmentAccount"
