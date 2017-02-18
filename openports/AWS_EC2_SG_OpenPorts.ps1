###################################################################################################################################################################
#                                                                                                                                                                 #
# Author : Marcus Dempsey                                                                                                                                         #
# Date   : 18/02/2017                                                                                                                                             #
# Version: 0.1                                                                                                                                                    #
# Desc   : Small script that will go through AWS and look for any security groups that have '0.0.0.0/0' in the rules and then output them to the screen, there is #
#          also an option to specify a port number, so you could search just for port 22 (SSH open to the world)                                                  #
#                                                                                                                                                                 #
###################################################################################################################################################################
Param(
   [string] $AccessKey,
   [string] $SecretKey,
   [string] $Port,     
   [switch] $SaveData = $false
)

If (Test-Path "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1") {  #Check to make sure that AWS powertools are installed, otherwise error out
   Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"
}
else {
   Write-Host "ERROR: It looks like the AWS PowerShell tools may not be installed." -ForegroundColor Red
   exit
}

Function DisplayHelp {
   Write-Host "AWS_EC2_SG_OpenPorts v0.1 (TeraByte - https://terabyteit.co.uk)"
   Write-Host "Usage: AWS_EC2_SG_OpenPorts.ps1 [options] [Port]"
   Write-Host ""
   Write-Host "The following are valid options:"
   Write-Host " -AccessKey        The access key that is going to be used for the AWS credentials"
   Write-Host " -SecretKey        The secret key that is going to be used for the AWS credentials"
   Write-Host " -Port             The TCP/UDP port that you want to check for, defaults to all ports"
   Write-Host " -SaveData         Do you want to save the results to a text file? $true/$false value, defaults to $false"
   Write-Host ""
   exit
}

Function Get-EC2SG ($AccessKey, $SecretKey, $Port, $SaveData) {
   If ($AccessKey -ne "" -and $SecretKey -ne "") {   # Make sure we have some something in the AWS keys for authentication
      Set-AWSCredentials -AccessKey $AccesKey -SecretKey $SecretKey
   }
   else {
      Write-Host "AWS Credentials not correct, please check." -ForegroundColor Red
      exit
   }

   If ($SaveData) {  # Do we want to save the output?
      Start-Transcript -path aws-output.txt -append
   }
   $Regions = Get-AWSRegion
   ForEach ($Region in $Regions) { # Loop through all the regions
      Write-Host ""
      Write-Host "[ Checking for ports open to Internet in:" $Region.Region"]" -ForegroundColor Cyan
      Write-Host ""
      $EC2SecurityGroups = Get-EC2SecurityGroup -Region $Region  # Loop through all the security groups in the current region
      ForEach ($SG in $EC2SecurityGroups) {
         $Count = 0
         If ($SG.IpPermissions.IpRanges -eq "0.0.0.0/0") {  # Loop for something open to the world
            If ($Port -ne $null) { # Port value was passed
               If ($Port -eq $SG.IpPermissions.FromPort) {  # Does the current SG port match the one we passed?
                  Write-Host "SG:"$SG.GroupName "("$SG.GroupId $SG.Description ")"
                  Write-Host "    VPC ID  : "$SG.VpcId
                  Write-Host "    FromPort: "$SG.IpPermissions.FromPort
                  Write-Host "    ToPort  : "$SG.IpPermissions.ToPort
                  Write-Host "    IP Range: "$SG.IpPermissions.IpRanges
                  Write-Host ""
               }
            }
            else { # No port value was passed, so do any port
                Write-Host "SG:"$SG.GroupName "("$SG.GroupId $SG.Description ")"
                Write-Host "    VPC ID  : "$SG.VpcId
                Write-Host "    FromPort: "$SG.IpPermissions.FromPort
                Write-Host "    ToPort  : "$SG.IpPermissions.ToPort
                Write-Host "    IP Range: "$SG.IpPermissions.IpRanges
                Write-Host ""
            }
            $Count += 1
         }

      }
      If ($Count -eq 0) {
         Write-Host "Nothing Found." -ForegroundColor Green
      }
   }
   If ($SaveData) { # Stop the output to a file
      Stop-Transcript
   }
}

If ($AccessKey -eq "" -or $SecretKey -eq "") { # Make sure we're passing some creds
   DisplayHelp
}
else {
   Get-EC2SG -AccessKey $AccessKey -SecretKey $SecretKey -Port $Port -SaveData $SaveData
}