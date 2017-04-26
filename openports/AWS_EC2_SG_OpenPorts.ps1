###################################################################################################################################################################
#                                                                                                                                                                 #
# Author : Marcus Dempsey                                                                                                                                         #
# Date   : 26/04/2017                                                                                                                                             #
# Version: 1.0                                                                                                                                                    #
# Desc   : Small script that will go through AWS and look for any security groups that have '0.0.0.0/0' in the rules and then output them to the screen, there is #
#          also an option to specify a port number, so you could search just for port 22 (SSH open to the world)                                                  #
#                                                                                                                                                                 #
###################################################################################################################################################################
Param(
   [Parameter(Mandatory=$true)][string] $AccessKey,
   [Parameter(Mandatory=$true)][string] $SecretKey,
   [string] $Port = ""
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
   Write-Host ""
   exit
}

Function Get-EC2SG ($AccessKey, $SecretKey, $Port, $SaveData) {
   If ($AccessKey -ne "" -and $SecretKey -ne "") {   # Make sure we have some something in the AWS keys for authentication
      Set-AWSCredentials -AccessKey $AccessKey -SecretKey $SecretKey
   }
   else {
      Write-Host "AWS Credentials not correct, please check." -ForegroundColor Red
      exit
   }

   $Regions = Get-AWSRegion
   ForEach ($Region in $Regions) { # Loop through all the regions
      $EC2SecurityGroups = Get-EC2SecurityGroup -Region $Region  # Loop through all the security groups in the current region
      ForEach ($SG in $EC2SecurityGroups) {
         if ($SG.IpPermissions.IpRanges -contains "0.0.0.0/0") {
             If ([string]::IsNullOrWhiteSpace($Port) -or ($Port -eq $SG.IpPermissions.FromPort)) {                
                 $table = New-Object system.Data.DataTable “Security Group”
                 $cols = @("From","To","CIDR","Region","Group","GroupID")
                 foreach ($col in $cols) {
                     $table.Columns.Add($col) | Out-Null
                 }
                 foreach ($perm in $SG.IpPermissions) {
                    if ($perm.IpRanges[0] -eq "0.0.0.0/0") {
                       $row = $table.NewRow()
                       $row[0] = $perm.FromPort
                       $row[1] = $perm.ToPort
                       $row[2] = $perm.IpRanges[0]
                       $row[3] = $Region
                       $row[4] = $SG.GroupName
                       $row[5] = $SG.GroupId
                       $table.Rows.Add($row)
                    }
                 }
                 $table | format-table -AutoSize 
                 $table | Export-Csv "openports.csv" -Append   # Append the results to the file
             }
         }
      }
   }
   $CurrentDirectory = (Get-Item -Path ".\").FullName
   Write-Host "Output saved to" "$CurrentDirectory\openports.csv"
}

If ($AccessKey -eq "" -or $SecretKey -eq "") { # Make sure we're passing some creds
   DisplayHelp
}
else {
   Get-EC2SG -AccessKey $AccessKey -SecretKey $SecretKey -Port $Port
}