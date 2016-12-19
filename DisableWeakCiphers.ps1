<#

Last Updated: 21/10/2014
Description : MS Security bulletin: https://technet.microsoft.com/en-us/library/security/3009008.aspx
              Azure post where this script originally came from: http://azure.microsoft.com/blog/2014/10/19/how-to-disable-ssl-3-0-in-azure-websites-roles-and-virtual-machines/


 NOTE: This registry change requires that the server be restarted. The script will detect if a change is applied and AUTOMATICALLY reboot the server.
       If you don't want automatic reboot comment out the final section of the script before running!
#>
 
Function Ensure-RegKeyExists {
    [cmdletbinding()]

	param ($RegKey)
 
	If (!(Test-Path -Path $RegKey)) {
		New-Item $RegKey | Out-Null
	}
}
 
Function Set-RegKey {
    [cmdletbinding()]
    
    param ($key,$value,$valuedata,$valuetype,$restart)
 
    # Check for existence of registry key, and create if it does not exist
    Ensure-RegKeyExists $key
 
    # Get data of registry value, or null if it does not exist
    $val = (Get-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue).$value
 
    If ($val -eq $null) {
        # Value does not exist - create and set to desired value
        New-ItemProperty -Path $key -Name $value -Value $valuedata -PropertyType $valuetype | Out-Null
        $restart = $True
    } Else {
        # Value does exist - if not equal to desired value, change it
        If ($val -ne $valuedata) {
            Set-ItemProperty -Path $key -Name $value -Value $valuedata
            $restart = $True
        }
    }
    return $restart
}

Function Get-RegKey {
    [cmdletbinding()]    
    param ($key,$value)

    If ((Test-Path -Path $Key)) {
        $value = Get-ItemPropertyValue -Path $key -Name $value -ErrorAction SilentlyContinue
    }
    else { $value = $null }
    return $value
}

Function DisableProtocols { 
    [cmdletbinding()]
    param ($checkOnly)

    # If any settings are changed, this will change to $true and the server will reboot
    $reboot = $false
    $PCT1_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0";
    $PCT1_Client_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client";
    $PCT1_Server_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server";
    $SSL2_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0";
    $SSL2_Client_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client";
    $SSL2_Server_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server";
    $SSL3_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0";
    $SSL3_Client_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client";
    $SSL3_Server_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server";
    $TLS1_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0";
    $TLS1_Client_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client";
    $TLS1_Server_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server";
    $TLS11_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1";
    $TLS11_Client_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client";
    $TLS11_Server_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server";
    $TLS12_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2";
    $TLS12_Client_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client";
    $TLS12_Server_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server";

    if ($checkOnly) {
        Write-Host "Checking for weak protocols that are enabled..." -ForegroundColor Green
        $Result = Get-RegKey $PCT1_Client_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "PCT 1.0 Client is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "PCT 1.0 Client registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $PCT1_Server_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "PCT 1.0 Server is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "PCT 1.0 Server registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $SSL2_Client_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "SSL 2.0 Client is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "SSL 2.0 Client registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $SSL2_Server_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "SSL 2.0 Server is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "SSL 2.0 Server registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $SSL3_Client_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "SSL 3.0 Client is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "SSL 3.0 Client registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $SSL3_Server_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "SSL 3.0 Server is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "SSL 3.0 Server registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $TLS1_Client_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "TLS 1.0 Client is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "TLS 1.0 Client registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $TLS1_Server_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "TLS 1.0 Server is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "TLS 1.0 Server registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        Write-Host "Finished checking for weak protocols." -ForegroundColor Green
    }
    else {
        # Check for existence of parent registry keys (PCT 1.0, SSL 2.0 and SSL 3.0), create if they do not exist
        Ensure-RegKeyExists $PCT1_Parent_Key
        Ensure-RegKeyExists $SSL2_Parent_Key
        Ensure-RegKeyExists $SSL3_Parent_Key
        Ensure-RegKeyExists $TLS1_Parent_Key
        Ensure-RegKeyExists $TLS11_Parent_Key
        Ensure-RegKeyExists $TLS12_Parent_Key
 
        # Ensure PCT 1.0 disabled for client
        $reboot = Set-RegKey $PCT1_Client_Key DisabledByDefault 1 DWord $reboot
 
        # Ensure PCT 1.0 disabled for server
        $reboot = Set-RegKey $PCT1_Server_Key Enabled 0 DWord $reboot

        # Ensure SSL 2.0 disabled for client
        $reboot = Set-RegKey $SSL2_Client_Key DisabledByDefault 1 DWord $reboot
 
        # Ensure SSL 2.0 disabled for server
        $reboot = Set-RegKey $SSL2_Server_Key Enabled 0 DWord $reboot
 
        # Ensure SSL 3.0 disabled for client
        $reboot = Set-RegKey $SSL3_Client_Key DisabledByDefault 1 DWord $reboot
 
        # Ensure SSL 3.0 disabled for server
        $reboot = Set-RegKey $SSL3_Server_Key Enabled 0 DWord $reboot

        # Ensure TLS 1.0 disabled for client
        $reboot = Set-RegKey $TLS1_Client_Key DisabledByDefault 1 DWord $reboot
 
        # Ensure TLS 1.0 disabled for server
        $reboot = Set-RegKey $TLS1_Server_Key Enabled 0 DWord $reboot
 
        # Ensure that TLS 1.1 is enabled for client
        $reboot = Set-RegKey $TLS11_Client_Key DisabledByDefault 0 DWord $reboot
        $reboot = Set-RegKey $TLS11_Client_Key Enabled 1 DWord $reboot

        # Ensure that TLS 1.1 is enabled for server
        $reboot = Set-RegKey $TLS11_Server_Key DisabledByDefault 0 DWord $reboot
        $reboot = Set-RegKey $TLS11_Server_Key Enabled ffffffff DWord $reboot
        
        # Ensure that TLS 1.2 is enabled for client
        $reboot = Set-RegKey $TLS12_Client_Key DisabledByDefault 0 DWord $reboot
        $reboot = Set-RegKey $TLS12_Client_Key Enabled 1 DWord $reboot

        # Ensure that TLS 1.2 is enabled for server
        $reboot = Set-RegKey $TLS12_Server_Key DisabledByDefault 0 DWord $reboot
        $reboot = Set-RegKey $TLS12_Server_Key Enabled ffffffff DWord $reboot

        # If any settings were changed, reboot
        If ($reboot) {
            Write-Host "Changes have been made, rebooting machine now..." -ForegroundColor Green
            shutdown.exe /r /t 5 /c "Crypto settings changed" /f /d p:2:4
        }
    }
}

function DisableCiphers {
    [cmdletbinding()]
    param ($checkOnly)

    # If any settings are changed, this will change to $true and the server will reboot
    $reboot = $false
    $DES_56_56_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56";
    $NULL_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL";
    $RC2_40_128_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128";
    $RC2_56_128_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128";
    $RC4_40_128_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128";
    $RC4_56_128_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128";
    $RC4_64_128_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128";
    $RC4_128_128_Parent_Key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128";
    
    if ($checkOnly) {
        Write-Host "Checking for weak ciphers that are enabled..." -ForegroundColor Green
        $Result = Get-RegKey $DES_56_56_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "DES 56/56 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "DES 56/56  registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $RC2_40_128_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "RC2 40/128 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "RC2 40/128 registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $RC2_56_128_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "RC2 56/128 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "RC2 56/128 registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $RC4_40_128_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "RC4 40/128 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "RC4 40/128 registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $RC4_56_128_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "RC4 56/128 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "RC4 56/128 registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $RC4_64_128_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "RC4 64/128 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "RC4 64/128 registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        $Result = Get-RegKey $RC4_128_128_Parent_Key Enabled -ErrorAction SilentlyContinue
        if ($Result -eq "1") { 
            Write-Host "RC4 128/128 is enabled." -ForegroundColor Red 
        }
        elseif ($Result -eq $null) {
            Write-Host "RC4 128/128 registry settings not found. Recommend setting registry values." -ForegroundColor Yellow
        }
        Write-Host "Finished checking for weak ciphers." -ForegroundColor Green
    }
    else {    
        # Check for existence of parent registry keys, create if they do not exist
        Ensure-RegKeyExists $DES_56_56_Parent_Key
        Ensure-RegKeyExists $NULL_Parent_Key
        Ensure-RegKeyExists $RC2_40_128_Parent_Key
        Ensure-RegKeyExists $RC2_56_128_Parent_Key
        Ensure-RegKeyExists $RC4_40_128_Parent_Key
        Ensure-RegKeyExists $RC4_56_128_Parent_Key
        Ensure-RegKeyExists $RC4_64_128_Parent_Key
        Ensure-RegKeyExists $RC4_128_128_Parent_Key

        # Ensure that weak ciphers are disabled
        $reboot = Set-RegKey $DES_56_56_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $NULL_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $RC2_40_128_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $RC2_56_128_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $RC4_40_128_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $RC4_56_128_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $RC4_64_128_Parent_Key Enabled 0 DWord $reboot
        $reboot = Set-RegKey $RC4_128_128_Parent_Key Enabled 0 DWord $reboot

        # If any settings were changed, reboot
        If ($reboot) {
            Write-Host "Changes have been made, reboot machine for changes to take affect." -ForegroundColor Green            
        }
    }
}

#only check the values below, remove parameters to apply changes
DisableProtocols -checkOnly $true
DisableCiphers -checkOnly $true
