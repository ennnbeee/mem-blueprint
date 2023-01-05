$Summary = New-Object -TypeName PSObject

# Local Administrator
$AdministratorStatus = @()
$admingroup = [ADSI] 'WinNT://./Administrators,group'
$adminmembers = @($admingroup.psbase.Invoke('Members'))
$AdminList = ($adminmembers | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })

$Users = Get-Process -Name explorer -IncludeUserName | Select-Object UserName -Unique
Foreach ($User in $Users) {
    $User = $User.UserName
    $UserName = $User.Split('\')[1]
    If ($AdminList -contains $UserName) {
        $AdministratorStatus += 'Yes'
    }
    Else {
        $AdministratorStatus += 'No'
    }
}

If ($AdministratorStatus -notcontains 'Yes') {
    $Status = 'Yes'
}
Else {
    $Status = 'No'
}

$Summary | Add-Member -MemberType NoteProperty -Name 'User Account is a Standard User' -Value $Status

# Guest Accounts
$GuestStatus = @()
$guestgroup = [ADSI] 'WinNT://./Guests,group'
$guestmembers = @($guestgroup.psbase.Invoke('Members'))
$GuestList = ($guestmembers | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
foreach ($Guest in $GuestList) {
    if ((Get-LocalUser -Name $Guest).Enabled -eq 'True') {
        $GuestStatus += 'Yes'
    }
    Else {
        $GuestStatus += 'No'
    }
}

If ($GuestStatus -notcontains 'Yes') {
    $Status = 'Yes'
}
Else {
    $Status = 'No'
}

$Summary | Add-Member -MemberType NoteProperty -Name 'Guest Account Disabled' -Value $Status

# Autoplay
Try {
    $AutoplayStatus = Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue
}
Catch {
    $Status = 'No'
}

if ($AutoplayStatus.NoDriveTypeAutoRun -ne '255') {
    $Status = 'No'
}
else {
    $Status = 'Yes'
}

$Summary | Add-Member -MemberType NoteProperty -Name 'Autoplay Disabled' -Value $Status

# Antivirus Definition Status and Real time protection
$AVProduct = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct | Select-Object -First 1

If ($AVProduct) {
    $hexProductState = [Convert]::ToString($AVProduct.productState, 16).PadLeft(6, '0')
    #$hexSecurityProvider = $hexProductState.Substring(0, 2) 
    $hexRealTimeProtection = $hexProductState.Substring(2, 2)
    $hexDefinitionStatus = $hexProductState.Substring(4, 2)

    If ($AVProduct.displayName -eq "Windows Defender") {
        $RealTimeProtectionStatus = switch ($hexRealTimeProtection) {
        '01' { 'Disabled' }
        '11' { 'On' }
        default { 'Unknown' }
        } 
    }
    Else {
        $RealTimeProtectionStatus = switch ($hexRealTimeProtection) {
        '00' { 'Off' }
        '01' { 'Expired' }
        '10' { 'On' }
        '11' { 'Snoozed' }
        default { 'Unknown' }
        } 
    }

    
    $DefinitionStatus = switch ($hexDefinitionStatus) {
        '00' { 'Up to Date' }
        '10' { 'Out of Date' }
        default { 'Unknown' }
    }  
    
    $Summary | Add-Member -MemberType NoteProperty -Name "Real time protection enabled" -Value $RealTimeProtectionStatus
    $Summary  | Add-Member -MemberType NoteProperty -Name "Definitions up-to-date" -Value $DefinitionStatus
}
Else {
    $Summary  | Add-Member -MemberType NoteProperty -Name "Real time protection enabled" -Value 'Error: No Antivirus product found'
    $Summary  | Add-Member -MemberType NoteProperty -Name "Definitions up-to-date" -Value 'Error: No Antivirus product found'
}

# Summary
return $Summary | ConvertTo-Json -Compress