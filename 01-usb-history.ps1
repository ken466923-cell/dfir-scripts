# USB Device History Forensics Script
# Extracts every USB device ever plugged into a Windows computer

$output = @()
$usbkey = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"

if (Test-Path $usbkey) {
    $devices = Get-ChildItem $usbkey
    
    foreach ($device in $devices) {
        $deviceName = (Get-ItemProperty -Path $device.PSPath -Name "FriendlyName" -ErrorAction SilentlyContinue).FriendlyName
        $firstInstall = (Get-ItemProperty -Path $device.PSPath -Name "DateInstalled" -ErrorAction SilentlyContinue).DateInstalled
        
        $output += [PSCustomObject]@{
            DeviceName    = $deviceName
            DeviceID      = $device.PSChildName
            FirstInstalled = $firstInstall
            RegistryPath  = $device.PSPath
        }
    }
}
