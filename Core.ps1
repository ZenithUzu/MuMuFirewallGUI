$script:Tag = 'MuMuDebloat-Scoped-v1'
$script:Prefix = 'MuMuDebloat-Scoped-v2-'
function Assert-Target([string]$Program,[string]$IP,[string]$Port) {
    if (-not [IO.Path]::IsPathRooted($Program) -or $Program -match '[*?%]' -or [IO.Path]::GetExtension($Program) -ne '.exe' -or -not (Test-Path -LiteralPath $Program -PathType Leaf)) { throw 'Se requiere una ruta absoluta a un ejecutable existente.' }
    $addr = $null
    if (-not [Net.IPAddress]::TryParse($IP,[ref]$addr)) { throw 'Solo se admite una IP literal; no rangos, subredes ni Any.' }
    $bytes = $addr.GetAddressBytes()
    if ([Net.IPAddress]::IsLoopback($addr) -or $addr.Equals([Net.IPAddress]::Any) -or $addr.Equals([Net.IPAddress]::IPv6Any) -or $addr.IsIPv6Multicast -or ($bytes.Length -eq 4 -and ($bytes[0] -ge 224 -or $bytes[0] -eq 0))) { throw 'IP local, no especificada o multicast no permitida.' }
    if ($Port -ne 'Any' -and ($Port -notmatch '^\d+$' -or [int]$Port -lt 1 -or [int]$Port -gt 65535)) { throw 'Puerto TCP inválido.' }
    return $addr.ToString()
}
function Get-RuleId([string]$Program,[string]$IP,[string]$Port) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Program.ToLowerInvariant()+'|'+$IP+'|'+$Port))) } finally { $sha.Dispose() }
    return $script:Prefix + ([BitConverter]::ToString($hash).Replace('-','').Substring(0,32))
}
function Get-ManagedRules {
    foreach ($r in @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.Group -eq $script:Tag -or $_.DisplayName -like "*$script:Tag*" -or $_.Name -like "$script:Tag*" -or $_.Name -like "$script:Prefix*" })) {
        $a = $r | Get-NetFirewallApplicationFilter -ErrorAction Stop
        $ip = $r | Get-NetFirewallAddressFilter -ErrorAction Stop
        $p = $r | Get-NetFirewallPortFilter -ErrorAction Stop
        [pscustomobject]@{ Name=$r.Name; Enabled=[string]$r.Enabled; Program=[string]$a.Program; IP=(@($ip.RemoteAddress) -join ','); Port=(@($p.RemotePort) -join ','); Protocol=[string]$p.Protocol; Direction=[string]$r.Direction; Action=[string]$r.Action; Profile=[string]$r.Profile; DisplayName=$r.DisplayName }
    }
}
function Add-ScopedRule([string]$Program,[string]$IP,[string]$Port='Any') {
    $IP = Assert-Target $Program $IP $Port
    $Program = (Get-Item -LiteralPath $Program).FullName
    $name = Get-RuleId $Program $IP $Port
    $existing = @(Get-ManagedRules)
    if (@($existing | Where-Object { $_.Name -eq $name -or ($_.Program -eq $Program -and $_.IP -eq $IP -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' -and ($_.Protocol -in @('TCP','6')) -and ($_.Port -eq $Port -or $_.Port -eq 'Any')) }).Count) { return 'Duplicada: se conserva su estado actual.' }
    $exeLabel = [IO.Path]::GetFileName($Program)
    if ($exeLabel.Length -gt 80) { $exeLabel = $exeLabel.Substring(0,80) }
    $displayName = "$script:Tag - $exeLabel - $IP TCP/$Port"
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName $displayName -Group $script:Tag -Description 'Creada manualmente con MuMuFirewallGUI v2.1. IP posiblemente compartida. Reversible.' -Direction Outbound -Action Block -Program $Program -RemoteAddress $IP -Protocol TCP -RemotePort $Port -Profile Any -Enabled True -ErrorAction Stop | Out-Null
    return 'Creada.'
}
function Set-ManagedRule([string]$Name,[ValidateSet('Enable','Disable','Delete')]$Operation) {
    if (-not (@(Get-ManagedRules | Where-Object Name -eq $Name).Count)) { throw 'La regla ya no pertenece al conjunto etiquetado.' }
    $r = Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction Stop | Where-Object Name -eq $Name
    if ($Operation -eq 'Delete') { $r | Remove-NetFirewallRule -ErrorAction Stop }
    else { $enabled = 'False'; if ($Operation -eq 'Enable') { $enabled = 'True' }; $r | Set-NetFirewallRule -Enabled $enabled -ErrorAction Stop }
}
function Export-Configuration([string]$File) {
    [pscustomobject]@{Schema=2; Created=(Get-Date).ToString('o'); Rules=@(Get-ManagedRules)} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $File -Encoding UTF8
}
function Read-Configuration([string]$File) {
    $cfg = Get-Content -LiteralPath $File -Raw | ConvertFrom-Json
    if ($cfg.Schema -ne 2) { throw 'Formato no compatible.' }
    foreach ($r in @($cfg.Rules)) {
        $null = Assert-Target $r.Program $r.IP $r.Port
        if ($r.Direction -ne 'Outbound' -or $r.Action -ne 'Block' -or $r.Protocol -notin @('TCP','6') -or $r.Enabled -notin @('True','False')) { throw 'Importación rechazada: solo reglas de salida TCP, bloqueo y estado válido.' }
    }
    return $cfg
}
