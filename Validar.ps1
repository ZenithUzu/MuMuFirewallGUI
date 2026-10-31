#requires -Version 5.1
$ErrorActionPreference='Stop'
. "$PSScriptRoot\Core.ps1"
$script:FakeRules=@(); $script:Calls=@()
function Get-ManagedRules { return $script:FakeRules }
function New-NetFirewallRule {
    param($PolicyStore,$Name,$DisplayName,$Group,$Description,$Direction,$Action,$Program,$RemoteAddress,$Protocol,$RemotePort,$Profile,$Enabled,$ErrorAction)
    if ($Program -eq 'Any' -or -not $Program -or $RemoteAddress -eq 'Any' -or $Direction -ne 'Outbound' -or $Protocol -ne 'TCP') { throw 'Regla insegura' }
    if ($DisplayName.Contains('|') -or $DisplayName.Length -gt 256) { throw 'Nombre de regla inválido' }
    # Objeto nativo aislado; no se añade a la colección del firewall.
    $native = New-Object -ComObject HNetCfg.FWRule
    try {
        $native.Name=$DisplayName
        $native.ApplicationName=$Program
        $native.Protocol=6
        $native.RemoteAddresses=$RemoteAddress
        if ($RemotePort -ne 'Any') { $native.RemotePorts=$RemotePort }
        $native.Direction=2
        $native.Action=0
    } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($native) }
    $script:Calls+= $PSBoundParameters
    $script:FakeRules+= [pscustomobject]@{Name=$Name;DisplayName=$DisplayName;Program=$Program;IP=$RemoteAddress;Port=$RemotePort;Protocol=$Protocol;Direction=$Direction;Action=$Action;Enabled=$Enabled;Profile=$Profile}
}
function Assert($Condition,$Message) { if (-not $Condition) { throw $Message } }
function Get-NetFirewallRule { param($PolicyStore,$Name,$ErrorAction); $script:FakeRules | Where-Object Name -eq $Name }
function Set-NetFirewallRule {
    param([Parameter(ValueFromPipeline=$true)]$InputObject,$Enabled)
    process { $InputObject.Enabled=$Enabled }
}
function Remove-NetFirewallRule {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { $script:FakeRules=@($script:FakeRules | Where-Object Name -ne $InputObject.Name) }
}
$exe=Join-Path $env:SystemRoot 'System32\notepad.exe'
$null=Add-ScopedRule $exe '203.0.113.10' '443'
$null=Add-ScopedRule $exe '203.0.113.10' '443'
Assert ($script:Calls.Count -eq 1) 'Falló deduplicación'
Assert ($script:Calls[0].Group -eq 'MuMuDebloat-Scoped-v1') 'Etiqueta incorrecta'
$name=$script:FakeRules[0].Name
Set-ManagedRule $name Disable
Assert ($script:FakeRules[0].Enabled -eq 'False') 'Falló desactivación'
$null=Add-ScopedRule $exe '203.0.113.10' '443'
Assert ($script:FakeRules[0].Enabled -eq 'False') 'Duplicar reactivó una regla'
Set-ManagedRule $name Enable
Assert ($script:FakeRules[0].Enabled -eq 'True') 'Falló activación'
$rejected=$false; try { Set-ManagedRule 'Regla-ajena' Delete } catch { $rejected=$true }; Assert $rejected 'Operación sobre regla ajena permitida'
foreach ($bad in @('Any','0.0.0.0','::','127.0.0.1','203.0.113.0/24','203.0.113.1-203.0.113.5','224.0.0.1')) {
    $rejected=$false; try { $null=Assert-Target $exe $bad '443' } catch { $rejected=$true }; Assert $rejected "No rechazó $bad"
}
foreach ($bad in @('Any','C:\*.exe','relative.exe')) { $rejected=$false; try { $null=Assert-Target $bad '203.0.113.10' '443' } catch { $rejected=$true }; Assert $rejected 'Ruta insegura aceptada' }
$tmp=Join-Path ([IO.Path]::GetTempPath()) ('MuMu-test-'+[guid]::NewGuid().ToString('N')+'.json')
try {
    Export-Configuration $tmp
    $cfg=Read-Configuration $tmp
    Assert (@($cfg.Rules).Count -eq 1) 'Falló exportación/importación'
    $cfg.Rules[0].IP='Any'; $cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $tmp -Encoding UTF8
    $rejected=$false; try { $null=Read-Configuration $tmp } catch { $rejected=$true }; Assert $rejected 'Importación global aceptada'
} finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
Set-ManagedRule $name Delete
Assert ($script:FakeRules.Count -eq 0) 'Falló eliminación'
'OK: deduplicación, alcance exe/IP/TCP, rechazo de rangos/Any, etiquetas, activación/desactivación/eliminación, protección de reglas ajenas, exportación y validación de importación. Firewall simulado; sin cambios reales.'
