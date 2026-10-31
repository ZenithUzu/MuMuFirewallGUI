#requires -Version 5.1
param([switch]$SmokeTest)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. "$PSScriptRoot\Core.ps1"
[Windows.Forms.Application]::EnableVisualStyles()
$script:Admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:History = @{}
$script:Processes = @{}
$script:Root = ''
$script:Busy = $false
$form = New-Object Windows.Forms.Form
$form.Text = 'MuMu Firewall GUI v2.1 — revisión manual'
$form.Size = New-Object Drawing.Size(1250,820)
$form.MinimumSize = New-Object Drawing.Size(950,650)
$layout = New-Object Windows.Forms.TableLayoutPanel
$layout.Dock='Fill'; $layout.ColumnCount=1; $layout.RowCount=7
foreach ($h in @(64,42,42,42)) { $null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',$h))) }
$null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)))
$null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',42)))
$null=$layout.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',48)))
$form.Controls.Add($layout)
$warning=New-Object Windows.Forms.Label
$warning.Dock='Fill'; $warning.Text='No identifica anuncios automáticamente. Una IP/CDN puede servir Google Play, juegos y publicidad al mismo tiempo. Bloquea una conexión por prueba y revierte si falla algo. Solo se crean reglas de salida TCP para una ruta .exe y una IP exactas.'
$warning.Padding=New-Object Windows.Forms.Padding(8); $layout.Controls.Add($warning,0,0)
function New-Bar { $b=New-Object Windows.Forms.FlowLayoutPanel; $b.Dock='Fill'; $b.WrapContents=$false; return $b }
$b1=New-Bar; $b2=New-Bar; $b3=New-Bar; $b4=New-Bar
$layout.Controls.Add($b1,0,1); $layout.Controls.Add($b2,0,2); $layout.Controls.Add($b3,0,3); $layout.Controls.Add($b4,0,5)
function Invoke-UI([scriptblock]$Action) { try { & $Action } catch { [Windows.Forms.MessageBox]::Show($_.Exception.Message,'Error') | Out-Null } }
function Add-Button($Bar,$Text,[scriptblock]$Action) {
    $btn=New-Object Windows.Forms.Button; $btn.Text=$Text; $btn.AutoSize=$true; $btn.Height=31
    $btn.Add_Click({ Invoke-UI $Action }.GetNewClosure()); $Bar.Controls.Add($btn); return $btn
}
function Confirm-Action([string]$Message) { return [Windows.Forms.MessageBox]::Show($Message,'Confirmar cambio','YesNo','Warning') -eq 'Yes' }
function Require-Admin { if (-not $script:Admin) { throw 'Abre PowerShell como administrador y ejecuta Iniciar.cmd para cambiar reglas. La consulta no requiere elevación automática.' } }
$rootLabel=New-Object Windows.Forms.Label; $rootLabel.AutoSize=$true; $rootLabel.Text='Carpeta MuMu opcional: (detección inicial por nombre MuMu)'; $b1.Controls.Add($rootLabel)
$null=Add-Button $b1 'Elegir carpeta' {
    $d=New-Object Windows.Forms.FolderBrowserDialog
    if ($d.ShowDialog() -eq 'OK') { $script:Root=$d.SelectedPath.TrimEnd('\')+'\'; $rootLabel.Text=$script:Root }
    $d.Dispose()
}
$null=Add-Button $b1 'Quitar carpeta' { $script:Root=''; $rootLabel.Text='Detección por nombre MuMu' }
$tabs=New-Object Windows.Forms.TabControl; $tabs.Dock='Fill'; $layout.Controls.Add($tabs,0,4)
function New-Grid([string]$Title,[string[]]$Columns) {
    $page=New-Object Windows.Forms.TabPage; $page.Text=$Title; $tabs.TabPages.Add($page)
    $g=New-Object Windows.Forms.DataGridView; $g.Dock='Fill'; $g.ReadOnly=$true; $g.AllowUserToAddRows=$false; $g.AllowUserToDeleteRows=$false; $g.SelectionMode='FullRowSelect'; $g.MultiSelect=$true; $g.AutoSizeColumnsMode='DisplayedCells'
    foreach ($c in $Columns) { $null=$g.Columns.Add($c,$c) }; $page.Controls.Add($g); return ,$g
}
$connections=New-Grid 'Conexiones TCP (historial)' @('PID','Ejecutable','Ruta','IP remota','Puerto','Estado','Primera vez','Última vez','Lista original')
$processGrid=New-Grid 'Procesos detectados' @('PID','Ejecutable','Ruta','Observado')
$rules=New-Grid 'Reglas etiquetadas v1 / v2' @('Nombre interno','Activa','Programa','IP','Puerto','Protocolo','Dirección','Acción','Perfiles')
$status=New-Object Windows.Forms.Label; $status.Dock='Fill'; $status.Text='Listo. Inicia la captura ANTES de arrancar MuMu. Administrador: '+$script:Admin; $layout.Controls.Add($status,0,6)
$script:Original=@(Get-Content "$PSScriptRoot\referencia-ips.txt" | Where-Object { $_ -notmatch '^#' -and $_.Trim() })
function Refresh-Rules {
    $rules.Rows.Clear()
    foreach ($r in @(Get-ManagedRules)) { $null=$rules.Rows.Add([object[]]@($r.Name,$r.Enabled,$r.Program,$r.IP,$r.Port,$r.Protocol,$r.Direction,$r.Action,$r.Profile)) }
}
function Scan-MuMu {
    if ($script:Busy) { return }; $script:Busy=$true
    try {
        $now=Get-Date; $map=@{}
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            if ($p.Name -match '(?i)mumu' -or ($script:Root -and $p.ExecutablePath -and $p.ExecutablePath.StartsWith($script:Root,[StringComparison]::OrdinalIgnoreCase))) {
                $id=[int]$p.ProcessId; $map[$id]=$p
                $script:Processes["$id|$($p.ExecutablePath)"]=[object[]]@($id,$p.Name,$p.ExecutablePath,$now.ToString('HH:mm:ss'))
            }
        }
        foreach ($v in $script:History.Values) { $v[5]='No observada' }
        foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
            $id=[int]$c.OwningProcess
            if (-not $map.ContainsKey($id) -or $c.RemotePort -eq 0) { continue }
            $p=$map[$id]; $key="$id|$($p.ExecutablePath)|$($c.LocalAddress)|$($c.LocalPort)|$($c.RemoteAddress)|$($c.RemotePort)"
            $reference='No'; if ($script:Original -contains $c.RemoteAddress) { $reference='Coincidencia exacta (no prueba publicidad)' }
            if ($c.RemoteAddress -match '^42\.186\.(\d+)\.' -and [int]$Matches[1] -lt 128) { $reference='Dentro del /17 original (no importar)' }
            if (-not $script:History.ContainsKey($key)) { $script:History[$key]=[object[]]@($id,$p.Name,$p.ExecutablePath,$c.RemoteAddress,[string]$c.RemotePort,[string]$c.State,$now.ToString('o'),$now.ToString('o'),$reference) }
            $script:History[$key][5]=[string]$c.State; $script:History[$key][7]=$now.ToString('o')
        }
        # Limita memoria en capturas prolongadas; conserva los 5000 eventos más recientes.
        if ($script:History.Count -gt 5000) { foreach ($k in @($script:History.Keys | Sort-Object { $script:History[$_][7] } | Select-Object -First ($script:History.Count-5000))) { $script:History.Remove($k) } }
        $connections.Rows.Clear(); foreach ($v in $script:History.Values) { $null=$connections.Rows.Add([object[]]$v) }
        $processGrid.Rows.Clear(); foreach ($v in $script:Processes.Values) { $null=$processGrid.Rows.Add([object[]]$v) }
        $status.Text="Captura: $($now.ToString('HH:mm:ss')) | Procesos actuales: $($map.Count) | Conexiones acumuladas: $($script:History.Count). Sin ruta no se permite bloquear."
    } finally { $script:Busy=$false }
}
$timer=New-Object Windows.Forms.Timer; $timer.Interval=1500
$timer.Add_Tick({ try { Scan-MuMu } catch { $timer.Stop(); $status.Text='Captura detenida: '+$_.Exception.Message } })
$null=Add-Button $b2 'Iniciar captura' { $timer.Start(); Scan-MuMu }
$null=Add-Button $b2 'Pausar' { $timer.Stop(); $status.Text='Captura pausada; historial conservado.' }
$null=Add-Button $b2 'Limpiar historial' { $timer.Stop(); $script:History.Clear(); $script:Processes.Clear(); $connections.Rows.Clear(); $processGrid.Rows.Clear() }
$portMode=New-Object Windows.Forms.CheckBox; $portMode.Text='Limitar al puerto observado (recomendado)'; $portMode.Width=340; $portMode.Checked=$true; $b2.Controls.Add($portMode)
function Save-Dialog([string]$Filter,[string]$Name) { $d=New-Object Windows.Forms.SaveFileDialog; $d.Filter=$Filter; $d.FileName=$Name; try { if ($d.ShowDialog() -eq 'OK') { return $d.FileName } } finally { $d.Dispose() } }
function Backup-Auto {
    $dir=Join-Path $PSScriptRoot 'Respaldos'; $null=New-Item -ItemType Directory -Force -Path $dir
    $file=Join-Path $dir ((Get-Date -Format 'yyyyMMdd-HHmmss-fff')+'-'+[guid]::NewGuid().ToString('N')+'.json')
    Export-Configuration $file
}
$null=Add-Button $b3 'Bloquear seleccionadas...' {
    Require-Admin; $timer.Stop(); $targets=@()
    foreach ($row in $connections.SelectedRows) {
        $program=[string]$row.Cells[2].Value; $ip=[string]$row.Cells[3].Value; $port='Any'
        if ($portMode.Checked) { $port=[string]$row.Cells[4].Value }
        $null=Assert-Target $program $ip $port
        $targets+= [pscustomobject]@{Program=$program;IP=$ip;Port=$port}
    }
    if (-not $targets.Count) { throw 'Selecciona filas en la tabla de conexiones.' }
    $preview=($targets | ForEach-Object { "$($_.Program)`r`n  -> $($_.IP) TCP/$($_.Port)" }) -join "`r`n"
    if (-not (Confirm-Action ("$preview`r`n`r`nEstas IP pueden ser compartidas/CDN. Puede fallar Google Play o un juego dentro del MISMO ejecutable. ¿Crear bloqueos?"))) { return }
    Backup-Auto
    $results=@(); foreach ($t in $targets) { $results+=Add-ScopedRule $t.Program $t.IP $t.Port }
    Refresh-Rules; $status.Text=$results -join ' '; $tabs.SelectedIndex=2
}
$null=Add-Button $b3 'Actualizar reglas' { Refresh-Rules; $tabs.SelectedIndex=2 }
foreach ($op in @('Enable','Disable','Delete')) {
    $label=@{Enable='Activar seleccionadas';Disable='Desactivar seleccionadas';Delete='Eliminar seleccionadas'}[$op]
    $action={
        Require-Admin
        $names=@($rules.SelectedRows | ForEach-Object { [string]$_.Cells[0].Value })
        if (-not $names.Count) { throw 'Selecciona reglas en la pestaña de reglas.' }
        if (-not (Confirm-Action ("Operación: $op`r`n"+($names -join "`r`n")))) { return }
        Backup-Auto
        foreach ($name in $names) { Set-ManagedRule $name $op }
        Refresh-Rules
    }.GetNewClosure()
    $null=Add-Button $b4 $label $action
}
$null=Add-Button $b3 'Exportar configuración' { $file=Save-Dialog 'JSON|*.json' 'MuMu-config.json'; if ($file) { Export-Configuration $file; $status.Text='Exportado: '+$file } }
$null=Add-Button $b4 'Restaurar JSON...' {
    Require-Admin
    $d=New-Object Windows.Forms.OpenFileDialog; $d.Filter='JSON|*.json'
    try { if ($d.ShowDialog() -ne 'OK') { return }; $cfg=Read-Configuration $d.FileName } finally { $d.Dispose() }
    $preview=(@($cfg.Rules) | ForEach-Object { "$($_.Program) -> $($_.IP) TCP/$($_.Port) [$($_.Enabled)]" }) -join "`r`n"
    if (-not (Confirm-Action ("Restauración aditiva; no elimina otras reglas. Reglas antiguas amplias no se importan.`r`n$preview`r`n¿Continuar?"))) { return }
    Backup-Auto
    foreach ($r in @($cfg.Rules)) {
        $null=Add-ScopedRule $r.Program $r.IP $r.Port
        $id=Get-RuleId (Get-Item -LiteralPath $r.Program).FullName $r.IP $r.Port
        # Solo restaura el estado si existe la regla v2 exacta; no altera una regla antigua que la cubra.
        if (@(Get-ManagedRules | Where-Object Name -eq $id).Count) { $op='Disable'; if ($r.Enabled -eq 'True') { $op='Enable' }; Set-ManagedRule $id $op }
    }
    Refresh-Rules; $status.Text='Restauración finalizada. Revisa la tabla de reglas.'
}
$null=Add-Button $b2 'Exportar captura CSV' {
    $file=Save-Dialog 'CSV|*.csv' 'MuMu-conexiones.csv'
    if ($file) { @($script:History.Values | ForEach-Object { [pscustomobject]@{PID=$_[0];Ejecutable=$_[1];Ruta=$_[2];IP=$_[3];Puerto=$_[4];Estado=$_[5];Primera=$_[6];Ultima=$_[7];Referencia=$_[8]} }) | Export-Csv -LiteralPath $file -NoTypeInformation -Encoding UTF8 }
}
$form.Add_FormClosed({ $timer.Stop(); $timer.Dispose() })
if ($SmokeTest) { $form.Dispose(); Write-Output 'UI construida correctamente; no se consultó ni modificó el firewall.'; return }
try { Refresh-Rules } catch { $status.Text='No se pudieron listar reglas: '+$_.Exception.Message }
[void]$form.ShowDialog()
$form.Dispose()
