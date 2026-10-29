# Cai Lantern chay ngam: tu khoi dong khi dang nhap Windows, khong hien cua so, tu chay lai neu bi tat.
# Sau khi cai, lich quet tu dong se chay dung gio du ban chua mo trinh duyet; mo http://127.0.0.1:8000 la thay ket qua.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$py   = Join-Path $root '.venv\Scripts\pythonw.exe'
$port = 8000
$name = 'Lantern ASM'
$me   = "$env:USERDOMAIN\$env:USERNAME"

if (-not (Test-Path $py)) {
    Write-Host "Khong thay $py" -ForegroundColor Red
    Write-Host "Hay tao .venv va cai thu vien truoc (xem README, Buoc 3)."
    exit 1
}

# Dung ban dang chay (neu co) de tranh trung cong
Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*serve.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$busy = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Write-Host "Cong $port dang duoc dung boi chuong trinh khac (co the la Lantern dang chay bang tay)." -ForegroundColor Yellow
    Write-Host "Hay tat cua so uvicorn dang mo roi chay lai file nay."
    exit 1
}

$mode = ''
try {
    $action    = New-ScheduledTaskAction -Execute $py -Argument 'serve.py' -WorkingDirectory $root
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $me
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
                   -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
                   -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $name
    $mode = 'Task Scheduler'
} catch {
    # Khong tao duoc task (thieu quyen...) -> dung thu muc Startup cua Windows
    $startup = [Environment]::GetFolderPath('Startup')
    $lnk = Join-Path $startup 'Lantern ASM.lnk'
    $sh = New-Object -ComObject WScript.Shell
    $s = $sh.CreateShortcut($lnk)
    $s.TargetPath = $py; $s.Arguments = 'serve.py'; $s.WorkingDirectory = $root; $s.WindowStyle = 7
    $s.Save()
    Start-Process -FilePath $py -ArgumentList 'serve.py' -WorkingDirectory $root -WindowStyle Hidden
    $mode = 'Startup folder'
}

# Phim tat mo giao dien tren Desktop
try {
    $desk = [Environment]::GetFolderPath('Desktop')
    Set-Content -Path (Join-Path $desk 'Lantern.url') -Value "[InternetShortcut]`r`nURL=http://127.0.0.1:$port/" -Encoding ASCII
} catch {}

Write-Host "Dang khoi dong..."
$ok = $false
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    try { if ((Invoke-RestMethod "http://127.0.0.1:$port/api/health" -TimeoutSec 2).ok) { $ok = $true; break } } catch {}
}
if ($ok) {
    Write-Host "OK - Lantern dang chay ngam ($mode). Mo http://127.0.0.1:$port (da tao shortcut 'Lantern' tren Desktop)." -ForegroundColor Green
    Write-Host "Luu y: may tinh phai dang bat (khong sleep/hibernate) thi lich quet moi chay dung gio. Neu lo gio, Lantern se quet bu ngay khi may bat lai."
} else {
    Write-Host "Chua thay Lantern phan hoi. Xem file lantern.log trong thu muc du an de biet loi." -ForegroundColor Red
    exit 1
}
