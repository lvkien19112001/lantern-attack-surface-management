# Go Lantern chay ngam (dung tien trinh + xoa muc tu khoi dong)
$name = 'Lantern ASM'
Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*serve.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-Item (Join-Path ([Environment]::GetFolderPath('Startup')) 'Lantern ASM.lnk') -ErrorAction SilentlyContinue
Write-Host "Da go Lantern chay ngam. Du lieu (lantern.db) khong bi xoa." -ForegroundColor Green
