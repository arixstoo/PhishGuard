# Programme la collecte quotidienne des flux sur ce PC (Planificateur de tâches Windows).
# C'est l'archive principale : les artefacts GitHub expirent après 90 jours.
#
# Usage :  powershell -ExecutionPolicy Bypass -File scripts\register_daily_fetch.ps1 [-Time 06:00]
# Retrait : Unregister-ScheduledTask -TaskName PhishGuard-FetchFeeds -Confirm:$false
param([string]$Time = "06:00")

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { $python = (Get-Command python).Source }
$logDir = Join-Path $root "data\logs"
New-Item -ItemType Directory -Force $logDir | Out-Null

$cmd = "`"$python`" scripts\fetch_feeds.py --output-dir data\raw >> data\logs\fetch_feeds.log 2>&1"
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $cmd" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
# StartWhenAvailable : si le PC était éteint à l'heure prévue, la collecte part au réveil.
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

Register-ScheduledTask -TaskName "PhishGuard-FetchFeeds" -Action $action -Trigger $trigger `
    -Settings $settings -Description "Collecte quotidienne des flux PhishGuard (data/raw)" -Force |
    Out-Null
Write-Host "Tâche PhishGuard-FetchFeeds programmée chaque jour à $Time (logs : data\logs\fetch_feeds.log)"
