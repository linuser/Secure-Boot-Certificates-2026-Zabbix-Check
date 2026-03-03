<#
.SYNOPSIS
    Zabbix Agent Check: Windows Secure Boot Zertifikate - Ablauf 2026

.DESCRIPTION
    Referenzen:
      - https://support.microsoft.com/de-de/topic/5062710
      - https://techcommunity.microsoft.com/blog/windowsservernewsandbestpractices/
        windows-server-secure-boot-playbook-for-certificates-expiring-in-2026/4495789
      - https://support.microsoft.com/en-us/topic/e2b43f9f-b424-42df-bc6a-8476db65ab2f

    WICHTIG: Windows Server bekommt die neuen Zertifikate NICHT automatisch!
    (Anders als Windows PCs via Controlled Feature Rollout.)

    Zertifikat-Pruefung basiert auf String-Matching der UEFI-Variablen-Bytes,
    wie von Microsoft und OEMs (Dell, MSI) offiziell dokumentiert:
      [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)

    HP/HPE-Kompatibilitaet:
      Manche HP/HPE-Firmware speichert Zertifikate nicht als ASCII sondern als
      UTF-16LE. Dieses Skript prueft beide Encodings. Zusaetzlich wird der
      Registry-Key WindowsUEFICA2023Capable als Fallback herangezogen.

    Installation:
      1. Kopiere in den zabbix-agent-scripts Ordner:
         C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\check_secureboot_certs.ps1
      2. UserParameter eintragen:
         Agent 1 (zabbix_agentd.conf):
           UserParameter=secureboot.status,powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\check_secureboot_certs.ps1"
           Timeout=30
         Agent 2 (zabbix_agent2.conf):
           UserParameter=secureboot.status,powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\check_secureboot_certs.ps1"
           Timeout=30
      3. Zabbix Agent Dienst neu starten
      4. Benoetigt Administratorrechte!

    Rueckgabe: JSON | Statuscode: 0=OK, 1=Warnung, 2=Kritisch
#>

$ErrorActionPreference = "Stop"

# ============================================================================
# Registry-Pfade (aus Microsoft Server Playbook)
# ============================================================================
$RegPathSecureBoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$RegPathServicing  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"

# ============================================================================
# Zertifikat-Definitionen fuer String-Match gegen UEFI-Bytes
# HINWEIS: Get-SecureBootUEFI gibt .Bytes zurueck, NICHT .Certificates!
#          Pruefung via String-Match (offizielle MS/Dell/MSI-Methode).
#          Doppeltes Encoding (ASCII + UTF-16LE) fuer HP/HPE-Kompatibilitaet.
# ============================================================================

$OldCertsKEK = @(
    @{ Name = "Microsoft Corporation KEK CA 2011"; SearchString = "Microsoft Corporation KEK CA 2011"; Expires = "2026-06-24" }
)
$OldCertsDB = @(
    @{ Name = "Microsoft Windows Production PCA 2011"; SearchString = "Microsoft Windows Production PCA 2011"; Expires = "2026-10-19" }
    @{ Name = "Microsoft Corporation UEFI CA 2011";    SearchString = "Microsoft Corporation UEFI CA 2011";    Expires = "2026-06-27" }
)

$NewCertsKEK = @(
    @{ Name = "Microsoft Corporation KEK 2K CA 2023"; SearchString = "Microsoft Corporation KEK 2K CA 2023" }
)
$NewCertsDB = @(
    @{ Name = "Windows UEFI CA 2023";              SearchString = "Windows UEFI CA 2023" }
    @{ Name = "Microsoft UEFI CA 2023";             SearchString = "Microsoft UEFI CA 2023" }
    @{ Name = "Microsoft Option ROM UEFI CA 2023";  SearchString = "Microsoft Option ROM UEFI CA 2023" }
)

# ============================================================================
# Hilfsfunktionen
# ============================================================================

function Get-SecureBootEnabled {
    try { return [bool](Confirm-SecureBootUEFI) }
    catch { return $false }
}

function Test-CertInUefiVar {
    <#
    .SYNOPSIS
        Prueft ob ein Zertifikat-Name in den Bytes einer UEFI-Variable enthalten ist.
        Testet sowohl ASCII als auch UTF-16LE Encoding fuer HP/HPE-Kompatibilitaet.
    .PARAMETER VariableName
        UEFI-Variable: "KEK" oder "db"
    .PARAMETER SearchString
        Der CN/Name des Zertifikats der gesucht wird.
    .OUTPUTS
        $true wenn gefunden, $false wenn nicht, $null bei Fehler
    #>
    param(
        [string]$VariableName,
        [string]$SearchString
    )
    try {
        $uefiVar = Get-SecureBootUEFI -Name $VariableName -ErrorAction Stop
        if ($null -eq $uefiVar -or $null -eq $uefiVar.Bytes) {
            return $null
        }

        $escapedSearch = [regex]::Escape($SearchString)

        # Methode 1: ASCII (Standard - Dell, MSI, viele Server)
        $asciiContent = [System.Text.Encoding]::ASCII.GetString($uefiVar.Bytes)
        if ($asciiContent -match $escapedSearch) {
            return $true
        }

        # Methode 2: UTF-16LE (manche HP/HPE-Firmware)
        $utf16Content = [System.Text.Encoding]::Unicode.GetString($uefiVar.Bytes)
        if ($utf16Content -match $escapedSearch) {
            return $true
        }

        # Methode 3: UTF-8 (Fallback)
        $utf8Content = [System.Text.Encoding]::UTF8.GetString($uefiVar.Bytes)
        if ($utf8Content -match $escapedSearch) {
            return $true
        }

        return $false
    }
    catch {
        return $null
    }
}

function Get-RegVal {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) { return $item.$Name }
    } catch { }
    return $null
}

function Get-SBEvents {
    <#
    .SYNOPSIS
        Sucht Secure Boot Events der Quelle Microsoft-Windows-TPM-WMI (letzte 30 Tage).
        1808 = Zertifikate erfolgreich angewendet
        1801 = Zertifikate muessen aktualisiert werden
        1800 = Reboot erforderlich fuer Boot Manager
        1795 = Firmware-Fehler beim Zertifikat-Handoff
        1803 = PK-signed KEK nicht gefunden (OEM-Problem)
    #>
    $ev = @{
        e1808=$false; e1801=$false; e1800=$false; e1795=$false; e1803=$false
        lastId=$null; lastTime=""; count_1808=0; count_1801=0
    }
    try {
        $logs = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-TPM-WMI'
            Id           = @(1808, 1801, 1800, 1795, 1803)
            StartTime    = (Get-Date).AddDays(-30)
        } -MaxEvents 50 -ErrorAction SilentlyContinue

        if ($logs -and $logs.Count -gt 0) {
            foreach ($l in $logs) {
                switch ($l.Id) {
                    1808 { $ev.e1808 = $true; $ev.count_1808++ }
                    1801 { $ev.e1801 = $true; $ev.count_1801++ }
                    1800 { $ev.e1800 = $true }
                    1795 { $ev.e1795 = $true }
                    1803 { $ev.e1803 = $true }
                }
            }
            $latest = $logs | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $ev.lastId   = [int]$latest.Id
            $ev.lastTime = $latest.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        }
    } catch { }
    return $ev
}

# ============================================================================
# Ergebnis-Objekt
# ============================================================================
$r = [ordered]@{
    # Grundstatus
    secure_boot_enabled       = $false
    affected                  = $false
    status                    = 0          # 0=OK, 1=Warnung, 2=Kritisch
    message                   = ""

    # Einzelne Zertifikate (Bool fuer Zabbix-Trigger)
    old_kek_ca_2011           = $false
    old_win_prod_pca_2011     = $false
    old_uefi_ca_2011          = $false
    new_kek_2k_ca_2023        = $false
    new_win_uefi_ca_2023      = $false
    new_uefi_ca_2023          = $false
    new_optrom_uefi_ca_2023   = $false

    # Zusammenfassungen
    old_certs_present         = @()
    new_certs_present         = @()
    new_certs_missing         = @()

    # Registry (MS Server Playbook)
    deployment_status         = "unknown"
    deployment_error          = $null
    available_updates         = $null
    update_configured         = $false
    win_uefi_ca_2023_capable  = $null     # HP/HPE Fallback Registry-Key

    # Event Log: Microsoft-Windows-TPM-WMI (letzte 30 Tage)
    event_1808_success        = $false
    event_1801_needs_update   = $false
    event_1800_reboot_needed  = $false
    event_1795_firmware_error = $false
    event_1803_kek_missing    = $false
    event_1808_count          = 0
    event_1801_count          = 0
    last_event_id             = $null
    last_event_time           = ""

    # Meta
    check_time                = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    hostname                  = $env:COMPUTERNAME
    os_version                = ""
    manufacturer              = ""
}

# ============================================================================
# 1. OS-Info + Hersteller
# ============================================================================
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) { $r.os_version = "$($os.Caption) ($($os.BuildNumber))" }
} catch { }

try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs) { $r.manufacturer = "$($cs.Manufacturer) $($cs.Model)".Trim() }
} catch { }

# ============================================================================
# 2. Secure Boot aktiv?
# ============================================================================
$r.secure_boot_enabled = Get-SecureBootEnabled
if (-not $r.secure_boot_enabled) {
    # Physischen Server von VM unterscheiden
    $isVM = $false
    if ($null -ne $cs -and $cs.Model -match "Virtual|VMware|KVM|Xen|HVM|BHYVE") {
        $isVM = $true
    }

    if ($isVM) {
        $r.message = "Secure Boot nicht aktiviert oder nicht verfuegbar (VM). Nicht betroffen."
    }
    else {
        $r.status = 1; $r.affected = $true
        $r.message = "WARNUNG - Secure Boot ist auf physischem Server deaktiviert ($($r.manufacturer)). Vom Zertifikats-Update nicht betroffen, aber Secure Boot wird aus Sicherheitsgruenden empfohlen."
    }
    $r | ConvertTo-Json -Compress -Depth 3
    exit 0
}

# ============================================================================
# 3. Zertifikate pruefen (String-Match gegen UEFI-Bytes, Multi-Encoding)
# ============================================================================

# --- Alte Zertifikate: KEK ---
foreach ($c in $OldCertsKEK) {
    $found = Test-CertInUefiVar -VariableName "KEK" -SearchString $c.SearchString
    if ($found -eq $true) {
        $r.old_certs_present += "$($c.Name) (exp: $($c.Expires))"
        $r.old_kek_ca_2011 = $true
    }
}

# --- Alte Zertifikate: DB ---
foreach ($c in $OldCertsDB) {
    $found = Test-CertInUefiVar -VariableName "db" -SearchString $c.SearchString
    if ($found -eq $true) {
        $r.old_certs_present += "$($c.Name) (exp: $($c.Expires))"
        if ($c.SearchString -like "*Production*") { $r.old_win_prod_pca_2011 = $true }
        if ($c.SearchString -like "*UEFI CA 2011*") { $r.old_uefi_ca_2011 = $true }
    }
}

# --- Neue Zertifikate: KEK ---
foreach ($c in $NewCertsKEK) {
    $found = Test-CertInUefiVar -VariableName "KEK" -SearchString $c.SearchString
    if ($found -eq $true) {
        $r.new_certs_present += $c.Name
        $r.new_kek_2k_ca_2023 = $true
    }
    else {
        $r.new_certs_missing += $c.Name
    }
}

# --- Neue Zertifikate: DB ---
foreach ($c in $NewCertsDB) {
    $found = Test-CertInUefiVar -VariableName "db" -SearchString $c.SearchString
    if ($found -eq $true) {
        $r.new_certs_present += $c.Name
        if ($c.SearchString -eq "Windows UEFI CA 2023")              { $r.new_win_uefi_ca_2023 = $true }
        if ($c.SearchString -eq "Microsoft UEFI CA 2023")            { $r.new_uefi_ca_2023 = $true }
        if ($c.SearchString -eq "Microsoft Option ROM UEFI CA 2023") { $r.new_optrom_uefi_ca_2023 = $true }
    }
    else {
        # Option ROM CA 2023 nur noetig wenn UEFI CA 2011 vorhanden war
        if ($c.SearchString -like "*Option ROM*" -and -not $r.old_uefi_ca_2011) {
            # Nicht als fehlend melden wenn das alte Zertifikat gar nicht da war
        }
        else {
            $r.new_certs_missing += $c.Name
        }
    }
}

# ============================================================================
# 4. Registry-Keys (MS Server Playbook)
# ============================================================================

# UEFICA2023Status - Deployment-Fortschritt
$uefiSt = Get-RegVal -Path $RegPathServicing -Name "UEFICA2023Status"
if ($null -ne $uefiSt) {
    $sl = $uefiSt.ToString().ToLower().Trim()
    if     ($sl -eq "updated")       { $r.deployment_status = "updated" }
    elseif ($sl -like "*progress*")  { $r.deployment_status = "in_progress" }
    elseif ($sl -like "*not*start*") { $r.deployment_status = "not_started" }
    else                             { $r.deployment_status = $sl }
}
else {
    $r.deployment_status = "key_not_found"
}

# UEFICA2023Error - existiert nur bei Fehlern (0 = kein Fehler)
$uefiErr = Get-RegVal -Path $RegPathServicing -Name "UEFICA2023Error"
if ($null -ne $uefiErr) {
    $errStr = $uefiErr.ToString()
    if ($errStr -ne "0" -and $errStr -ne "") {
        $r.deployment_error = $errStr
    }
}

# AvailableUpdates - 0x5944 = alle Zertifikate deployen
$avUpd = Get-RegVal -Path $RegPathSecureBoot -Name "AvailableUpdates"
if ($null -ne $avUpd) {
    $iv = [int]$avUpd
    $r.available_updates = "0x{0:X4}" -f $iv
    $r.update_configured = ($iv -gt 0)
}

# WindowsUEFICA2023Capable - HP/HPE Fallback
# 0 = nicht vorhanden, 1 = Zertifikat in DB, 2 = Zertifikat in DB + 2023 Boot Manager aktiv
$capVal = Get-RegVal -Path $RegPathServicing -Name "WindowsUEFICA2023Capable"
if ($null -ne $capVal) {
    $r.win_uefi_ca_2023_capable = [int]$capVal
}

# ============================================================================
# 5. Event Log: Microsoft-Windows-TPM-WMI (letzte 30 Tage)
# ============================================================================
$ev = Get-SBEvents
$r.event_1808_success        = $ev.e1808
$r.event_1801_needs_update   = $ev.e1801
$r.event_1800_reboot_needed  = $ev.e1800
$r.event_1795_firmware_error = $ev.e1795
$r.event_1803_kek_missing    = $ev.e1803
$r.event_1808_count          = $ev.count_1808
$r.event_1801_count          = $ev.count_1801
$r.last_event_id             = $ev.lastId
$r.last_event_time           = $ev.lastTime

# ============================================================================
# 6. Gesamtbewertung (Prioritaetsreihenfolge)
# ============================================================================
$hasOld       = $r.old_certs_present.Count -gt 0
$hasNew       = $r.new_certs_present.Count -gt 0
$allNewDone   = $r.new_certs_missing.Count -eq 0
$regUpdated   = $r.deployment_status -eq "updated"
$hasDeployErr = ($null -ne $r.deployment_error)
$hasFWError   = $r.event_1795_firmware_error -or $r.event_1803_kek_missing

# Registry-Fallback: WindowsUEFICA2023Capable (relevant fuer HP/HPE
# wo der UEFI-Byte-Match komplett fehlschlagen kann)
$regCapable      = ($null -ne $r.win_uefi_ca_2023_capable -and $r.win_uefi_ca_2023_capable -ge 1)
# Byte-Match hat ueberhaupt etwas gefunden? Wenn ja, sind die Ergebnisse vertrauenswuerdig
$byteMatchWorked = ($hasOld -or $hasNew)

# Prio 1: Registry=updated UND Event 1808 -> sicherster OK-Zustand
if ($regUpdated -and $r.event_1808_success) {
    $r.status = 0; $r.affected = $false
    $r.message = "OK - Deployment abgeschlossen (Registry=updated, Event 1808 bestaetigt, $($r.event_1808_count)x)."
}
# Prio 2: Alle neuen Zertifikate per Byte-Match in Firmware verifiziert
elseif ($allNewDone -and $hasNew) {
    $r.status = 0; $r.affected = $false
    $r.message = "OK - Alle neuen 2023-Zertifikate in der Firmware verifiziert."
}
# Prio 3: Registry sagt "updated" (Event-Logs ggf. schon rotiert)
elseif ($regUpdated) {
    $r.status = 0; $r.affected = $false
    $r.message = "OK - Deployment-Status laut Registry: updated."
}
# Prio 4: Deployment-Fehler (Registry oder Firmware-Events)
elseif ($hasDeployErr -or $hasFWError) {
    $r.status = 2; $r.affected = $true
    $ed = @()
    if ($hasDeployErr)               { $ed += "UEFICA2023Error=$($r.deployment_error)" }
    if ($r.event_1795_firmware_error) { $ed += "Event 1795 (Firmware-Fehler bei Cert-Handoff an UEFI)" }
    if ($r.event_1803_kek_missing)   { $ed += "Event 1803 (PK-signed KEK fehlt - OEM kontaktieren)" }
    $r.message = "KRITISCH - Fehler beim Deployment: $($ed -join '; ')"
}
# Prio 5: Deployment laeuft gerade
elseif ($r.deployment_status -eq "in_progress") {
    $r.status = 1; $r.affected = $true
    if ($r.event_1800_reboot_needed) {
        $r.message = "WARNUNG - Deployment laeuft. Reboot erforderlich fuer Boot Manager (Event 1800)."
    }
    else {
        $r.message = "WARNUNG - Deployment laeuft (in_progress). Dauert ca. 12h nach Konfiguration."
    }
}
# Prio 6: Teilweise aktualisiert (einige neue Zerts da, aber nicht alle)
elseif ($hasNew -and -not $allNewDone) {
    $r.status = 1; $r.affected = $true
    if (-not $r.update_configured) {
        $r.message = "WARNUNG - Teilweise aktualisiert. Fehlend: $($r.new_certs_missing -join ', '). Deployment NICHT konfiguriert! Setze AvailableUpdates=0x5944 oder GPO."
    }
    else {
        $r.message = "WARNUNG - Teilweise aktualisiert. Fehlend: $($r.new_certs_missing -join ', ')"
    }
}
# Prio 7: Nur alte Zertifikate, keine neuen -> kritisch
elseif ($hasOld -and -not $hasNew) {
    $r.status = 2; $r.affected = $true
    if (-not $r.update_configured) {
        $r.message = "KRITISCH - Nur alte 2011-Zertifikate vorhanden. Deployment NICHT konfiguriert! Setze Registry AvailableUpdates=0x5944 oder GPO 'Enable Secure Boot certificate deployment'."
    }
    else {
        $r.message = "KRITISCH - Nur alte 2011-Zertifikate. AvailableUpdates=$($r.available_updates) gesetzt, aber kein Fortschritt erkennbar."
    }
}
# Prio 8: Byte-Match fand GAR NICHTS -> HP/HPE-Fallback via Registry
elseif (-not $byteMatchWorked) {
    if ($regCapable -and -not $r.event_1801_needs_update) {
        # Byte-Match komplett leer + Registry sagt OK + kein Event 1801 -> vertrauen
        $r.status = 0; $r.affected = $false
        $capText = if ($r.win_uefi_ca_2023_capable -ge 2) { "Zertifikat + 2023 Boot Manager aktiv" } else { "Zertifikat in DB" }
        $r.message = "OK - UEFI-Byte-Match lieferte keine Treffer (Firmware-Kodierung), aber WindowsUEFICA2023Capable=$($r.win_uefi_ca_2023_capable) ($capText) bestaetigt Update."
    }
    elseif ($regCapable -and $r.event_1801_needs_update) {
        # Registry sagt teilweise OK, aber Event 1801 warnt -> noch nicht fertig
        $r.status = 1; $r.affected = $true
        $r.message = "WARNUNG - WindowsUEFICA2023Capable=$($r.win_uefi_ca_2023_capable), aber Event 1801 meldet weiterhin Update-Bedarf ($($r.event_1801_count)x). Deployment ggf. unvollstaendig."
    }
    else {
        $r.status = 1; $r.affected = $true
        $r.message = "WARNUNG - Keine bekannten MS Secure Boot Zertifikate per UEFI-Byte-Match gefunden. Bei HP/HPE kann dies an der Firmware-Kodierung liegen. Manuelle Pruefung empfohlen."
    }
}
# Fallback
else {
    $r.status = 1; $r.affected = $true
    $r.message = "WARNUNG - Status nicht eindeutig bestimmbar. Manuelle Pruefung empfohlen."
}

# ============================================================================
# 7. JSON-Ausgabe fuer Zabbix
# ============================================================================
$r | ConvertTo-Json -Compress -Depth 3
