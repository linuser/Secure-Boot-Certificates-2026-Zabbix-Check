# Zabbix Template: Windows Secure Boot Zertifikate 2026

> Monitoring-Loesung fuer den Ablauf der Microsoft Secure Boot Zertifikate (Juni-Oktober 2026) mit Zabbix Agent.

![Zabbix](https://img.shields.io/badge/Zabbix-7.0%2B-red)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Windows](https://img.shields.io/badge/Windows-Server%202012--2025-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Warum?

Die originalen Windows Secure Boot Zertifikate von 2011 laufen 2026 ab:

| Zertifikat | Ablaufdatum | UEFI-Variable |
|---|---|---|
| Microsoft Corporation KEK CA 2011 | 24. Juni 2026 | KEK |
| Microsoft Corporation UEFI CA 2011 | 27. Juni 2026 | DB |
| Microsoft Windows Production PCA 2011 | 19. Oktober 2026 | DB |

**Windows Server bekommt die neuen 2023-Zertifikate NICHT automatisch!** Anders als Windows PCs muss bei Servern das Deployment manuell konfiguriert werden (Registry oder GPO).

Ohne Update verlieren Server nach Ablauf die Faehigkeit, neue Secure Boot Security Updates zu installieren.

### Betroffene Windows Server Versionen

| Version | Support-Status (Stand 2026) | Betroffen | Registry/GPO Deployment | Hinweis |
|---|---|---|---|---|
| Windows Server 2012 | ESU endet Okt. 2026 | Ja | Nein (manuell) | Kein Registry-Key-Support, manuelles Cert-Enrollment noetig |
| Windows Server 2012 R2 | ESU endet Okt. 2026 | Ja | Nein (manuell) | Kein Registry-Key-Support, manuelles Cert-Enrollment noetig |
| Windows Server 2016 | Extended Support bis Jan. 2027 | Ja | Nein (manuell) | Kein Registry-Key-Support, manuelles Cert-Enrollment noetig |
| Windows Server 2019 | Extended Support bis Jan. 2029 | Ja | Nein (manuell) | Kein Registry-Key-Support, manuelles Cert-Enrollment noetig |
| Windows Server 2022 | Mainstream bis Okt. 2026 | Ja | Ja (Registry + GPO) | Vollstaendiger Support fuer automatisches Deployment |
| Windows Server 2025 | Mainstream Support | Ja* | Ja (Registry + GPO) | *Zertifizierte Plattformen haben 2023-Certs bereits ab Werk |

> **Wichtig:** Der automatische Deployment-Mechanismus via Registry-Key `AvailableUpdates` und GPO ist laut Microsoft nur fuer **Windows Server 2022 und neuer** verfuegbar. Aeltere Versionen (2012-2019) erfordern alternative Methoden wie das WinCS PowerShell-Modul oder manuelles Enrollment.

Auch betroffen sind **alle Generation-2 VMs** (Hyper-V, VMware) sowie physische Server mit Secure Boot. Nicht betroffen sind Generation-1 Hyper-V VMs (kein UEFI/Secure Boot) und Copilot+ PCs ab 2025.

### Referenzen

- [MS Support: Secure Boot Zertifikat-Ablauf](https://support.microsoft.com/de-de/topic/5062710)
- [MS TechCommunity: Windows Server Playbook](https://techcommunity.microsoft.com/blog/windowsservernewsandbestpractices/windows-server-secure-boot-playbook-for-certificates-expiring-in-2026/4495789)
- [MS Support: IT-Leitfaden fuer Organisationen](https://support.microsoft.com/en-us/topic/e2b43f9f-b424-42df-bc6a-8476db65ab2f)

---

## Features

- **3-Ebenen-Pruefung**: UEFI-Firmware + Registry-Keys + Event Log
- **Multi-Encoding**: ASCII, UTF-16LE, UTF-8 (HP/HPE-kompatibel)
- **Registry-Fallback**: `WindowsUEFICA2023Capable` fuer Systeme mit nicht-standardem Firmware-Encoding
- **VM-Erkennung**: Unterscheidet physische Server von VMs (Hyper-V, VMware, KVM, Xen)
- **Physischer Server Warnung**: Meldet wenn Secure Boot auf physischer Hardware deaktiviert ist
- **11 Zabbix Items**: Master-JSON + 10 abgeleitete Items mit JSONPATH-Preprocessing
- **3 Trigger**: Kritisch, Warnung, Deployment-Status
- **Valuemaps**: Deutsche Beschriftung (Ja/Nein, OK/Warnung/Kritisch)

---

## Dateiuebersicht

```
check_secureboot_certs.ps1         # PowerShell-Skript (Zabbix Agent UserParameter)
zbx_template_secureboot_certs.xml  # Zabbix 7.0 Template (XML-Import)
README.md                          # Diese Datei
```

---

## Schnellstart

### Voraussetzungen

- Zabbix Server/Proxy **7.0** oder neuer
- Zabbix Agent 1 oder Agent 2 auf Windows
- **Administratorrechte** auf dem Zielserver (fuer UEFI-Variablen-Zugriff)
- PowerShell 5.1+ (auf allen unterstuetzten Windows-Versionen vorinstalliert)

### 1. Skript auf den Zielserver kopieren

```powershell
# Zielverzeichnis erstellen (falls noetig)
New-Item -Path "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts" -ItemType Directory -Force

# Skript kopieren
Copy-Item check_secureboot_certs.ps1 "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\"
```

> **Hinweis:** Den Pfad an eure Umgebung anpassen. Das Skript kann in jedem beliebigen Verzeichnis liegen, solange der UserParameter-Pfad uebereinstimmt.

### 2. UserParameter konfigurieren

In `zabbix_agent2.conf` (oder `zabbix_agentd.conf` fuer Agent 1) bzw. als eigene `.conf` Datei in `zabbix_agent2.d/`:

```ini
UserParameter=secureboot.status,powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\check_secureboot_certs.ps1"
Timeout=30
```

> **Wichtig:** `Timeout=30` setzen! Das Skript fragt UEFI-Variablen, Registry und Event Log ab. Der Default-Timeout von 3 Sekunden ist zu kurz.

### 3. Zabbix Agent neu starten

```cmd
net stop "Zabbix Agent 2" && net start "Zabbix Agent 2"
```

### 4. Template importieren

1. Zabbix Web UI > **Datenerfassung** > **Templates** > **Importieren**
2. `zbx_template_secureboot_certs.xml` hochladen
3. Template dem Host oder der Hostgruppe zuweisen

### 5. Manuell testen

```powershell
# Als Administrator ausfuehren!
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\check_secureboot_certs.ps1"
```

Lesbare Ausgabe:

```powershell
$json = powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\Zabbix Agent 2\zabbix-agent-scripts\check_secureboot_certs.ps1"
$json | ConvertFrom-Json | Format-List
```

---

## So funktioniert es

Das Skript prueft auf **drei Ebenen** und bewertet den Gesamtstatus:

### Ebene 1: UEFI-Firmware (Zertifikate direkt pruefen)

Liest die UEFI-Variablen `KEK` und `db` aus und sucht per String-Match nach den Zertifikat-Namen. Drei Encodings werden getestet fuer maximale Firmware-Kompatibilitaet:

```powershell
# Standard (Dell, Lenovo, die meisten Server):
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes)

# HP/HPE-Firmware:
[System.Text.Encoding]::Unicode.GetString((Get-SecureBootUEFI db).bytes)

# Fallback:
[System.Text.Encoding]::UTF8.GetString((Get-SecureBootUEFI db).bytes)
```

### Ebene 2: Registry-Keys

| Registry-Pfad | Key | Bedeutung |
|---|---|---|
| `HKLM:\...\SecureBoot\Servicing` | `UEFICA2023Status` | `updated` / `in_progress` / `not_started` |
| `HKLM:\...\SecureBoot\Servicing` | `UEFICA2023Error` | Fehlerwert (existiert nur bei Fehler) |
| `HKLM:\...\SecureBoot\Servicing` | `WindowsUEFICA2023Capable` | 0=nein, 1=Cert in DB, 2=Cert+BootMgr |
| `HKLM:\...\SecureBoot` | `AvailableUpdates` | `0x5944` = Deployment konfiguriert |

### Ebene 3: Event Log (Microsoft-Windows-TPM-WMI, letzte 30 Tage)

| Event ID | Bedeutung |
|---|---|
| 1808 | Zertifikate erfolgreich angewendet |
| 1801 | Zertifikate muessen aktualisiert werden |
| 1800 | Reboot erforderlich fuer Boot Manager |
| 1795 | Firmware-Fehler beim Zertifikat-Handoff |
| 1803 | PK-signed KEK nicht gefunden (OEM kontaktieren) |

### Bewertungslogik (Prioritaetsreihenfolge)

| Prio | Bedingung | Status | Code |
|:----:|-----------|:------:|:----:|
| 1 | Registry=updated + Event 1808 | OK | 0 |
| 2 | Alle neuen Zerts in Firmware verifiziert | OK | 0 |
| 3 | Registry=updated | OK | 0 |
| 4 | UEFICA2023Error oder Event 1795/1803 | Kritisch | 2 |
| 5 | deployment_status=in_progress | Warnung | 1 |
| 6 | Teilweise aktualisiert (neue + fehlende Zerts) | Warnung | 1 |
| 7 | Nur alte Zerts, Deployment nicht konfiguriert | Kritisch | 2 |
| 8 | Byte-Match leer, HP/HPE Registry-Fallback | variabel | 0-1 |
| - | Secure Boot deaktiviert (VM) | OK | 0 |
| - | Secure Boot deaktiviert (physischer Server) | Warnung | 1 |

---

## Template-Details

### Items (11)

| Item | Key | Typ | Beschreibung |
|------|-----|-----|-------------|
| Raw JSON Status | `secureboot.status` | Zabbix Active, 12h | Master-Item mit allen Rohdaten |
| Aktiviert | `secureboot.enabled` | Dependent | Secure Boot aktiv (0/1) |
| Betroffen | `secureboot.affected` | Dependent | Server vom Ablauf betroffen (0/1) |
| Statuscode | `secureboot.statuscode` | Dependent | 0=OK, 1=Warnung, 2=Kritisch |
| Statusmeldung | `secureboot.message` | Dependent | Lesbarer Statustext |
| Deployment Status | `secureboot.deployment_status` | Dependent | Registry UEFICA2023Status |
| Update konfiguriert | `secureboot.update_configured` | Dependent | AvailableUpdates gesetzt (0/1) |
| Fehlende Zertifikate | `secureboot.missing` | Dependent | Liste fehlender 2023-Zerts |
| Event 1808 Anzahl | `secureboot.event_1808_count` | Dependent | Erfolgs-Events (30 Tage) |
| Event 1801 Anzahl | `secureboot.event_1801_count` | Dependent | Update-noetig-Events (30 Tage) |
| Windows UEFI CA 2023 | `secureboot.new_win_uefi_ca_2023` | Dependent | Wichtigstes neues Zertifikat (0/1) |

### Trigger (3)

| Severity | Bedingung | Beschreibung |
|----------|-----------|-------------|
| **High** | `statuscode = 2` | Nur alte Zerts vorhanden oder Deployment-Fehler |
| **Warning** | `statuscode = 1` | Teilweise aktualisiert oder Deployment laeuft |
| **Warning** | `enabled=1` + `update_configured=0` + `statuscode>0` | Deployment nicht konfiguriert |

### Valuemaps

- **Secure Boot Ja/Nein**: 0=Nein, 1=Ja
- **Secure Boot Statuscode**: 0=OK, 1=Warnung, 2=Kritisch

---

## HP/HPE-Kompatibilitaet

Manche HP/HPE-Firmware speichert Zertifikate nicht als ASCII in den UEFI-Variablen. Der Standard-ASCII-Match liefert dann `False`, obwohl die Zertifikate vorhanden sind.

Das Skript loest dieses Problem durch:

1. **Multi-Encoding**: Test mit ASCII, UTF-16LE und UTF-8
2. **Registry-Fallback**: `WindowsUEFICA2023Capable` als zusaetzlicher Indikator
3. **Hersteller-Info**: `Win32_ComputerSystem.Manufacturer` im JSON-Output

> **HPE ProLiant + Event 1795:** Ggf. ist ein BIOS/SPP-Update erforderlich bevor das Zertifikat-Deployment funktioniert.

---

## Getestet mit

| Plattform | Encoding | Status |
|-----------|----------|--------|
| Dell PowerEdge | ASCII | OK |
| HPE ProLiant Gen10/Gen10+ | UTF-16LE + Registry-Fallback | OK |
| HP Workstations Z-Serie | UTF-8/UTF-16LE | OK |
| Lenovo ThinkSystem | ASCII | OK |
| Hyper-V Gen2 VMs | ASCII | OK |
| VMware VMs | ASCII | OK |
| Proxmox/KVM (OVMF) | ASCII | OK |

---

## Deployment per GPO oder Registry

Falls das Monitoring fehlende Zertifikate meldet, kann das Deployment so konfiguriert werden:

### Option A: Registry (einzelner Server)

```powershell
# Als Administrator:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x5944 -Type DWord
```

Danach ca. 12 Stunden warten + Reboot wenn Event 1800 erscheint.

### Option B: GPO (domainweit)

```
Computerkonfiguration > Administrative Vorlagen > Windows-Komponenten > Secure Boot
  > "Enable Secure Boot certificate deployment" = Aktiviert
```

> Fuer die neuesten ADMX-Vorlagen: [Administrative Templates (.admx) for Windows Server](https://www.microsoft.com/en-us/download/details.aspx?id=105667)

---

## JSON-Output (Beispiel)

<details>
<summary>Vollstaendige JSON-Ausgabe aufklappen</summary>

```json
{
  "secure_boot_enabled": true,
  "affected": true,
  "status": 1,
  "message": "WARNUNG - Teilweise aktualisiert. Fehlend: Microsoft UEFI CA 2023. Deployment NICHT konfiguriert! Setze AvailableUpdates=0x5944 oder GPO.",
  "old_kek_ca_2011": true,
  "old_win_prod_pca_2011": true,
  "old_uefi_ca_2011": false,
  "new_kek_2k_ca_2023": true,
  "new_win_uefi_ca_2023": true,
  "new_uefi_ca_2023": false,
  "new_optrom_uefi_ca_2023": false,
  "old_certs_present": [
    "Microsoft Corporation KEK CA 2011 (exp: 2026-06-24)",
    "Microsoft Windows Production PCA 2011 (exp: 2026-10-19)"
  ],
  "new_certs_present": [
    "Microsoft Corporation KEK 2K CA 2023",
    "Windows UEFI CA 2023"
  ],
  "new_certs_missing": [
    "Microsoft UEFI CA 2023"
  ],
  "deployment_status": "not_started",
  "deployment_error": null,
  "available_updates": "0x0000",
  "update_configured": false,
  "win_uefi_ca_2023_capable": null,
  "event_1808_success": false,
  "event_1801_needs_update": true,
  "event_1800_reboot_needed": false,
  "event_1795_firmware_error": false,
  "event_1803_kek_missing": false,
  "event_1808_count": 0,
  "event_1801_count": 12,
  "last_event_id": 1801,
  "last_event_time": "2026-03-01 08:15:22",
  "check_time": "2026-03-01 14:00:00",
  "hostname": "SERVER01",
  "os_version": "Microsoft Windows Server 2022 Standard (20348)",
  "manufacturer": "Dell Inc. PowerEdge R750"
}
```

</details>

---

## Troubleshooting

| Problem | Ursache | Loesung |
|---------|---------|---------|
| Leerer Output / Timeout | Skript braucht laenger als Agent-Timeout | `Timeout=30` in Agent-Config setzen |
| Alle Felder `false`/leer | Keine Admin-Rechte | Agent als LocalSystem ausfuehren |
| Event 1795 | Firmware unterstuetzt Cert-Handoff nicht | BIOS/Firmware-Update vom OEM einspielen |
| Event 1803 | PK-signed KEK fehlt in Firmware | OEM/Hersteller kontaktieren |
| Byte-Match findet nichts | HP/HPE Firmware-Encoding | Skript prueft bereits 3 Encodings + Registry-Fallback |
| `AvailableUpdates` bleibt auf `0x4104` | KEK-Deployment haengt | Event 1803 pruefen, OEM kontaktieren |
| Template-Import schlaegt fehl | Falsche Zabbix-Version | Template benoetigt Zabbix 7.0+ |

---

## Hinweise

- **Abfrageintervall**: 12 Stunden (Zertifikate aendern sich selten)
- **Admin-Rechte**: Zwingend erforderlich fuer UEFI-Variablen-Zugriff
- **VMs ohne UEFI**: `Confirm-SecureBootUEFI` gibt Fehler, wird als "nicht betroffen" erkannt
- **Hyper-V Gen1**: Kein Secure Boot, korrekt als "nicht betroffen" erkannt
- **Hyper-V Gen2**: Zertifikat-Deployment aktuell teilweise nicht moeglich (Firmware-Limitation), Skript erkennt dies korrekt als Warnung
- **VM-Erkennung**: Basiert auf `Win32_ComputerSystem.Model` (Virtual, VMware, KVM, Xen, HVM, BHYVE)
- **Windows Server 2025**: Bereits mit 2023-Zertifikaten ausgeliefert (Neuinstallation)
- **Zabbix Agent Rechte**: Falls nicht als LocalSystem, braucht der Service-Account Admin-Rechte

---

## Lizenz

MIT License - siehe [LICENSE](LICENSE)

## Mitwirken

Issues und Pull Requests sind willkommen. Bitte beim Testen den Hersteller und das Modell des Servers angeben, damit die Kompatibilitaetsliste erweitert werden kann.
