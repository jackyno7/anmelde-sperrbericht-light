<#
.SYNOPSIS
    LIGHT VERSION (5 of 18 checks, free). Logon and lockout report: evaluates account lockouts and failed logons from the Security log
    of domain controllers and generates an HTML report.

    Deutsch:
    LIGHT-VERSION (5 von 18 Prüfpunkten, kostenlos). Anmelde- und Sperrbericht: wertet Kontosperrungen und fehlgeschlagene Anmeldungen aus dem Sicherheitsprotokoll
    der Domänencontroller aus und erzeugt einen HTML-Bericht.

.DESCRIPTION
    The script operates exclusively in READ-ONLY mode. It changes nothing in Active Directory and nothing on the servers,
    does not unlock accounts, does not delete logs, and does not transfer data. It writes exactly one HTML file
    (and, if requested, CSV files) to the specified output folder.

    Prerequisites: Windows PowerShell 5.1, the "ActiveDirectory" module, and an account that can read the Security log
    of domain controllers (Administrator; start PowerShell "Run as administrator"). The script runs fastest
    directly on a domain controller. It reads other domain controllers via Event Log remote management
    or, if the firewall does not allow this, via WMI (slower).

    The report evaluates personal logon data. Before deployment, clarify whether and to what extent this is permitted in your organization.

    Deutsch:
    Das Skript arbeitet ausschließlich LESEND. Es ändert nichts im Active Directory und nichts an den Servern,
    entsperrt keine Konten, löscht keine Protokolle und überträgt keine Daten. Es schreibt genau eine HTML-Datei
    (und auf Wunsch CSV-Dateien) in den angegebenen Ausgabeordner.

    Voraussetzungen: Windows PowerShell 5.1, das Modul "ActiveDirectory" und ein Konto, das das Sicherheitsprotokoll
    der Domänencontroller lesen darf (Administrator; PowerShell "Als Administrator" starten). Am schnellsten läuft
    das Skript direkt auf einem Domänencontroller. Andere Domänencontroller liest es über die Ereignisprotokoll-
    Fernverwaltung oder, wenn die Firewall das nicht zulässt, über WMI (langsamer).

    Der Bericht wertet Anmeldedaten von Personen aus. Vor dem Einsatz klären, ob und in welchem Umfang das im
    eigenen Unternehmen zulässig ist.

.PARAMETER Ausgabe
    Path of the HTML file. Default: Anmelde-Sperrbericht_<Domäne>_<Datum>.html in the current folder.

    Deutsch:
    Pfad der HTML-Datei. Standard: Anmelde-Sperrbericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER Stunden
    Evaluation period in hours, backwards from now (default 24).

    Deutsch:
    Auswertungszeitraum in Stunden, rückwärts ab jetzt (Standard 24).

.PARAMETER FehlSchwelle
    Report accounts after so many "incorrect password" events (default 20).

    Deutsch:
    Konten ab so vielen Ereignissen "falsches Kennwort" melden (Standard 20).

.PARAMETER SprayKonten
    Report sources that generated failed attempts for at least so many different accounts (default 10).

    Deutsch:
    Quellen melden, von denen Fehlversuche für mindestens so viele verschiedene Konten kamen (Standard 10).

.PARAMETER WiederholtAb
    Report accounts that were locked out at least so many times in the period (default 3).

    Deutsch:
    Konten melden, die im Zeitraum mindestens so oft gesperrt wurden (Standard 3).

.PARAMETER MaxEreignisse
    Upper limit of events read per domain controller and query (default 50000).

    Deutsch:
    Obergrenze der gelesenen Ereignisse je Domänencontroller und Abfrage (Standard 50000).

.PARAMETER DomaenenController
    Evaluate only these domain controllers (default: all).

    Deutsch:
    Nur diese Domänencontroller auswerten (Standard: alle).

.PARAMETER Server
    Specific domain controller or domain for directory queries (optional).

    Deutsch:
    Bestimmter Domänencontroller oder Domäne für die Verzeichnisabfragen (optional).

.PARAMETER Anmeldung
    Credentials for an administrator account (Get-Credential), if the script is not running under such an account.

    Deutsch:
    Anmeldedaten eines Administratorkontos (Get-Credential), falls das Skript nicht unter einem solchen läuft.

.PARAMETER Csv
    Writes all failed attempts, all lockouts, and a CSV file alongside the report for each checkpoint with hits.

    Deutsch:
    Schreibt alle Fehlversuche, alle Sperrungen und je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Does not automatically open the completed report in a browser.

    Deutsch:
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Additionally returns the findings as objects (for custom analysis).

    Deutsch:
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.PARAMETER Language
    Language of the report and the console output: 'de' (German) or 'en' (English). Default: German if the Windows display language
    is German, otherwise English.

    Deutsch:
    Sprache von Bericht und Konsolenausgabe: 'de' (Deutsch) oder 'en' (Englisch). Standard: Deutsch, wenn die Anzeigesprache von
    Windows Deutsch ist, sonst Englisch.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Anmelde-Sperrbericht.ps1

.EXAMPLE
    .\Anmelde-Sperrbericht.ps1 -Stunden 72 -Csv -Ausgabe C:\Berichte\anmeldungen.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Protokollüberwachung (SIEM) oder Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('de', 'en')][string]$Language = $(if ((Get-UICulture).TwoLetterISOLanguageName -eq 'de') { 'de' } else { 'en' }),
    [Alias('Output')][string]$Ausgabe,
    [ValidateRange(1, 720)][int]$Stunden = 24,
    [ValidateRange(1, 100000)][int]$FehlSchwelle = 20,
    [ValidateRange(2, 100000)][int]$SprayKonten = 10,
    [ValidateRange(2, 1000)][int]$WiederholtAb = 3,
    [ValidateRange(100, 5000000)][int]$MaxEreignisse = 50000,
    [string[]]$DomaenenController,
    [string]$Server,
    [Alias('Credential')][System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [Alias('NoOpen')][switch]$NichtOeffnen,
    [switch]$PassThru
)
# Sprache des Berichts: de oder en (Parameter -Language). T 'deutsch' 'english' liefert den Text der gewählten Sprache.
$En = ($Language -eq 'en')
function T([string]$de, [string]$en) { if ($script:En) { $en } else { $de } }

$ErrorActionPreference = 'Stop'
$Version = '1.1'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host (T 'Das PowerShell-Modul "ActiveDirectory" fehlt.' 'The PowerShell module "ActiveDirectory" is missing.') -ForegroundColor Red
    Write-Host (T 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.' 'Windows 10/11: Settings > Optional features > add "RSAT: Active Directory Domain Services".')
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

#@SPRACHE@
# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = $null) { if ($null -eq $leer) { $leer = T 'nie' 'never' }; if ($d) { ([datetime]$d).ToString((T 'dd.MM.yyyy' 'yyyy-MM-dd')) } else { $leer } }
function JaNein($b) { if ($b) { T 'Ja' 'Yes' } else { T 'Nein' 'No' } }
function Ort($dn) { ($dn -replace '^(CN|OU)=.+?(?<!\\),', '') -replace ',DC=.*$', '' }
function Html($t) { [System.Net.WebUtility]::HtmlEncode([string]$t) }
function Kurz($t, $n = 220) { $t = ([string]$t -replace '\s+', ' ').Trim(); if ($t.Length -gt $n) { $t.Substring(0, $n) + ' ...' } else { $t } }

# CSV-Dateien öffnen sich in Excel: Werte, die mit = + - @ beginnen, würden dort als Formel ausgeführt (Namen von Dateien, Ordnern, Konten oder Computern
# stammen von Benutzern). Diese Funktion ersetzt für dieses Skript den Befehl Export-Csv und setzt vor solche Werte ein Hochkomma.
function Export-Csv {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$InputObject, [Parameter(Mandatory)][string]$Path, [switch]$NoTypeInformation, [string]$Delimiter = ';', [string]$Encoding = 'UTF8')
    begin { $alle = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $alle.Add($InputObject) } }
    end {
        $sicher = foreach ($o in $alle) {
            $n = [ordered]@{}
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if (($v -is [string]) -and ($v -match '^[=+@\t\r]|^-.')) { $v = "'" + $v }; $n[$p.Name] = $v }
            [pscustomobject]$n
        }
        if ($alle.Count) { $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding }   # leere Liste: keine Datei (sie hätte keine Kopfzeile)
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -ge 2) {
        $namen = New-Object System.Collections.Generic.List[string]
        foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
        if ($namen.Count -ne @($liste[0].PSObject.Properties.Name).Count) { $liste = @($liste | Select-Object -Property $namen) }
    }
    SpaltenAnzeige $liste
}
# Englische Berichte: Spaltenüberschriften aus der Übersetzungstabelle (intern bleiben die deutschen Namen, der Code liest sie weiter)
$SpaltenEn = @{
    'Abfrage' = 'Query'
    'Administrator' = 'Administrator'
    'Adresse' = 'Address'
    'Aktiv' = 'Active'
    'Aktiv verknüpft mit' = 'Active linked to'
    'Aktive Verknüpfungen' = 'Active links'
    'Alter in Tagen' = 'Age in days'
    'Angelegt' = 'Created'
    'Anmeldung' = 'Last logon'
    'Anmeldungen' = 'Logons'
    'Anteil (%)' = 'Share (%)'
    'Anzahl' = 'Count'
    'Art' = 'Account type'
    'Auf Domänencontroller' = 'On domain controller'
    'Aufräumen' = 'Cleanup'
    'Auslastung' = 'Utilization'
    'Auslösender Rechner' = 'Triggering computer'
    'Auslösender Rechner (Anzahl)' = 'Triggering computers (count)'
    'Aussteller' = 'Issuer'
    'Beispiele' = 'Examples'
    'Belegt' = 'Used'
    'Belegt (%)' = 'Used (%)'
    'Benutzer und Computer (auch verschachtelt)' = 'Users and computers (also nested)'
    'Benutzereinstellungen' = 'User settings'
    'Benutzername' = 'Username'
    'Berechtigter' = 'Principal'
    'Bereich' = 'Scope'
    'Bereiche' = 'Scopes'
    'Beschreibung' = 'Description'
    'Besitzer' = 'Owner'
    'Betriebssystem' = 'OS'
    'Betroffene Konten' = 'Affected accounts'
    'Bewertung' = 'Rating'
    'Bis' = 'To'
    'BitLocker' = 'BitLocker'
    'Computer' = 'Computer'
    'Computereinstellungen' = 'Computer settings'
    'Darf anwenden' = 'Can apply'
    'Darf delegieren an' = 'Can delegate to'
    'Darf sich hier als Benutzer ausgeben' = 'Can log on as user'
    'Datei' = 'File'
    'Dateien' = 'Files'
    'Dateisystem' = 'File system'
    'Dateityp' = 'File type'
    'Datenbank' = 'Database'
    'Detail' = 'Detail'
    'Details' = 'Details'
    'Direkte Mitglieder' = 'Direct members'
    'Domäne' = 'Domain'
    'Domänencontroller' = 'Domain controller'
    'Domänennamenmaster' = 'Domain naming master'
    'Dynamische Updates' = 'Dynamic updates'
    'E-Mail' = 'Email'
    'Eigenschaft' = 'Property'
    'Einstellung' = 'Setting'
    'Empfohlen' = 'Recommended'
    'Enthaltene Gruppen' = 'Included groups'
    'Ereignisse' = 'Events'
    'Erreichbar' = 'Reachable'
    'Erste' = 'First'
    'Erster' = 'First'
    'Erzwungen' = 'Forced'
    'Failover' = 'Failover'
    'Falsches Kennwort' = 'Wrong password'
    'Fehlanmeldungen am DC' = 'Failed logons at DC'
    'Fehlversuche' = 'Failed attempts'
    'Feststellung' = 'Finding'
    'Fingerabdruck' = 'Fingerprint'
    'Firewall' = 'Firewall'
    'Frei' = 'Free'
    'Freigabe' = 'Share'
    'Freigaberecht' = 'Share permission'
    'Funktion' = 'Function'
    'Gelesen von' = 'Read by'
    'Geprüft' = 'Checked'
    'Gesamtgröße' = 'Total size'
    'Geschützte Benutzer' = 'Protected users'
    'Gesperrt seit' = 'Locked since'
    'Geändert' = 'Changed'
    'Gilt' = 'Applies to'
    'Gilt für' = 'Applies to'
    'Globaler Katalog' = 'Global catalog'
    'Grenze' = 'Limit'
    'Groesse' = 'Size'
    'Grund' = 'Reason'
    'Gruppe' = 'Group'
    'Gruppen' = 'Groups'
    'Gruppen (auch verschachtelt)' = 'Groups (including nested)'
    'Gruppenrichtlinie' = 'Group policy'
    'Größe' = 'Size'
    'Größe (GB)' = 'Size (GB)'
    'Gültig ab' = 'Valid from'
    'Gültig bis' = 'Valid to'
    'Herkunft' = 'Origin'
    'Hersteller' = 'Vendor'
    'Hinweis' = 'Note'
    'Häufigster Grund' = 'Most common reason'
    'IP-Adresse' = 'IP address'
    'Im AD gespeichert' = 'Stored in AD'
    'In der Domäne vorhanden' = 'Present in domain'
    'Infrastrukturmaster' = 'Infrastructure master'
    'Inhalt' = 'Content'
    'Ist' = 'Is'
    'Kennung' = 'ID'
    'Kennwort gesetzt' = 'Password set'
    'Kennwort läuft nie ab' = 'Password never expires'
    'Kerberos' = 'Kerberos'
    'Konten' = 'Accounts'
    'Konten (auch verschachtelt)' = 'Accounts (also nested)'
    'Konto' = 'Account'
    'Konto für DNS-Einträge' = 'Account for DNS entries'
    'Kopie bleibt im Postfach' = 'Copy remains in mailbox'
    'LAPS' = 'LAPS'
    'LAPS-Ablauf' = 'LAPS expiry'
    'Laufwerk' = 'Drive'
    'Lease-Dauer' = 'Lease duration'
    'Leitet weiter an' = 'Forwards to'
    'Leseweg' = 'Read path'
    'Letzte Aktualisierung' = 'Last update'
    'Letzte Anmeldung' = 'Last logon'
    'Letzte Vollsicherung' = 'Last full backup'
    'Letzte inkrementelle Sicherung' = 'Last incremental backup'
    'Letzter' = 'Last'
    'Letzter Aufräumlauf' = 'Last cleanup run'
    'Letzter Start' = 'Last start'
    'Lokale Admins' = 'Local admins'
    'Mindestlänge' = 'Minimum length'
    'Mitglied' = 'Member'
    'Mitglieder' = 'Members'
    'NLA' = 'NLA'
    'NTLM' = 'NTLM'
    'Name' = 'Name'
    'Nr.' = 'No.'
    'Objekt' = 'Object'
    'Ordner' = 'Folder'
    'Organisationseinheit' = 'OU'
    'Ort' = 'Location'
    'PDC-Emulator' = 'PDC emulator'
    'Pfad' = 'Path'
    'Postfach' = 'Mailbox'
    'Postfach-Typ' = 'Mailbox type'
    'Postfachtyp' = 'Mailbox type'
    'Postfächer' = 'Mailboxes'
    'Privilegierte Gruppen' = 'Privileged groups'
    'Programm' = 'Program'
    'Prüfpunkt' = 'Checkpoint'
    'Quelle' = 'Source'
    'Quelle (Anzahl)' = 'Sources (count)'
    'RID-Master' = 'RID master'
    'Recht' = 'Permission'
    'Rechte' = 'Permissions'
    'Regel' = 'Rule'
    'Reihenfolge' = 'Order'
    'SPN' = 'SPN'
    'Schemamaster' = 'Schema master'
    'Schlüssel' = 'Key'
    'Schreibgeschützt' = 'Read-only'
    'Sendesperre ab' = 'Send blocked from'
    'Server' = 'Server'
    'Sid' = 'SID'
    'Signatur' = 'Signature'
    'Speicher' = 'Storage'
    'Sperrungen' = 'Lockouts'
    'Stand' = 'Status'
    'Standort' = 'Site'
    'Status' = 'Status'
    'Support-Ende' = 'End of support'
    'Support-Ende (spätestes)' = 'End of support (latest)'
    'Tage bis Ablauf' = 'Days until expiry'
    'Tage her' = 'Days ago'
    'Tage ohne Anmeldung' = 'Days without logon'
    'Tage seit Ablauf' = 'Days since expiry'
    'Treffer' = 'Hits'
    'Typ' = 'Type'
    'Vererbung' = 'Inheritance'
    'Verschiedene Konten' = 'Distinct accounts'
    'Verschlüsselt' = 'Encrypted'
    'Version' = 'Version'
    'Version C/B' = 'Version C/B'
    'Verweigert für' = 'Denied for'
    'Verwendung' = 'Use'
    'Virenschutz' = 'Antivirus'
    'Von' = 'From'
    'WMI-Filter' = 'WMI filter'
    'Weg' = 'Path'
    'Weiterleitungen' = 'Forwarding'
    'Wert' = 'Value'
    'Wirksame Richtlinie' = 'Effective policy'
    'Wirksames Recht' = 'Effective permission'
    'Wirkung' = 'Effect'
    'Zeit' = 'Time'
    'Zeitpunkt' = 'Time'
    'Zeitraum' = 'Period'
    'Zertifikat' = 'Certificate'
    'Zone' = 'Zone'
    'Zonen' = 'Zones'
    'Zonenübertragung' = 'Zone transfer'
    'Zugriff für große Gruppen' = 'Access for large groups'
    'Zugriffsbasierte Aufzählung' = 'Access-based enumeration'
    'Zuletzt' = 'Last'
    'Zustand' = 'State'
    'davon Größe (GB)' = 'Of which size (GB)'
    'davon aktiv' = 'Of which active'
    'davon inaktiv' = 'Of which inactive'
    'davon unbekannte Konten' = 'Of which unknown accounts'
    'ist Mitglied von' = 'Member of'
    'Älter als 5 Jahre' = 'Older than 5 years'
    'Älter als 5 Jahren' = 'Older than 5 years'
    'Ältester Eintrag' = 'Oldest entry'
    'Über' = 'Via'
    'Überwachungsprotokoll' = 'Audit log'
}
# Werte, die der Code intern auf Deutsch vergleicht (z. B. Art = 'Benutzer'), erscheinen im englischen Bericht übersetzt (nur Anzeige und CSV)
$WerteEn = New-Object System.Collections.Specialized.OrderedDictionary([System.StringComparer]::Ordinal)   # Groß-/Kleinschreibung zählt (Verwaist / verwaist)
$WerteEn.Add('Alle erweiterten Rechte (u. a. Kennwort zurücksetzen)', 'All extended rights (including password reset)')
$WerteEn.Add('Kein Serverbetriebssystem (Support nicht bewertet)', 'No server operating system (support not assessed)')
$WerteEn.Add('Rechte je Ordner (nur dort, wo sie gesetzt werden)', 'Permissions per folder (only where set)')
$WerteEn.Add('Mehrfach freigegebene Ordner (nur einmal gezählt)', 'Folders shared multiple times (counted only once)')
$WerteEn.Add('Übersprungene Verknüpfungen (Junctions/Symlinks)', 'Skipped links (Junctions/Symlinks)')
$WerteEn.Add('Der Ordner der Freigabe existiert nicht mehr.', 'The share folder no longer exists.')
$WerteEn.Add('DHCP-Überwachungsprotokoll ist ausgeschaltet', 'DHCP audit log is disabled')
$WerteEn.Add('Vollzugriff und "Senden als" im Überblick', 'Full access and "Send as" overview')
$WerteEn.Add('Ordner der Freigabe existiert nicht mehr', 'Share folder no longer exists')
$WerteEn.Add('Enthält außer Sicherheitseinstellungen:', 'Contains except security settings:')
$WerteEn.Add('Nicht geprüft - Postfach nicht gefunden', 'Not checked - mailbox not found')
$WerteEn.Add('WMI-Filter nicht lesbar - nicht geprüft', 'WMI filter not readable - not checked')
$WerteEn.Add('Abfrage fehlgeschlagen - nicht geprüft', 'Query failed - not checked')
$WerteEn.Add('Nicht im Active Directory gespeichert', 'Not stored in Active Directory')
$WerteEn.Add('keine im Active Directory autorisiert', 'None authorized in Active Directory')
$WerteEn.Add('Zugriff auf den Ordner nicht möglich', 'Access to folder not possible')
$WerteEn.Add('Zertifikate (öffentliche Schlüssel)', 'Certificates (public keys)')
$WerteEn.Add('Domänencontroller der Organisation', 'Organization domain controllers')
$WerteEn.Add('Remotedesktop erlaubt Verbindungen', 'Remote Desktop allows connections')
$WerteEn.Add('autorisierte DHCP-Server ermitteln', 'Determine authorized DHCP servers')
$WerteEn.Add('Windows Server 2008 R2 und älter', 'Windows Server 2008 R2 and older')
$WerteEn.Add('Konto deaktiviert oder gesperrt', 'Account disabled or locked')
$WerteEn.Add('Vollzugriff (Zusatz: ObjectType', 'Full access (additional: ObjectType')
$WerteEn.Add('Kennwort oder Konto abgelaufen', 'Password or account expired')
$WerteEn.Add('Lokale Administratorengruppen', 'Local administrator groups')
$WerteEn.Add('Berechtigungen/Besitz ändern', 'Change permissions/ownership')
$WerteEn.Add('Freigabepfade nicht sichtbar', 'Share paths not visible')
$WerteEn.Add('Aktive privilegierte Konten', 'Active privileged accounts')
$WerteEn.Add('Gruppe hat keine Mitglieder', 'Group has no members')
$WerteEn.Add('Keine Verbindung zum Server', 'No connection to server')
$WerteEn.Add('unerlaubte Zeichen im Namen', 'Illegal characters in name')
$WerteEn.Add('Geprüfte Domänencontroller', 'Checked domain controllers')
$WerteEn.Add('Authentifizierte Benutzer', 'Authenticated Users')
$WerteEn.Add('Schwellen dieses Berichts', 'Thresholds of this report')
$WerteEn.Add('Benutzer (inetOrgPerson)', 'User (inetOrgPerson)')
$WerteEn.Add('Datenbestand je Freigabe', 'Data inventory per share')
$WerteEn.Add('Kontosperrungsrichtlinie', 'Account lockout policy')
$WerteEn.Add('Sicherheitseinstellungen', 'Security settings')
$WerteEn.Add('Alle erweiterten Rechte', 'All extended rights')
$WerteEn.Add('Hinweise zur Auswertung', 'Notes for evaluation')
$WerteEn.Add('Nicht abgefragte Server', 'Servers not queried')
$WerteEn.Add('Unterordner und Dateien', 'Subfolders and files')
$WerteEn.Add('Bestätigtes Schreiben:', 'Validated write:')
$WerteEn.Add('Installierte Programme', 'Installed programs')
$WerteEn.Add('Konto für DNS-Einträge', 'Account for DNS records')
$WerteEn.Add('Kontosperrungsschwelle', 'Account lockout threshold')
$WerteEn.Add('Nicht lesbare Bereiche', 'Unreadable areas')
$WerteEn.Add('Berechtigungen ändern', 'Change permissions')
$WerteEn.Add('Hinweise zum Auslesen', 'Notes for reading')
$WerteEn.Add('Windows 8.1 und älter', 'Windows 8.1 and older')
$WerteEn.Add('Überwachungsprotokoll', 'Audit log')
$WerteEn.Add('Nicht berücksichtigt', 'Not considered')
$WerteEn.Add('Anonymous-Anmeldung', 'Anonymous logon')
$WerteEn.Add('Infrastrukturmaster', 'Infrastructure master')
$WerteEn.Add('Secure Boot ist aus', 'Secure Boot is off')
$WerteEn.Add('Domänennamenmaster', 'Domain naming master')
$WerteEn.Add('Kennwortrichtlinie', 'Password policy')
$WerteEn.Add('Komponentenwartung', 'Component servicing')
$WerteEn.Add('alle Eigenschaften', 'all properties')
$WerteEn.Add('Besitz übernehmen', 'Take ownership')
$WerteEn.Add('Domänencontroller', 'Domain Controllers')
$WerteEn.Add('Falsches Kennwort', 'Incorrect password')
$WerteEn.Add('Konten-Operatoren', 'Account Operators')
$WerteEn.Add('Nur dieser Ordner', 'Only this folder')
$WerteEn.Add('Domänen-Benutzer', 'Domain Users')
$WerteEn.Add('Format unbekannt', 'Format unknown')
$WerteEn.Add('Sonstige Dateien', 'Other files')
$WerteEn.Add('Ältester Eintrag', 'Oldest entry')
$WerteEn.Add('Domänencomputer', 'Domain Computers')
$WerteEn.Add('Konto unbekannt', 'Account unknown')
$WerteEn.Add('Standard (alle)', 'Default (all)')
$WerteEn.Add('Computerkonten', 'Computer accounts')
$WerteEn.Add('Konto gesperrt', 'Account locked')
$WerteEn.Add('Nicht erreicht', 'Not reached')
$WerteEn.Add('DHCP-Bereiche', 'DHCP scopes')
$WerteEn.Add('Dieser Ordner', 'This folder')
$WerteEn.Add('Gruppe/System', 'Group/system')
$WerteEn.Add('Remotedesktop', 'Remote Desktop')
$WerteEn.Add('Arbeitsplatz', 'Workstation')
$WerteEn.Add('Schemamaster', 'Schema master')
$WerteEn.Add('DHCP-Server', 'DHCP server')
$WerteEn.Add('Datenbanken', 'Databases')
$WerteEn.Add('Sonderkonto', 'Special account')
$WerteEn.Add('Unterordner', 'Subfolders')
$WerteEn.Add('Vollzugriff', 'Full control')
$WerteEn.Add('Zugriff von', 'Access from')
$WerteEn.Add('DNS-Server', 'DNS server')
$WerteEn.Add('Inaktiv ab', 'Inactive from')
$WerteEn.Add('Schreiben:', 'Write:')
$WerteEn.Add('Verweigern', 'Deny')
$WerteEn.Add('DNS-Zonen', 'DNS zones')
$WerteEn.Add('Schreiben', 'Write')
$WerteEn.Add('Sonstiges', 'Other')
$WerteEn.Add('Standorte', 'Sites')
$WerteEn.Add('Unbekannt', 'Unknown')
$WerteEn.Add('unbekannt', 'unknown')
$WerteEn.Add('(Wurzel)', '(root)')
$WerteEn.Add('Anlegen:', 'Create:')
$WerteEn.Add('Benutzer', 'User')
$WerteEn.Add('Erlauben', 'Allow')
$WerteEn.Add('Netzwerk', 'Network')
$WerteEn.Add('Verwaist', 'Orphaned')
$WerteEn.Add('verwaist', 'orphaned')
$WerteEn.Add('Dateien', 'Files')
$WerteEn.Add('Gruppen', 'Groups')
$WerteEn.Add('Anonym', 'Anonymous')
$WerteEn.Add('Domäne', 'Domain')
$WerteEn.Add('Gruppe', 'Group')
$WerteEn.Add('Umfang', 'Scope')
$WerteEn.Add('direkt', 'direct')
$WerteEn.Add('Ändern', 'Change')
$WerteEn.Add('Lesen', 'Read')
$WerteEn.Add('über', 'via')
$WerteMuster = @()
foreach ($k in ($WerteEn.Keys | Sort-Object Length -Descending)) { $WerteMuster += , @([regex]::new('(?<![\p{L}\d])' + [regex]::Escape($k) + '(?![\p{L}\d])'), $WerteEn[$k]) }
function WertAnzeige($v) {
    if (-not $script:En -or $v -isnot [string] -or -not $v) { return $v }
    if ($v.Contains('\')) { return $v }   # Kontonamen (DOMÄNE\Name) und Pfade bleiben, wie sie sind
    foreach ($m in $WerteMuster) { $v = $m[0].Replace($v, $m[1]) }
    $v
}
function SpaltenAnzeige($liste) {
    if (-not $script:En -or -not @($liste).Count) { return $liste }
    foreach ($o in @($liste)) {
        $n = [ordered]@{}
        foreach ($p in $o.PSObject.Properties) { $k = $p.Name; if ($SpaltenEn.ContainsKey($k)) { $k = $SpaltenEn[$k] }; $i = 2; $k0 = $k; while ($n.Contains($k)) { $k = "$k0 $i"; $i++ }; $n[$k] = WertAnzeige $p.Value }
        [pscustomobject]$n
    }
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
# Deutsch und Englisch: Skripte erzeugen den Text je nach -Language, erkannt werden beide Fassungen
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft',
    'Query failed - not checked', 'Permissions not readable - not checked', 'SYSVOL not readable - not checked', 'WMI filter not readable - not checked', 'No domain controller found - SYSVOL not checked', 'Folder content not readable - policy not checked')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *') -or ("$($o.Feststellung)" -clike 'Not checked - *')
}

# Besteht ein Prüfpunkt nur aus Platzhalterzeilen (Abfrage fehlgeschlagen), ist das kein Mangel dieses Prüfpunkts: als Info führen statt
# mit seiner Stufe, damit es in den Kacheln nicht als hoher Befund zählt. Nur für Prüfpunkte, deren Ergebnis von einer Abfrage abhängt.
function InfoWennNurNichtGeprueft([string]$IdMuster) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster -and $_.Anzahl -gt 0 -and $_.Stufe -ne 'Info' })) {
        if (-not @($x.Objekte | Where-Object { -not (IstPlatzhalter $_) }).Count) { $x.Stufe = 'Info' }
    }
}

# Prüfpunkte, die für einzelne Server nicht ausgewertet werden konnten (Abfrage fehlgeschlagen), dürfen nicht als "ohne Befund" erscheinen:
# je Server eine Zeile "nicht geprüft" anhängen; hatte der Prüfpunkt sonst keinen Treffer, steht er als Info statt als OK.
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = $(T 'Abfrage nicht möglich' 'query not possible')) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = (T "Nicht geprüft - $Grund (siehe $Verweis)" "Not checked - $Grund (see $Verweis)"); Details = '' } })
        $x.Objekte = @($x.Objekte) + $zeilen
        $x.Anzahl = $x.Objekte.Count
        if (-not $war) { $x.Stufe = 'Info' }
    }
}
function Befund {
    param([string]$Id, [string]$Bereich, [string]$Titel, [ValidateSet('Hoch', 'Mittel', 'Niedrig', 'Info')][string]$Stufe,
        $Objekte, [string]$Erklaerung, [string]$Empfehlung)
    $liste = @($Objekte | Where-Object { $null -ne $_ })
    $status = $Stufe
    if ($liste.Count -eq 0) { $status = 'OK' }
    $Befunde.Add([pscustomobject]@{
            Id = $Id; Bereich = $Bereich; Titel = $Titel; Stufe = $status; Anzahl = $liste.Count
            Objekte = $liste; Erklaerung = $Erklaerung; Empfehlung = $Empfehlung
        })
}

# Schreibt den HTML-Bericht (und auf Wunsch CSV-Dateien). $Abschnitte: Überschrift -> Objekte oder fertiges HTML,
# erscheinen vor den Befunden. $Anhang: Überschrift -> Text, erscheint am Ende unverändert.
function BerichtSchreiben {
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = $(T 'Domäne' 'Domain'), [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host (T '  Bericht schreiben ...' '  Writing report ...')
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, ($Bezug -replace '[^\w.\-]+', '-'), $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

    $stufeText = @{ Hoch = (T 'Hoch' 'High'); Mittel = (T 'Mittel' 'Medium'); Niedrig = (T 'Niedrig' 'Low'); Info = 'Info'; OK = 'OK' }
    $rang = @{ Hoch = 0; Mittel = 1; Niedrig = 2; Info = 3; OK = 4 }
    $zahl = @{}
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') { $zahl[$s] = @($Befunde | Where-Object Stufe -eq $s).Count }
    $css = @'
body{font-family:Segoe UI,Arial,sans-serif;color:#2b2f36;margin:0;background:#f4f6fa}
.seite{max-width:1100px;margin:0 auto;padding:28px 24px 60px}
h1{color:#1f5fae;margin:0 0 4px;font-size:28px} h2{color:#1f5fae;font-size:19px;margin:34px 0 10px;border-bottom:2px solid #d0d5dd;padding-bottom:6px}
.meta{color:#6b7280;font-size:13px;margin-bottom:22px}
.kacheln{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}
.kachel{flex:1;min-width:150px;background:#fff;border-radius:10px;padding:14px 18px;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.kachel b{display:block;font-size:30px} .kachel span{font-size:13px;color:#6b7280}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;margin:8px 0 4px}
th{background:#1f5fae;color:#fff;text-align:left;padding:7px 9px;font-weight:600} td{padding:6px 9px;border-bottom:1px solid #e5e7eb;vertical-align:top;overflow-wrap:break-word}
tr:nth-child(even) td{background:#f9fafb}
.marke{display:inline-block;min-width:58px;text-align:center;padding:2px 9px;border-radius:11px;color:#fff;font-size:12px;font-weight:600}
.m-Hoch{background:#d92d20}.m-Mittel{background:#f79009}.m-Niedrig{background:#ca8a04}.m-OK{background:#12b76a}.m-Info{background:#1f5fae}
.befund{background:#fff;border-radius:10px;padding:16px 20px;margin:14px 0;border-left:8px solid #999;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.befund h3{margin:0 0 6px;font-size:16px} .befund p{margin:5px 0;font-size:14px;line-height:1.45} .befund .emp{color:#14532d}
.Hoch{border-color:#d92d20}.Mittel{border-color:#f79009}.Niedrig{border-color:#eab308}.OK{border-color:#12b76a}.Info{border-color:#1f5fae}
.klein{color:#6b7280;font-size:12px} a{color:#1f5fae;text-decoration:none}
pre{background:#fff;border:1px solid #d0d5dd;border-radius:8px;padding:12px 14px;font-size:12px;white-space:pre-wrap;word-break:break-word}
.fuss{margin-top:40px;color:#6b7280;font-size:12px;border-top:1px solid #d0d5dd;padding-top:12px}
@media print{body{background:#fff}.befund,.kachel{box-shadow:none;border:1px solid #d0d5dd;border-left-width:8px;break-inside:avoid}}
'@
    $h = New-Object System.Text.StringBuilder
    [void]$h.Append("<!DOCTYPE html><html lang='$Language'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · $(T 'erstellt am' 'created') $($jetzt.ToString((T 'dd.MM.yyyy HH:mm' 'yyyy-MM-dd HH:mm'))) $(T 'von' 'by') $(Html "$env:USERDOMAIN\$env:USERNAME") $(T 'auf' 'on') $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = (T 'Befunde mit hoher Priorität' 'findings, high priority'); Mittel = (T 'mit mittlerer Priorität' 'medium priority'); Niedrig = (T 'mit niedriger Priorität' 'low priority'); Info = (T 'Hinweise und nicht geprüft' 'notes and not checked'); OK = (T 'Prüfpunkte ohne Befund' 'checks without findings') }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>$(T 'Umgebung' 'Environment')</h2><table><tr><th>$(T 'Eigenschaft' 'Property')</th><th>$(T 'Wert' 'Value')</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html (WertAnzeige $k))</td><td>$(Html (WertAnzeige $Umgebung[$k]))</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>$(T 'Übersicht der Prüfpunkte' 'Overview of checks')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Bereich' 'Area')</th><th>$(T 'Prüfpunkt' 'Check')</th><th>$(T 'Treffer' 'Hits')</th><th>$(T 'Bewertung' 'Rating')</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html (WertAnzeige $k))</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>$(T 'Keine Einträge.' 'No entries.')</p>") }
    }

    [void]$h.Append("<h2>$(T 'Befunde' 'Findings')</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($stufeText[$x.Stufe])</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) $(T 'Treffer' 'hits'))</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>$(T 'Empfehlung' 'Recommendation'):</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>$(T 'Keine Auffälligkeiten gefunden.' 'No anomalies found.')</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>$(T 'Ohne Befund' 'No findings')</h2><table><tr><th>$(T 'Nr.' 'No.')</th><th>$(T 'Prüfpunkt' 'Check')</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · $(T 'Das Skript hat ausschließlich gelesen und nichts verändert.' 'The script only read and changed nothing.') $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ((T "Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." "Done: {0} high, {1} medium, {2} low, {3} without findings.") -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host ((T 'Bericht' 'Report') + ": $ziel")
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

function Zeit($d) { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy HH:mm') } else { '' } }
function Konto($n) { (("$n" -replace '^.*\\', '') -replace '@.*$', '').Trim().ToLower() }
function Quelle($q, $dcName) {
    $q = ("$q" -replace '^::ffff:', '').Trim().TrimStart('\')
    if ($q -in '', '-') { 'unbekannt' } elseif ($q -in '::1', '127.0.0.1') { (T "$dcName (lokal)" "$dcName (local)") } else { $q.ToUpper() }
}
# Bedeutung der Fehlercodes (Kerberos und NTLM) in fünf Gruppen
function Grund($code) {
    switch -Regex ("$code".ToLower()) {
        '^0x18$|c000006a' { 'Falsches Kennwort'; break }
        '^0x6$|c0000064' { 'Konto unbekannt'; break }
        'c0000234' { 'Konto gesperrt'; break }
        '^0x12$|c0000072' { 'Konto deaktiviert oder gesperrt'; break }
        '^0x17$|c0000071|c0000193|c0000224' { 'Kennwort oder Konto abgelaufen'; break }
        '^0x25$' { (T 'Uhrzeit weicht ab' 'Time differs'); break }
        'c000006f|c0000070' { (T 'Anmeldezeit oder Arbeitsstation nicht erlaubt' 'Logon time or workstation not allowed'); break }
        'c000015b' { (T 'Anmeldeart für dieses Konto nicht erlaubt' 'Logon type not allowed for this account'); break }
        default { (T "Sonstiges ($code)" "Other ($code)") }
    }
}
$anmeldeTyp = @{ '2' = (T 'Konsole' 'Console'); '3' = (T 'Netzwerk' 'Network'); '4' = (T 'Stapel' 'Batch'); '5' = (T 'Dienst' 'Service'); '7' = (T 'Entsperren' 'Unlock'); '8' = (T 'Netzwerk (Klartext)' 'Network (cleartext)'); '9' = (T 'Neue Anmeldedaten' 'New credentials'); '10' = (T 'Remotedesktop' 'Remote Desktop'); '11' = (T 'Zwischengespeichert' 'Cached') }

# ------------------------------------------------------------------ Daten aus dem Verzeichnis
Write-Host (T 'Anmelde- und Sperrbericht - es wird nur gelesen, nichts verändert.' 'Logon and lockout report - read-only, nothing is changed.') -ForegroundColor Cyan
$dom = Get-ADDomain @ad
$dn = $dom.DistinguishedName
$jetzt = Get-Date
$ab = $jetzt.AddHours(-$Stunden)
$abDmtf = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($ab)

Write-Host (T '  Konten und Richtlinie ...' 'Accounts and policy ...')
$richtlinie = Get-ADDefaultDomainPasswordPolicy @ad
$admins = @{}
try {
    $adminDn = (Get-ADGroup -Identity 'S-1-5-32-544' @ad).DistinguishedName
    Get-ADUser -LDAPFilter "(memberOf:1.2.840.113556.1.4.1941:=$adminDn)" @ad | ForEach-Object { $admins[$_.SamAccountName.ToLower()] = $true }
} catch { }
$gesperrt = @(Get-ADUser -LDAPFilter '(lockoutTime>=1)' -Properties LockedOut, lockoutTime, LastLogonDate, Enabled @ad | Where-Object LockedOut | Sort-Object SamAccountName)
$bekannteKonten = @{}
Get-ADObject -LDAPFilter '(&(sAMAccountName=*)(|(objectClass=user)(objectClass=computer)))' -Properties sAMAccountName @ad | ForEach-Object { $bekannteKonten[$_.sAMAccountName.ToLower()] = $true }

$alleDcs = @(Get-ADDomainController -Filter * @ad | Sort-Object Name)
if ($DomaenenController) { $alleDcs = @($alleDcs | Where-Object { $_.Name -in $DomaenenController -or $_.HostName -in $DomaenenController }) }
if (-not $alleDcs.Count) { Write-Host (T 'Kein Domänencontroller gefunden (Parameter -DomaenenController prüfen).' 'No domain controller found (check the -DomaenenController parameter).') -ForegroundColor Red; exit 2 }

# ------------------------------------------------------------------ Sicherheitsprotokolle lesen
$fehlAudit = [long]4503599627370496     # Schlüsselwort "Überwachung gescheitert"
function Nutzlast($hex) {
    # Windows Server 2025 schreibt abgelehnte Ticketanforderungen (4768) teils in einem Format, das Windows selbst nicht
    # in Felder zerlegen kann. Die Rohdaten enthalten dieselben Angaben; hier werden Konto, Status und Adresse herausgelesen.
    $b = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring(2 * $i, 2), 16) }
    $pos = 0
    $text = { $start = $script:np; while ($script:np + 1 -lt $b.Length -and ($b[$script:np] -ne 0 -or $b[$script:np + 1] -ne 0)) { $script:np += 2 }
        $s = [System.Text.Encoding]::Unicode.GetString($b, $start, $script:np - $start); $script:np += 2; $s }
    $script:np = 0
    $konto = & $text; $bereich = & $text
    $script:np += 8 + 4 * $b[$script:np + 1]          # Benutzer-SID
    $dienst = & $text
    $script:np += 8 + 4 * $b[$script:np + 1]          # Dienst-SID
    $script:np += 4                                   # Ticketoptionen
    $status = '0x{0:x}' -f [BitConverter]::ToUInt32($b, $script:np); $script:np += 8      # Status, danach Verschlüsselungstyp
    $vorab = & $text; $adresse = & $text
    , @($konto, $bereich, '', $dienst, '', '', $status, '', $vorab, $adresse)
}
function Ereignisse($z, [int[]]$Ids, [switch]$NurFehler, [string]$XPath) {
    # Liefert Ereignisse als Objekte mit Id, Zeit und den Datenfeldern D in der Reihenfolge des Ereignisses
    if ($z.Weg -ne 'WMI') {
        $arg = @{ MaxEvents = $MaxEreignisse; ErrorAction = 'Stop' }
        if ($XPath) { $arg.LogName = 'Security'; $arg.FilterXPath = $XPath }
        else {
            $f = @{ LogName = 'Security'; Id = $Ids; StartTime = $ab }
            if ($NurFehler) { $f.Keywords = $fehlAudit }
            $arg.FilterHashtable = $f
        }
        if (-not $z.Lokal) { $arg.ComputerName = $z.Host; if ($Anmeldung) { $arg.Credential = $Anmeldung } }
        $roh = @()
        try { $roh = @(Get-WinEvent @arg) } catch { if ("$($_.FullyQualifiedErrorId)" -notlike 'NoMatchingEventsFound*') { throw } }
        foreach ($e in $roh) {
            $x = [xml]$e.ToXml()
            $felder = @()
            if ($x.Event.EventData) { $felder = @($x.Event.EventData.Data | ForEach-Object { if ($_ -is [string]) { $_ } else { "$($_.'#text')" } }) }
            elseif ($e.Id -eq 4768 -and $x.Event.ProcessingErrorData.EventPayload) { try { $felder = Nutzlast "$($x.Event.ProcessingErrorData.EventPayload)" } catch { } }
            [pscustomobject]@{ Id = [int]$e.Id; Zeit = $e.TimeCreated; D = $felder }
        }
    } else {
        $q = "Logfile='Security' AND (" + (($Ids | ForEach-Object { "EventCode=$_" }) -join ' OR ') + ") AND TimeGenerated>='$abDmtf'"
        if ($NurFehler) { $q += (T ' AND EventType=5' 'AND EventType=5') }
        Get-CimInstance -CimSession $z.Cim -ClassName Win32_NTLogEvent -Filter $q -OperationTimeoutSec 900 -ErrorAction Stop | Select-Object -First $MaxEreignisse |
            ForEach-Object { [pscustomobject]@{ Id = [int]$_.EventCode; Zeit = $_.TimeGenerated; D = @($_.InsertionStrings | ForEach-Object { "$_" }) } }
    }
}

$p1 = @(); $p3 = @(); $p4 = @(); $a1 = @(); $a1Fehler = @()
$mindestFelder = @{ 4771 = 7; 4768 = 10; 4776 = 4; 4625 = 20 }
$fehl = New-Object System.Collections.Generic.List[object]       # Fehlversuche (Kerberos, NTLM)
$direkt = New-Object System.Collections.Generic.List[object]     # fehlgeschlagene Anmeldungen am DC selbst
$sperr = New-Object System.Collections.Generic.List[object]      # Kontosperrungen
$stand = @()
foreach ($d in $alleDcs) {
    Write-Host (T "  Domänencontroller $($d.Name) ..." "Domain controller $($d.Name) ...")
    $z = [pscustomobject]@{ Name = $d.Name; Host = $d.HostName; Lokal = ($d.Name -eq $env:COMPUTERNAME -and -not $Anmeldung); Weg = 'lokal'; Cim = $null }
    $info = [ordered]@{ Domänencontroller = $d.Name; Leseweg = ''; 'Ältester Eintrag' = ''; Sperrungen = 0; Fehlversuche = 0; 'Fehlanmeldungen am DC' = 0 }
    try {
        # Leseweg bestimmen: lokal, Ereignisprotokoll-Fernverwaltung oder WMI
        $aeltester = $null
        if ($z.Lokal) { $aeltester = (Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated }
        else {
            $z.Weg = 'Fernverwaltung'
            try {
                $arg = @{ LogName = 'Security'; Oldest = $true; MaxEvents = 1; ComputerName = $z.Host; ErrorAction = 'Stop' }
                if ($Anmeldung) { $arg.Credential = $Anmeldung }
                $aeltester = (Get-WinEvent @arg).TimeCreated
            } catch {
                if ("$($_.Exception.Message)" -match 'Zugriff|Access|autorisiert|unauthorized') { throw }
                $z.Weg = 'WMI'
                $c = @{ ComputerName = $z.Host; OperationTimeoutSec = 60; ErrorAction = 'Stop' }
                if ($Anmeldung) { $c.Credential = $Anmeldung }
                try { $z.Cim = New-CimSession @c } catch { $z.Cim = New-CimSession @c -SessionOption (New-CimSessionOption -Protocol Dcom) }
            }
        }
        $info.Leseweg = $z.Weg

        $e = @(Ereignisse $z 4740)
        if ($e.Count -ge $MaxEreignisse) { $p1 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T "Obergrenze von $MaxEreignisse Ereignissen erreicht (Sperrungen) - Auswertung unvollständig" "Upper limit of $MaxEreignisse events reached (lockouts) - analysis incomplete"); Details = (T 'Es fehlen die ältesten Ereignisse des Zeitraums (gelesen wird von neu nach alt). Zeitraum verkürzen oder -MaxEreignisse erhöhen' 'The oldest events in the period are missing (read from newest to oldest). Shorten the period or increase -MaxEreignisse') } }
        foreach ($x in $e) { $sperr.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[0]; Quelle = Quelle $x.D[1] $d.Name }) }
        $info.Sperrungen = $e.Count

        $e = @(Ereignisse $z 4768, 4771, 4776, 4625 -NurFehler)
        if ($e.Count -ge $MaxEreignisse) { $p1 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T "Obergrenze von $MaxEreignisse Ereignissen erreicht (Fehlversuche) - Auswertung unvollständig" "Upper limit of $MaxEreignisse events reached (failed attempts) - analysis incomplete"); Details = (T 'Es fehlen die ältesten Ereignisse des Zeitraums (gelesen wird von neu nach alt). Zeitraum verkürzen oder -MaxEreignisse erhöhen' 'The oldest events in the period are missing (read from newest to oldest). Shorten the period or increase -MaxEreignisse') } }
        $ohneDaten = 0
        foreach ($x in $e) {
            if (@($x.D | Where-Object { $_ }).Count -eq 0 -or $x.D.Count -lt $mindestFelder[$x.Id]) { $ohneDaten++; continue }
            switch ($x.Id) {
                4771 { $fehl.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[0]; Quelle = Quelle $x.D[6] $d.Name; Grund = Grund $x.D[4]; Art = 'Kerberos' }) }
                4768 { $fehl.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[0]; Quelle = Quelle $x.D[9] $d.Name; Grund = Grund $x.D[6]; Art = 'Kerberos' }) }
                4776 { $fehl.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[1]; Quelle = Quelle $x.D[2] $d.Name; Grund = Grund $x.D[3]; Art = 'NTLM' }) }
                4625 {
                    $q = if ("$($x.D[19])" -notin '', '-') { $x.D[19] } else { $x.D[13] }
                    $code = if ("$($x.D[9])" -notin '', '0x0') { $x.D[9] } else { $x.D[7] }
                    $typ = "$($x.D[10])"
                    $direkt.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[5]; Quelle = Quelle $q $d.Name; Grund = Grund $code; Art = $(if ($anmeldeTyp.ContainsKey($typ)) { $anmeldeTyp[$typ] } else { (T "Typ $typ" "Type $typ") }) })
                }
            }
        }
        if ($ohneDaten) { $p4 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T "$ohneDaten Fehlereignisse ohne lesbare Daten - nicht ausgewertet" "$ohneDaten error events without readable data - not evaluated"); Details = $(if ($z.Weg -eq 'WMI') { (T 'Über WMI nicht lesbar. Skript auf diesem Domänencontroller starten oder dort die Firewallregel "Remote-Ereignisprotokollverwaltung" freigeben' 'Not readable via WMI. Start the script on this domain controller or open the firewall rule "Remote-Ereignisprotokollverwaltung" there') } else { 'Format unbekannt' }) } }
        $info.Fehlversuche = @($fehl | Where-Object DC -eq $d.Name).Count
        $info.'Fehlanmeldungen am DC' = @($direkt | Where-Object DC -eq $d.Name).Count

        # Interaktive Anmeldungen am Domänencontroller (Konsole und Remotedesktop); über WMI nicht gezielt abfragbar
        if ($z.Weg -eq 'WMI') { $a1Fehler += [pscustomobject][ordered]@{ Konto = (T '(alle)' '(all)'); Domänencontroller = $d.Name; (T 'Art' 'Logon type') = (T 'nicht geprüft' 'Not checked'); Feststellung = (T 'Über WMI nicht abfragbar - Skript auf diesem Domänencontroller starten oder dort die Firewallregel "Remote-Ereignisprotokollverwaltung" freigeben' 'Not queryable via WMI - start the script on this domain controller or open the firewall rule "Remote-Ereignisprotokollverwaltung" there') } }
        else {
            $ms = [long]$Stunden * 3600000
            $xp = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10']]"
            foreach ($x in @(Ereignisse $z -XPath $xp)) {
                # Konten des Fenster-Managers und des Schriftartentreibers melden sich bei jeder Sitzung selbst an
                if ("$($x.D[4])" -match '^S-1-5-(90|96)-' -or "$($x.D[5])" -match '\$$') { continue }
                $a1 += [pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[5]; Art = $anmeldeTyp["$($x.D[8])"]; Quelle = Quelle $x.D[18] $d.Name }
            }
        }

        # Reicht das Protokoll über den Zeitraum zurück?
        if ($z.Weg -eq 'WMI') {
            try {
                $datei = Get-CimInstance -CimSession $z.Cim -ClassName Win32_NTEventlogFile -Filter "LogfileName='Security'" -ErrorAction Stop
                $neu = @(Get-CimInstance -CimSession $z.Cim -ClassName Win32_NTLogEvent -Filter "Logfile='Security' AND TimeGenerated>='$([System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($jetzt.AddMinutes(-30)))'" -Property RecordNumber -OperationTimeoutSec 900 -ErrorAction Stop | Measure-Object RecordNumber -Maximum)
                $erste = [long]$neu[0].Maximum - [long]$datei.NumberOfRecords + 1
                if ($neu[0].Count -and $erste -ge 0) {
                    $aeltester = (Get-CimInstance -CimSession $z.Cim -ClassName Win32_NTLogEvent -Filter "Logfile='Security' AND RecordNumber=$erste" -Property TimeGenerated -OperationTimeoutSec 900 -ErrorAction Stop | Select-Object -First 1).TimeGenerated
                }
            } catch { }
        }
        if (-not $aeltester) { $p3 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T 'Ältester Eintrag nicht ermittelbar - nicht geprüft' 'Oldest entry cannot be determined - not checked'); Details = '' } }
        elseif ($aeltester -gt $ab) { $p3 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T "Protokoll beginnt erst am $(Zeit $aeltester)" "Log starts only on $(Zeit $aeltester)"); Details = (T "Ausgewertet werden sollte ab $(Zeit $ab) - ältere Ereignisse sind überschrieben oder gelöscht, oder der Domänencontroller ist neu" "Analysis should start from $(Zeit $ab) - older events have been overwritten or deleted, or the domain controller is new") } }
        $info.'Ältester Eintrag' = Zeit $aeltester
    } catch {
        $text = Kurz $_.Exception.Message
        if ($text -match 'Zugriff|Access|autorisiert|unauthorized|Berechtigung') { $text += (T ' - PowerShell "Als Administrator" starten bzw. ein Konto mit Administratorrechten auf dem Domänencontroller verwenden' '- Start PowerShell "As Administrator" or use an account with administrator rights on the domain controller') }
        $p1 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T 'Sicherheitsprotokoll nicht lesbar - nicht geprüft' 'Security log not readable - not checked'); Details = $text }
        $info.Leseweg = 'fehlgeschlagen'
    } finally { if ($z.Cim) { try { Remove-CimSession -CimSession $z.Cim } catch { } } }
    $stand += [pscustomobject]$info
}
$gelesen = @($stand | Where-Object { $_.Leseweg -ne 'fehlgeschlagen' } | ForEach-Object { $_.Domänencontroller })


# Laut Verzeichnis gab es Fehlversuche, im Protokoll steht aber keiner: Überwachung ist nicht eingeschaltet
$p2 = @()
$abDatei = $ab.ToFileTimeUtc()
foreach ($d in ($alleDcs | Where-Object { $_.Name -in $gelesen })) {
    try {
        $arg = @{ Server = $d.HostName }
        if ($Anmeldung) { $arg.Credential = $Anmeldung }
        $n = @(Get-ADUser -LDAPFilter "(badPasswordTime>=$abDatei)" @arg).Count
        $prot = @($fehl | Where-Object DC -eq $d.Name).Count
        if ($n -gt 0 -and $prot -eq 0) { $p2 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = (T "Das Verzeichnis vermerkt Fehlversuche bei $n Konten, im Sicherheitsprotokoll steht kein einziger" "The directory records failed attempts for $n accounts, but the security log contains none."); Details = (T 'Die Überwachung fehlgeschlagener Anmeldungen ist hier vermutlich nicht eingeschaltet' 'Monitoring of failed logons is probably not enabled here') } }
    } catch { $p2 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = 'Abfrage fehlgeschlagen - nicht geprüft'; Details = Kurz $_.Exception.Message } }
}
Befund 'P2' (T 'Protokoll' 'Log') (T 'Fehlgeschlagene Anmeldungen werden nicht protokolliert' 'Failed logons are not logged') 'Hoch' $p2 `
    (T 'In der Standardeinstellung protokollieren Domänencontroller bei Kerberos und NTLM nur erfolgreiche Anmeldungen. Fehlversuche - und damit Kennwortangriffe - bleiben unsichtbar; auch dieser Bericht kann sie dann nicht zeigen.' 'By default, domain controllers log only successful logons for Kerberos and NTLM. Failed attempts - and therefore password attacks - remain invisible; this report cannot show them either.') `
    (T 'In der "Default Domain Controllers Policy" unter Erweiterte Überwachungsrichtlinienkonfiguration > Kontoanmeldung die Punkte "Kerberos-Authentifizierungsdienst überwachen" und "Überprüfung der Anmeldeinformationen überwachen" auf Erfolg und Fehler stellen.' 'In the "Default Domain Controllers Policy" under Advanced Audit Policy Configuration > Account Logon, set the "Audit Kerberos Authentication Service" and "Audit Credential Validation" settings to Success and Failure.')

# ------------------------------------------------------------------ Prüfungen: Sperrungen
$sperrNach = @{}
foreach ($g in ($sperr | Group-Object Konto)) { $sperrNach[$g.Name] = $g.Group }
function QuellenText($liste) { (@($liste | Group-Object Quelle | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ') }

Befund 'S1' (T 'Sperrungen' 'Lockouts') (T 'Derzeit gesperrte Konten' 'Currently locked accounts') 'Mittel' `
($gesperrt | ForEach-Object {
    $k = $_.SamAccountName.ToLower()
    [pscustomobject][ordered]@{ Konto = $_.SamAccountName; Name = $_.Name; 'Gesperrt seit' = Zeit ([datetime]::FromFileTime([int64]$_.lockoutTime)); 'Auslösender Rechner' = $(if ($sperrNach.ContainsKey($k)) { QuellenText $sperrNach[$k] } else { (T 'kein Ereignis im Zeitraum' 'No event in the period') }); Ort = Ort $_.DistinguishedName }
}) `
    (T 'Diese Konten sind im Augenblick gesperrt. Der auslösende Rechner zeigt, wo das falsche Kennwort herkam - meist ein Gerät mit einem alten gespeicherten Kennwort (Handy, Netzlaufwerk, Dienst, geplante Aufgabe).' 'These accounts are currently locked. The triggering computer shows where the incorrect password came from - usually a device with an old saved password (phone, network drive, service, scheduled task).') `
    (T 'Ursache am genannten Rechner beseitigen, erst dann entsperren - sonst sperrt sich das Konto sofort wieder.' 'Resolve the cause on the specified computer, then unlock - otherwise the account will immediately be locked again.')

Befund 'S2' (T 'Sperrungen' 'Lockouts') (T "Kontosperrungen in den letzten $Stunden Stunden" "Account lockouts in the last $Stunden hours") 'Niedrig' `
($sperr | Group-Object Konto | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject][ordered]@{ Konto = $_.Name; Sperrungen = $_.Count; Zuletzt = Zeit (($_.Group | Sort-Object Zeit -Descending)[0].Zeit); 'Auslösender Rechner (Anzahl)' = QuellenText $_.Group }
}) `
    (T 'Jede Zeile ist ein Konto, das im Zeitraum mindestens einmal gesperrt wurde. Einzelne Sperrungen nach einem Kennwortwechsel sind normal.' 'Each row is an account that was locked out at least once during the period. Individual lockouts after a password change are normal.') `
    (T 'Bei Häufungen den auslösenden Rechner prüfen (siehe S3 und S5).' 'If there are clusters, check the triggering computer (see S3 and S5).')

# ------------------------------------------------------------------ Prüfungen: Fehlversuche
$falsch = @($fehl | Where-Object Grund -eq 'Falsches Kennwort')
Befund 'F1' (T 'Fehlversuche' 'Failed attempts') (T "Konten mit vielen Fehlversuchen (ab $FehlSchwelle)" "Accounts with many failed attempts (from $FehlSchwelle)") 'Mittel' `
($falsch | Group-Object Konto | Where-Object Count -ge $FehlSchwelle | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject][ordered]@{ Konto = $_.Name; 'Falsches Kennwort' = $_.Count; Erster = Zeit (($_.Group | Sort-Object Zeit)[0].Zeit); Letzter = Zeit (($_.Group | Sort-Object Zeit -Descending)[0].Zeit); 'Quelle (Anzahl)' = QuellenText $_.Group }
}) `
    (T 'Bei diesen Konten wurde im Zeitraum auffällig oft ein falsches Kennwort verwendet. Gezählt werden Ereignisse, nicht Tastatureingaben: Ein einzelner Versuch kann je nach Protokoll mehrere Ereignisse erzeugen.' 'For these accounts, an incorrect password was used unusually often during the period. Events are counted, not keystrokes: a single attempt can generate multiple events depending on the protocol.') `
    (T 'Quelle prüfen: ein Gerät mit altem Kennwort oder ein Angriff? Bei Verdacht Kennwort ändern und die Quelle untersuchen.' 'Check the source: a device with an old password or an attack? If suspected, change the password and investigate the source.')

# ------------------------------------------------------------------ Prüfungen: Richtlinie
$r1 = @(); $r2 = @()
$schwelle = [int]$richtlinie.LockoutThreshold
$dauer = [int]$richtlinie.LockoutDuration.TotalMinutes
$fenster = [int]$richtlinie.LockoutObservationWindow.TotalMinutes
if ($schwelle -eq 0) { $r1 += [pscustomobject][ordered]@{ Einstellung = 'Kontosperrungsschwelle'; Ist = (T '0 (keine Sperrung)' '0 (no lockout)'); Empfohlen = (T '10 oder weniger' '10 or less') } }
else {
    if ($schwelle -gt 10) { $r2 += [pscustomobject][ordered]@{ Einstellung = 'Kontosperrungsschwelle'; Ist = (T "$schwelle Fehlversuche" "$schwelle failed attempts"); Empfohlen = (T '10 oder weniger' '10 or less') } }
    if ($dauer -gt 0 -and $dauer -lt 15) { $r2 += [pscustomobject][ordered]@{ Einstellung = 'Kontosperrdauer'; Ist = (T "$dauer Minuten" "$dauer minutes"); Empfohlen = (T 'mindestens 15 Minuten' 'At least 15 minutes') } }
    if ($fenster -lt 15) { $r2 += [pscustomobject][ordered]@{ Einstellung = (T 'Zurücksetzungsdauer des Kontosperrungszählers' 'Account lockout counter reset duration'); Ist = (T "$fenster Minuten" "$fenster minutes"); Empfohlen = (T 'mindestens 15 Minuten' 'At least 15 minutes') } }
}
Befund 'R1' (T 'Richtlinie' 'Policy') (T 'Kontosperrung ist nicht eingerichtet' 'Account lockout is not configured') 'Hoch' $r1 `
    (T 'Ohne Kontosperrung lassen sich Kennwörter beliebig oft durchprobieren. Der Bericht kann dann auch keine Sperrungen zeigen. Abgestimmte Kennwortrichtlinien (PSO) für einzelne Gruppen sind hier nicht berücksichtigt.' 'Without account lockout, passwords can be tried arbitrarily many times. The report then cannot show any lockouts either. Fine-grained password policies (PSO) for individual groups are not considered here.') `
    (T 'In der Default Domain Policy eine Kontosperrungsschwelle setzen (Microsoft-Sicherheitsbaseline: 10 Fehlversuche, Sperrdauer und Zurücksetzung je 15 Minuten).' 'In the Default Domain Policy, set an account lockout threshold (Microsoft security baseline: 10 failed attempts, lockout duration and reset time each 15 minutes).')

# Ohne ein einziges gelesenes Protokoll dürfen die Prüfpunkte, die darauf beruhen, nicht als "ohne Befund" erscheinen
if (-not $gelesen.Count) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match '^(P[234]|S[235]|F\d|A1)$' -and $_.Anzahl -eq 0 })) {
        $x.Objekte = @([pscustomobject]@{ Feststellung = (T 'Kein Sicherheitsprotokoll lesbar - nicht geprüft (siehe P1)' 'No security log readable - not checked (see P1)') }); $x.Anzahl = 1; $x.Stufe = 'Info'
    }
    # S4 besteht aus zwei Teilen: "derzeit gesperrt" kommt aus dem Verzeichnis und ist auch ohne Protokoll gültig, "im Zeitraum gesperrt" nicht
    $x = $Befunde | Where-Object Id -eq 'S4'
    $war = $x.Anzahl
    $x.Objekte = @($x.Objekte) + [pscustomobject][ordered]@{ Konto = '(Zeitraum)'; Feststellung = (T 'Sperrungen im Zeitraum nicht geprüft (siehe P1)' 'Lockouts in the period not checked (see P1)'); Zeitpunkt = ''; 'Auslösender Rechner' = '' }
    $x.Anzahl = $x.Objekte.Count
    if (-not $war) { $x.Stufe = 'Info' }
}

# ------------------------------------------------------------------ Bericht
$nachKonto = $fehl | Group-Object Konto | Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object {
    [pscustomobject][ordered]@{ Konto = $_.Name; 'In der Domäne vorhanden' = JaNein $bekannteKonten.ContainsKey($_.Name); Administrator = JaNein $admins.ContainsKey($_.Name); Ereignisse = $_.Count
        'Häufigster Grund' = ($_.Group | Group-Object Grund | Sort-Object Count -Descending | Select-Object -First 1).Name; Zuletzt = Zeit (($_.Group | Sort-Object Zeit -Descending)[0].Zeit); 'Quelle (Anzahl)' = QuellenText $_.Group }
}
$nachQuelle = $fehl | Group-Object Quelle | Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object {
    [pscustomobject][ordered]@{ Quelle = $_.Name; Ereignisse = $_.Count; 'Verschiedene Konten' = @($_.Group | Group-Object Konto).Count; Kerberos = @($_.Group | Where-Object Art -eq 'Kerberos').Count; NTLM = @($_.Group | Where-Object Art -eq 'NTLM').Count
        Zuletzt = Zeit (($_.Group | Sort-Object Zeit -Descending)[0].Zeit) }
}
$umgebung = [ordered]@{
    (T 'Domäne (NetBIOS)' 'Domain (NetBIOS)')        = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    (T 'Ausgewerteter Zeitraum' 'Evaluated period')  = (T "$(Zeit $ab) bis $(Zeit $jetzt) ($Stunden Stunden)" "$(Zeit $ab) to $(Zeit $jetzt) ($Stunden hours)")
    (T 'Domänencontroller gelesen' 'Domain controller read') = (T "$($gelesen.Count) von $($alleDcs.Count)" "$($gelesen.Count) of $($alleDcs.Count)")
    (T 'Kontosperrungen / Fehlversuche / Fehlanmeldungen am DC' 'Account lockouts / failed attempts / failed logons on the domain controller') = (T "$($sperr.Count) / $($fehl.Count) / $($direkt.Count) Ereignisse" "$($sperr.Count) / $($fehl.Count) / $($direkt.Count) events")
    (T 'Derzeit gesperrte Konten' 'Currently locked accounts') = $gesperrt.Count
    'Kontosperrungsrichtlinie' = $(if ($schwelle) { (T "Sperrung nach $schwelle Fehlversuchen, Dauer $(if ($dauer) { "$dauer Minuten" } else { 'bis zur Entsperrung' }), Zähler zurück nach $fenster Minuten" "Lockout after $schwelle failed attempts, duration $(if ($dauer) { ""$dauer Minuten"" } else { 'bis zur Entsperrung' }), counter reset after $fenster minutes") } else { (T 'keine Kontosperrung' 'No account lockout') })
    (T 'Schwellen dieses Berichts' 'Thresholds for this report') = (T "viele Fehlversuche ab $FehlSchwelle, viele Konten je Quelle ab $SprayKonten, wiederholt gesperrt ab $WiederholtAb" "many failed attempts from $FehlSchwelle, many accounts per source from $SprayKonten, repeatedly locked out from $WiederholtAb")
}
$basis = BerichtSchreiben -Name (T 'Anmelde- und Sperrbericht Light' 'Logon and lockout report Light') -Datei 'Anmelde-Sperrbericht' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ (T 'Gelesene Domänencontroller' 'Domain controllers read') = $stand; (T 'Fehlversuche nach Konto (die 25 häufigsten)' 'Failed attempts by account (top 25)') = $nachKonto; (T 'Fehlversuche nach Quelle (die 25 häufigsten)' 'Failed attempts by source (top 25)') = $nachQuelle }) `
    -Fuss (T 'Light-Version mit 5 von 18 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/ztktaaq). Grundlage sind die Sicherheitsprotokolle der Domänencontroller im genannten Zeitraum; gezählt werden Ereignisse. Der Bericht enthält personenbezogene Anmeldedaten - vertraulich behandeln, nur für den festgelegten Zweck verwenden und danach löschen. Er ersetzt keine laufende Überwachung und erhebt keinen Anspruch auf Vollständigkeit.' 'Light version with 5 of 18 checks of the full version (https://mueller86.gumroad.com/l/ztktaaq). Based on the security logs of the domain controllers in the specified period; events are counted. The report contains personal logon data - handle confidentially, use only for the defined purpose, and delete afterward. It does not replace ongoing monitoring and makes no claim to completeness.')
if ($Csv) {
    SpaltenAnzeige @($fehl + $direkt | Sort-Object Zeit | ForEach-Object { [pscustomobject][ordered]@{ Zeit = $_.Zeit.ToString('dd.MM.yyyy HH:mm:ss'); Domänencontroller = $_.DC; Konto = $_.Konto; Quelle = $_.Quelle; Grund = $_.Grund; (T 'Art' 'Logon type') = $_.Art } }) |
        Export-Csv -Path "${basis}_Fehlversuche.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
    SpaltenAnzeige @($sperr | Sort-Object Zeit | ForEach-Object { [pscustomobject][ordered]@{ Zeit = $_.Zeit.ToString('dd.MM.yyyy HH:mm:ss'); Domänencontroller = $_.DC; Konto = $_.Konto; 'Auslösender Rechner' = $_.Quelle } }) |
        Export-Csv -Path "${basis}_Sperrungen.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
}
if ($PassThru) { $Befunde }
