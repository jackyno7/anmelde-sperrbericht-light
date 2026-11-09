#Requires -Version 5.1
<#
.SYNOPSIS
    LIGHT-VERSION (5 von 18 Prüfpunkten, kostenlos). Anmelde- und Sperrbericht: wertet Kontosperrungen und fehlgeschlagene Anmeldungen aus dem Sicherheitsprotokoll
    der Domänencontroller aus und erzeugt einen HTML-Bericht.

.DESCRIPTION
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
    Pfad der HTML-Datei. Standard: Anmelde-Sperrbericht_<Domäne>_<Datum>.html im aktuellen Ordner.

.PARAMETER Stunden
    Auswertungszeitraum in Stunden, rückwärts ab jetzt (Standard 24).

.PARAMETER FehlSchwelle
    Konten ab so vielen Ereignissen "falsches Kennwort" melden (Standard 20).

.PARAMETER SprayKonten
    Quellen melden, von denen Fehlversuche für mindestens so viele verschiedene Konten kamen (Standard 10).

.PARAMETER WiederholtAb
    Konten melden, die im Zeitraum mindestens so oft gesperrt wurden (Standard 3).

.PARAMETER MaxEreignisse
    Obergrenze der gelesenen Ereignisse je Domänencontroller und Abfrage (Standard 50000).

.PARAMETER DomaenenController
    Nur diese Domänencontroller auswerten (Standard: alle).

.PARAMETER Server
    Bestimmter Domänencontroller oder Domäne für die Verzeichnisabfragen (optional).

.PARAMETER Anmeldung
    Anmeldedaten eines Administratorkontos (Get-Credential), falls das Skript nicht unter einem solchen läuft.

.PARAMETER Csv
    Schreibt alle Fehlversuche, alle Sperrungen und je Prüfpunkt mit Treffern eine CSV-Datei neben den Bericht.

.PARAMETER NichtOeffnen
    Öffnet den fertigen Bericht nicht automatisch im Browser.

.PARAMETER PassThru
    Gibt die Befunde zusätzlich als Objekte zurück (für eigene Auswertungen).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Anmelde-Sperrbericht.ps1

.EXAMPLE
    .\Anmelde-Sperrbericht.ps1 -Stunden 72 -Csv -Ausgabe C:\Berichte\anmeldungen.html

.NOTES
    IT Admin Tools by MM - Version 1.0 (10.2026)
    Kein Ersatz für eine Protokollüberwachung (SIEM) oder Sicherheitsprüfung. Nutzung auf eigene Verantwortung.
#>
[CmdletBinding()]
param(
    [string]$Ausgabe,
    [ValidateRange(1, 720)][int]$Stunden = 24,
    [ValidateRange(1, 100000)][int]$FehlSchwelle = 20,
    [ValidateRange(2, 100000)][int]$SprayKonten = 10,
    [ValidateRange(2, 1000)][int]$WiederholtAb = 3,
    [ValidateRange(100, 5000000)][int]$MaxEreignisse = 50000,
    [string[]]$DomaenenController,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Anmeldung,
    [switch]$Csv,
    [switch]$NichtOeffnen,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$Version = '1.0'

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host 'Das PowerShell-Modul "ActiveDirectory" fehlt.' -ForegroundColor Red
    Write-Host 'Windows 10/11: Einstellungen > Optionale Features > "RSAT: Active Directory Domain Services" hinzufügen.'
    Write-Host 'Windows Server:  Install-WindowsFeature RSAT-AD-PowerShell'
    exit 2
}
Import-Module ActiveDirectory

$ad = @{}
if ($Server) { $ad.Server = $Server }
if ($Anmeldung) { $ad.Credential = $Anmeldung }

# ------------------------------------------------------------------ Hilfsfunktionen
function Datum($d, $leer = 'nie') { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy') } else { $leer } }
function JaNein($b) { if ($b) { 'Ja' } else { 'Nein' } }
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
        $sicher | Microsoft.PowerShell.Utility\Export-Csv -Path $Path -NoTypeInformation:$NoTypeInformation -Delimiter $Delimiter -Encoding $Encoding
    }
}

# Tabellen: ConvertTo-Html und Export-Csv nehmen die Spalten des ersten Objekts. Haben die Zeilen einer Liste verschiedene
# Eigenschaften (z. B. Fehlzeile neben normalen Treffern), gingen Spalten verloren: alle Namen der Reihe nach vereinigen.
function Einheitlich($liste) {
    $liste = @($liste | Where-Object { $null -ne $_ })
    if ($liste.Count -lt 2) { return $liste }
    $namen = New-Object System.Collections.Generic.List[string]
    foreach ($o in $liste) { foreach ($p in $o.PSObject.Properties.Name) { if (-not $namen.Contains($p)) { $namen.Add($p) } } }
    if ($namen.Count -eq @($liste[0].PSObject.Properties.Name).Count) { return $liste }
    @($liste | Select-Object -Property $namen)
}
# Sortierschluessel fuer Nummern wie K2, K10: erst Buchstaben, dann die Zahl als Zahl
function IdZahl($id) { $m = [regex]::Match([string]$id, '\d+'); if ($m.Success) { [int]$m.Value } else { 0 } }
function IdText($id) { [regex]::Replace([string]$id, '\d+', '') }

$Befunde = New-Object System.Collections.Generic.List[object]

# Platzhalterzeilen ("nicht geprüft") erkennt das Skript nur an den vollständigen, festen Texten, die es selbst erzeugt - keine Teilstring-Suche
# in Konto-, Objekt- oder Beschreibungstexten, die ein Angreifer beeinflussen könnte
$PlatzhalterTexte = @('Abfrage fehlgeschlagen - nicht geprüft', 'Berechtigungen nicht lesbar - nicht geprüft', 'SYSVOL nicht lesbar - nicht geprüft', 'WMI-Filter nicht lesbar - nicht geprüft', 'Kein Domänencontroller ermittelbar - SYSVOL nicht geprüft', 'Inhalt des Ordners nicht lesbar - Richtlinie nicht geprüft')
function IstPlatzhalter($o) {
    # Ein Skript kann $script:PlatzhalterSpalten setzen: dann zählen nur diese Spalten (Namensspalten sind von Benutzern beeinflussbar)
    foreach ($pr in $o.PSObject.Properties) {
        if ($script:PlatzhalterSpalten -and ($pr.Name -notin $script:PlatzhalterSpalten)) { continue }
        if (($pr.Value -is [string]) -and ($PlatzhalterTexte -ccontains $pr.Value)) { return $true }
    }
    ("$($o.Feststellung)" -clike 'Nicht geprüft - *')
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
function NichtGeprueft([string]$IdMuster, [string[]]$Namen, [string]$Verweis, [string]$Spalte = 'Server', [string]$Grund = 'Abfrage nicht möglich') {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match $IdMuster })) {
        $war = $x.Anzahl
        $zeilen = @($Namen | ForEach-Object { [pscustomobject][ordered]@{ $Spalte = $_; Feststellung = "Nicht geprüft - $Grund (siehe $Verweis)"; Details = '' } })
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
    param([string]$Name, [string]$Datei, [string]$Bezug, [string]$BezugName = 'Domäne', [System.Collections.IDictionary]$Umgebung,
        [System.Collections.IDictionary]$Abschnitte = @{}, [System.Collections.IDictionary]$Anhang = @{}, [string]$Fuss)
    Write-Host '  Bericht schreiben ...'
    $jetzt = Get-Date
    $ziel = $script:Ausgabe
    if (-not $ziel) { $ziel = Join-Path (Get-Location).Path ("{0}_{1}_{2:yyyy-MM-dd_HHmm}.html" -f $Datei, $Bezug, $jetzt) }
    $ziel = [System.IO.Path]::GetFullPath($ziel)
    $ordner = Split-Path $ziel -Parent
    if (-not (Test-Path $ordner)) { New-Item -ItemType Directory -Path $ordner -Force | Out-Null }

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
    [void]$h.Append("<!DOCTYPE html><html lang='de'><head><meta charset='utf-8'><title>$(Html $Name) $(Html $Bezug)</title><style>$css</style></head><body><div class='seite'>")
    [void]$h.Append("<h1>$(Html $Name)</h1><div class='meta'>$(Html $BezugName) <b>$(Html $Bezug)</b> · erstellt am $($jetzt.ToString('dd.MM.yyyy HH:mm')) von $(Html "$env:USERDOMAIN\$env:USERNAME") auf $(Html $env:COMPUTERNAME)</div>")
    [void]$h.Append("<div class='kacheln'>")
    foreach ($s in 'Hoch', 'Mittel', 'Niedrig', 'Info', 'OK') {
        $text = @{ Hoch = 'Befunde mit hoher Priorität'; Mittel = 'mit mittlerer Priorität'; Niedrig = 'mit niedriger Priorität'; Info = 'Hinweise und nicht geprüft'; OK = 'Prüfpunkte ohne Befund' }[$s]
        [void]$h.Append("<div class='kachel $s'><b>$($zahl[$s])</b><span>$text</span></div>")
    }
    [void]$h.Append("</div><h2>Umgebung</h2><table><tr><th>Eigenschaft</th><th>Wert</th></tr>")
    foreach ($k in $Umgebung.Keys) { [void]$h.Append("<tr><td>$(Html $k)</td><td>$(Html $Umgebung[$k])</td></tr>") }
    [void]$h.Append("</table>")

    [void]$h.Append("<h2>Übersicht der Prüfpunkte</h2><table><tr><th>Nr.</th><th>Bereich</th><th>Prüfpunkt</th><th>Treffer</th><th>Bewertung</th></tr>")
    foreach ($x in $Befunde) {
        [void]$h.Append("<tr><td>$($x.Id)</td><td>$(Html $x.Bereich)</td><td><a href='#$($x.Id)'>$(Html $x.Titel)</a></td><td>$($x.Anzahl)</td><td><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span></td></tr>")
    }
    [void]$h.Append("</table>")

    foreach ($k in $Abschnitte.Keys) {
        [void]$h.Append("<h2>$(Html $k)</h2>")
        $inhalt = $Abschnitte[$k]
        if ($inhalt -is [string]) { [void]$h.Append($inhalt) }
        elseif (@($inhalt).Count) { [void]$h.Append(((Einheitlich $inhalt | ConvertTo-Html -Fragment) -join "`n")) }
        else { [void]$h.Append("<p class='klein'>Keine Einträge.</p>") }
    }

    [void]$h.Append("<h2>Befunde</h2>")
    $offen = @($Befunde | Where-Object { $_.Stufe -ne 'OK' } | Sort-Object { $rang[$_.Stufe] }, { IdText $_.Id }, { IdZahl $_.Id })
    foreach ($x in $offen) {
        [void]$h.Append("<div class='befund $($x.Stufe)' id='$($x.Id)'><h3><span class='marke m-$($x.Stufe)'>$($x.Stufe)</span> $($x.Id) · $(Html $x.Titel) <span class='klein'>($($x.Anzahl) Treffer)</span></h3>")
        [void]$h.Append("<p>$(Html $x.Erklaerung)</p><p class='emp'><b>Empfehlung:</b> $(Html $x.Empfehlung)</p>")
        [void]$h.Append(((Einheitlich $x.Objekte | ConvertTo-Html -Fragment) -join "`n"))
        [void]$h.Append("</div>")
    }
    if (-not $offen.Count) { [void]$h.Append("<p>Keine Auffälligkeiten gefunden.</p>") }
    $ok = @($Befunde | Where-Object Stufe -eq 'OK')
    if ($ok.Count) {
        [void]$h.Append("<h2>Ohne Befund</h2><table><tr><th>Nr.</th><th>Prüfpunkt</th></tr>")
        foreach ($x in $ok) { [void]$h.Append("<tr id='$($x.Id)'><td>$($x.Id)</td><td>$(Html $x.Titel)</td></tr>") }
        [void]$h.Append("</table>")
    }
    foreach ($k in $Anhang.Keys) { [void]$h.Append("<h2>$(Html $k)</h2><pre>$(Html $Anhang[$k])</pre>") }
    [void]$h.Append("<div class='fuss'>$(Html $Name) Version $script:Version · IT Admin Tools by MM · Das Skript hat ausschließlich gelesen und nichts verändert. $(Html $Fuss)</div>")
    [void]$h.Append("</div></body></html>")
    [System.IO.File]::WriteAllText($ziel, $h.ToString(), (New-Object System.Text.UTF8Encoding($true)))

    $basis = [System.IO.Path]::ChangeExtension($ziel, $null).TrimEnd('.')
    if ($script:Csv) {
        foreach ($x in ($Befunde | Where-Object { $_.Anzahl -gt 0 })) {
            Einheitlich $x.Objekte | Export-Csv -Path "${basis}_$($x.Id).csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
        }
    }
    Write-Host ''
    Write-Host ("Fertig: {0} hoch, {1} mittel, {2} niedrig, {3} ohne Befund." -f $zahl.Hoch, $zahl.Mittel, $zahl.Niedrig, $zahl.OK) -ForegroundColor Green
    Write-Host "Bericht: $ziel"
    if (-not $script:NichtOeffnen -and [Environment]::UserInteractive) { try { Start-Process $ziel } catch { } }
    $basis
}

function Zeit($d) { if ($d) { ([datetime]$d).ToString('dd.MM.yyyy HH:mm') } else { '' } }
function Konto($n) { (("$n" -replace '^.*\\', '') -replace '@.*$', '').Trim().ToLower() }
function Quelle($q, $dcName) {
    $q = ("$q" -replace '^::ffff:', '').Trim().TrimStart('\')
    if ($q -in '', '-') { 'unbekannt' } elseif ($q -in '::1', '127.0.0.1') { "$dcName (lokal)" } else { $q.ToUpper() }
}
# Bedeutung der Fehlercodes (Kerberos und NTLM) in fünf Gruppen
function Grund($code) {
    switch -Regex ("$code".ToLower()) {
        '^0x18$|c000006a' { 'Falsches Kennwort'; break }
        '^0x6$|c0000064' { 'Konto unbekannt'; break }
        'c0000234' { 'Konto gesperrt'; break }
        '^0x12$|c0000072' { 'Konto deaktiviert oder gesperrt'; break }
        '^0x17$|c0000071|c0000193|c0000224' { 'Kennwort oder Konto abgelaufen'; break }
        '^0x25$' { 'Uhrzeit weicht ab'; break }
        'c000006f|c0000070' { 'Anmeldezeit oder Arbeitsstation nicht erlaubt'; break }
        'c000015b' { 'Anmeldeart für dieses Konto nicht erlaubt'; break }
        default { "Sonstiges ($code)" }
    }
}
$anmeldeTyp = @{ '2' = 'Konsole'; '3' = 'Netzwerk'; '4' = 'Stapel'; '5' = 'Dienst'; '7' = 'Entsperren'; '8' = 'Netzwerk (Klartext)'; '9' = 'Neue Anmeldedaten'; '10' = 'Remotedesktop'; '11' = 'Zwischengespeichert' }

# ------------------------------------------------------------------ Daten aus dem Verzeichnis
Write-Host 'Anmelde- und Sperrbericht - es wird nur gelesen, nichts verändert.' -ForegroundColor Cyan
$dom = Get-ADDomain @ad
$dn = $dom.DistinguishedName
$jetzt = Get-Date
$ab = $jetzt.AddHours(-$Stunden)
$abDmtf = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($ab)

Write-Host '  Konten und Richtlinie ...'
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
if (-not $alleDcs.Count) { Write-Host 'Kein Domänencontroller gefunden (Parameter -DomaenenController prüfen).' -ForegroundColor Red; exit 2 }

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
        if ($NurFehler) { $q += ' AND EventType=5' }
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
    Write-Host "  Domänencontroller $($d.Name) ..."
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
        if ($e.Count -ge $MaxEreignisse) { $p1 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = "Obergrenze von $MaxEreignisse Ereignissen erreicht (Sperrungen) - Auswertung unvollständig"; Details = 'Es fehlen die ältesten Ereignisse des Zeitraums (gelesen wird von neu nach alt). Zeitraum verkürzen oder -MaxEreignisse erhöhen' } }
        foreach ($x in $e) { $sperr.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[0]; Quelle = Quelle $x.D[1] $d.Name }) }
        $info.Sperrungen = $e.Count

        $e = @(Ereignisse $z 4768, 4771, 4776, 4625 -NurFehler)
        if ($e.Count -ge $MaxEreignisse) { $p1 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = "Obergrenze von $MaxEreignisse Ereignissen erreicht (Fehlversuche) - Auswertung unvollständig"; Details = 'Es fehlen die ältesten Ereignisse des Zeitraums (gelesen wird von neu nach alt). Zeitraum verkürzen oder -MaxEreignisse erhöhen' } }
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
                    $direkt.Add([pscustomobject]@{ Zeit = $x.Zeit; DC = $d.Name; Konto = Konto $x.D[5]; Quelle = Quelle $q $d.Name; Grund = Grund $code; Art = $(if ($anmeldeTyp.ContainsKey($typ)) { $anmeldeTyp[$typ] } else { "Typ $typ" }) })
                }
            }
        }
        if ($ohneDaten) { $p4 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = "$ohneDaten Fehlereignisse ohne lesbare Daten - nicht ausgewertet"; Details = $(if ($z.Weg -eq 'WMI') { 'Über WMI nicht lesbar. Skript auf diesem Domänencontroller starten oder dort die Firewallregel "Remote-Ereignisprotokollverwaltung" freigeben' } else { 'Format unbekannt' }) } }
        $info.Fehlversuche = @($fehl | Where-Object DC -eq $d.Name).Count
        $info.'Fehlanmeldungen am DC' = @($direkt | Where-Object DC -eq $d.Name).Count

        # Interaktive Anmeldungen am Domänencontroller (Konsole und Remotedesktop); über WMI nicht gezielt abfragbar
        if ($z.Weg -eq 'WMI') { $a1Fehler += [pscustomobject][ordered]@{ Konto = '(alle)'; Domänencontroller = $d.Name; Art = 'nicht geprüft'; Feststellung = 'Über WMI nicht abfragbar - Skript auf diesem Domänencontroller starten oder dort die Firewallregel "Remote-Ereignisprotokollverwaltung" freigeben' } }
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
        if (-not $aeltester) { $p3 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = 'Ältester Eintrag nicht ermittelbar - nicht geprüft'; Details = '' } }
        elseif ($aeltester -gt $ab) { $p3 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = "Protokoll beginnt erst am $(Zeit $aeltester)"; Details = "Ausgewertet werden sollte ab $(Zeit $ab) - ältere Ereignisse sind überschrieben oder gelöscht, oder der Domänencontroller ist neu" } }
        $info.'Ältester Eintrag' = Zeit $aeltester
    } catch {
        $text = Kurz $_.Exception.Message
        if ($text -match 'Zugriff|Access|autorisiert|unauthorized|Berechtigung') { $text += ' - PowerShell "Als Administrator" starten bzw. ein Konto mit Administratorrechten auf dem Domänencontroller verwenden' }
        $p1 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = 'Sicherheitsprotokoll nicht lesbar - nicht geprüft'; Details = $text }
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
        if ($n -gt 0 -and $prot -eq 0) { $p2 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = "Das Verzeichnis vermerkt Fehlversuche bei $n Konten, im Sicherheitsprotokoll steht kein einziger"; Details = 'Die Überwachung fehlgeschlagener Anmeldungen ist hier vermutlich nicht eingeschaltet' } }
    } catch { $p2 += [pscustomobject][ordered]@{ Domänencontroller = $d.Name; Feststellung = 'Abfrage fehlgeschlagen - nicht geprüft'; Details = Kurz $_.Exception.Message } }
}
Befund 'P2' 'Protokoll' 'Fehlgeschlagene Anmeldungen werden nicht protokolliert' 'Hoch' $p2 `
    'In der Standardeinstellung protokollieren Domänencontroller bei Kerberos und NTLM nur erfolgreiche Anmeldungen. Fehlversuche - und damit Kennwortangriffe - bleiben unsichtbar; auch dieser Bericht kann sie dann nicht zeigen.' `
    'In der "Default Domain Controllers Policy" unter Erweiterte Überwachungsrichtlinienkonfiguration > Kontoanmeldung die Punkte "Kerberos-Authentifizierungsdienst überwachen" und "Überprüfung der Anmeldeinformationen überwachen" auf Erfolg und Fehler stellen.'

# ------------------------------------------------------------------ Prüfungen: Sperrungen
$sperrNach = @{}
foreach ($g in ($sperr | Group-Object Konto)) { $sperrNach[$g.Name] = $g.Group }
function QuellenText($liste) { (@($liste | Group-Object Quelle | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ') }

Befund 'S1' 'Sperrungen' 'Derzeit gesperrte Konten' 'Mittel' `
($gesperrt | ForEach-Object {
    $k = $_.SamAccountName.ToLower()
    [pscustomobject][ordered]@{ Konto = $_.SamAccountName; Name = $_.Name; 'Gesperrt seit' = Zeit ([datetime]::FromFileTime([int64]$_.lockoutTime)); 'Auslösender Rechner' = $(if ($sperrNach.ContainsKey($k)) { QuellenText $sperrNach[$k] } else { 'kein Ereignis im Zeitraum' }); Ort = Ort $_.DistinguishedName }
}) `
    'Diese Konten sind im Augenblick gesperrt. Der auslösende Rechner zeigt, wo das falsche Kennwort herkam - meist ein Gerät mit einem alten gespeicherten Kennwort (Handy, Netzlaufwerk, Dienst, geplante Aufgabe).' `
    'Ursache am genannten Rechner beseitigen, erst dann entsperren - sonst sperrt sich das Konto sofort wieder.'

Befund 'S2' 'Sperrungen' "Kontosperrungen in den letzten $Stunden Stunden" 'Niedrig' `
($sperr | Group-Object Konto | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject][ordered]@{ Konto = $_.Name; Sperrungen = $_.Count; Zuletzt = Zeit (($_.Group | Sort-Object Zeit -Descending)[0].Zeit); 'Auslösender Rechner (Anzahl)' = QuellenText $_.Group }
}) `
    'Jede Zeile ist ein Konto, das im Zeitraum mindestens einmal gesperrt wurde. Einzelne Sperrungen nach einem Kennwortwechsel sind normal.' `
    'Bei Häufungen den auslösenden Rechner prüfen (siehe S3 und S5).'

# ------------------------------------------------------------------ Prüfungen: Fehlversuche
$falsch = @($fehl | Where-Object Grund -eq 'Falsches Kennwort')
Befund 'F1' 'Fehlversuche' "Konten mit vielen Fehlversuchen (ab $FehlSchwelle)" 'Mittel' `
($falsch | Group-Object Konto | Where-Object Count -ge $FehlSchwelle | Sort-Object Count -Descending | ForEach-Object {
    [pscustomobject][ordered]@{ Konto = $_.Name; 'Falsches Kennwort' = $_.Count; Erster = Zeit (($_.Group | Sort-Object Zeit)[0].Zeit); Letzter = Zeit (($_.Group | Sort-Object Zeit -Descending)[0].Zeit); 'Quelle (Anzahl)' = QuellenText $_.Group }
}) `
    'Bei diesen Konten wurde im Zeitraum auffällig oft ein falsches Kennwort verwendet. Gezählt werden Ereignisse, nicht Tastatureingaben: Ein einzelner Versuch kann je nach Protokoll mehrere Ereignisse erzeugen.' `
    'Quelle prüfen: ein Gerät mit altem Kennwort oder ein Angriff? Bei Verdacht Kennwort ändern und die Quelle untersuchen.'

# ------------------------------------------------------------------ Prüfungen: Richtlinie
$r1 = @(); $r2 = @()
$schwelle = [int]$richtlinie.LockoutThreshold
$dauer = [int]$richtlinie.LockoutDuration.TotalMinutes
$fenster = [int]$richtlinie.LockoutObservationWindow.TotalMinutes
if ($schwelle -eq 0) { $r1 += [pscustomobject][ordered]@{ Einstellung = 'Kontosperrungsschwelle'; Ist = '0 (keine Sperrung)'; Empfohlen = '10 oder weniger' } }
else {
    if ($schwelle -gt 10) { $r2 += [pscustomobject][ordered]@{ Einstellung = 'Kontosperrungsschwelle'; Ist = "$schwelle Fehlversuche"; Empfohlen = '10 oder weniger' } }
    if ($dauer -gt 0 -and $dauer -lt 15) { $r2 += [pscustomobject][ordered]@{ Einstellung = 'Kontosperrdauer'; Ist = "$dauer Minuten"; Empfohlen = 'mindestens 15 Minuten' } }
    if ($fenster -lt 15) { $r2 += [pscustomobject][ordered]@{ Einstellung = 'Zurücksetzungsdauer des Kontosperrungszählers'; Ist = "$fenster Minuten"; Empfohlen = 'mindestens 15 Minuten' } }
}
Befund 'R1' 'Richtlinie' 'Kontosperrung ist nicht eingerichtet' 'Hoch' $r1 `
    'Ohne Kontosperrung lassen sich Kennwörter beliebig oft durchprobieren. Der Bericht kann dann auch keine Sperrungen zeigen. Abgestimmte Kennwortrichtlinien (PSO) für einzelne Gruppen sind hier nicht berücksichtigt.' `
    'In der Default Domain Policy eine Kontosperrungsschwelle setzen (Microsoft-Sicherheitsbaseline: 10 Fehlversuche, Sperrdauer und Zurücksetzung je 15 Minuten).'

# Ohne ein einziges gelesenes Protokoll dürfen die Prüfpunkte, die darauf beruhen, nicht als "ohne Befund" erscheinen
if (-not $gelesen.Count) {
    foreach ($x in ($Befunde | Where-Object { $_.Id -match '^(P[234]|S[235]|F\d|A1)$' -and $_.Anzahl -eq 0 })) {
        $x.Objekte = @([pscustomobject]@{ Feststellung = 'Kein Sicherheitsprotokoll lesbar - nicht geprüft (siehe P1)' }); $x.Anzahl = 1; $x.Stufe = 'Info'
    }
    # S4 besteht aus zwei Teilen: "derzeit gesperrt" kommt aus dem Verzeichnis und ist auch ohne Protokoll gültig, "im Zeitraum gesperrt" nicht
    $x = $Befunde | Where-Object Id -eq 'S4'
    $war = $x.Anzahl
    $x.Objekte = @($x.Objekte) + [pscustomobject][ordered]@{ Konto = '(Zeitraum)'; Feststellung = 'Sperrungen im Zeitraum nicht geprüft (siehe P1)'; Zeitpunkt = ''; 'Auslösender Rechner' = '' }
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
    'Domäne (NetBIOS)'        = "$($dom.DNSRoot) ($($dom.NetBIOSName))"
    'Ausgewerteter Zeitraum'  = "$(Zeit $ab) bis $(Zeit $jetzt) ($Stunden Stunden)"
    'Domänencontroller gelesen' = "$($gelesen.Count) von $($alleDcs.Count)"
    'Kontosperrungen / Fehlversuche / Fehlanmeldungen am DC' = "$($sperr.Count) / $($fehl.Count) / $($direkt.Count) Ereignisse"
    'Derzeit gesperrte Konten' = $gesperrt.Count
    'Kontosperrungsrichtlinie' = $(if ($schwelle) { "Sperrung nach $schwelle Fehlversuchen, Dauer $(if ($dauer) { "$dauer Minuten" } else { 'bis zur Entsperrung' }), Zähler zurück nach $fenster Minuten" } else { 'keine Kontosperrung' })
    'Schwellen dieses Berichts' = "viele Fehlversuche ab $FehlSchwelle, viele Konten je Quelle ab $SprayKonten, wiederholt gesperrt ab $WiederholtAb"
}
$basis = BerichtSchreiben -Name 'Anmelde- und Sperrbericht Light' -Datei 'Anmelde-Sperrbericht' -Bezug $dom.DNSRoot -Umgebung $umgebung `
    -Abschnitte ([ordered]@{ 'Gelesene Domänencontroller' = $stand; 'Fehlversuche nach Konto (die 25 häufigsten)' = $nachKonto; 'Fehlversuche nach Quelle (die 25 häufigsten)' = $nachQuelle }) `
    -Fuss 'Light-Version mit 5 von 18 Prüfpunkten der Vollversion (https://mueller86.gumroad.com/l/ztktaaq). Grundlage sind die Sicherheitsprotokolle der Domänencontroller im genannten Zeitraum; gezählt werden Ereignisse. Der Bericht enthält personenbezogene Anmeldedaten - vertraulich behandeln, nur für den festgelegten Zweck verwenden und danach löschen. Er ersetzt keine laufende Überwachung und erhebt keinen Anspruch auf Vollständigkeit.'
if ($Csv) {
    $fehl + $direkt | Sort-Object Zeit | ForEach-Object { [pscustomobject][ordered]@{ Zeit = $_.Zeit.ToString('dd.MM.yyyy HH:mm:ss'); Domänencontroller = $_.DC; Konto = $_.Konto; Quelle = $_.Quelle; Grund = $_.Grund; Art = $_.Art } } |
        Export-Csv -Path "${basis}_Fehlversuche.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
    $sperr | Sort-Object Zeit | ForEach-Object { [pscustomobject][ordered]@{ Zeit = $_.Zeit.ToString('dd.MM.yyyy HH:mm:ss'); Domänencontroller = $_.DC; Konto = $_.Konto; 'Auslösender Rechner' = $_.Quelle } } |
        Export-Csv -Path "${basis}_Sperrungen.csv" -NoTypeInformation -Delimiter ';' -Encoding UTF8
}
if ($PassThru) { $Befunde }
