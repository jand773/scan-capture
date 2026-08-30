# =====================================================================
#  SCAN & KILL CAPTURE / RECORDING AGENTS  (v2 - maximizada)
#  Objetivo: revisar una PC remota (via AnyDesk/RDP) y detectar cualquier
#  metodo de grabacion de pantalla activo o posible, para que NO te graben
#  la sesion mientras trabajas.
#
#  Detecta (en orden de fiabilidad):
#    A) Grabadores de escritorio (OBS, Bandicam, Fraps, Camtasia, ShareX,
#       XSplit, DXTory, Nvidia/AMD capture...) por proceso + modulos.
#    B) Navegadores que estan CAPTURANDO pantalla en este momento
#       (proceso del navegador con Windows.Graphics.Capture.dll cargada).
#    C) Extensiones de navegador con permisos de captura de pantalla
#       instaladas (las que podrian grabar via desktopCapture).
#    D) Captura/Streaming de Windows (Xbox Game Bar, BroadcastDVR, etc.)
#    E) Software espia / keyloggers conocidos.
#
#  Parametros:
#    -Json       Salida JSON (para automatizar con scripts).
#    -AutoKill   Mata los grabadores de escritorio detectados sin preguntar.
#    -ListExt    Solo lista extensiones de navegador con permiso de captura.
#    -NoColor    Sin colores.
# =====================================================================

[CmdletBinding()]
param(
    [switch]$AutoKill,
    [switch]$Json,
    [switch]$ListExt,
    [switch]$NoColor
)

$ErrorActionPreference = "SilentlyContinue"

function Write-Line {
    param([string]$Text, [string]$Color = "White")
    if ($NoColor) { Write-Host $Text } else { Write-Host $Text -ForegroundColor $Color }
}

# =====================================================================
#  A) GRABADORES DE ESCRITORIO conocidos
# =====================================================================
$forbiddenProcesses = @(
    # Grabacion / Streaming de escritorio
    "obs","obs32","obs64","streamlabs","camtasia","bandicam","xsplit",
    "fraps","action","dxtory","sharex","screenrec","flashback","bdcam",
    "screenpresso","greenshotrs","faststone","snagit","snippingtool",
    "lightshot","puush","picpick","monosnap","firecam","loilo","mirillis",
    "action!","smartoft","capacity","freecam","icecream screen recorder",
    "movavi","apeksoft","demo creator","evo","kdenlive","openshot",
    "debut","nch","captura","ocam","apowersoft","ezvid","bb flashback",
    "kazam","simplescreenrecorder","recordmyscreen","screenflow",
    "litmus","du recoder","reco","boxcasts","dpcapture","capturebyuzer",
    "tux rec","green rec","recmaster","hdd","zapsplat","recordit",
    "cropper","snapcrab","jing","fastone capture","rerec","qrecorder",
    "webcam recorder","CamStudio","Screen Recorder Pro","vokoscreen",
    "screencast-o-matic","tellagami","playclaw","msi afterburner",
    "d3dx","shadowplay","geforce experience","nvidia share",
    "replay buffer","twitch","tutorial builder","dvd soft","allavsoft",
    "vidcoder","handbrake","ffmpeg",

    # Streamers / Communicacion con comparticion
    "discord","discordcanary","discordptb","zoom","teams","skype",
    "slack","webex","googlemeet","microsoft teams","gotoassist","goto",

    # Captura nativa Windows (Xbox Game Bar / DVR)
    "gamebar","gamebarpresencewriter","xboxgamebar","broadcastdvr",
    "explorerframeapp","windowsinternal.composableshell.experiences",

    # NVIDIA
    "nvcontainer","nvdisplay.container","nvidiashare","nvbackend",
    "nvsphelper64","nvstreamer","nvtray","nvtelemetry","nvfbc","nvifrex",

    # AMD
    "amdsoftware","radeonsoftware","amdxcapture","amdenc","amddvr"
)

# Modulos cuya presencia en un proceso indica que TIENE captura activa de
# pantalla/encodeo de video cargado en memoria (metodo mas fiable).
$captureModules = @(
    "Windows.Graphics.Capture.dll",
    "GraphicsCapture.dll",
    "nvencodeapi",
    "nvencodeapi64",
    "nvFBC",
    "amdenc",
    "amfrt64",
    "amdxc64",
    "obs-virtualcam",
    "screen-capture-recorder",
    "virtualcam"
)

# =====================================================================
#  ESCANEO A+B+D: procesos con captura
# =====================================================================
$results = @{}

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $p = $_
    $name = $p.Name.ToLower()
    $isBrowser = $name -match 'chrome|msedge|firefox|opera|brave|vivaldi|webview|electron'
    $isMainProc = $p.MainWindowHandle -ne 0

    # --- A) Por nombre en lista negra (excluye navegadores, se tratan aparte) ---
    $reason = $null
    if (-not $isBrowser -and ($forbiddenProcesses -contains $name)) {
        $reason = "Grabador conocido"
    }

    # --- B/D) Por modulos DE CAPTURA DE PANTALLA cargados (senal EN VIVO) ---
    if (-not $reason) {
        $mods = @($p.Modules.ModuleName | ForEach-Object { $_.ToLower() })

        # Senal FUERTE: API oficial de captura de pantalla de Windows.
        # Si un proceso la tiene cargada es porque esta capturando pantalla.
        $gCapture = $mods -like "*windows.graphics.capture*"
        if ($gCapture) {
            if ($isBrowser) {
                $reason = "!! NAVEGADOR CAPTURANDO PANTALLA EN VIVO (getDisplayMedia)"
            } else {
                $reason = "!! CAPTURANDO PANTALLA EN VIVO (Graphics.Capture)"
            }
        }

        # Senal MEDIA en navegador: codificador de video AMD/NV en el proceso
        # PRINCIPAL (con ventana) del navegador => compartiendo/encodeando.
        if (-not $reason -and $isBrowser -and $isMainProc) {
            if (($mods -like "*amdenc*") -or ($mods -like "*amfrt64*") -or ($mods -like "*nvencodeapi*") -or ($mods -like "*nvfbc*")) {
                $reason = "Posible compartiendo pantalla (encodeador $($mods | Where-Object { $_ -match 'amdenc|amfrt|nvenc|nvfbc' } | Select-Object -First 1))"
            }
        }

        # Apps de escritorio con codificador de video = grabador de video
        if (-not $reason -and -not $isBrowser) {
            if (($mods -like "*amdenc*") -or ($mods -like "*amfrt64*") -or ($mods -like "*nvencodeapi*") -or ($mods -like "*nvfbc*")) {
                $reason = "Encodeador de video activo"
            }
        }

        # Camara virtual (se usa para enviar video por apps)
        if (-not $reason) {
            if (($mods -like "*obs-virtualcam*") -or ($mods -like "*virtualcam*") -or ($mods -like "*screen-capture-recorder*")) {
                $reason = "Camara virtual / captura (OBS)"
            }
        }
    }

    if ($reason) {
        $uniq = $name
        if ($results.ContainsKey($uniq)) { return }
        $results[$uniq] = @{
            Name   = $p.Name
            PID    = $p.Id
            Reason = $reason
            Path   = $p.Path
            Kind   = "GRABADOR"
        }
    }
}

# =====================================================================
#  C) EXTENSIONES DE NAVEGADOR con permiso de captura de pantalla
# =====================================================================
# Las extensiones viven dentro del navegador (no son procesos individuales),
# asi que se revisan las carpetas de extensiones instaladas y su manifest.json.
#
# IMPORTANTE (Metodo Moderno):
#  - Muchas extensiones de grabacion modernas usan la API "getDisplayMedia"
#    desde contenido/offscreen, que NO siempre declara desktopCapture/tabCapture
#    en el manifest. Para no perderlas, se detecta por VARIAS señales:
#      * Permisos NOTORIOS de captura: desktopCapture / tabCapture.
#      * API de captura de tab de video/audio (tabCapture).
#      * Palabras clave de grabacion en el nombre/manifest.
#      * IDs conocidos de grabadores de pantalla de la Web Store.
#  - Los nombres pueden venir localizados (__MSG_*__); se resuelven con _locales.

# Funcion: resuelve el nombre real (maneja nombres localizados __MSG_*__)
function Resolve-ExtName {
    param($Name, $ExtRoot)
    if ($Name -match '^__MSG_(.+?)__$') {
        $msgKey = $Matches[1]
        foreach ($loc in @('es','en','en_US','es_419')) {
            $f = "$ExtRoot\_locales\$loc\messages.json"
            if (Test-Path $f) {
                try {
                    $m = [System.IO.File]::ReadAllText($f, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
                    if ($m.$msgKey.message) { return $m.$msgKey.message }
                } catch {}
            }
        }
    }
    return $Name
}

$extResults = @()

# IDs conocidos de extensiones grabadoras de pantalla (refuerzo por si el
# manifest no declara permisos tecnicos).
$knownCaptureExtNames = @('screen rec','screen recorder','recorder','record','capture','screenrecorder','screen capture')

$browserExtDirs = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\*\Extensions",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\*\Extensions",
    "$env:APPDATA\Mozilla\Firefox\Profiles\*\extensions",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\*\Extensions",
    "$env:LOCALAPPDATA\Opera Software\Opera Stable\Extensions",
    "$env:LOCALAPPDATA\Vivaldi\User Data\*\Extensions",
    "$env:LOCALAPPDATA\Chromium\User Data\*\Extensions"
)

foreach ($extRootDir in $browserExtDirs) {
    # $extRootDir tiene comodin para el perfil -> Get-ChildItem expande a las
    # carpetas "Extensions" de cada perfil. Dentro de cada una están los IDs.
    $browserKind = if ($extRootDir -match 'Chrome') {'Chrome'}
                   elseif ($extRootDir -match 'Edge') {'Edge'}
                   elseif ($extRootDir -match 'Firefox') {'Firefox'}
                   elseif ($extRootDir -match 'Brave') {'Brave'}
                   elseif ($extRootDir -match 'Opera') {'Opera'}
                   elseif ($extRootDir -match 'Vivaldi') {'Vivaldi'}
                   elseif ($extRootDir -match 'Chromium') {'Chromium'}
                   else {'?'}
    Get-ChildItem -Path $extRootDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extensionsDir = $_.FullName

        Get-ChildItem -Path $extensionsDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extId = $_.Name
            $extBase = $_.FullName

            # Dentro de cada ID puede haber una o mas subcarpetas de version
            $verDirs = Get-ChildItem -Path $extBase -Directory -ErrorAction SilentlyContinue
            if (-not $verDirs) { $verDirs = @(Get-Item $extBase) }

            foreach ($vd in $verDirs) {
                $manifest = Join-Path $vd.FullName "manifest.json"
                if (-not (Test-Path $manifest)) { continue }
                try {
                    $m = Get-Content $manifest -Raw | ConvertFrom-Json

                # Reunir todos los permisos (permissions + host_permissions)
                $allPerms = @()
                $allPerms += @($m.permissions)
                $allPerms += @($m.host_permissions)
                $permStr = ($allPerms -join ' ').ToLower()

                $realName = Resolve-ExtName -Name $m.name -ExtRoot $vd.FullName

                # Señal FUERTE: permisos tecnicos de captura
                $strong = $permStr -match 'desktopCapture|tabCapture'

                # Señal DEBIL: nombre o palabras sugieren grabador
                $weakName = $false
                foreach ($k in $knownCaptureExtNames) {
                    if ($realName.ToLower() -match [regex]::Escape($k)) { $weakName = $true; break }
                }

                if ($strong -or $weakName) {
                    $extResults += [pscustomobject]@{
                        Nombre   = $realName
                        ID       = $extId
                        Version  = $m.version
                        Browser  = $browserKind
                        Permisos = $permStr
                        Confianza= if ($strong) {'ALTA'} else {'MEDIA (por nombre)'}
                        }
                    }
                } catch {}
            }
        }
    }
}

# =====================================================================
#  E) SOFTWARE ESPIA / KEYLOGGER conocido
# =====================================================================
$spywareProcesses = @(
    "keylogger","keylogg","refog","actual keylogger","revealer keylogger",
    "all in one keylogger","spytector","ardent","crono","ei keylogger",
    "easy keylogger","best free keylogger","phantom","spyrix","micro keylogger",
    "ksoft","absolute keylogger","malwarebytes","spywareterminator",
    "towebcam","spyagent","spytech","activtrak","teramind","hubstaff",
    "time doctor","desktime","veriato","awareness technologies","remote keylogger"
)

$spyResults = @()
Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $n = $_.Name.ToLower()
    if ($spywareProcesses -contains $n) {
        $spyResults += [pscustomobject]@{ Name=$_.Name; PID=$_.Id; Path=$_.Path }
    }
}

# =====================================================================
#  SALIDA
# =====================================================================
if ($Json) {
    $out = @{
        Grabadores    = $results.Values
        Extensiones   = $extResults
        SoftwareEspia = $spyResults
    }
    $out | ConvertTo-Json -Depth 4
    exit
}

if (-not $NoColor) { Clear-Host }

Write-Line "==============================================================" "Cyan"
Write-Line "   SCAN & KILL CAPTURE AGENTS  (v2 - para sesiones remotas)" "Cyan"
Write-Line "==============================================================" "Cyan"
Write-Line ""

# --- Grabadores ---
Write-Line ("[SECTION 1] GRABADORES / CAPTURA ACTIVA  ->  {0} detectados" -f $results.Count) "White"
if ($results.Count -eq 0) {
    Write-Line "   [+] Ningun grabador de escritorio activo." "Green"
} else {
    $i = 0
    $results.Values | ForEach-Object {
        $i++
        Write-Line ("   [{0}] {1}.exe (PID {2}) - {3}" -f $i, $_.Name, $_.PID, $_.Reason) "Yellow"
        if ($_.Path) { Write-Line ("         {0}" -f $_.Path) "DarkGray" }
    }
}
Write-Line ""

# --- Extensiones ---
Write-Line ("[SECTION 2] EXTENSIONES DE NAVEGADOR CON CAPACIDAD DE CAPTURA  ->  {0}" -f ($extResults | Select-Object Nombre,Browser -Unique).Count) "White"
if ($extResults.Count -eq 0) {
    Write-Line "   [+] No se encontraron extensiones con capacidades de captura de pantalla." "Green"
} else {
    $extResults | ForEach-Object {
        Write-Line ("   - [{0}] {1} (v{2})" -f $_.Browser, $_.Nombre, $_.Version) "Yellow"
        Write-Line ("         ID: {0}  |  Confianza: {1}" -f $_.ID, $_.Confianza) "DarkGray"
        if ($_.Permisos) { Write-Line ("         Permisos: {0}" -f $_.Permisos) "DarkGray" }
    }
}
Write-Line ""

# --- Spyware ---
Write-Line ("[SECTION 3] SOFTWARE ESPIA / KEYLOGGER  ->  {0} detectados" -f $spyResults.Count) "White"
if ($spyResults.Count -eq 0) {
    Write-Line "   [+] Ningun keylogger/espia conocido en procesos." "Green"
} else {
    $spyResults | ForEach-Object {
        Write-Line ("   [!] {0}.exe (PID {1})" -f $_.Name, $_.PID) "Red"
    }
}
Write-Line ""

# --- Acciones ---
if ($AutoKill) {
    Write-Line "[!] Modo AutoKill: terminando GRABADORES de escritorio (seccion 1)..." "Red"
    foreach ($item in ($results.Values | Where-Object { $_.Kind -eq "GRABADOR" })) {
        Stop-Process -Id $item.PID -Force
        Write-Line ("   [Terminado] {0} (PID {1})" -f $item.Name, $item.PID) "Red"
    }
    exit
}

$total = $results.Count
if ($total -gt 0) {
    Write-Line "[A] Terminar TODOS los grabadores detectados" "White"
    Write-Line "[B] Terminar 1 proceso especifico" "White"
    Write-Line "[N] No hacer nada / Salir" "White"
    Write-Line ""
    $choice = Read-Host "Opcion (A/B/N)"

    switch ($choice.ToUpper()) {
        "A" {
            foreach ($item in $results.Values) {
                Stop-Process -Id $item.PID -Force
                Write-Line ("   [Terminado] {0} (PID {1})" -f $item.Name, $item.PID) "Red"
            }
        }
        "B" {
            $target = Read-Host "Nombre del proceso (ej: chrome o chrome.exe)"
            $target = $target.ToLower().Replace(".exe","")
            $item = $results[$target]
            if ($item) {
                Stop-Process -Id $item.PID -Force
                Write-Line ("   [Terminado] {0} (PID {1})" -f $item.Name, $item.PID) "Red"
            } else {
                Write-Line "[Error] No encontrado." "Red"
            }
        }
        default { Write-Line "[+] Sin accion." "Green" }
    }
} else {
    Write-Line "   [+] No hay grabadores que terminar. Sesion limpia." "Green"
}