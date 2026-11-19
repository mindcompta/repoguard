# RepoGuard: rapport local approfondi sous Windows PowerShell.
# Exemple : .\scripts\analyser-projet.ps1 -Projet "C:\chemin\Briefly-"
# Ajouter -OSV seulement pour envoyer noms et versions des paquets a OSV.
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Projet,
    [switch]$OSV
)

$ErrorActionPreference = 'Stop'
try {
    $dossier = Get-Item -LiteralPath $Projet -ErrorAction Stop
    if (-not $dossier.PSIsContainer) {
        throw 'Le chemin du projet doit etre un dossier.'
    }
    $projetComplet = $dossier.FullName
    $outil = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    if (-not (Test-Path -LiteralPath (Join-Path $outil 'repoguard\__main__.py') -PathType Leaf)) {
        throw 'Le dossier RepoGuard est introuvable a cote du script.'
    }

    $python = $null
    $pythonOptions = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $python = 'py'
        $pythonOptions = @('-3')
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $python = 'python'
    } else {
        throw 'Python est introuvable. Installe Python 3.10 ou plus recent.'
    }
    & $python @pythonOptions -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    if ($LASTEXITCODE -ne 0) {
        throw 'Python 3.10 ou plus recent est requis.'
    }

    $dossierRapports = Join-Path $HOME 'RepoGuard-rapports'
    New-Item -ItemType Directory -Path $dossierRapports -Force -ErrorAction Stop | Out-Null
    $suffixe = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $rapport = Join-Path $dossierRapports ("rapport-" + $suffixe + '.html')
    $arguments = @('-m', 'repoguard', 'scan', $projetComplet, '--deep', '--lang', 'fr',
                   '--progress', '--format', 'html', '-o', $rapport)
    if ($OSV) {
        $arguments += '--osv'
        Write-Host 'OSV est active : noms, ecosystemes et versions des dependances lui sont transmis.'
    } else {
        Write-Host 'Analyse locale : aucune recherche OSV. Ajouter -OSV pour la demander.'
    }
    Write-Host "Analyse approfondie de : $projetComplet" -ForegroundColor Green
    Write-Host 'Cela peut prendre plusieurs minutes sur un grand projet.'
    Push-Location -LiteralPath $outil -ErrorAction Stop
    try {
        & $python @pythonOptions @arguments
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath $rapport -PathType Leaf)) {
        throw "Aucun rapport cree. Code de sortie : $code. Consulte les erreurs ci-dessus."
    }
    if ($code -ne 0) {
        Write-Warning "Le rapport existe mais l'analyse ou la recherche OSV peut etre incomplete (code $code). Consulte les notes de couverture."
    }
    Write-Host "Rapport local : $rapport" -ForegroundColor Green
    try {
        Start-Process -FilePath $rapport -ErrorAction Stop
    } catch {
        Write-Warning "Ouverture automatique impossible. Ouvre ce fichier manuellement : $rapport"
    }
    exit $code
} catch {
    Write-Host "Erreur : $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
