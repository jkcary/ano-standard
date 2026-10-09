[CmdletBinding()]
param(
    [string]$KindCommand = "kind",
    [string]$KubectlCommand = "kubectl",
    [string]$DockerCommand = "docker",
    [string]$PythonCommand = ""
)

$ErrorActionPreference = "Stop"
$standardRoot = Split-Path -Parent $PSScriptRoot
$clusterName = "ano-alpha8"
if (-not $PythonCommand) {
    $PythonCommand = Join-Path $standardRoot ".venv\Scripts\python.exe"
}
$kindConfig = Join-Path $standardRoot "lab\kind-calico.yaml"
$harness = Join-Path $standardRoot "tools\run_cluster_lab.py"
$calicoUri = "https://raw.githubusercontent.com/projectcalico/calico/v3.31.6/manifests/calico.yaml"
$calicoExpectedHash = "34012557637766d4367f0e7d2ea8b6507fca6df68e08b87fcdcd527f689e2637"
$busyboxTag = "busybox:1.36.1"
$busyboxDigest = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
$temporaryParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = [IO.Path]::GetFullPath((Join-Path $temporaryParent ("ano-alpha8-" + [guid]::NewGuid().ToString("N"))))
$manifest = Join-Path $temporaryRoot "calico-v3.31.6.yaml"
$clusterCreated = $false

function Assert-NativeSuccess([string]$Operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code $LASTEXITCODE"
    }
}

try {
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $existingClusters = @(& $KindCommand get clusters 2>$null)
    if ($existingClusters -contains $clusterName) {
        throw "Refusing to replace existing kind cluster '$clusterName'"
    }
    & $DockerCommand pull $busyboxTag
    Assert-NativeSuccess "docker pull"
    $repoDigestsJson = & $DockerCommand image inspect $busyboxTag --format "{{json .RepoDigests}}"
    Assert-NativeSuccess "docker image inspect"
    $repoDigests = $repoDigestsJson | ConvertFrom-Json
    if ($repoDigests -notcontains $busyboxDigest) {
        throw "BusyBox tag does not resolve to the approved digest"
    }

    $clusterCreated = $true
    & $KindCommand create cluster --config $kindConfig
    Assert-NativeSuccess "kind create cluster"

    Invoke-WebRequest -UseBasicParsing $calicoUri -OutFile $manifest
    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $manifest).Hash.ToLowerInvariant()
    if ($actualHash -ne $calicoExpectedHash) {
        throw "Calico manifest digest mismatch: $actualHash"
    }
    & $KubectlCommand --context "kind-$clusterName" apply -f $manifest
    Assert-NativeSuccess "Calico apply"
    & $KubectlCommand --context "kind-$clusterName" -n kube-system rollout status daemonset/calico-node --timeout=240s
    Assert-NativeSuccess "Calico rollout"

    & $KindCommand load docker-image $busyboxTag --name $clusterName
    Assert-NativeSuccess "kind image load"
    $kindVersionOutput = (& $KindCommand version) -join " "
    $kindVersion = [regex]::Match($kindVersionOutput, "v\d+\.\d+\.\d+").Value
    if (-not $kindVersion) { $kindVersion = $kindVersionOutput }

    & $PythonCommand $harness `
        --context "kind-$clusterName" `
        --image $busyboxDigest `
        --cluster-type kind `
        --cluster-runtime-version $kindVersion `
        --network-policy-provider calico `
        --network-policy-version v3.31.6 `
        --network-policy-manifest-sha256 "sha256:$calicoExpectedHash"
    Assert-NativeSuccess "ANO isolated cluster validation"
}
finally {
    if ($clusterCreated) {
        & $KindCommand delete cluster --name $clusterName
    }
    if ($temporaryRoot.StartsWith($temporaryParent, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $temporaryRoot)) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
