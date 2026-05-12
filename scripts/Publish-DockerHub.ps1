[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,

    [string]$Tag = "latest",

    [string]$ImageName = "semantic-soc-analyst",

    [string]$ContextPath,

    [switch]$SkipSmokeTest,

    [string]$EnvFile
)

$ErrorActionPreference = "Stop"

function Invoke-DockerCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: docker $($Arguments -join ' ')"
    }
}

if (-not $ContextPath) {
    $ContextPath = Resolve-Path (Join-Path $PSScriptRoot "..")
}
else {
    $ContextPath = Resolve-Path $ContextPath
}

$localImage = "$ImageName`:$Tag"
$remoteImage = "$Repository`:$Tag"

Push-Location $ContextPath
try {
    if ($PSCmdlet.ShouldProcess($localImage, "build Docker image")) {
        Write-Host "Building $localImage from $ContextPath"
        Invoke-DockerCommand -Arguments @("build", "-t", $localImage, ".")
    }

    if ($PSCmdlet.ShouldProcess($remoteImage, "tag Docker image")) {
        Write-Host "Tagging $localImage as $remoteImage"
        Invoke-DockerCommand -Arguments @("tag", $localImage, $remoteImage)
    }

    if ($PSCmdlet.ShouldProcess($remoteImage, "push Docker image to DockerHub")) {
        Write-Host "Pushing $remoteImage"
        Invoke-DockerCommand -Arguments @("push", $remoteImage)
    }

    if ($PSCmdlet.ShouldProcess($remoteImage, "pull Docker image from DockerHub")) {
        Write-Host "Pulling $remoteImage to confirm the published image is available"
        Invoke-DockerCommand -Arguments @("pull", $remoteImage)
    }

    if (-not $SkipSmokeTest) {
        $safeTag = ($Tag -replace "[^a-zA-Z0-9_.-]", "-")
        $containerName = "semantic-soc-analyst-smoke-$safeTag"
        $runArguments = @("run", "--rm", "-d", "--name", $containerName, "-p", "8501:8501")

        if ($EnvFile) {
            $runArguments += @("--env-file", $EnvFile)
        }

        $runArguments += $remoteImage

        if ($PSCmdlet.ShouldProcess($remoteImage, "start a smoke-test container")) {
            $containerId = & docker @runArguments
            if ($LASTEXITCODE -ne 0) {
                throw "Smoke-test container could not start."
            }

            Write-Host "Smoke-test container started: $containerId"
            Write-Host "Review the logs with: docker logs --tail 50 $containerName"
            Write-Host "Stop the container with: docker stop $containerName"
        }
    }
}
finally {
    Pop-Location
}