using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

if (-not (Get-Module -ListAvailable -Name PSMinifier)) {
    try {
        Install-Module -Name PSMinifier -AllowClobber -Confirm:$False -Force
    }
    catch [System.Exception] {
        $_.message 
        exit
    }
} 

# Copied from:
# https://stackoverflow.com/a/42108420/7381355
function Using-Object {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [AllowNull()]
        [Object]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock
    )

    try {
        . $ScriptBlock
    }
    finally {
        if ($null -ne $InputObject -and $InputObject -is [System.IDisposable]) {
            $InputObject.Dispose()
        }
    }
}

# Ported from:
# https://stackoverflow.com/a/43858011/7381355
function Create-Derive-Bytes {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SecureString]
        $password,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $salt,

        [Parameter(Mandatory = $true)]
        [Int32]
        $iterations,

        [Parameter(Mandatory = $true)]
        [HashAlgorithmName]
        $hashAlgorithm
    )

    $ptr = [Marshal]::SecureStringToBSTR($password)
    $passwordByteArray = $null
    try {
        $length = [Marshal]::ReadInt32($ptr, -4)
        $passwordByteArray = [byte[]]::new($length)
        $handle = [GCHandle]::Alloc($passwordByteArray, [GCHandleType]::Pinned)
        try {
            for ($i = 0; $i -lt $length; $i++) {
                $passwordByteArray[$i] = [Marshal]::ReadByte($ptr, $i)
            }

            [Rfc2898DeriveBytes]::new(
                $passwordByteArray,
                $salt,
                $iterations,
                $hashAlgorithm
            )
        }
        finally {
            # Clearing `$passworByteArray` is okay since .NET clones the array.
            # https://stackoverflow.com/questions/9734043/rfc2898derivebytes-pbkdf2-securestring-is-it-possible-to-use-a-secure-string/43858011#comment122723615_43858011
            [System.Array]::Clear($passwordByteArray, 0, $passwordByteArray.length)
            $handle.Free()
        }
    }
    finally {
        [Marshal]::ZeroFreeBSTR($ptr)
    }
}

$scriptBlock = {
}

$compressedScriptBlockCreateCommand = Compress-ScriptBlock -ScriptBlock $scriptBlock -GZip -NoBlock

$salt = $null
$nonceRef = [ref]$null
$ciphertextRef = [ref]$null
$tagRef = [ref]$null

# Salt size taken from here:
# https://www.veracrypt.fr/en/Header%20Key%20Derivation.html
$saltBytes = [byte[]]::new(64)
Using-Object ($rng = [RandomNumberGenerator]::Create()) {
    $rng.GetBytes($saltBytes)
}
$salt = [System.Convert]::ToBase64String($saltBytes)

# Iterations and hash algorithm taken from:
# https://www.veracrypt.fr/en/Header%20Key%20Derivation.html
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
# No need to pre-hash since .NET already does it:
# https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/rfc2898derivebytes.cs,112
# https://referencesource.microsoft.com/#mscorlib/system/security/cryptography/hmac.cs,81
$deriveBytesArguments = @{
    password      = (Read-Host -Prompt 'Enter Password' -AsSecureString)
    salt          = $saltBytes
    iterations    = 500000
    hashAlgorithm = [HashAlgorithmName]::SHA256
}
Using-Object ($deriveBytes = Create-Derive-Bytes @deriveBytesArguments) {
    $key = $null
    $handle = $null

    try {
        $key = $deriveBytes.GetBytes(32)
        $handle = [GCHandle]::Alloc($key, [GCHandleType]::Pinned)
        Using-Object ($aesGcm = [AesGcm]::new($key)) {
            $nonceBytes = [byte[]]::new([AesGcm]::NonceByteSizes.MaxSize)
            Using-Object ($rng = [RandomNumberGenerator]::Create()) {
                $rng.GetBytes($nonceBytes)
            }

            $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($compressedScriptBlockCreateCommand)
            $ciphertextBytes = [byte[]]::new($plaintextBytes.Length)
            $tagBytes = [byte[]]::new([AesGcm]::TagByteSizes.Maxsize)

            $aesGcm.Encrypt(
                $nonceBytes,
                $plaintextBytes,
                $ciphertextBytes,
                $tagBytes
            )

            $nonceRef.Value = [System.Convert]::ToBase64String($nonceBytes)
            $ciphertextRef.Value = [System.Convert]::ToBase64String($ciphertextBytes)
            $tagRef.Value = [System.Convert]::ToBase64String($tagBytes)
        }
    }
    finally {
        if ($null -ne $key) {
            [System.Array]::Clear($key, 0, $key.length)
        }
        if ($null -ne $handle) {
            $handle.Free()
        }
    }
}

$decryptAndRunScriptBlockCreateCommand = @(@'
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices
'@, @"

function Using-Object {${function:Using-Object}}

function Create-Derive-Bytes {${function:Create-Derive-Bytes}}
"@, @"

`$saltBytes = [System.Convert]::FromBase64String('$salt')
`$nonceBytes = [System.Convert]::FromBase64String('$($nonceRef.Value)')
`$ciphertextBytes = [System.Convert]::FromBase64String('$($ciphertextRef.Value)')
`$tagBytes = [System.Convert]::FromBase64String('$($tagRef.Value)')
"@, {
$command = $null

$deriveBytesArguments = @{
    password      = (Read-Host -Prompt 'Enter Password' -AsSecureString)
    salt          = $saltBytes
    iterations    = 500000
    hashAlgorithm = [HashAlgorithmName]::SHA256
}
Using-Object ($deriveBytes = Create-Derive-Bytes @deriveBytesArguments) {
    $key = $null
    $handle = $null

    try {
        $key = $deriveBytes.GetBytes(32)
        $handle = [GCHandle]::Alloc($key, [GCHandleType]::Pinned)
        Using-Object ($aesGcm = [AesGcm]::new($key)) {
            $plaintextBytes = [byte[]]::new($ciphertextBytes.Length)

            try {
                $aesGcm.Decrypt(
                    $nonceBytes,
                    $ciphertextBytes,
                    $tagBytes,
                    $plaintextBytes
                )
            } catch [CryptographicException] {
                Write-Host 'Wrong Password'
                exit
            }

            Set-Variable -Scope 2 -Name command -Value ([System.Text.Encoding]::UTF8.GetString($plainTextBytes))
        }
    } finally {
        if ($null -ne $key) {
            [System.Array]::Clear($key, 0, $key.length)
        }
        if ($null -ne $handle) {
            $handle.Free()
        }
    }
}

$command |
Invoke-Expression |
ForEach-Object { & $_ }
}.ToString()
) -join "`r`n"

$decryptAndRunScriptBlockCreateScriptBlock = [scriptblock]::Create($decryptAndRunScriptBlockCreateCommand)

"$(Compress-ScriptBlock -ScriptBlock $decryptAndRunScriptBlockCreateScriptBlock -GZip -NoBlock)|%{&`$_}"
