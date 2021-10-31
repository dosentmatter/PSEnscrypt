# PSEnscrypt
Create an encrypted and password-protected PowerShell script.

1. Uses `PSMinifier` to compress your input Script block before encryption.
2. Uses `AES-GCM` for encryption.
3. Uses `PSMinifier` to compress the encrypted output decrypt and run script for obfuscation.

## Usage
1. Currently, I haven't implemented any command line parameter passing, so you have to add your script in the [`$scriptBlock` variable](https://github.com/dosentmatter/PSEnscrypt/blob/bd00590bc9130bbf6c0cd80d0a5b76b0549013c6/PSEnscrypt.ps1#L93-L94).
2. Run `.\PSEnscrypt.ps1`.
3. Enter a password at the prompt.
4. Encrypted and compressed output script will be shown.

To execute the output immediately:
1. `.\PSEnscrypt.ps1 | iex`.
2. Enter the same password twice.

To output script to another file for delayed execution:
1. `.\PSEnscrypt.ps1 | Set-Content .\MyScript.ps1`.
2. Enter a password at the prompt.
3. To run the encrypted script, use `.\MyScript.ps1`.
4. Enter the previously used password.

## Windows PowerShell 5.1 Support
Currently, `PSEnscrypt` doesn't support Windows PowerShell 5.1 because I am using the .NET `AesGcm` Class, which doesn't exist in the .NET Framework that Windows PowerShell 5.1 is built on.
I plan to support Windows PowerShell 5.1 in the future. Probably by using `AEAD-AES-CBC-HMAC-SHA`.

## Disclaimer
I am not a cryptographer, so use this at your own risk.
