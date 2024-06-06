# c_sharp_tls_debugger

Example source code written in C# in order to debug TLS communication


# how to build

```
dotnet restore
dotnet build --configuration Release
```

# usage

```
MTLSExample.exe <https_endpoint> <pfx_path> <pfx_passphrase> <tls_version> <cipher_suite> <ca_chain_path>
```

Example command:

```
MTLSExample.exe https://example.com clientcert.pfx mypassphrase TLS1.2 AES256-SHA256 ca_chain.pem
```
