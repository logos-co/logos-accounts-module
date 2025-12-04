# Logos Accounts Module

A Logos module that provides accounts functionality, including mnemonic generation, extended and private key management and keystores via the go-wallet-sdk.

## Prerequisites

- CMake 3.14 or later
- Qt 6 (or Qt 5)
- Go compiler (for building go-wallet-sdk)
- C++ compiler with C++17 support

## Building

## Building with Nix

```bash
# Build
nix build

# Enter development shell
nix develop
```

## Module Structure

- `accounts_module_plugin.cpp/h` - Main plugin implementation
- `accounts_module_interface.h` - Module interface definition
- `metadata.json` - Module metadata
- `lib/` - Contains the built accounts library
- `vendor/` - Vendored dependencies (logos-liblogos, logos-cpp-sdk, go-wallet-sdk)

## Output

The built plugin will be in `build/modules/accounts_module_plugin.dylib` (macOS) or `build/modules/accounts_module_plugin.so` (Linux).

## Usage

The accounts module can be loaded by the Logos core system and provides accounts-related capabilities to applications.

## Dependencies

- **logos-liblogos** - Core Logos library interface
- **logos-cpp-sdk** - C++ SDK for building Logos modules
- **go-wallet-sdk** - Go-based wallet SDK (compiled to C library)

