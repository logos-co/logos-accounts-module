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

## Testing

Unit tests live in `tests/` and use the [Logos Test Framework](https://github.com/logos-co/logos-test-framework). All Go Wallet SDK C calls are mocked at link time, so no Go toolchain is needed to run tests.

### Running tests

From inside the repo:

```bash
nix build .#unit-tests -L
```

Or from the workspace root:

```bash
ws test logos-accounts-module --auto-local
```

### Test structure

```
tests/
├── CMakeLists.txt              # Uses logos_test() from LogosTest.cmake
├── main.cpp                    # LOGOS_TEST_MAIN() entry point
├── test_keystore.cpp           # 35 tests covering keystore, ext-keystore, keys, mnemonic
├── mocks/
│   └── mock_gowalletsdk.cpp    # Link-time mocks for all GoWSK_* C functions
└── stubs/
    └── lib/
        └── libgowalletsdk.h    # Stub header (replaces CGo-generated header)
```

Tests cover:
- Keystore init/close, account creation, import/export, delete, address lookup
- Lock/unlock, timed unlock, signing (hash and transaction), ECDSA import
- Extended keystore (same operations plus key derivation)
- Key operations: mnemonic-to-extended-key, key derivation, ECDSA conversion, public-key-to-address
- Mnemonic generation (random, default-length, entropy strength)
- Edge cases: all operations return errors when keystore is not initialized

### Writing new tests

Add test cases to `test_keystore.cpp` or create new `test_*.cpp` files. Each test uses the framework's `LOGOS_TEST` macro and `LogosTestContext` for mocking:

```cpp
#include <logos_test.h>
#include "accounts_module_impl.h"

LOGOS_TEST(my_new_test) {
    auto t = LogosTestContext("accounts_module");
    t.mockCFunction("GoWSK_accounts_keystore_NewKeyStore").returns(1);

    AccountsModuleImpl impl;
    impl.initKeystore("/tmp/ks", 4096, 6);
    LOGOS_ASSERT_TRUE(impl.closeKeystore(""));
}
```

New test source files must be added to `TEST_SOURCES` in `tests/CMakeLists.txt`.

## Dependencies

- **logos-liblogos** - Core Logos library interface
- **logos-cpp-sdk** - C++ SDK for building Logos modules
- **go-wallet-sdk** - Go-based wallet SDK (compiled to C library)

