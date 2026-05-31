# Running This Accounts Module Against logoscore

`logos-accounts-module` is a Logos `core` module that wraps the
[go-wallet-sdk](https://github.com/status-im/go-wallet-sdk) C library to provide
mnemonic generation and keystore/key management. This doc-test exercises **this**
accounts-module commit end-to-end through the headless `logoscore` runtime:

1. Build the `logoscore` CLI and the `lgpm` local package manager from their
   published flakes. `logoscore` is the headless frontend for `logos-liblogos`,
   so building it brings in the whole module-runtime stack (`logos_host`,
   `liblogos_core`, the IPC layer).
2. Build **this** accounts module as an installable `.lgx` package straight from
   its own flake's `#lgx` output, **pinned to the commit under test** — so the
   module you run is built from exactly what is checked out here, not the latest
   published release.
3. Install the `.lgx` into a `./modules` directory with `lgpm`.
4. Start `logoscore` in daemon mode (`-D`), load `accounts_module`, introspect
   it with `module-info`, and call several of its methods — verifying the module
   actually runs and round-trips real values through the go-wallet-sdk.

Because the module is built from the commit under test and then loaded and called
through a real `logoscore` daemon, a green run is real evidence that this change
keeps the accounts module loadable and callable.

**What you'll build:** This `accounts_module`, packaged as `.lgx`, installed with `lgpm`, and called through a `logoscore` daemon.

**What you'll learn:**

- How to build the `logoscore` runtime and the `lgpm` package manager from their flakes
- How a module's flake exposes a ready-to-install `.lgx` via its `#lgx` output
- How to install an `.lgx` into a modules directory with `lgpm`
- How to start the `logoscore` daemon, load a module, introspect it, and call its methods
- How to shut the daemon down and confirm it has exited

## Prerequisites

- **Nix** with flakes enabled. Install from [nixos.org](https://nixos.org/download.html), then enable flakes:

```bash
mkdir -p ~/.config/nix
echo 'experimental-features = nix-command flakes' >> ~/.config/nix/nix.conf
```

Verify: `nix flake --help >/dev/null 2>&1 && echo "Flakes enabled"`

- **A Linux or macOS machine.**

---

## Step 1: Build logoscore

Build the `logoscore` CLI from its published flake. The result is symlinked to
`./logos/`. `logoscore` is the headless frontend for `logos-liblogos`, so this
one build brings in the whole module-runtime stack the daemon needs.

### 1.1 Build the CLI

```bash
nix build 'github:logos-co/logos-logoscore-cli' --out-link ./logos
```

The build produces `logos/bin/logoscore` plus bundled runtime libraries
and a `logos/modules/` directory containing the built-in
`capability_module` (required for the auth handshake when loading
modules).

---

## Step 2: Build the lgpm package manager

`lgpm` installs `.lgx` packages into a modules directory and scans what is
installed. Build it from the `logos-package-manager` flake and link it as
`./lgpm`.

### 2.1 Build lgpm

```bash
nix build 'github:logos-co/logos-package-manager#cli' -o lgpm
```

The executable is at `./lgpm/bin/lgpm`.

---

## Step 3: Build and install this accounts module

Build **this** accounts module's `.lgx` straight from its flake's `#lgx`
output and install it into a local `./modules` directory with `lgpm`. Every
module built with
[`logos-module-builder`](https://github.com/logos-co/logos-module-builder)
exposes a ready-to-install `#lgx`.

> The `` in the URL is what pins the build to a specific commit: the
> doc-test runner expands it to a concrete ref. Locally that is this
> checkout's `HEAD` (see `run.sh`); in CI it is the commit being tested. With
> no pin it falls back to the latest `master`.

### 3.1 Build the module's .lgx

Build the `#lgx` output and link it as `./accounts-lgx`. (This compiles
the module and its SDK dependencies through Nix, so the first build is
slow.)

```bash
# From inside the clone this is simply: nix build '.#lgx'
nix build 'github:logos-co/logos-accounts-module/a419d24945cbed127667a4a2a92770839294decb#lgx' -o accounts-lgx
```

The `.lgx` package is now under `./accounts-lgx/`:

```bash
ls accounts-lgx/*.lgx
```

### 3.2 Seed the modules directory with the bundled capability module

`accounts_module` is loaded through the host's capability layer, so the
modules directory also needs the `capability_module` that ships with
`logoscore`. Copy it across first.

```bash
mkdir -p modules
cp -RL ./logos/modules/. ./modules/

```

### 3.3 Install the .lgx with lgpm

Install the freshly-built package into `./modules`. `accounts_module` is
a `core` module, so it goes to `--modules-dir`. The package is unsigned
(a local dev build), so we pass `--allow-unsigned`.

```bash
./lgpm/bin/lgpm --modules-dir ./modules --allow-unsigned install --file accounts-lgx/*.lgx
```

### 3.4 Confirm the install

Scan the directory and confirm the module landed:

```bash
./lgpm/bin/lgpm --modules-dir ./modules list
```

---

## Step 4: Run the daemon and call the module

Start `logoscore` in daemon mode pointed at `./modules`, then use the client
subcommands to load `accounts_module`, introspect it, and call several of its
methods. Daemon output is captured in `logs.txt`.

### 4.1 Start the daemon

Start logoscore in daemon mode in the background, capturing output to
`logs.txt`:

```bash
logoscore -D -m ./modules > logs.txt &
```

The `-D` flag starts the daemon. The client subcommands below connect to
this running process via the config written under `~/.logoscore/`.

```bash
sleep 3
```

### 4.2 Inspect the startup log

Review the daemon's startup output:

```bash
cat logs.txt
```

### 4.3 Check daemon status

Verify the daemon is running:

```bash
logoscore status
```

### 4.4 List discovered modules

`accounts_module` should be visible in the scan directory:

```bash
logoscore list-modules
```

### 4.5 Load the module

Load `accounts_module` into the running daemon:

```bash
logoscore load-module accounts_module
```

### 4.6 Confirm the module is loaded

Re-run `status`; the module that was `not_loaded` before now reports
`loaded`:

```bash
logoscore status
```

### 4.7 Introspect the module with module-info

`module-info` lists the `Q_INVOKABLE` methods the module exposes — the
same methods you can `call`:

```bash
logoscore module-info accounts_module
```

### 4.8 Generate a random mnemonic

`createRandomMnemonic` takes a word count and returns a fresh BIP-39
phrase — a real round-trip through the go-wallet-sdk C library wrapped by
the module, dispatched over liblogos' IPC:

```bash
logoscore call accounts_module createRandomMnemonic 12
```

### 4.9 Generate a default-length mnemonic

`createRandomMnemonicWithDefaultLength` takes no arguments and returns a
phrase of the SDK's default length:

```bash
logoscore call accounts_module createRandomMnemonicWithDefaultLength
```

### 4.10 Map a word count to entropy strength

`lengthToEntropyStrength` maps a mnemonic word count to its entropy
strength in bits — 12 words is 128 bits. This exercises an `int`
round-trip:

```bash
logoscore call accounts_module lengthToEntropyStrength 12
```

```bash
logoscore call accounts_module lengthToEntropyStrength 24
```

### 4.11 Create and use a keystore

Initialise a keystore in a fresh directory (`scryptN`=4096, `scryptP`=6
keep the test fast), then create a new account in it. `keystoreNewAccount`
returns the new account's address:

```bash
logoscore call accounts_module initKeystore ./ks 4096 6
```

```bash
logoscore call accounts_module keystoreNewAccount test-passphrase
```

### 4.12 List the keystore's accounts

`keystoreAccounts` returns the accounts now present in the keystore — the
one we just created:

```bash
logoscore call accounts_module keystoreAccounts
```

### 4.13 Stop the daemon

Shut the daemon down cleanly:

```bash
logoscore stop
```

The daemon removes its state file and exits.

```bash
sleep 2
```

### 4.14 Confirm the daemon has stopped

With no daemon running, the client reports `not_running` and exits
non-zero, so we add `|| true` to let the doc-test assert on the output:

```bash
logoscore status
```
