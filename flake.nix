{
  description = "Logos Accounts Module - An accounts plugin for Logos";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    nix-bundle-lgx.url = "github:logos-co/nix-bundle-lgx";
    go-wallet-sdk = {
      url = "github:status-im/go-wallet-sdk/0938a704506b0ff444378045d17be9e19e699d80";
      flake = false;
    };
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
      externalLibInputs = {
        gowalletsdk = inputs.go-wallet-sdk;
      };
      # The builder copies external lib binaries to lib/ but not headers.
      # Copy the generated CGo header alongside the static library.
      preConfigure = ''
        for store_path in /nix/store/*-logos-external-gowalletsdk-*/include; do
          if [ -d "$store_path" ]; then
            cp "$store_path"/*.h lib/ 2>/dev/null || true
          fi
        done

        # Run LIDL generator to produce Qt glue
        logos-cpp-generator --lidl accounts_module.lidl \
          --backend qt \
          --impl-class AccountsModuleImpl \
          --impl-header accounts_module_impl.h \
          --output-dir ./generated_code

        # Remove generated Plugin class (we use our own loader)
        sed -i '/^class AccountsModulePlugin/,/^};$/d' generated_code/accounts_module_qt_glue.h
      '';
    };
}
