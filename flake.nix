{
  description = "Logos Accounts Module - An accounts plugin for Logos";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder/use_experimental_backend";
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
        # Generate Qt glue directly from impl header (no .lidl file needed)
        logos-cpp-generator --from-header src/accounts_module_impl.h \
          --backend qt \
          --impl-class AccountsModuleImpl \
          --impl-header accounts_module_impl.h \
          --metadata metadata.json \
          --output-dir ./generated_code
      '';
    };
}
