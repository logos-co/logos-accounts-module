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
      tests = {
        dir = ./tests;
        mockCLibs = ["gowalletsdk"];
      };
    };
}
