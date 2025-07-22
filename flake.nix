
{
  description = "swtpm-proxy Go package";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
        f (import nixpkgs { inherit system; })
      );
    in {
      packages = forAllSystems (pkgs:
        pkgs.buildGoModule {
          pname = "swtpm-proxy";
          version = "0.0.1";
          src = ./.;
          vendorHash = "sha256-s1oLreAT112iz7NP/KKKjjlBKNnclmmfj/3nIZuKnSA="; 
          subPackages = [ "cmd/swtpm-proxy" ];

          overrideModAttrs = old: {
            buildFlags = [ "-mod=mod" ];
          };

          meta = with pkgs.lib; {
            description = "A proxy for swtpm written in Go.";
            license = licenses.mit;
            platforms = platforms.linux;
          };
        }
      );
      defaultPackage = forAllSystems (pkgs: self.packages.${pkgs.system});
    };
}