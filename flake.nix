{
  description = "Unicode standard — machine-checked specifications in Lean 4 (UCD 17.0.0)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Swift 5.10.1 is the only swift in nixpkgs and cannot build from source
    # against current glibc (2.42 defaults TLS to gnu2; swift's bundled clang-16
    # rejects `-mtls-dialect=gnu2`), which is why nixpkgs HEAD has no cached
    # swift. This pin resolves swift to a store path that IS substitutable, so
    # the swift port builds+tests from a binary rather than a doomed source
    # build. Only the swift derivation reads this input; everything else tracks
    # the latest nixpkgs above.
    nixpkgs-swift.url = "github:NixOS/nixpkgs/0726a0ecb6d4e08f6adced58726b95db924cef57";
  };

  outputs = { self, nixpkgs, nixpkgs-swift, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        pkgsSwift = nixpkgs-swift.legacyPackages.${system};
        hsPkgs = pkgs.haskell.packages.ghc912;
        hsPortGhc = hsPkgs.ghcWithPackages (hpkgs: [
          hpkgs.QuickCheck
          hpkgs.tasty
          hpkgs.tasty-hunit
          hpkgs.tasty-quickcheck
        ]);
        runtimeVersion = "0.1.0";
        runtimePackages = [
          pkgs.git
          pkgs.cacert
          pkgs.cmake
          pkgs.ninja
          pkgs.gcc
          pkgs.clang-tools
          pkgs.shellcheck
          pkgs.rustc
          pkgs.cargo
          pkgs.rustfmt
          pkgs.uv
          pkgs.python3
          pkgs.python3Packages.build
          pkgs.python3Packages.hatchling
          pkgs.python3Packages.pip
          pkgs.python3Packages.pytest
          hsPortGhc
          pkgs.cabal-install
          pkgs.go
          pkgs.jdk
          pkgs.nodejs
          pkgs.ruby
          pkgs.lua5_4
          pkgs.php
          pkgs.dotnet-sdk_8
          pkgs.swift
          pkgs.swiftpm
          pkgs.zig
        ];

        unicodeSecurity = pkgs.rustPlatform.buildRustPackage {
          pname = "unicode-security";
          version = runtimeVersion;
          src = ./ports/rust;
          cargoLock.lockFile = ./ports/rust/Cargo.lock;
          cargoBuildFlags = [ "--bin" "unicode-security" ];
          doCheck = false;
        };

        unicodePython = pkgs.python3Packages.buildPythonPackage {
          pname = "unicode-python";
          version = runtimeVersion;
          pyproject = true;
          src = ./ports/python;
          build-system = [ pkgs.python3Packages.hatchling ];
          doCheck = false;
          pythonImportsCheck = [ "unicode_python" ];
        };

        unicodeCpp = pkgs.stdenv.mkDerivation {
          pname = "unicode-cpp";
          version = runtimeVersion;
          src = ./ports/cpp;
          nativeBuildInputs = [ pkgs.cmake ];
          cmakeFlags = [ "-DUNICODE_CPP_BUILD_TESTS=OFF" ];
        };

        unicodeHaskell = hsPkgs.callCabal2nix "unicode-haskell" ./ports/haskell {};

        unicodeJvm = pkgs.stdenv.mkDerivation {
          pname = "unicode-jvm";
          version = runtimeVersion;
          src = ./ports/jvm;
          nativeBuildInputs = [ pkgs.jdk ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            bash scripts/test.sh
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-jvm
            cp -R README.md scripts src testdata $out/share/unicode-jvm/
            runHook postInstall
          '';
        };

        unicodeGo = pkgs.stdenv.mkDerivation {
          pname = "unicode-go";
          version = runtimeVersion;
          src = ./ports/go;
          nativeBuildInputs = [ pkgs.go ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            export HOME=$TMPDIR/home
            export GOCACHE=$TMPDIR/go-build
            export GOMODCACHE=$TMPDIR/go-mod
            mkdir -p "$HOME" "$GOCACHE" "$GOMODCACHE"
            go test ./...
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-go
            cp -R README.md go.mod security $out/share/unicode-go/
            runHook postInstall
          '';
        };

        unicodeTypescript = pkgs.stdenv.mkDerivation {
          pname = "unicode-typescript";
          version = runtimeVersion;
          src = ./ports/typescript;
          nativeBuildInputs = [ pkgs.nodejs ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            node --test test/*.test.js
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-typescript
            cp -R README.md package.json src test testdata $out/share/unicode-typescript/
            runHook postInstall
          '';
        };

        unicodeRuby = pkgs.stdenv.mkDerivation {
          pname = "unicode-ruby";
          version = runtimeVersion;
          src = ./ports/ruby;
          nativeBuildInputs = [ pkgs.ruby ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            find lib -name '*.rb' -print0 | xargs -0 -n1 ruby -c
            bash scripts/test.sh
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-ruby
            cp -R data lib scripts test testdata $out/share/unicode-ruby/
            runHook postInstall
          '';
        };

        unicodeLua = pkgs.stdenv.mkDerivation {
          pname = "unicode-lua";
          version = runtimeVersion;
          src = ./ports/lua;
          nativeBuildInputs = [ pkgs.lua5_4 ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            bash scripts/test.sh
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-lua
            cp -R data scripts src test testdata $out/share/unicode-lua/
            runHook postInstall
          '';
        };

        unicodePhp = pkgs.stdenv.mkDerivation {
          pname = "unicode-php";
          version = runtimeVersion;
          src = ./ports/php;
          nativeBuildInputs = [ pkgs.php ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            find src test -name '*.php' -print0 | xargs -0 -n1 php -l
            bash scripts/test.sh
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-php
            cp -R data scripts src test testdata $out/share/unicode-php/
            runHook postInstall
          '';
        };

        unicodeDotnet = pkgs.stdenv.mkDerivation {
          pname = "unicode-dotnet";
          version = runtimeVersion;
          src = ./ports/dotnet;
          nativeBuildInputs = [ pkgs.dotnet-sdk_8 ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            export DOTNET_CLI_HOME=$TMPDIR/dotnet-home
            export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
            export DOTNET_NOLOGO=1
            dotnet run --project test/UnicodeSecurity.Tests/UnicodeSecurity.Tests.csproj
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-dotnet
            cp -R README.md Data src test testdata $out/share/unicode-dotnet/
            find $out/share/unicode-dotnet -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +
            runHook postInstall
          '';
        };

        unicodeSwift = pkgsSwift.swiftPackages.stdenv.mkDerivation {
          pname = "unicode-swift";
          version = runtimeVersion;
          src = ./ports/swift;
          # swiftpm's setup hook assembles the Foundation/Dispatch/CoreFoundation
          # resource directory into the swift module search path; Foundation is a
          # real build input so `import Foundation` resolves on Linux. A bare
          # `nix shell #swift` does NOT wire this and cannot compile the port.
          # swift comes from nixpkgs-swift (a pinned rev with a cached swift),
          # not the top-level latest nixpkgs whose swift is unbuildable.
          nativeBuildInputs = [ pkgsSwift.swift pkgsSwift.swiftpm ];
          buildInputs = [ pkgsSwift.swiftPackages.Foundation pkgsSwift.swiftPackages.Dispatch ];
          dontConfigure = true;
          # swiftpm's Package.swift manifest binary is executed with an rpath
          # that omits libdispatch in this nixpkgs pin; put the Dispatch and
          # Foundation runtime libs on LD_LIBRARY_PATH so the manifest compile
          # and the built test binary both load.
          swiftRuntimeLibs = pkgsSwift.lib.makeLibraryPath [
            pkgsSwift.swiftPackages.Dispatch
            pkgsSwift.swiftPackages.Foundation
          ];
          buildPhase = ''
            runHook preBuild
            export HOME=$TMPDIR/home
            mkdir -p "$HOME"
            export LD_LIBRARY_PATH="$swiftRuntimeLibs''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            swift build -c release
            runHook postBuild
          '';
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            export LD_LIBRARY_PATH="$swiftRuntimeLibs''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            swift run -c release UnicodeSecurityContractTests
            runHook postCheck
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/share/unicode-swift
            cp -R README.md Package.swift scripts Sources ContractTests $out/share/unicode-swift/
            find $out/share/unicode-swift -type d -name .build -prune -exec rm -rf {} +
            runHook postInstall
          '';
        };

        unicodeZig = pkgs.stdenv.mkDerivation {
          pname = "unicode-zig";
          version = runtimeVersion;
          src = ./.;
          nativeBuildInputs = [ pkgs.zig ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            cd ports/zig
            export ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-global
            zig build install --prefix $out
            mkdir -p $out/share/unicode-zig
            cp -R README.md build.zig src testdata $out/share/unicode-zig/
            runHook postBuild
          '';
          installPhase = "true";
        };

        # Lean 4.32.0 toolchain (see ./lean-toolchain) pinned via elan; fetched
        # at build time because no Lean 4.32.0 derivation exists in nixpkgs yet.
        runtimeShell = pkgs.mkShell {
          packages = runtimePackages;
        };

        leanShell = pkgs.mkShell {
          packages = runtimePackages ++ [
            pkgs.elan
          ];
          shellHook = ''
            export ELAN_HOME="$PWD/.elan"
            export PATH="$ELAN_HOME/bin:$PATH"
            elan toolchain install $(cat lean-toolchain) 2>/dev/null || true
            elan default $(cat lean-toolchain) 2>/dev/null || true
          '';
        };
      in {
        # ── nix build ──────────────────────────────────────────────
        # Builds the full Lean library via lake. Self-contained: no
        # Mathlib, no external Lean dependencies. The Lean toolchain
        # is fetched at build time via elan (network access required
        # on first build; cached thereafter).
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "unicode";
          version = "0.1.0";
          src = ./.;

          nativeBuildInputs = [
            pkgs.elan
            pkgs.git
            pkgs.curl
            pkgs.cacert
          ];

          __noChroot = true;

          buildPhase = ''
            export HOME=$TMPDIR
            export ELAN_HOME=$TMPDIR/.elan
            export PATH=$ELAN_HOME/bin:$PATH
            elan toolchain install $(cat lean-toolchain)
            elan default $(cat lean-toolchain)
            lake build
          '';

          installPhase = ''
            mkdir -p $out
            cp -r .lake/build $out/
          '';
        };

        packages.unicode-lean = self.packages.${system}.default;
        packages.unicode-security = unicodeSecurity;
        packages.unicode-rust = unicodeSecurity;
        packages.unicode-python = unicodePython;
        packages.unicode-cpp = unicodeCpp;
        packages.unicode-haskell = unicodeHaskell;
        packages.unicode-jvm = unicodeJvm;
        packages.unicode-go = unicodeGo;
        packages.unicode-typescript = unicodeTypescript;
        packages.unicode-ruby = unicodeRuby;
        packages.unicode-lua = unicodeLua;
        packages.unicode-php = unicodePhp;
        packages.unicode-dotnet = unicodeDotnet;
        packages.unicode-swift = unicodeSwift;
        packages.unicode-zig = unicodeZig;

        # ── nix flake check ───────────────────────────────────────
        # Two checks: the build itself, plus the proof-gap scan.
        checks.no-sorry = pkgs.runCommand "unicode-no-sorry" {
          src = ./.;
          buildInputs = [ pkgs.bash ];
        } ''
          cp -r $src/* .
          ${pkgs.bash}/bin/bash scripts/check-sorry.sh
          mkdir -p $out
          touch $out/result
        '';

        checks.runtime-boundary = pkgs.runCommand "unicode-runtime-boundary" {
          src = ./.;
          buildInputs = [ pkgs.bash pkgs.gnugrep pkgs.gawk pkgs.coreutils ];
        } ''
          cp -r $src/* .
          ${pkgs.bash}/bin/bash scripts/check-runtime-import-boundary.sh
          mkdir -p $out
          touch $out/result
        '';

        checks.build = self.packages.${system}.default;

        # ── nix run ────────────────────────────────────────────────
        # Status report: file count, theorem count, proof-gap count, per-pillar
        # progress.
        apps.default = {
          type = "app";
          program = toString (pkgs.writeShellScript "unicode-status" ''
            set -euo pipefail
            cd $PWD
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "                // unicode // status //"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""

            FILES=$(find Unicode/ -name '*.lean' | wc -l)
            DEFS=$(grep -rcE '^def |^structure |^inductive ' --include='*.lean' Unicode/ | \
              awk -F: '{s+=$2} END {print s}')
            THEOREMS=$(grep -rcE '^theorem |^lemma ' --include='*.lean' Unicode/ | \
              awk -F: '{s+=$2} END {print s}')
            SORRY=$(grep -rnE '\bsorry([[:space:]]*$|[;,)}])' --include='*.lean' Unicode/ | \
              grep -cv '^[^:]*:[0-9]*:[[:space:]]*--' || true)

            echo "  files:      $FILES"
            echo "  defs:       $DEFS"
            echo "  theorems:   $THEOREMS"
            echo "  sorry:      $SORRY"
            echo ""

            if [ "$SORRY" -gt 0 ]; then
              echo "  !! sorry found:"
              grep -rnE '\bsorry([[:space:]]*$|[;,)}])' --include='*.lean' Unicode/ | \
                grep -v '^[^:]*:[0-9]*:[[:space:]]*--'
              echo ""
            fi

            echo "── pillar status ────────────────────────────────"
            for pillar in Normalization Precis Bidi Generated; do
              if [ -d "Unicode/$pillar" ]; then
                pf=$(find Unicode/$pillar -name '*.lean' | wc -l)
                pt=$(grep -rcE '^theorem |^lemma ' --include='*.lean' Unicode/$pillar/ | \
                  awk -F: '{s+=$2} END {print s}')
                ps=$(grep -rnE '\bsorry([[:space:]]*$|[;,)}])' --include='*.lean' Unicode/$pillar/ | \
                  grep -cv '^[^:]*:[0-9]*:[[:space:]]*--' || true)
                printf "  %-18s %3d files  %4d theorems  %d sorry\n" "$pillar" "$pf" "$pt" "$ps"
              fi
            done

            echo ""
            echo "── headline theorems ────────────────────────────"
            echo "  UAX #15  / NFC quick-check soundness:"
            echo "    Unicode.Normalization.QuickCheckSoundnessTheorem.quickCheck_sound"
            echo "  RFC 8264 / PRECIS preparation idempotence:"
            echo "    Unicode.Precis.Preparation.precis_idempotent"
            echo "  UAX  #9  / Bidirectional Algorithm pipeline:"
            echo "    Unicode.Bidi.Algorithm.bidiParagraph"
            echo "  UTS #39  / Confusable skeleton equivalence:"
            echo "    Unicode.Confusables.areConfusable_trans"
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
          '');
        };

        apps.unicode-security = {
          type = "app";
          program = "${unicodeSecurity}/bin/unicode-security";
        };

        # ── nix develop ────────────────────────────────────────────
        # Dev shell with elan + lake + git. First entry installs the
        # pinned toolchain via elan.
        devShells.default = leanShell;
        devShells.runtime = runtimeShell;
      }
    );
}
