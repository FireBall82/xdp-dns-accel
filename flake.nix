{
  description = "eBPF/XDP DNS Accelerator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    (flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        llvm = pkgs.llvmPackages;
      in
      {
        packages.default = pkgs.callPackage ./nix/package.nix {};
        packages.xdp = pkgs.callPackage ./nix/package.nix { enableXdp = true; };
        checks.local-deployment = import ./nix/vm-test.nix {
          inherit pkgs;
          package = pkgs.callPackage ./nix/package.nix {};
        };
        checks.xdp-smoke = import ./nix/xdp-test.nix {
          inherit pkgs;
          package = pkgs.callPackage ./nix/package.nix { enableXdp = true; };
        };
        checks.daily-dns = import ./nix/daily-test.nix {
          inherit pkgs;
          package = pkgs.callPackage ./nix/package.nix {};
        };
        checks.standalone-daily = import ./nix/standalone-test.nix {
          inherit pkgs;
          package = pkgs.callPackage ./nix/package.nix {};
        };
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.pkg-config
            llvm.clang
            llvm.clang-unwrapped
            llvm.llvm
            pkgs.bpftools
          ];

          buildInputs = with pkgs; [
            libbpf
            xdp-tools
            linuxHeaders
            elfutils
            zlib
            zstd
          ];

          shellHook = ''
            export CLANG="${llvm.clang-unwrapped}/bin/clang"
            export LLVM_STRIP="${llvm.llvm}/bin/llvm-strip"

            mkdir -p include
            if [ ! -f include/vmlinux.h ]; then
              echo "Dumping host BTF to include/vmlinux.h..."
              btf_header=$(mktemp include/vmlinux.h.XXXXXX)
              if bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$btf_header"; then
                mv "$btf_header" include/vmlinux.h
              else
                rm -f "$btf_header"
                echo "Warning: BTF dump failed."
              fi
            fi
          '';
        };
      }
    )) // {
      nixosModules.default = import ./nix/module.nix;
    };
}
