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
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        llvm = pkgs.llvmPackages;
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.pkg-config
            llvm.clang
            llvm.clang-unwrapped
            llvm.libllvm
            llvm.llvm # <-- Changed from bintools to the core llvm package
            pkgs.bpftools
          ];

          buildInputs = with pkgs; [
            libbpf
            xdp-tools
            liburing
            linuxHeaders
            elfutils
            zlib
            zstd
          ];

          shellHook = ''
            export CLANG="${llvm.clang-unwrapped}/bin/clang"
            export LLVM_STRIP="${llvm.llvm}/bin/llvm-strip" # <-- Updated path

            mkdir -p include
            if [ ! -f include/vmlinux.h ]; then
              echo "Dumping host BTF to include/vmlinux.h..."
              bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h 2>/dev/null || echo "Warning: BTF dump failed."
            fi
          '';
        };
      }
    );
}
