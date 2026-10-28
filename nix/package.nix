{ lib, stdenv, cmake, python3, systemd, unbound, pkg-config, clang, llvm, libbpf, xdp-tools
, enableXdp ? false }:
stdenv.mkDerivation {
  pname = "net-accel-dns";
  version = "0.3.0";
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let name = baseNameOf path; in
      lib.cleanSourceFilter path type
      && !(lib.hasPrefix "build" name)
      && !(builtins.elem name [ ".agents" ".codex" ".aws" "__pycache__" ]);
  };
  nativeBuildInputs = [ cmake python3 ] ++ lib.optionals enableXdp [ pkg-config clang llvm ];
  buildInputs = lib.optionals enableXdp [ libbpf xdp-tools ];
  cmakeFlags = [
    "-DENABLE_XDP=${if enableXdp then "ON" else "OFF"}"
    "-DBUILD_TESTING=OFF"
    "-DUNBOUND_EXECUTABLE=${unbound}/bin/unbound"
    "-DUNBOUND_CHECKCONF=${unbound}/bin/unbound-checkconf"
    "-DSYSTEMCTL_EXECUTABLE=${systemd}/bin/systemctl"
  ] ++ lib.optionals enableXdp [
    "-DBPF_CLANG=${clang.cc}/bin/clang"
    "-DBPF_STRIP=${llvm}/bin/llvm-strip"
  ];
  meta = {
    description = "Local DNS cache with terminal monitoring and optional XDP adapter";
    platforms = lib.platforms.linux;
    mainProgram = "dnsctl";
  };
}
