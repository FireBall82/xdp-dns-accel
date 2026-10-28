{ pkgs, package }:
pkgs.testers.runNixOSTest {
  name = "net-accel-dns-local";
  nodes.machine = { ... }: {
    imports = [ ./module.nix ];
    services.net-accel-dns = { enable = true; inherit package; };
    environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];
    virtualisation.memorySize = 1024;
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("NET_ACCEL_ISOLATED_TEST=1 PYTHONPATH=${../tests}:${../admin} ${pkgs.python3}/bin/python3 ${../tests/deployment_test.py} ${package}/bin/dnsctl")
  '';
}
