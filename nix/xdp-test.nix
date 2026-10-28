{ pkgs, package }:
pkgs.testers.runNixOSTest {
  name = "net-accel-dns-xdp";
  nodes.machine = { ... }: {
    environment.systemPackages = [ pkgs.python3 pkgs.iproute2 package ];
    virtualisation.memorySize = 1024;
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("${pkgs.python3}/bin/python3 ${../tests/xdp_smoke.py} ${package}/bin/dns_daemon generic")
    machine.succeed("${pkgs.python3}/bin/python3 ${../tests/xdp_smoke.py} ${package}/bin/dns_daemon native")
  '';
}
