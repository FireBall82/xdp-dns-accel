{ pkgs, package }:
pkgs.testers.runNixOSTest {
  name = "net-accel-dns-daily";
  nodes.machine = { ... }: {
    imports = [ ./module.nix ];
    services.net-accel-dns = {
      enable = true;
      inherit package;
      systemDns = { enable = true; searchDomains = [ "private.test" ]; };
      forwardZones."private.test" = "127.0.0.1:15354";
    };
    environment.systemPackages = [ pkgs.python3 ];
    virtualisation.memorySize = 1024;
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("NET_ACCEL_ISOLATED_TEST=1 PYTHONPATH=${../tests}:${../admin} ${pkgs.python3}/bin/python3 ${../tests/daily_test.py}")
  '';
}
