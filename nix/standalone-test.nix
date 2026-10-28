{ pkgs, package }:
let
  tailscaleFixture = pkgs.writeShellScriptBin "tailscale" ''
    exec ${pkgs.python3}/bin/python3 ${../tests/fake_tailscale.py} "$@"
  '';
in pkgs.testers.runNixOSTest {
  name = "net-accel-dns-standalone";
  nodes.machine = { ... }: {
    # Deliberately do not import the project's NixOS module.
    networking.networkmanager.enable = true;
    networking.networkmanager.ensureProfiles.profiles.daily-test = {
      connection = { id = "daily-test"; type = "ethernet"; interface-name = "eth1"; autoconnect-priority = 100; };
      ipv4 = { method = "manual"; address1 = "192.168.1.20/24"; dns = "127.0.0.2;"; dns-priority = -100; };
      ipv6.method = "disabled";
    };
    networking.useDHCP = false;
    environment.systemPackages = [ pkgs.python3 pkgs.iproute2 tailscaleFixture ];
    environment.etc."nixos/configuration.nix".text = "# Must remain unchanged by dnsctl enable\n";
    systemd.services.tailscaled = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
    # Simulate an older installed deployment. The standalone package must stop
    # it, mask it while enabled, and restore its prior active state on disable.
    systemd.services.net-accel-dns = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
    systemd.services.net-accel-dns-tcp = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
    };
    # The VM framework configures eth1 outside NetworkManager on every boot.
    # Explicitly activate our baseline fixture profile before network-online,
    # otherwise NM preserves that external connection and uses QEMU's DNS.
    systemd.services.test-network-profile = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "NetworkManager-ensure-profiles.service" ];
      after = [ "NetworkManager-ensure-profiles.service" "network.target" ];
      before = [ "network-online.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.networkmanager}/bin/nmcli connection up daily-test";
      };
    };
    systemd.services.dns-fixture = {
      wantedBy = [ "multi-user.target" ];
      before = [ "net-accel-dns-daily.service" ];
      preStart = "${pkgs.iproute2}/bin/ip address replace 100.100.100.100/32 dev lo";
      environment.PYTHONPATH = "${../tests}:${../admin}";
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${../tests/daily_fixture.py}";
    };
    virtualisation.memorySize = 1024;
  };
  testScript = ''
    machine.start(allow_reboot=True)
    machine.wait_for_unit("multi-user.target")
    machine.succeed("NET_ACCEL_ISOLATED_TEST=1 PYTHONPATH=${../tests}:${../admin} ${pkgs.python3}/bin/python3 ${../tests/standalone_test.py} ${package}/bin/dnsctl before")
    machine.reboot()
    machine.wait_for_unit("net-accel-dns-daily.service")
    machine.succeed("NET_ACCEL_ISOLATED_TEST=1 PYTHONPATH=${../tests}:${../admin} ${pkgs.python3}/bin/python3 ${../tests/standalone_test.py} ${package}/bin/dnsctl after")
  '';
}
