{ config, lib, pkgs, ... }:
let
  cfg = config.services.net-accel-dns;
  tailZones = lib.optionalAttrs (cfg.systemDns.enable && cfg.systemDns.tailscale.enable) (
    builtins.listToAttrs (map (domain: { name = domain; value = "100.100.100.100:53"; }) (
      [ "ts.net" "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa" ]
      ++ lib.genList (index: "${toString (index + 64)}.100.in-addr.arpa") 64
    ))
  );
  routingFile = pkgs.writeText "net-accel-dns-routing.json" (builtins.toJSON {
    version = 1;
    system_dns = cfg.systemDns.enable;
    search_domains = lib.optionals cfg.systemDns.enable cfg.systemDns.searchDomains;
    forward_zones = tailZones // cfg.forwardZones;
  });
in {
  options.services.net-accel-dns = {
    enable = lib.mkEnableOption "localhost DNS and terminal monitoring";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix {};
      description = "The net-accel-dns package. Includes the dnsctl terminal monitor.";
    };
    forwardZones = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      example = { "internal.example" = "192.0.2.53:53"; };
      description = "Fixed domain-to-IPv4[:port] routes, shared by UDP and TCP.";
    };
    systemDns = {
      enable = lib.mkEnableOption "daily system DNS through the local resolver and systemd-resolved";
      searchDomains = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = config.networking.search;
        description = "DNS search suffixes, including your tailnet suffix for short MagicDNS names.";
      };
      tailscale.enable = lib.mkOption {
        type = lib.types.bool;
        default = config.services.tailscale.enable;
        description = "Keep MagicDNS/reverse lookups on Quad100 and disable Tailscale's OS DNS ownership.";
      };
    };
  };
  config = lib.mkIf cfg.enable (lib.mkMerge [{
    environment.systemPackages = [ cfg.package ];
    users.groups.net-accel-dns = {};
    users.users.net-accel-dns = { isSystemUser = true; group = "net-accel-dns"; };
    systemd.packages = [ cfg.package ];
    systemd.services.net-accel-dns.wantedBy = [ "multi-user.target" ];
    systemd.services.net-accel-dns-tcp.wantedBy = [ "multi-user.target" ];
    environment.etc."net-accel-dns/routing.json".source = routingFile;
    systemd.services.net-accel-dns-prepare.restartTriggers = [ routingFile ];
    systemd.services.net-accel-dns.partOf = [ "net-accel-dns-prepare.service" ];
    systemd.services.net-accel-dns-tcp.partOf = [ "net-accel-dns-prepare.service" ];
  }
  (lib.mkIf cfg.systemDns.enable {
    services.resolved.enable = true;
    networking.nameservers = lib.mkForce [ "127.0.0.1" ];
    networking.networkmanager.dns = lib.mkIf config.networking.networkmanager.enable (lib.mkForce "systemd-resolved");
    services.resolved.settings.Resolve = {
      DNS = lib.mkForce [ "127.0.0.1" ];
      Domains = lib.mkForce ([ "~." ] ++ cfg.systemDns.searchDomains);
      Cache = false;
      FallbackDNS = "";
    };
    # resolved is an early-boot service (Before=sysinit.target). Ordering it
    # after ordinary services creates a sysinit cycle. It can start its stub
    # first; DNS services are ready before consumers waiting for network-online.
    systemd.services.net-accel-dns.before = [ "network-online.target" ];
    systemd.services.net-accel-dns-tcp.before = [ "network-online.target" ];
  })
  (lib.mkIf (cfg.systemDns.enable && cfg.systemDns.tailscale.enable) {
    assertions = [
      { assertion = config.services.tailscale.enable;
        message = "net-accel-dns MagicDNS integration requires services.tailscale.enable."; }
      { assertion = !(builtins.elem "--accept-dns=true" config.services.tailscale.extraSetFlags);
        message = "Remove --accept-dns=true when net-accel-dns manages daily DNS."; }
    ];
    services.tailscale.extraSetFlags = lib.mkAfter [ "--accept-dns=false" ];
  })]);
}
