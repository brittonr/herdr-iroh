# NixOS module: relay the local herdr socket over iroh.
#
# iroh meets peers through outbound relay connections. There is no
# openFirewall option, because nothing needs an inbound TCP or UDP port.
# Leave the host firewall closed.
#
# The service user must be the user who owns herdr.sock. Herdr creates that
# socket mode 0600.
{ config, lib, pkgs, ... }:
let
  cfg = config.services.herdr-iroh;
  stateDir = "/var/lib/${cfg.stateDirectory}";
  methodsLine = methods:
    if builtins.isString methods then
      "methods = ${builtins.toJSON methods}"
    else
      ''
        methods = [
        ${lib.concatMapStrings (method: "  ${builtins.toJSON method}\n") methods}
        ]'';
  peerBlocks = lib.concatStringsSep "\n" (
    lib.mapAttrsToList (name: peer: ''
      [peers.${builtins.toJSON name}]
      endpoint_id = ${builtins.toJSON peer.endpointId}
      ${methodsLine peer.methods}
    '') cfg.allowedPeers
  );
  configFile = pkgs.writeText "herdr-iroh-server.toml" ''
    relays = ${if cfg.relays then "true" else "false"}
    relay_timeout_ms = ${toString cfg.relayTimeoutMs}
    gateway = ${if cfg.gateway then "true" else "false"}
    ${lib.optionalString (cfg.socketPath != null) "socket_path = ${builtins.toJSON cfg.socketPath}"}
    ${lib.optionalString (cfg.herdrPackage != null) "herdr_bin = ${builtins.toJSON "${cfg.herdrPackage}/bin/herdr"}"}

    ${peerBlocks}
  '';
  exec = lib.escapeShellArgs (
    [
      (lib.getExe cfg.package)
      "serve"
      "--config"
      configFile
      "--state-dir"
      stateDir
    ]
    ++ lib.optionals (cfg.secretKeyFile != null) [
      "--secret-key-file"
      cfg.secretKeyFile
    ]
  );
in
{
  options.services.herdr-iroh = {
    enable = lib.mkEnableOption "herdr socket API relayed over iroh";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        herdr-iroh package. The flake module sets this to
        `self.packages.''${system}.default`.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      example = "britton";
      description = ''
        Account the service runs as. This user must be able to connect to
        herdr.sock. Use the same user that runs herdr.
      '';
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "herdr-iroh";
      description = ''
        systemd StateDirectory under /var/lib. The endpoint ticket is written
        here. The secret key is too, unless `secretKeyFile` is set.
        `herdr-iroh id` on a normal login uses ~/.local/state/herdr-iroh and
        will not see this key. Print the service id with
        `sudo -u <user> herdr-iroh id --state-dir /var/lib/<stateDirectory>`.
      '';
    };

    secretKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/herdr-iroh/secret_key";
      description = ''
        Absolute path of an existing or to-be-created 32-byte iroh secret key.
        A string, not a Nix path, so the key is not copied into the store.
        When unset, the service creates `secret_key` in the state directory.
      '';
    };

    socketPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/home/britton/.config/herdr/herdr.sock";
      description = ''
        Herdr Unix socket. When unset, the service user's
        ~/.config/herdr/herdr.sock is used (or HERDR_SOCKET_PATH, if you set
        it on the unit). A release build of herdr uses the directory name
        `herdr`. A debug build uses `herdr-dev`. Named sessions live at
        ~/.config/herdr/sessions/<name>/herdr.sock. One serve process talks
        to one socket.
      '';
    };

    relays = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Use the n0 relays. Leave this true so hosts can be dialed by endpoint
        id. Direct-only operation needs a ticket and usually a bind address.
      '';
    };

    relayTimeoutMs = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 900000;
      description = ''
        Cap on one relayed call, including waits and event streams.
        0 waits until herdr closes the socket.
      '';
    };

    gateway = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Forward API calls to SSH machines saved for this user
        (`herdr machine list`). Requires herdr 0.9.1 or newer on this
        host and on each saved machine. The remote server must already
        be running. Set false to relay only the local socket.
      '';
    };

    herdrPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = ''
        Herdr package used by the saved-machine gateway. When set,
        `<package>/bin/herdr` is written as `herdr_bin` and the package
        is added to the service PATH. `ssh` is taken from OpenSSH.
        When unset, the service user's PATH must provide `herdr` and `ssh`.
      '';
    };

    allowedPeers = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            endpointId = lib.mkOption {
              type = lib.types.str;
              example = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
              description = "Endpoint id from `herdr-iroh id` on the bot box.";
            };
            methods = lib.mkOption {
              type = lib.types.either lib.types.str (lib.types.listOf lib.types.str);
              default = "full";
              example = "full";
              description = ''
                "full" allows every herdr method except server.stop and
                server.live_handoff. A list allows only those exact methods
                and globs such as "agent.*" or "*". Always-denied methods
                stay denied even if the list names them.
              '';
            };
          };
        }
      );
      default = { };
      example = {
        britton-grok = {
          endpointId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        };
      };
      description = ''
        Peers allowed to open the herdr relay. Names are labels. An empty
        set starts the listener and rejects every connection.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.user != "";
        message = "services.herdr-iroh.user must be the account that owns herdr.sock";
      }
      {
        assertion = builtins.match "[A-Za-z0-9._-]+" cfg.stateDirectory != null;
        message = "services.herdr-iroh.stateDirectory must be a single path segment";
      }
      {
        assertion = lib.all (
          name: builtins.match "[A-Za-z0-9._-]{1,64}" name != null
        ) (lib.attrNames cfg.allowedPeers);
        message = "services.herdr-iroh.allowedPeers names must be letters, digits, '.', '_' or '-'";
      }
      {
        assertion = lib.all (
          peer: builtins.match "[0-9a-fA-F]{64}" peer.endpointId != null
        ) (lib.attrValues cfg.allowedPeers);
        message = "services.herdr-iroh.allowedPeers.<name>.endpointId must be 64 hex characters";
      }
      {
        assertion = lib.all (
          peer:
          if builtins.isString peer.methods then peer.methods == "full" else true
        ) (lib.attrValues cfg.allowedPeers);
        message = "services.herdr-iroh.allowedPeers.<name>.methods must be \"full\" or a list of patterns";
      }
      {
        assertion =
          cfg.secretKeyFile == null
          || (
            lib.hasPrefix "/" cfg.secretKeyFile
            && !lib.hasPrefix builtins.storeDir cfg.secretKeyFile
          );
        message = "services.herdr-iroh.secretKeyFile must be an absolute path outside the Nix store";
      }
    ];

    systemd.services.herdr-iroh = {
      description = "herdr API over iroh";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      # ssh for the saved-machine gateway. herdr is added when herdrPackage
      # is set; otherwise the service user's PATH must already provide it.
      path = [ pkgs.openssh ]
        ++ lib.optionals (cfg.herdrPackage != null) [ cfg.herdrPackage ];
      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        StateDirectory = cfg.stateDirectory;
        StateDirectoryMode = "0700";
        UMask = "0077";
        ExecStart = exec;
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = "on-failure";
        RestartSec = "3s";
        NoNewPrivileges = true;
        PrivateTmp = true;
        # ProtectHome would hide herdr.sock under the user's home.
        ProtectSystem = "strict";
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        LockPersonality = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        SystemCallArchitectures = "native";
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
      };
    };
  };
}
