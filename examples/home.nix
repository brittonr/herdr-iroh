# Home Manager snippet. The unit runs as you, which is what herdr.sock expects.
{ pkgs, ... }:
{
  home.packages = [ pkgs.herdr-iroh ];

  systemd.user.services.herdr-iroh = {
    Unit.Description = "herdr API over iroh";
    Service = {
      ExecStart = "${pkgs.herdr-iroh}/bin/herdr-iroh serve";
      Restart = "on-failure";
      RestartSec = "3s";
    };
    Install.WantedBy = [ "default.target" ];
  };
}
