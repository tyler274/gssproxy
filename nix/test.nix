{ pkgs, module }:

# Smoke test: bring up a single NixOS node with the NFS-server drop-in enabled
# and verify that gssproxy starts, registers with the kernel via
# /proc/net/rpc/use-gss-proxy, and that the classic rpc.svcgssd is masked.
#
# End-to-end Kerberos authentication (KDC + real keytabs) is intentionally out
# of scope here; see nix/README.md for manual verification steps.
pkgs.testers.nixosTest {
  name = "gssproxy-nfs-server";

  nodes.server = { config, pkgs, ... }: {
    imports = [ module ];

    services.gssproxy = {
      enable = true;
      nfs.server.enable = true;
    };

    services.nfs.server = {
      enable = true;
      exports = "/srv/nfs *(rw,sec=krb5,fsid=0,no_subtree_check)";
    };

    # gssproxy references this keytab; an empty placeholder is enough for the
    # daemon to start and register with the kernel in this smoke test.
    systemd.tmpfiles.rules = [
      "d /srv/nfs 0755 root root -"
      "f /etc/krb5.keytab 0600 root root -"
    ];
  };

  testScript = ''
    # Type=notify only reaches "active" if sd_notify(READY=1) is sent, which
    # also proves the daemon parsed its config and started serving.
    server.wait_for_unit("gssproxy.service")

    # The kernel module that exposes the proc switch must be present before
    # gssproxy can register; nfsd pulls it in.
    server.succeed("modprobe nfsd")
    server.wait_until_succeeds("test -e /proc/net/rpc/use-gss-proxy")

    # gssproxy retries kernel registration every 10s, so once the proc file
    # exists it claims the upcall path (value becomes "1") without a restart.
    server.wait_until_succeeds("grep -q 1 /proc/net/rpc/use-gss-proxy")

    # The classic helper must be masked so it does not race gssproxy.
    server.fail("systemctl is-active rpc-svcgssd.service")

    # Our generated drop-in config must be in place.
    server.succeed("grep -q kernel_nfsd /etc/gssproxy/gssproxy.conf")

    # Regression test: gssproxy must shut down cleanly on SIGTERM. When linked
    # against krb5's embedded (BUILTIN_MODULE) libverto, verto_cleanup() frees a
    # static record and aborts ("free(): invalid pointer"), so systemd records a
    # core-dump on every stop. The package disables that exit-time call; assert
    # the daemon stops without being killed by a signal.
    server.succeed("systemctl stop gssproxy.service")
    result = server.succeed(
        "systemctl show -p Result --value gssproxy.service"
    ).strip()
    assert result == "success", f"gssproxy did not stop cleanly: Result={result}"

    # After a restart the daemon re-registers with the kernel on its own via the
    # retry timer, with no manual intervention; the proc switch stays claimed.
    server.succeed("systemctl start gssproxy.service")
    server.wait_for_unit("gssproxy.service")
    server.wait_until_succeeds("grep -q 1 /proc/net/rpc/use-gss-proxy")
  '';
}
