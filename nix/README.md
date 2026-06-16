# gssproxy on NixOS

This directory contains a Nix flake that builds `gssproxy` from this repository
and exports a NixOS module (`services.gssproxy`). The primary use case is to run
gssproxy as the in-kernel NFS server GSS helper, a drop-in replacement for
`rpc.svcgssd`, so the kernel NFS server can handle large RPCSEC/GSS credentials
(for example Kerberos tickets carrying a Microsoft PAC payload from Active
Directory or FreeIPA). This addresses the `RPCSEC/GSS credential too large -
please use gssproxy` error tracked in
[nixpkgs#528636](https://github.com/nixos/nixpkgs/issues/528636).

## Usage

Add this flake as an input and import the module:

```nix
{
  inputs.gssproxy.url = "github:gssapi/gssproxy";

  outputs = { nixpkgs, gssproxy, ... }: {
    nixosConfigurations.my-nfs-server = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        gssproxy.nixosModules.gssproxy
        ({ ... }: {
          services.gssproxy.enable = true;
          services.gssproxy.nfs.server.enable = true;

          # The existing nixpkgs NFS server module:
          services.nfs.server = {
            enable = true;
            exports = ''
              /srv/nfs client.example.com(rw,sec=krb5)
            '';
          };
        })
      ];
    };
  };
}
```

You also need a working Kerberos setup: a `/etc/krb5.conf` and a keytab at
`/etc/krb5.keytab` containing the `nfs/` and `host/` service principals for the
server.

## Important: reboot requirement

The kernel decides **once**, on the first GSS authentication request, whether to
use the classic `rpc.svcgssd` protocol or the gssproxy protocol, and the choice
cannot be changed afterwards. If kerberized NFS has already been used on the
machine, you must **reboot** the server after enabling this module for gssproxy
to take over. Enabling `services.gssproxy.nfs.server.enable` masks the
`rpc-svcgssd` service so it cannot race gssproxy for the kernel upcall.

## Options

- `services.gssproxy.enable` - run the gssproxy daemon.
- `services.gssproxy.nfs.server.enable` - add the NFS-server drop-in
  (`service/nfs-server` with `kernel_nfsd = yes`).
- `services.gssproxy.nfs.server.keytab` - keytab path (default `/etc/krb5.keytab`).
- `services.gssproxy.nfs.server.socket` - kernel socket path
  (default `/run/gssproxy.sock`; hardcoded in the kernel, change only if you
  know what you are doing).
- `services.gssproxy.debugLevel` - global `debug_level`.
- `services.gssproxy.settings` - free-form configuration. Section name maps to an
  attribute set of `key = value` pairs; list values produce repeated lines
  (needed for `cred_store`). These deep-merge over the NFS-server defaults, so
  you can extend or override any generated entry.

Example adding an NFS client service definition alongside the server drop-in:

```nix
services.gssproxy.settings."service/nfs-client" = {
  mechs = "krb5";
  cred_store = [
    "keytab:/etc/krb5.keytab"
    "ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U"
  ];
  cred_usage = "initiate";
  allow_any_uid = true;
  euid = 0;
};
```

## Building and testing

- `nix build .#gssproxy` - build the daemon and the `proxymech.so` interposer.
- `nix flake check` - run all checks:
  - `integration-tests` ([nix/integration-tests.nix](integration-tests.nix)) -
    the full upstream in-repo test suite (`tests/runtests.py` via `make check`).
    It stands up a real MIT KDC with an OpenLDAP backend and exercises the
    acquire/accept/impersonation/constrained-delegation/interposer/reload flows
    against a live gssproxy, then runs `userproxytest`. `socket_wrapper`/
    `nss_wrapper` fake the network, so it needs neither real networking nor KVM
    and runs on Hydra.
  - `vm-test` ([nix/test.nix](test.nix)) - a NixOS VM smoke test that verifies
    gssproxy starts, registers via `/proc/net/rpc/use-gss-proxy`, and that
    `rpc-svcgssd` is masked. (Requires KVM.)
- `nix build .#checks.<system>.integration-tests` - run just the upstream suite.
- `nix develop` - drop into a shell with the autotools build dependencies
  (`autoreconf -fi && ./configure && make`).

### Running the upstream suite outside Nix

The suite (`tests/runtests.py`) historically assumes an FHS layout (tools under
`/bin`, `/usr/lib/mit/sbin`, …), a `/bin/bash`, and that it may binary-patch
`libgssapi` to load the interposer. To run it in non-FHS environments such as a
Nix build, it honors these optional overrides (defaults preserve the previous
behavior):

- `GSSPROXY_TEST_BASH` - shell to run test commands with (default `/bin/bash`).
- `GSSPROXY_TEST_OPENLDAP_SCHEMA_DIR` - directory containing the OpenLDAP
  `*.schema` files.
- `GSSPROXY_TEST_KRB5_LDAP_SCHEMA` - path to krb5's `kerberos.schema`.
- `GSSPROXY_TEST_SOCKET_WRAPPER_LIB` / `GSSPROXY_TEST_NSS_WRAPPER_LIB` -
  absolute paths to the wrapper libraries for `LD_PRELOAD`.
- `GSSPROXY_TEST_USE_GSS_MECH_CONFIG` - load the interposer via the
  `GSS_MECH_CONFIG` environment variable instead of binary-patching `libgssapi`
  (needed when the embedded mech.d path is not `/etc/gss/mech.d`).

## Manual end-to-end verification

The smoke test does not exercise real Kerberos authentication. To verify a full
setup, join the server and a client to a KDC (for example FreeIPA), provision
keytabs, mount `server:/srv/nfs` with `sec=krb5` from the client, and confirm a
user can access files without the `credential too large` error appearing in the
server's `dmesg`.

## Upstreaming to nixpkgs

The package derivation in [nix/package.nix](package.nix) and the module in
[nix/module.nix](module.nix) are structured to ease an eventual contribution to
nixpkgs (`Resolves #528636`).
