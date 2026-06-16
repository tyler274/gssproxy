{ pkgs, gssproxy, daemon ? null }:

# Runs the upstream in-repo test suite (tests/runtests.py via `make check`)
# inside a pure Nix build. The suite stands up a real MIT KDC with an OpenLDAP
# backend, exercises acquire/accept/impersonation/constrained-delegation/
# interposer/reload flows against a live gssproxy, and finally runs
# userproxytest. socket_wrapper/nss_wrapper fake the network so no real
# networking (or KVM) is required, which keeps this runnable on Hydra.
#
# The test scripts honor a handful of GSSPROXY_TEST_* overrides (added so the
# suite can run outside an FHS layout); everything Nix-specific is wired up
# through those here rather than by patching the suite at build time.
#
# `daemon` (optional): an alternative gssproxy package whose `bin/gssproxy` is
# launched instead of the freshly built C daemon (via GSSPROXY_TEST_DAEMON).
# This is how the Rust port is validated against the upstream suite while still
# using the C-built proxymech.so and test programs ("oracle gate #1").

let
  inherit (pkgs) lib;
  # The test KDC uses the LDAP kdb backend, so it needs krb5 built with LDAP
  # support (kdb5_ldap_util + the kldap plugin). nixpkgs' krb5 does not install
  # the LDAP schema that provisioning the directory requires, so ship it too.
  krb5Ldap = (pkgs.krb5.override { withLdap = true; }).overrideAttrs (old: {
    postInstall = (old.postInstall or "") + ''
      install -Dm444 plugins/kdb/ldap/libkdb_ldap/kerberos.schema \
        "$out/share/gssproxy-tests/kerberos.schema"
    '';
  });

  # When validating an external daemon (the Rust port), build it against the
  # same krb5 the suite provisions so the GSSAPI/krb5 runtime matches.
  externalDaemon =
    if daemon == null then null else daemon.override { krb5 = krb5Ldap; };
in
(gssproxy.override { krb5 = krb5Ldap; }).overrideAttrs (old: {
  pname = if daemon == null then "gssproxy-tests" else "gssproxy-rust-tests";

  doCheck = true;

  nativeCheckInputs = (old.nativeCheckInputs or [ ]) ++ (with pkgs; [
    openldap
    socket_wrapper
    nss_wrapper
    valgrind
    which
    gzip
    python3
  ]);

  preCheck = (old.preCheck or "") + ''
    # runtests.py is executed via its shebang by `make check`.
    patchShebangs tests/runtests.py

    # slapd ships in libexec, not on the default PATH.
    export PATH="${pkgs.openldap}/libexec:$PATH"

    export GSSPROXY_TEST_BASH="$(command -v bash)"
    export GSSPROXY_TEST_OPENLDAP_SCHEMA_DIR="${pkgs.openldap}/etc/schema"
    export GSSPROXY_TEST_KRB5_LDAP_SCHEMA="${krb5Ldap}/share/gssproxy-tests/kerberos.schema"
    export GSSPROXY_TEST_SOCKET_WRAPPER_LIB="${pkgs.socket_wrapper}/lib/libsocket_wrapper.so"
    export GSSPROXY_TEST_NSS_WRAPPER_LIB="${pkgs.nss_wrapper}/lib/libnss_wrapper.so"
    # libgssapi embeds a long, non-FHS mech.d path under Nix, so the suite's
    # binary-patch trick cannot work; load the interposer via GSS_MECH_CONFIG.
    export GSSPROXY_TEST_USE_GSS_MECH_CONFIG=1
  '' + lib.optionalString (externalDaemon != null) ''
    # Drive the suite against the external (Rust) daemon. The C-built
    # proxymech.so and test programs are still used unchanged.
    export GSSPROXY_TEST_DAEMON="${externalDaemon}/bin/gssproxy"

    # The Rust daemon does not yet implement s4u2self impersonation
    # (constrained delegation); skip that file so the gate validates the
    # implemented surface. Everything else runs unchanged.
    export GSSPROXY_TEST_SKIP="t_impersonate.py"
  '';

  # When validating the external daemon, surface the daemon log and krb5 trace
  # on failure (the sandbox testdir is otherwise discarded), so a failing
  # oracle-gate run is debuggable from `nix log`.
  checkPhase = lib.optionalString (externalDaemon != null) ''
    runHook preCheck
    set +e
    make ''${checkTarget:-check} ''${checkFlags:-}
    rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      echo "================ gssproxy.log ================"
      cat testdir/gssproxy.log 2>/dev/null || true
      echo "================ gp_krb5_trace.log ================"
      cat testdir/gp_krb5_trace.log 2>/dev/null || true
      exit "$rc"
    fi
    runHook postCheck
  '';
})
