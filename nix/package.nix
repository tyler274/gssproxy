{ lib
, stdenv
, autoreconfHook
, pkg-config
, gettext
, libxslt
, libxml2
, docbook-xsl-nons
, docbook_xml_dtd_45
, findutils
, krb5
, libverto
, ding-libs
, keyutils
, popt
, systemdLibs
, libselinux
, libcap
, withSelinux ? false
, withCap ? true
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "gssproxy";
  version = "0.9.2";

  src = lib.cleanSource ../.;

  outputs = [ "out" "man" ];

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
    gettext
    libxslt
    libxml2
    docbook-xsl-nons
    docbook_xml_dtd_45
    findutils
  ];

  buildInputs = [
    krb5
    libverto
    ding-libs
    keyutils
    popt
    # libsystemd: enables sd_notify so the daemon supports Type=notify (the
    # unit shipped by the NixOS module relies on readiness notification).
    systemdLibs
  ]
  ++ lib.optional withSelinux libselinux
  ++ lib.optional withCap libcap;

  configureFlags = [
    # The NixOS module ships its own systemd unit; avoid installing into an
    # impure absolute systemdunitdir while keeping the proxy daemon enabled.
    "--with-initscript=none"
    # Compile in the runtime FHS locations (gssproxy reads /etc/gssproxy and the
    # kernel socket lives under /var). `make install` is redirected back into
    # $out via installFlags below so nothing is written outside the store.
    "--sysconfdir=/etc"
    "--localstatedir=/var"
  ]
  ++ lib.optional withSelinux "--with-selinux"
  ++ lib.optional (!withSelinux) "--with-selinux=no"
  ++ lib.optional withCap "--with-cap";

  # The compiled-in paths point at /etc and /var, but `make install` must write
  # only into $out. sysconfdir/localstatedir cover the generic autotools dirs;
  # the gssproxy-specific install dirs below are expanded from configure-time
  # values, so they are redirected explicitly as well.
  installFlags = [
    "sysconfdir=${placeholder "out"}/etc"
    "localstatedir=${placeholder "out"}/var"
    "gssconfdir=${placeholder "out"}/etc/gss/mech.d"
    "pubconfpath=${placeholder "out"}/etc/gssproxy"
    "logpath=${placeholder "out"}/var/log/gssproxy"
    "gpstatedir=${placeholder "out"}/var/lib/gssproxy"
    "gpclidir=${placeholder "out"}/var/lib/gssproxy/clients"
  ];

  # The man pages are built with `xmllint/xsltproc --catalogs`, which resolve the
  # DocBook DTD and stylesheet URLs through SGML_CATALOG_FILES (a single path
  # accepted by --with-xml-catalog-path). Build one combined catalog that
  # delegates to both the DTD and the (non-namespaced) XSL catalogs so the build
  # works offline in the sandbox.
  preConfigure = ''
    combinedCatalog="$PWD/.nix-docbook-catalog.xml"
    xmlcatalog --noout --create "$combinedCatalog"
    xmlcatalog --noout --add nextCatalog "" \
      "${docbook_xml_dtd_45}/xml/dtd/docbook/catalog.xml" "$combinedCatalog"
    xmlcatalog --noout --add nextCatalog "" \
      "${docbook-xsl-nons}/share/xml/docbook-xsl-nons/catalog.xml" "$combinedCatalog"
    configureFlagsArray+=("--with-xml-catalog-path=$combinedCatalog")
  '';

  enableParallelBuilding = true;

  # The upstream test suite ("make check") needs a full MIT KDC, OpenLDAP and
  # network namespaces, which is not available in the build sandbox.
  doCheck = false;

  meta = {
    description = "GSSAPI proxy daemon, a drop-in replacement for rpc.svcgssd handling large Kerberos tickets";
    longDescription = ''
      GSS Proxy is a daemon that sits between GSSAPI clients (such as the
      in-kernel NFS server and client) and the Kerberos credentials they use.
      It allows the kernel NFS server to handle large RPCSEC/GSS credentials
      (for example tickets carrying a Microsoft PAC payload from Active
      Directory or FreeIPA) that the classic rpc.svcgssd cannot.
    '';
    homepage = "https://github.com/gssapi/gssproxy";
    changelog = "https://github.com/gssapi/gssproxy/releases/tag/v${finalAttrs.version}";
    license = lib.licenses.gpl3Plus;
    platforms = lib.platforms.linux;
    mainProgram = "gssproxy";
  };
})
