Name:           rockyray
Version:        0.7.0
Release:        2%{?dist}
Summary:        RockyRay GUI VPN client

# Nuitka has already prepared the executable and its bundled shared objects.
# Running RPM's generic strip hooks changes the launcher binary and breaks its
# internal loader, so leave this self-contained payload intact.
%global __brp_strip %{nil}
%global __brp_strip_comment_note %{nil}
%global __brp_strip_lto %{nil}
%global __brp_strip_static_archive %{nil}

License:        GPL-3.0-or-later
URL:            https://github.com/artemygroshev/Furious
Source0:        RockyRay-%{version}.tar.gz
BuildArch:      x86_64
Requires:       glibc, libstdc++, libglvnd-glx, libXcursor, libXinerama
Requires:       iproute, nftables, python3, curl, sudo
AutoReqProv:    no

%description
RockyRay is a self-contained GUI VPN client with Xray-core, Hysteria and
TUN split-routing support.

%prep
%setup -q -n RockyRay-%{version}
find app -type f -name '*.before-*' -delete
rm -rf app/Furious/CrashLog

%install
rm -rf %{buildroot}

install -d %{buildroot}/opt/RockyRay
cp -a app/. %{buildroot}/opt/RockyRay/

install -Dpm 0755 rockyray %{buildroot}/usr/bin/rockyray
install -Dpm 0755 rockyray-split-routing %{buildroot}/usr/local/sbin/rockyray-split-routing
install -Dpm 0644 rockyray.desktop %{buildroot}/usr/share/applications/rockyray.desktop
install -Dpm 0644 rockyray.png %{buildroot}/usr/share/icons/hicolor/512x512/apps/rockyray.png

%files
/opt/RockyRay
/usr/bin/rockyray
/usr/local/sbin/rockyray-split-routing
/usr/share/applications/rockyray.desktop
/usr/share/icons/hicolor/512x512/apps/rockyray.png

%changelog
* Thu Aug 27 2026 RockyRay maintainers - 0.7.0-2
- Route AnyDesk service traffic through the physical gateway during TUN use

* Thu Aug 27 2026 RockyRay maintainers - 0.7.0-1
- Initial RockyRay package
