%global _missing_build_ids_terminate_build 0
%global _build_id_links none
%global __strip /bin/true

Name:           gatewarden
Version:        %{gw_version}
Release:        %{gw_release}
Summary:        Blocks repeated failed SSH login sources with eBPF/XDP
License:        Proprietary
URL:            https://nexus.manty.co.kr/repository/yum-hosted/gatewarden/
BuildArch:      %{gw_arch}
AutoReqProv:    no

%description
Gatewarden follows OpenSSH authentication failures and temporarily blocks
repeat offenders with an eBPF/XDP map on the configured Ethernet interface.
The package does not enable or start the service.

%install
rm -rf %{buildroot}
install -d %{buildroot}/usr/bin
install -d %{buildroot}/usr/lib/systemd/system
install -d %{buildroot}/etc/gatewarden
install -m 0755 %{_sourcedir}/gatewarden %{buildroot}/usr/bin/gatewarden
install -m 0644 %{_sourcedir}/gatewarden.service %{buildroot}/usr/lib/systemd/system/gatewarden.service
install -m 0644 %{_sourcedir}/gatewarden.sysconfig %{buildroot}/etc/gatewarden/gatewarden.env

%files
/usr/bin/gatewarden
/usr/lib/systemd/system/gatewarden.service
%dir /etc/gatewarden
%config(noreplace) /etc/gatewarden/gatewarden.env

%post
systemctl daemon-reload >/dev/null 2>&1 || :

%preun
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now gatewarden.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge 1 ]; then
    systemctl try-restart gatewarden.service >/dev/null 2>&1 || :
fi
