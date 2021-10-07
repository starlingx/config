Summary: StarlingX FPGA Agent Package
Name: sysinv-fpga-agent
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires: systemd-devel

%description
StarlingX FPGA Agent Package

%define local_etc_initd /etc/init.d/
%define local_etc_pmond /etc/pmon.d/

%define debug_package %{nil}

%prep
%setup

%build

%install
# compute init scripts
install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 755 sysinv-fpga-agent %{buildroot}%{local_etc_initd}/sysinv-fpga-agent

install -d -m 755 %{buildroot}%{local_etc_pmond}
install -p -D -m 644 sysinv-fpga-agent.conf %{buildroot}%{local_etc_pmond}/sysinv-fpga-agent.conf
install -p -D -m 644 sysinv-fpga-agent.service %{buildroot}%{_unitdir}/sysinv-fpga-agent.service
install -p -D -m 644 sysinv-conf-watcher.service %{buildroot}%{_unitdir}/sysinv-conf-watcher.service
install -p -D -m 644 sysinv-conf-watcher.path %{buildroot}%{_unitdir}/sysinv-conf-watcher.path

%post
/usr/bin/systemctl enable sysinv-fpga-agent.service >/dev/null 2>&1
/usr/bin/systemctl enable sysinv-conf-watcher.service >/dev/null 2>&1
/usr/bin/systemctl enable sysinv-conf-watcher.path >/dev/null 2>&1

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_etc_initd}/sysinv-fpga-agent
%{local_etc_pmond}/sysinv-fpga-agent.conf
%{_unitdir}/sysinv-fpga-agent.service
%{_unitdir}/sysinv-conf-watcher.service
%{_unitdir}/sysinv-conf-watcher.path
