Summary: StarlingX FPGA Agent Package
Name: sysinv-fpga-agent
Version: 1.0.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: Development/Tools/Other
URL: https://opendev.org/starlingx/config
Source0: %{name}-%{version}.tar.gz

BuildRequires: systemd-devel

Requires: python-django
Requires: python-oslo.messaging
Requires: python-retrying

BuildArch: noarch

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

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%service_add_pre sysinv-fpga-agent.service sysinv-fpga-agent.target

%post
%service_add_post sysinv-fpga-agent.service sysinv-fpga-agent.target

%preun
%service_del_preun sysinv-fpga-agent.service sysinv-fpga-agent.target

%postun
%service_del_postun sysinv-fpga-agent.service sysinv-fpga-agent.target


%files
%defattr(-,root,root,-)
%doc LICENSE
%dir %{local_etc_pmond}
%{local_etc_initd}/sysinv-fpga-agent
%config %{local_etc_pmond}/sysinv-fpga-agent.conf
%{_unitdir}/sysinv-fpga-agent.service

%changelog
