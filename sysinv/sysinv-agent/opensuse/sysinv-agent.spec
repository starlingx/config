Summary: StarlingX Host Inventory Init Package
Name: sysinv-agent
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
StarlingX Host Inventory Init Agent Package

%define local_etc_initd /etc/init.d/
%define local_etc_pmond /etc/pmon.d/

%define debug_package %{nil}

%prep
%setup

%build

%install
# compute init scripts
install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 755 sysinv-agent %{buildroot}%{local_etc_initd}/sysinv-agent

install -d -m 755 %{buildroot}%{local_etc_pmond}
install -p -D -m 644 sysinv-agent.conf %{buildroot}%{local_etc_pmond}/sysinv-agent.conf
install -p -D -m 644 sysinv-agent.service %{buildroot}%{_unitdir}/sysinv-agent.service

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%service_add_pre sysinv-agent.service sysinv-agent.target

%post
%service_add_post sysinv-agent.service sysinv-agent.target

%preun
%service_del_preun sysinv-agent.service sysinv-agent.target

%postun
%service_del_postun sysinv-agent.service sysinv-agent.target


%files
%defattr(-,root,root,-)
%doc LICENSE
%dir %{local_etc_pmond}
%{local_etc_initd}/sysinv-agent
%config %{local_etc_pmond}/sysinv-agent.conf
%{_unitdir}/sysinv-agent.service

%changelog
