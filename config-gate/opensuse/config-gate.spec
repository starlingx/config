Summary: General config initialization gate
Name: config-gate
Version: 1.0.0
Release: 1
License: Apache-2.0
Group: Development/Tools/Other
URL: https://opendev.org/starlingx/config
Source0: %{name}-%{version}.tar.gz
BuildArch: noarch

BuildRequires: systemd

%define debug_package %{nil}

%description
General configuration for the initialization gate

%package -n %{name}-worker
Summary: Startup configuration gate
BuildRequires: -devel
Group: Development/Tools/Other

%description -n %{name}-worker
General configuration for the initialization gate

%define local_etc_systemd /etc/systemd/system/

%prep
%setup -n %{name}-%{version}/files

%build

%install
make install SBINDIR=%{buildroot}%{_sbindir} SYSTEMDDIR=%{buildroot}%{local_etc_systemd}

%post
%service_add_post config.service config.target

%post -n %{name}-worker
systemctl enable worker-config-gate.service

%clean

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_sbindir}/wait_for_config_init.sh
%{local_etc_systemd}/config.service
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system

%files -n %{name}-worker
%defattr(-,root,root,-)
%{_sbindir}/wait_for_worker_config_init.sh
%{local_etc_systemd}/worker-config-gate.service
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system

%changelog
