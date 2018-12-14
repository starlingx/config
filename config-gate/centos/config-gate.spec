Summary: config-gate
Name: config-gate
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

%define debug_package %{nil}

Requires: systemd

%description
Startup configuration gate

%package -n %{name}-worker
Summary: config-gate-worker
Group: base

%description -n %{name}-worker
Startup worker configuration gate

%define local_etc_systemd /etc/systemd/system/

%prep
%setup

%build

%install
make install SBINDIR=%{buildroot}%{_sbindir} SYSTEMDDIR=%{buildroot}%{local_etc_systemd}

%post
systemctl enable config.service

%post -n %{name}-worker
systemctl enable worker-config-gate.service

%clean

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_sbindir}/wait_for_config_init.sh
%{local_etc_systemd}/config.service

%files -n %{name}-worker
%defattr(-,root,root,-)
%{_sbindir}/wait_for_worker_config_init.sh
%{local_etc_systemd}/worker-config-gate.service
