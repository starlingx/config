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

%package -n %{name}-compute
Summary: config-gate-compute
Group: base

%description -n %{name}-compute
Startup compute configuration gate

%define local_etc_systemd /etc/systemd/system/

%prep
%setup

%build

%install
install -d -m 755 %{buildroot}%{_sbindir}
install -p -D -m 555 wait_for_config_init.sh %{buildroot}%{_sbindir}/
install -p -D -m 555 wait_for_compute_config_init.sh %{buildroot}%{_sbindir}/

install -d -m 755 %{buildroot}%{local_etc_systemd}
install -p -D -m 444 config.service %{buildroot}%{local_etc_systemd}/config.service
install -p -D -m 444 compute-config-gate.service %{buildroot}%{local_etc_systemd}/compute-config-gate.service

%post
systemctl enable config.service

%post -n %{name}-compute
systemctl enable compute-config-gate.service

%clean
# rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_sbindir}/wait_for_config_init.sh
%{local_etc_systemd}/config.service

%files -n %{name}-compute
%defattr(-,root,root,-)
%{_sbindir}/wait_for_compute_config_init.sh
%{local_etc_systemd}/compute-config-gate.service
