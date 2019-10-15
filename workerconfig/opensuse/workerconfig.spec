Summary: Worker config package
Name: workerconfig
Version: 1.0.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: System/Packages
URL: https://opendev.org/starlingx/config/
Source0: %{name}-%{version}.tar.gz
BuildArch: noarch

%define debug_package %{nil}

BuildRequires: systemd
Requires: pkgconfig(systemd)

%description
Initial worker node configuration package for StarlingX project.

%package -n workerconfig-standalone
Summary: The worker config standalone package
Group: System/Packages

%description -n workerconfig-standalone
Initial worker node configuration for StarlingX project.

%package -n workerconfig-subfunction
Summary: The worker config subfunction package
Group: System/Packages

%description -n workerconfig-subfunction
Initial worker node configuration for StarlingX project.

%define initddir %{_sysconfdir}/init.d/
%define goenableddir %{_sysconfdir}/goenabled.d/
%define systemddir %{_sysconfdir}/systemd/system/

%prep
%setup -n %{name}-%{version}/%{name}

%build

%install
make install INITDDIR=%{buildroot}%{initddir} GOENABLEDDIR=%{buildroot}%{goenableddir} SYSTEMDDIR=%{buildroot}%{systemddir}

%post -n workerconfig-standalone
cp $D%{systemddir}/config/workerconfig-standalone.service $D%{systemddir}/workerconfig.service
systemctl enable workerconfig.service


%post -n workerconfig-subfunction
cp $D%{systemddir}/config/workerconfig-combined.service $D%{systemddir}/workerconfig.service
systemctl enable workerconfig.service

%clean

%files
%defattr(-,root,root,-)
%doc LICENSE
%{initddir}/*

%files -n workerconfig-standalone
%defattr(-,root,root,-)
%dir %{systemddir}/config
%{systemddir}/config/workerconfig-standalone.service
%{goenableddir}/*
%dir %{_sysconfdir}/goenabled.d
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system
%config %{systemddir}/config/workerconfig-standalone.service

%files -n workerconfig-subfunction
%defattr(-,root,root,-)
%dir %{systemddir}/config
%{systemddir}/config/workerconfig-combined.service
%dir %{_sysconfdir}/systemd
%dir %{_sysconfdir}/systemd/system
%config %{systemddir}/config/workerconfig-combined.service

%changelog
