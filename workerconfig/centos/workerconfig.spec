Summary: workerconfig
Name: workerconfig
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
Initial worker node configuration

%package -n workerconfig-standalone
Summary: workerconfig
Group: base

%description -n workerconfig-standalone
Initial worker node configuration

%define initddir /etc/init.d/
%define goenableddir /etc/goenabled.d/
%define systemddir /etc/systemd/system/

%prep
%setup

%build

%install
make install INITDDIR=%{buildroot}%{initddir} GOENABLEDDIR=%{buildroot}%{goenableddir} SYSTEMDDIR=%{buildroot}%{systemddir}

%post -n workerconfig-standalone
if [ ! -e $D%{systemddir}/workerconfig.service ]; then
    cp $D%{systemddir}/config/workerconfig-standalone.service $D%{systemddir}/workerconfig.service
else
    cmp -s $D%{systemddir}/config/workerconfig-standalone.service $D%{systemddir}/workerconfig.service
    if [ $? -ne 0 ]; then
        rm -f $D%{systemddir}/workerconfig.service
        cp $D%{systemddir}/config/workerconfig-standalone.service $D%{systemddir}/workerconfig.service
    fi
fi
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

