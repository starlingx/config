Summary: computeconfig
Name: computeconfig
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
Initial compute node configuration

%package -n computeconfig-standalone
Summary: computeconfig
Group: base

%description -n computeconfig-standalone
Initial compute node configuration

%package -n computeconfig-subfunction
Summary: computeconfig
Group: base

%description -n computeconfig-subfunction
Initial compute node configuration

%define initddir /etc/init.d/
%define goenableddir /etc/goenabled.d/
%define systemddir /etc/systemd/system/

%prep
%setup

%build

%install
make install INITDDIR=%{buildroot}%{initddir} GOENABLEDDIR=%{buildroot}%{goenableddir} SYSTEMDDIR=%{buildroot}%{systemddir}

%post -n computeconfig-standalone
if [ ! -e $D%{systemddir}/computeconfig.service ]; then
    cp $D%{systemddir}/config/computeconfig-standalone.service $D%{systemddir}/computeconfig.service
else
    cmp -s $D%{systemddir}/config/computeconfig-standalone.service $D%{systemddir}/computeconfig.service
    if [ $? -ne 0 ]; then
        rm -f $D%{systemddir}/computeconfig.service
        cp $D%{systemddir}/config/computeconfig-standalone.service $D%{systemddir}/computeconfig.service
    fi
fi
systemctl enable computeconfig.service


%post -n computeconfig-subfunction
if [ ! -e $D%{systemddir}/computeconfig.service ]; then
    cp $D%{systemddir}/config/computeconfig-combined.service $D%{systemddir}/computeconfig.service
else
    cmp -s $D%{systemddir}/config/computeconfig-combined.service $D%{systemddir}/computeconfig.service
    if [ $? -ne 0 ]; then
        rm -f $D%{systemddir}/computeconfig.service
        cp $D%{systemddir}/config/computeconfig-combined.service $D%{systemddir}/computeconfig.service
    fi
fi
systemctl enable computeconfig.service

%clean

%files
%defattr(-,root,root,-)
%doc LICENSE
%{initddir}/*

%files -n computeconfig-standalone
%defattr(-,root,root,-)
%dir %{systemddir}/config
%{systemddir}/config/computeconfig-standalone.service
%{goenableddir}/*

%files -n computeconfig-subfunction
%defattr(-,root,root,-)
%dir %{systemddir}/config
%{systemddir}/config/computeconfig-combined.service
