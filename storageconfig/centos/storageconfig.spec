Summary: Initial storage node configuration
Name: storageconfig
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

Requires: systemd

%description
Initial storage node configuration

%define local_etc_initd /etc/init.d/
%define local_etc_goenabledd /etc/goenabled.d/

%define debug_package %{nil}

%prep
%setup

%build

%install
make install \
     INITDDIR=%{buildroot}%{local_etc_initd} \
     GOENABLEDDIR=%{buildroot}%{local_etc_goenabledd} \
     SYSTEMDDIR=%{buildroot}%{_unitdir}

%post
systemctl enable storageconfig.service

# TODO: Support different root partitions for small footprint (see --root)
# if [ -n "$D" ]; then
#     OPT="-r $D"
# else
#     OPT=""
# fi
# update-rc.d $OPT storage_config defaults 60

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_etc_initd}/*
%{local_etc_goenabledd}/*
%{_unitdir}/*
