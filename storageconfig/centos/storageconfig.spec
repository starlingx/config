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
%define local_etc_systemd /etc/systemd/system/

%define debug_package %{nil}

%prep
%setup

%build

%install

install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 700 storage_config %{buildroot}%{local_etc_initd}/storage_config

install -d -m 755 %{buildroot}%{local_etc_goenabledd}
install -p -D -m 755 config_goenabled_check.sh %{buildroot}%{local_etc_goenabledd}/config_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_systemd}
install -p -D -m 664 storageconfig.service %{buildroot}%{local_etc_systemd}/storageconfig.service
#install -p -D -m 664 config.service %{buildroot}%{local_etc_systemd}/config.service

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
rm -rf $RPM_BUILD_ROOT 

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_etc_initd}/*
%{local_etc_goenabledd}/*
%{local_etc_systemd}/*
