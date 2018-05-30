Summary: Controller node configuration
Name: controllerconfig
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires: python-setuptools
Requires: systemd
Requires: python-netaddr
Requires: python-keyring
Requires: python-six
Requires: python-iso8601
Requires: psmisc
Requires: lshell
Requires: python-pyudev
Requires: python-netifaces

%description
Controller node configuration

%define local_dir /usr/
%define local_bindir %{local_dir}/bin/
%define local_etc_initd /etc/init.d/
%define local_goenabledd /etc/goenabled.d/
%define local_etc_upgraded /etc/upgrade.d/
%define local_etc_systemd /etc/systemd/system/
%define pythonroot /usr/lib64/python2.7/site-packages
%define debug_package %{nil}

%prep
%setup

%build
%{__python} setup.py build

# TODO: NO_GLOBAL_PY_DELETE (see python-byte-compile.bbclass), put in macro/script
%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed

install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 700 scripts/keyringstaging %{buildroot}%{local_bindir}/keyringstaging
install -p -D -m 700 scripts/openstack_update_admin_password %{buildroot}%{local_bindir}/openstack_update_admin_password
install -p -D -m 700 scripts/install_clone.py %{buildroot}%{local_bindir}/install_clone
install -p -D -m 700 scripts/finish_install_clone.sh %{buildroot}%{local_bindir}/finish_install_clone.sh

install -d -m 755 %{buildroot}%{local_goenabledd}
install -p -D -m 700 scripts/config_goenabled_check.sh %{buildroot}%{local_goenabledd}/config_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 755 scripts/controller_config %{buildroot}%{local_etc_initd}/controller_config

# Install Upgrade scripts
install -d -m 755 %{buildroot}%{local_etc_upgraded}
install -p -D -m 755 upgrade-scripts/* %{buildroot}%{local_etc_upgraded}/

install -d -m 755 %{buildroot}%{local_etc_systemd}
install -p -D -m 664 scripts/controllerconfig.service %{buildroot}%{local_etc_systemd}/controllerconfig.service
#install -p -D -m 664 scripts/config.service %{buildroot}%{local_etc_systemd}/config.service

%post
systemctl enable controllerconfig.service

%clean
rm -rf $RPM_BUILD_ROOT 

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_bindir}/*
%dir %{pythonroot}/%{name}
%{pythonroot}/%{name}/*
%dir %{pythonroot}/%{name}-%{version}.0-py2.7.egg-info
%{pythonroot}/%{name}-%{version}.0-py2.7.egg-info/*
%{local_goenabledd}/*
%{local_etc_initd}/*
%dir %{local_etc_upgraded}
%{local_etc_upgraded}/*
%{local_etc_systemd}/*
