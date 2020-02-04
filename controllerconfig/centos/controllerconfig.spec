Summary: Controller node configuration
Name: controllerconfig
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires: python3-setuptools
BuildRequires: python3-pip
BuildRequires: python3-wheel
Requires: fm-api
Requires: psmisc
Requires: sysinv
Requires: systemd
Requires: tsconfig
Requires: python3-iso8601
Requires: python3-keyring
Requires: python3-netaddr
Requires: python3-netifaces
Requires: python3-pyudev
Requires: python3-six
Requires: python3-crypto
Requires: python3-oslo-utils
Requires: python3-pysnmp
Requires: python3-ruamel-yaml

%description
Controller node configuration

%define local_dir /usr/
%define local_bindir %{local_dir}/bin/
%define local_etc_initd /etc/init.d/
%define local_goenabledd /etc/goenabled.d/
%define local_etc_upgraded /etc/upgrade.d/
%define local_etc_systemd /etc/systemd/system/
%define pythonroot %python3_sitearch
%define debug_package %{nil}

%prep
%setup

%build
%{__python3} setup.py build
%py3_build_wheel

# TODO: NO_GLOBAL_PY_DELETE (see python-byte-compile.bbclass), put in macro/script
%install
%{__python3} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 700 scripts/openstack_update_admin_password %{buildroot}%{local_bindir}/openstack_update_admin_password

install -d -m 755 %{buildroot}%{local_goenabledd}
install -p -D -m 700 scripts/config_goenabled_check.sh %{buildroot}%{local_goenabledd}/config_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 755 scripts/controller_config %{buildroot}%{local_etc_initd}/controller_config

# Install Upgrade scripts
install -d -m 755 %{buildroot}%{local_etc_upgraded}
install -p -D -m 755 upgrade-scripts/* %{buildroot}%{local_etc_upgraded}/

install -d -m 755 %{buildroot}%{local_etc_systemd}
install -p -D -m 664 scripts/controllerconfig.service %{buildroot}%{local_etc_systemd}/controllerconfig.service

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
%dir %{pythonroot}/%{name}-%{version}.0-py3.6.egg-info
%{pythonroot}/%{name}-%{version}.0-py3.6.egg-info/*
%{local_goenabledd}/*
%{local_etc_initd}/*
%dir %{local_etc_upgraded}
%{local_etc_upgraded}/*
%{local_etc_systemd}/*

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
