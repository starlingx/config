Summary: Controller node configuration
Name: controllerconfig
Version: 1.0.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: Development/Tools/Other
URL: https://opendev.org/starlingx/config
Source0: %{name}-%{version}.tar.gz

BuildRequires: python-setuptools
BuildRequires: python2-pip
BuildRequires: python2-wheel
BuildRequires: systemd-devel

Requires: fm-api
Requires: psmisc
Requires: sysinv
Requires: tsconfig
Requires: python-iso8601
Requires: python-keyring
Requires: python-netaddr
Requires: python-netifaces
Requires: python-pyudev
Requires: python-six
Requires: python2-oslo.utils
Requires: python2-pycrypto
Requires: python2-pysnmp
Requires: python2-ruamel.yaml

%description
Configuration for the Controller node.

%define local_bindir %{_bindir}
%define local_etc_initd /%{_sysconfdir}/init.d/
%define local_goenabledd /etc/goenabled.d/
%define local_etc_upgraded /etc/upgrade.d/
%define local_etc_systemd /etc/systemd/system/
%define pythonroot /usr/lib64/python2.7/site-packages
%define debug_package %{nil}

%prep
%setup -n %{name}-%{version}/%{name}

%build
%{__python} setup.py build

# TODO: NO_GLOBAL_PY_DELETE (see python-byte-compile.bbclass), put in macro/script
%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
#mkdir -p $RPM_BUILD_ROOT/wheels
#install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 700 scripts/openstack_update_admin_password %{buildroot}%{local_bindir}/openstack_update_admin_password

install -d -m 755 %{buildroot}%{local_goenabledd}
install -p -D -m 700 scripts/config_goenabled_check.sh %{buildroot}%{local_goenabledd}/config_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 755 scripts/controller_config %{buildroot}%{local_etc_initd}/controller_config

# Install Upgrade scripts
install -d -m 755 %{buildroot}%{local_etc_upgraded}
# install -p -D -m 755 upgrade-scripts/* %{buildroot}%{local_etc_upgraded}/

install -p -D -m 664 scripts/controllerconfig.service %{buildroot}%{_unitdir}/controllerconfig.service

%pre
%service_add_pre controllerconfig.service controllerconfig.target

%post
%service_add_post controllerconfig.service controllerconfig.target

%preun
%service_del_preun controllerconfig.service controllerconfig.target

%postun
%service_del_postun controllerconfig.service controllerconfig.target

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_bindir}/*
%dir %{pythonroot}/%{name}
%{pythonroot}/%{name}/*
%dir %{pythonroot}/%{name}-%{version}-py2.7.egg-info
%{pythonroot}/%{name}-%{version}-py2.7.egg-info/*
%dir %{local_goenabledd}
%{local_goenabledd}/*
%{local_etc_initd}/*
%dir %{local_etc_upgraded}
# %{local_etc_upgraded}/*
%{_unitdir}/*

#%%package wheels
#Summary: %%{name} wheels

#%%description wheels
#Contains python wheels for %%{name}

#%%files wheels
#/wheels/*

%changelog
