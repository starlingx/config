Summary: configutilities
Name: configutilities
Version: 3.1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz
Source1: LICENSE

%define debug_package %{nil}

BuildRequires: python-setuptools
BuildRequires: python2-pip
BuildRequires: python2-wheel
Requires: python-netaddr
#Requires: wxPython

%description
Titanium Cloud Controller configuration utilities

%package -n %{name}-cgts-sdk
Summary: configutilities sdk files
Group: devel

%description -n %{name}-cgts-sdk
SDK files for configutilities

%define local_bindir /usr/bin
%define pythonroot /usr/lib64/python2.7/site-packages
%define cgcs_sdk_deploy_dir /opt/deploy/cgcs_sdk
%define cgcs_sdk_tarball_name wrs-%{name}-%{version}.tgz

%prep
%setup

%build
%{__python} setup.py build
%py2_build_wheel

%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

sed -i "s#xxxSW_VERSIONxxx#%{platform_release}#" %{name}/common/validator.py
tar czf %{cgcs_sdk_tarball_name} %{name}
mkdir -p $RPM_BUILD_ROOT%{cgcs_sdk_deploy_dir}
install -m 644 %{cgcs_sdk_tarball_name} $RPM_BUILD_ROOT%{cgcs_sdk_deploy_dir}

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

%files -n %{name}-cgts-sdk
%{cgcs_sdk_deploy_dir}/%{cgcs_sdk_tarball_name}

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
