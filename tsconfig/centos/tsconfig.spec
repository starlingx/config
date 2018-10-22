Summary: Titanium Cloud Config Info
Name: tsconfig
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

%define debug_package %{nil}

BuildRequires: python-setuptools
BuildRequires: python2-pip
BuildRequires: python2-wheel

%description
Titanium Cloud Config Info

%define local_dir /usr/
%define local_bindir %{local_dir}/bin/
%define pythonroot /usr/lib64/python2.7/site-packages

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

install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 700 scripts/tsconfig %{buildroot}%{local_bindir}/tsconfig

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

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
