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

BuildRequires: python3-setuptools
BuildRequires: python3-pip
BuildRequires: python3-wheel

%description
Titanium Cloud Config Info

%define local_dir /usr/
%define local_bindir %{local_dir}/bin/
%define pythonroot %{python3_sitearch}

%prep
%setup

%build
%{__python3} setup.py build
%py3_build_wheel

%install
%{__python3} setup.py install --root=$RPM_BUILD_ROOT \
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
%dir %{pythonroot}/%{name}-%{version}.0-py3.6.egg-info
%{pythonroot}/%{name}-%{version}.0-py3.6.egg-info/*

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
