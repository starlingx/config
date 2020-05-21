Summary: System Client and CLI
Name: cgts-client
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires: git
BuildRequires: python3-setuptools
BuildRequires: python3-pbr
BuildRequires: python3-pip
BuildRequires: python3-wheel
Requires: python3-httplib2
Requires: python3-prettytable
Requires: bash-completion
Requires: python3-neutronclient
Requires: python3-keystoneclient
Requires: python3-oslo-i18n
Requires: python3-oslo-serialization
Requires: python3-oslo-utils
Requires: python3-requests-toolbelt
# Needed for python2 and python3 compatible
Requires: python3-six

%description
System Client and CLI

%define local_bindir /usr/bin/
%define local_etc_bash_completiond /etc/bash_completion.d/
%define pythonroot %python3_sitearch
%define debug_package %{nil}

%prep
%autosetup -n %{name}-%{version} -S git

# Remove bundled egg-info
rm -rf *.egg-info


%build
export PBR_VERSION=%{version}
%{__python3} setup.py build
%py3_build_wheel

%install
export PBR_VERSION=%{version}
%{__python3} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

install -d -m 755 %{buildroot}%{local_etc_bash_completiond}
install -p -D -m 664 tools/system.bash_completion %{buildroot}%{local_etc_bash_completiond}/system.bash_completion

%clean
rm -rf $RPM_BUILD_ROOT

# Note: Package name is cgts-client but the import name is cgtsclient so
# can't use '%{name}'.
%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_bindir}/*
%{local_etc_bash_completiond}/*
%{pythonroot}/cgtsclient
%{pythonroot}/cgtsclient-%{version}*.egg-info


%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
