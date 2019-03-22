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
BuildRequires: python-setuptools
BuildRequires: python-pbr
BuildRequires: python2-pip
BuildRequires: python2-wheel
Requires: python-httplib2
Requires: python-prettytable
Requires: bash-completion
Requires: python-neutronclient
Requires: python-keystoneclient
# Needed for python2 and python3 compatible
Requires: python-six

%description
System Client and CLI

%define local_bindir /usr/bin/
%define local_etc_bash_completiond /etc/bash_completion.d/
%define pythonroot /usr/lib64/python2.7/site-packages
%define debug_package %{nil}

%package          sdk
Summary:          SDK files for %{name}

%description      sdk
Contains SDK files for %{name} package

%prep
%autosetup -n %{name}-%{version} -S git

# Remove bundled egg-info
rm -rf *.egg-info


%build
export PBR_VERSION=%{version}
%{__python} setup.py build
%py2_build_wheel

%install
export PBR_VERSION=%{version}
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
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
