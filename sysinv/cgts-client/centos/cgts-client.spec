Summary: System Client and CLI
Name: cgts-client
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires: python-setuptools
Requires: python-httplib2
Requires: python-prettytable
Requires: bash-completion
Requires: python-neutronclient
Requires: python-keystoneclient

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
%setup

%build
%{__python} setup.py build

%install
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed

install -d -m 755 %{buildroot}%{local_etc_bash_completiond}
install -p -D -m 664 tools/system.bash_completion %{buildroot}%{local_etc_bash_completiond}/system.bash_completion

# prep SDK package
mkdir -p %{buildroot}/usr/share/remote-clients
tar zcf %{buildroot}/usr/share/remote-clients/python-wrs-system-client-%{version}.tgz --exclude='.gitignore' --exclude='.gitreview' -C .. --transform="s/%{name}-%{version}/python-wrs-system-client-%{version}/" %{name}-%{version}

%clean
rm -rf $RPM_BUILD_ROOT

# Note: Package name is cgts-client but the import name is cgtsclient so
# can't use '%{name}'.
%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_bindir}/*
%{local_etc_bash_completiond}/*
%dir %{pythonroot}/cgtsclient
%{pythonroot}/cgtsclient/*
%dir %{pythonroot}/cgtsclient-%{version}.0-py2.7.egg-info
%{pythonroot}/cgtsclient-%{version}.0-py2.7.egg-info/*

%files sdk
/usr/share/remote-clients/python-wrs-system-client-%{version}.tgz
