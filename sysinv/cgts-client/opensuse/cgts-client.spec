Summary: System Client and CLI
Name: cgts-client
Version: 1.0.0
Release: 2
License: Apache-2.0
Group: System/Base
URL: https://www.starlingx.io
Source0: %{name}-%{version}.tar.gz

BuildRequires: python-setuptools
BuildRequires: python-pbr
BuildRequires: python2-pip
BuildRequires: fdupes
Requires: python-httplib2
Requires: python-prettytable
Requires: bash-completion
Requires: python-keystoneclient
Requires: python-dateutil
# Needed for python2 and python3 compatible
Requires: python-six

%description
System Client and command line interface

%define local_bindir /usr/bin/
%define local_etc_bash_completiond /etc/bash_completion.d/
%define pythonroot /usr/lib64/python2.7/site-packages
%define debug_package %{nil}

%prep
%setup -n %{name}-%{version}/%{name}

# Remove bundled egg-info
rm -rf *.egg-info

%build
export PBR_VERSION=%{version}
%{__python} setup.py build

%install
export PBR_VERSION=%{version}
%{__python} setup.py install --root=$RPM_BUILD_ROOT \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed

install -d -m 755 %{buildroot}%{local_etc_bash_completiond}
install -p -D -m 664 tools/system.bash_completion %{buildroot}%{local_etc_bash_completiond}/system.bash_completion
%fdupes %{buildroot}%{pythonroot}/cgtsclient-1.0-py2.7.egg-info
%fdupes %{buildroot}%{pythonroot}/cgtsclient/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_bindir}/*
%{local_etc_bash_completiond}/*
%{pythonroot}/cgtsclient
%{pythonroot}/cgtsclient-%{version}*.egg-info

%changelog

