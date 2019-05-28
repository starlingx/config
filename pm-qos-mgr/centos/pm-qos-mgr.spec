%define debug_package %{nil}
%global pypi_name pm_qos_mgr

Name: pm-qos-mgr
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
Summary: PM QoS CPU wakeup latency manager for kubelet cpu-manager
License: Apache-2.0
Group: base
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires:  git
BuildRequires:  python-pbr >= 2.0.0
BuildRequires:  python-setuptools
BuildRequires:  python2-pip
BuildRequires:  systemd-devel

Requires:       python-pbr >= 2.0.0
Requires:       python-inotify
Requires:       systemd

%description
A daemon that monitors kubelet cpu-manager static cpu assignments
and modifies PM QoS CPU wakeup latency.

%define pythonroot %{_libdir}/python2.7/site-packages

%prep
%autosetup -n %{name}-%{version} -S git

# Remove bundled egg-info
rm -rf *.egg-info

%build
export PBR_VERSION=%{version}
%{__python} setup.py build

%install
export PBR_VERSION=%{version}
%{__python} setup.py install --root=%{buildroot} \
                             --install-lib=%{pythonroot} \
                             --prefix=%{_prefix} \
                             --install-data=%{_datadir} \
                             --single-version-externally-managed

install -p -D -m 664 pm-qos-mgr.service %{buildroot}%{_unitdir}/pm-qos-mgr.service

%post
systemctl enable pm-qos-mgr.service

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/*
%{pythonroot}/%{pypi_name}/*
%{pythonroot}/%{pypi_name}-%{version}*.egg-info
%{_unitdir}/*
