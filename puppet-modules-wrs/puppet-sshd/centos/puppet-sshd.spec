%global module_dir  sshd

Name:           puppet-%{module_dir}
Version:        1.0.0
Release:        %{tis_patch_ver}%{?_tis_dist}
Summary:        Puppet sshd module
License:        Apache-2.0
Packager:       Wind River <info@windriver.com>

URL:            unknown

Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires: python2-devel

%description
A puppet module for sshd

%prep
%setup

#
# The src for this puppet module needs to be staged to puppet/modules
#
%install
make install \
     MODULEDIR=%{buildroot}%{_datadir}/puppet/modules/%{module_dir}

%files
%license LICENSE
%{_datadir}/puppet/modules/%{module_dir}
