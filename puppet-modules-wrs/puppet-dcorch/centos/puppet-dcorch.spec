%global module_dir  dcorch

Name:           puppet-%{module_dir}
Version:        1.0.0
Release:        %{tis_patch_ver}%{?_tis_dist}
Summary:        Puppet dcorch module
License:        Apache
Packager:       Wind River <info@windriver.com>

URL:            unknown

Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires: python2-devel

%description
A puppet module for dcorch

%prep
%setup

#
# The src for this puppet module needs to be staged to puppet/modules
#
%install
make install \
     MODULEDIR=%{buildroot}%{_datadir}/puppet/modules

%files
%license  LICENSE
%{_datadir}/puppet/modules/%{module_dir}

