%global module_dir  sysinv

Name:           puppet-%{module_dir}
Version:        1.0.0
Release:        %{tis_patch_ver}%{?_tis_dist}
Summary:        Puppet sysinv module
License:        Apache
Packager:       Wind River <info@windriver.com>

URL:            unknown

Source0:        %{name}-%{version}.tar.gz
Source1:        LICENSE

BuildArch:      noarch

BuildRequires: python2-devel

%description
A puppet module for sysinv

%prep
%autosetup -c %{module_dir}

#
# The src for this puppet module needs to be staged to puppet/modules
#
%install
install -d -m 0755 %{buildroot}%{_datadir}/puppet/modules/%{module_dir}
cp -R %{name}-%{version}/%{module_dir} %{buildroot}%{_datadir}/puppet/modules

%files
%license  %{name}-%{version}/LICENSE
%{_datadir}/puppet/modules/%{module_dir}

