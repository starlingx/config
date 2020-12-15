Summary: StarlingX Certificate Monitor Package
Name: cert-mon
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildArch: noarch
BuildRequires: systemd-devel

%define ocf_resourced        /usr/lib/ocf/resource.d

%description
StarlingX Certificate Monitor Package

%define local_etc_initd /etc/init.d/

%define debug_package %{nil}

%prep
%setup

%build

%install
install -m 755 -p -D cert-mon %{buildroot}/usr/lib/ocf/resource.d/platform/cert-mon
install -m 644 -p -D cert-mon.service %{buildroot}%{_unitdir}/cert-mon.service
install -m 644 -p -D cert-mon.syslog %{buildroot}%{_sysconfdir}/syslog-ng/conf.d/cert-mon.conf
install -m 644 -p -D cert-mon.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/cert-mon.conf


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE

# SM OCF Start/Stop/Monitor Scripts
%{ocf_resourced}/platform/cert-mon

# systemctl service files
%{_unitdir}/cert-mon.service

# logfile config files
%{_sysconfdir}/syslog-ng/conf.d/cert-mon.conf
%{_sysconfdir}/logrotate.d/cert-mon.conf
