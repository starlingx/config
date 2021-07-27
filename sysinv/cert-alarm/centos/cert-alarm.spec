Summary: StarlingX Certificate Alarm Package
Name: cert-alarm
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
StarlingX Certificate Alarm Package

%define local_etc_initd /etc/init.d/

%define debug_package %{nil}

%prep
%setup

%build

%install
install -m 755 -p -D cert-alarm %{buildroot}/usr/lib/ocf/resource.d/platform/cert-alarm
install -m 644 -p -D cert-alarm.service %{buildroot}%{_unitdir}/cert-alarm.service
install -m 644 -p -D cert-alarm.syslog %{buildroot}%{_sysconfdir}/syslog-ng/conf.d/cert-alarm.conf
install -m 644 -p -D cert-alarm.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/cert-alarm.conf


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE

# SM OCF Start/Stop/Monitor Scripts
%{ocf_resourced}/platform/cert-alarm

# systemctl service files
%{_unitdir}/cert-alarm.service

# logfile config files
%{_sysconfdir}/syslog-ng/conf.d/cert-alarm.conf
%{_sysconfdir}/logrotate.d/cert-alarm.conf
