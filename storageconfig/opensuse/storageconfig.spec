%define local_etc_initd /etc/init.d/
%define local_etc_goenabledd /etc/goenabled.d/
%define debug_package %{nil}

Name:           storageconfig
Version:	1.0.0
Release:	1
License:	Apache-2.0
Summary:	Initial Storage Node Configuration
Url:		https://opendev.org/starlingx/config
Group:		Development/Tools/Other
Source:		%{name}-%{version}.tar.gz

BuildRequires:	systemd-devel
Requires:	systemd
BuildRequires:  insserv-compat

BuildArch:	noarch

%description
StarlingX initial storage node configuration

%prep
%setup -n %{name}-%{version}/%{name}

%build

%install
make install \
     INITDDIR=%{buildroot}%{local_etc_initd} \
     GOENABLEDDIR=%{buildroot}%{local_etc_goenabledd} \
     SYSTEMDDIR=%{buildroot}%{_unitdir}

install -dD -m 0755 %{buildroot}%{_sbindir}
ln -s /usr/sbin/service %{buildroot}%{_sbindir}/rcstorageconfig
ln -s /usr/sbin/service %{buildroot}%{_sbindir}/rcstorage_config

%pre
%service_add_pre storageconfig.service

%post
%service_add_post storageconfig.service

%preun
%stop_on_removal
%service_del_preun storageconfig.service

%postun
%restart_on_update
%insserv_cleanup
%service_del_postun storageconfig.service

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%dir %{local_etc_initd}/
%dir %{local_etc_goenabledd}/
%{local_etc_initd}/*
%{local_etc_goenabledd}/*
%{_sbindir}/rcstorageconfig
%{_sbindir}/rcstorage_config
%{_unitdir}/*

%changelog
