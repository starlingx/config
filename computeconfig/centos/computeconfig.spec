Summary: computeconfig
Name: computeconfig
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

%define debug_package %{nil}

Requires: systemd

%description
Initial compute node configuration

%package -n computeconfig-standalone                                            
Summary: computeconfig
Group: base                                                                     
                                                                                
%description -n computeconfig-standalone                                        
Initial compute node configuration                                              

%package -n computeconfig-subfunction                                           
Summary: computeconfig
Group: base                                                                     

%description -n computeconfig-subfunction                                       
Initial compute node configuration                                              

%define local_etc_initd /etc/init.d/
%define local_goenabledd /etc/goenabled.d/
%define local_etc_systemd /etc/systemd/system/

%prep
%setup

%build

%install
install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 700 compute_config %{buildroot}%{local_etc_initd}/compute_config
install -p -D -m 700 compute_services %{buildroot}%{local_etc_initd}/compute_services

install -d -m 755 %{buildroot}%{local_goenabledd}
install -p -D -m 755 config_goenabled_check.sh %{buildroot}%{local_goenabledd}/config_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_systemd}
install -d -m 755 %{buildroot}%{local_etc_systemd}/config
install -p -D -m 664 computeconfig.service %{buildroot}%{local_etc_systemd}/config/computeconfig-standalone.service
install -p -D -m 664 computeconfig-combined.service %{buildroot}%{local_etc_systemd}/config/computeconfig-combined.service
#install -p -D -m 664 config.service %{buildroot}%{local_etc_systemd}/config.service

%post -n computeconfig-standalone
if [ ! -e $D%{local_etc_systemd}/computeconfig.service ]; then
    cp $D%{local_etc_systemd}/config/computeconfig-standalone.service $D%{local_etc_systemd}/computeconfig.service
else
    cmp -s $D%{local_etc_systemd}/config/computeconfig-standalone.service $D%{local_etc_systemd}/computeconfig.service
    if [ $? -ne 0 ]; then
        rm -f $D%{local_etc_systemd}/computeconfig.service
        cp $D%{local_etc_systemd}/config/computeconfig-standalone.service $D%{local_etc_systemd}/computeconfig.service
    fi
fi
systemctl enable computeconfig.service


%post -n computeconfig-subfunction
if [ ! -e $D%{local_etc_systemd}/computeconfig.service ]; then
    cp $D%{local_etc_systemd}/config/computeconfig-combined.service $D%{local_etc_systemd}/computeconfig.service
else
    cmp -s $D%{local_etc_systemd}/config/computeconfig-combined.service $D%{local_etc_systemd}/computeconfig.service
    if [ $? -ne 0 ]; then
        rm -f $D%{local_etc_systemd}/computeconfig.service
        cp $D%{local_etc_systemd}/config/computeconfig-combined.service $D%{local_etc_systemd}/computeconfig.service
    fi
fi
systemctl enable computeconfig.service

%clean
# rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_etc_initd}/*

%files -n computeconfig-standalone
%defattr(-,root,root,-)
%dir %{local_etc_systemd}/config
%{local_etc_systemd}/config/computeconfig-standalone.service
#%{local_etc_systemd}/config.service
%{local_goenabledd}/*

%files -n computeconfig-subfunction
%defattr(-,root,root,-)
%dir %{local_etc_systemd}/config
%{local_etc_systemd}/config/computeconfig-combined.service

