Summary: System Inventory
Name: sysinv
Version: 1.0.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: Development/Tools/Other
URL: https://opendev.org/starlingx/update
Source0: %{name}-%{version}.tar.gz

BuildRequires: python-setuptools
BuildRequires: python-pbr
BuildRequires: python2-pip
BuildRequires: systemd

Requires: cgcs-patch
Requires: controllerconfig
Requires: platform-utils
Requires: python-boto3
Requires: python-cephclient
Requires: python-fmclient
Requires: python-parted
Requires: python2-coverage
Requires: python2-docker
Requires: python2-eventlet
Requires: python2-ipaddr
Requires: python2-jsonpatch
Requires: python2-keyring
Requires: python2-keystoneauth1
Requires: python2-keystonemiddleware
Requires: python2-kubernetes
Requires: python2-netaddr
Requires: python2-paste
Requires: python2-rfc3986
Requires: python2-pyudev
Requires: python2-pbr
Requires: python2-psutil
Requires: python2-requests
Requires: python2-retrying
Requires: python2-webob
Requires: python2-WebTest
Requires: python2-WSME
Requires: python2-six
Requires: python2-sqlalchemy
Requires: python2-stevedore
Requires: python2-oslo.i18n
Requires: python2-oslo.config
Requires: python2-oslo.concurrency
Requires: python2-oslo.db
Requires: python2-oslo.log
Requires: python2-oslo.policy
Requires: python2-oslo.rootwrap
Requires: python2-oslo.serialization
Requires: python2-oslo.service
Requires: python2-oslo.utils
Requires: python2-pecan
Requires: tsconfig


%description
StarlingX System Inventory

%define local_bindir         /usr/bin/
%define local_etc_goenabledd /etc/goenabled.d/
%define local_etc_sysinv     /etc/sysinv/
%define local_etc_motdd      /etc/motd.d/
%define pythonroot           /usr/lib64/python2.7/site-packages
%define ocf_resourced        /usr/lib/ocf/resource.d

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
%{__python} setup.py install --root=%{buildroot} \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed

install -d -m 755 %{buildroot}%{local_etc_goenabledd}
install -p -D -m 755 etc/sysinv/sysinv_goenabled_check.sh %{buildroot}%{local_etc_goenabledd}/sysinv_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_sysinv}
install -p -D -m 644 etc/sysinv/policy.yaml %{buildroot}%{local_etc_sysinv}/policy.yaml

install -p -D -m 644 etc/sysinv/crushmap-storage-model.txt %{buildroot}%{local_etc_sysinv}/crushmap-storage-model.txt
install -p -D -m 644 etc/sysinv/crushmap-controller-model.txt %{buildroot}%{local_etc_sysinv}/crushmap-controller-model.txt
install -p -D -m 644 etc/sysinv/crushmap-aio-sx.txt %{buildroot}%{local_etc_sysinv}/crushmap-aio-sx.txt

install -d -m 755 %{buildroot}%{local_etc_motdd}
install -p -D -m 755 etc/sysinv/motd-system %{buildroot}%{local_etc_motdd}/10-system

install -d -m 755 %{buildroot}%{local_etc_sysinv}/upgrades
install -p -D -m 755 etc/sysinv/delete_load.sh %{buildroot}%{local_etc_sysinv}/upgrades/delete_load.sh

install -m 755 -p -D scripts/sysinv-api %{buildroot}/usr/lib/ocf/resource.d/platform/sysinv-api
install -m 755 -p -D scripts/sysinv-conductor %{buildroot}/usr/lib/ocf/resource.d/platform/sysinv-conductor

install -m 644 -p -D scripts/sysinv-api.service %{buildroot}%{_unitdir}/sysinv-api.service
install -m 644 -p -D scripts/sysinv-conductor.service %{buildroot}%{_unitdir}/sysinv-conductor.service

#install -p -D -m 755 %%{buildroot}/usr/bin/sysinv-api %%{buildroot}/usr/bin/sysinv-api
#install -p -D -m 755 %%{buildroot}/usr/bin/sysinv-agent %%{buildroot}/usr/bin/sysinv-agent
#install -p -D -m 755 %%{buildroot}/usr/bin/sysinv-conductor %%{buildroot}/usr/bin/sysinv-conductor

install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 755 scripts/partition_info.sh %{buildroot}%{local_bindir}/partition_info.sh
install -p -D -m 755 scripts/manage-partitions %{buildroot}%{local_bindir}/manage-partitions
install -p -D -m 755 scripts/query_pci_id %{buildroot}%{local_bindir}/query_pci_id

# Add once she-bang is fixed
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/agent.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/conductor.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/dbsync.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/dnsmasq_lease_update.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/helm.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/puppet.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/sysinv_deploy_helper.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/cmd/upgrade.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/openstack/common/rootwrap/cmd.py
#chmod 755 %%{buildroot}%%{pythonroot}/sysinv/openstack/common/rpc/zmq_receiver.py


%clean
echo "CLEAN CALLED"
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE

%{local_bindir}/*

%{pythonroot}/%{name}

%{pythonroot}/%{name}-%{version}*.egg-info

%dir %{local_etc_goenabledd}
%{local_etc_goenabledd}/*

%dir %{local_etc_sysinv}
%config %{local_etc_sysinv}/*

%dir %{local_etc_motdd}
%{local_etc_motdd}/*

# SM OCF Start/Stop/Monitor Scripts
%dir /usr/lib/ocf
%dir %{ocf_resourced}
%dir %{ocf_resourced}/platform
%{ocf_resourced}/platform/sysinv-api
%{ocf_resourced}/platform/sysinv-conductor

# systemctl service files
%{_unitdir}/sysinv-api.service
%{_unitdir}/sysinv-conductor.service

%{_bindir}/sysinv-agent
%{_bindir}/sysinv-api
%{_bindir}/sysinv-conductor
%{_bindir}/sysinv-dbsync
%{_bindir}/sysinv-dnsmasq-lease-update
%{_bindir}/sysinv-rootwrap
%{_bindir}/sysinv-upgrade
%{_bindir}/sysinv-puppet
%{_bindir}/sysinv-helm
%{_bindir}/sysinv-utils
%pre
%service_add_pre sysinv-api.service sysinv-api.target
%service_add_pre sysinv-conductor.service sysinv-conductor.target

%post
%service_add_post sysinv-api.service sysinv-api.target
%service_add_post sysinv-conductor.service sysinv-conductor.target

%preun
%service_del_preun sysinv-api.service sysinv-api.target
%service_del_preun sysinv-conductor.service sysinv-conductor.target

%postun
%service_del_postun sysinv-api.service sysinv-api.target
%service_del_postun sysinv-conductor.service sysinv-conductor.target

%changelog
