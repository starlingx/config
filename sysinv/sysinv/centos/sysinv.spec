Summary: System Inventory
Name: sysinv
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz

BuildRequires: python3-setuptools
BuildRequires: python3-pbr
BuildRequires: python3-pip
BuildRequires: python3-wheel
BuildRequires: systemd
Requires: python3-pyparted
Requires: python3-boto3
Requires: python3-botocore >= 1.13.21
Requires: python3-docker
Requires: python3-eventlet
Requires: python3-ipaddr
Requires: python3-jsonpatch
Requires: python3-keyring
Requires: python3-keystoneauth1
Requires: python3-keystonemiddleware
Requires: python3-kubernetes
Requires: python3-netaddr
Requires: python3-paste
Requires: python3-pbr
Requires: python3-psutil
Requires: python3-pyudev
Requires: python3-requests
Requires: python3-retrying
Requires: python3-sqlalchemy
Requires: python3-stevedore
Requires: python3-webob
Requires: python3-webtest
Requires: python3-wsme
Requires: python3-six
Requires: python3-django
Requires: python3-mox3
Requires: python3-oslo-i18n
Requires: python3-oslo-config
Requires: python3-oslo-concurrency
Requires: python3-oslo-db
Requires: python3-oslo-log
Requires: python3-oslo-serialization
Requires: python3-oslo-service
Requires: python3-oslo-utils
Requires: python3-pecan
Requires: tsconfig

%description
System Inventory

%define local_bindir         /usr/bin/
%define local_etc_goenabledd /etc/goenabled.d/
%define local_etc_sysinv     /etc/sysinv/
%define local_etc_motdd      /etc/motd.d/
%define pythonroot           %python3_sitearch
%define ocf_resourced        /usr/lib/ocf/resource.d

%define debug_package %{nil}

%prep
%setup

# Remove bundled egg-info
rm -rf *.egg-info

%build
export PBR_VERSION=%{version}
%{__python3} setup.py build
%py3_build_wheel

%install
export PBR_VERSION=%{version}
%{__python3} setup.py install --root=%{buildroot} \
                             --install-lib=%{pythonroot} \
                             --prefix=/usr \
                             --install-data=/usr/share \
                             --single-version-externally-managed
mkdir -p $RPM_BUILD_ROOT/wheels
install -m 644 dist/*.whl $RPM_BUILD_ROOT/wheels/

install -d -m 755 %{buildroot}%{local_etc_goenabledd}
install -p -D -m 755 etc/sysinv/sysinv_goenabled_check.sh %{buildroot}%{local_etc_goenabledd}/sysinv_goenabled_check.sh

install -d -m 755 %{buildroot}%{local_etc_sysinv}
install -p -D -m 755 etc/sysinv/policy.json %{buildroot}%{local_etc_sysinv}/policy.json
install -p -D -m 640 etc/sysinv/profileSchema.xsd %{buildroot}%{local_etc_sysinv}/profileSchema.xsd

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

#install -p -D -m 755 %{buildroot}/usr/bin/sysinv-api %{buildroot}/usr/bin/sysinv-api
#install -p -D -m 755 %{buildroot}/usr/bin/sysinv-agent %{buildroot}/usr/bin/sysinv-agent
#install -p -D -m 755 %{buildroot}/usr/bin/sysinv-conductor %{buildroot}/usr/bin/sysinv-conductor

install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 755 scripts/partition_info.sh %{buildroot}%{local_bindir}/partition_info.sh
install -p -D -m 755 scripts/manage-partitions %{buildroot}%{local_bindir}/manage-partitions
install -p -D -m 755 scripts/query_pci_id %{buildroot}%{local_bindir}/query_pci_id
install -p -D -m 700 scripts/kube-cert-rotation.sh %{buildroot}%{local_bindir}/kube-cert-rotation.sh

%clean
echo "CLEAN CALLED"
rm -rf $RPM_BUILD_ROOT 

%files
%defattr(-,root,root,-)
%doc LICENSE

%{local_bindir}/*

%{pythonroot}/%{name}

%{pythonroot}/%{name}-%{version}*.egg-info

%{local_etc_goenabledd}/*

%{local_etc_sysinv}/*

%{local_etc_motdd}/*

# SM OCF Start/Stop/Monitor Scripts
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

%package wheels
Summary: %{name} wheels

%description wheels
Contains python wheels for %{name}

%files wheels
/wheels/*
