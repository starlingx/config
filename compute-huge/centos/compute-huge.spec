Summary: Initial compute node hugepages and reserved cpus configuration
Name: compute-huge
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
License: Apache-2.0
Group: base
Packager: Wind River <info@windriver.com>
URL: unknown
Source0: %{name}-%{version}.tar.gz
Source1: LICENSE

BuildRequires: systemd-devel
Requires: systemd
Requires: python
Requires: /bin/systemctl

%description
Initial compute node hugepages and reserved cpus configuration

%define local_bindir /usr/bin/
%define local_etc_initd /etc/init.d/
%define local_etc_nova /etc/nova/
%define local_etc_goenabledd /etc/goenabled.d/

%define debug_package %{nil}

%prep
%setup

%build
%{__python} -m compileall topology.py

%install

# compute init scripts
install -d -m 755 %{buildroot}%{local_etc_initd}
install -p -D -m 755 affine-platform.sh %{buildroot}%{local_etc_initd}/affine-platform.sh
install -p -D -m 755 compute-huge.sh %{buildroot}%{local_etc_initd}/compute-huge.sh

# utility scripts
install -p -D -m 755 cpumap_functions.sh %{buildroot}%{local_etc_initd}/cpumap_functions.sh
install -p -D -m 755 task_affinity_functions.sh %{buildroot}%{local_etc_initd}/task_affinity_functions.sh
install -p -D -m 755 log_functions.sh %{buildroot}%{local_etc_initd}/log_functions.sh
install -d -m 755 %{buildroot}%{local_bindir}
install -p -D -m 755 ps-sched.sh %{buildroot}%{local_bindir}/ps-sched.sh
# TODO: Only ship pyc ?
install -p -D -m 755 topology.py %{buildroot}%{local_bindir}/topology.py
install -p -D -m 755 topology.pyc %{buildroot}%{local_bindir}/topology.pyc
install -p -D -m 755 affine-interrupts.sh %{buildroot}%{local_bindir}/affine-interrupts.sh
install -p -D -m 755 set-cpu-wakeup-latency.sh %{buildroot}%{local_bindir}/set-cpu-wakeup-latency.sh
install -p -D -m 755 bin/topology %{buildroot}%{local_bindir}/topology

# compute config data
install -d -m 755 %{buildroot}%{local_etc_nova}
install -p -D -m 755 compute_reserved.conf %{buildroot}%{local_etc_nova}/compute_reserved.conf
install -p -D -m 755 compute_hugepages_total.conf %{buildroot}%{local_etc_nova}/compute_hugepages_total.conf

# goenabled check
install -d -m 755 %{buildroot}%{local_etc_goenabledd}
install -p -D -m 755 compute-huge-goenabled.sh %{buildroot}%{local_etc_goenabledd}/compute-huge-goenabled.sh

# systemd services
install -d -m 755 %{buildroot}%{_unitdir}
install -p -D -m 664 affine-platform.sh.service %{buildroot}%{_unitdir}/affine-platform.sh.service
install -p -D -m 664 compute-huge.sh.service %{buildroot}%{_unitdir}/compute-huge.sh.service

%post
/bin/systemctl enable affine-platform.sh.service >/dev/null 2>&1
/bin/systemctl enable compute-huge.sh.service >/dev/null 2>&1

%clean
rm -rf $RPM_BUILD_ROOT

%files

%defattr(-,root,root,-)

%{local_bindir}/*
%{local_etc_initd}/*
%{local_etc_goenabledd}/*
%config(noreplace) %{local_etc_nova}/compute_reserved.conf
%config(noreplace) %{local_etc_nova}/compute_hugepages_total.conf

%{_unitdir}/compute-huge.sh.service
%{_unitdir}/affine-platform.sh.service
