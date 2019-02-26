Name: playbookconfig
Version: 1.0
Release: %{tis_patch_ver}%{?_tis_dist}
Summary: Ansible Playbooks for StarlingX Configurations

Group: base
License: Apache-2.0
URL: unknown
Source0: %{name}-%{version}.tar.gz

Requires: python
Requires: python-netaddr
Requires: sshpass
Requires: python2-ptyprocess
Requires: python2-pexpect
Requires: ansible

%description
This package contains playbooks used for configuring StarlingX.

%define local_stx_ansible_dir %{_datadir}/ansible/stx-ansible
%define local_etc_ansible /etc/ansible
%define debug_package %{nil}

%prep
%setup -q

%build

%install
make install DESTDIR=%{buildroot}%{local_stx_ansible_dir}

%post
cp %{local_stx_ansible_dir}/playbooks/bootstrap/ansible.cfg %{local_etc_ansible}
cp %{local_stx_ansible_dir}/playbooks/bootstrap/hosts %{local_etc_ansible}
chmod 644 %{local_etc_ansible}/ansible.cfg
chmod 644 %{local_etc_ansible}/hosts

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE
%{local_stx_ansible_dir}/*
