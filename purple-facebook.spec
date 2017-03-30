%global commit0 2a24dfffb9a79f86a922866dda4391d5f402144c
%global gittag0  66ee77378d82 
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})
%global date 20160409

Name:           purple-facebook
Version:        0
Release:        1.%{date}git%{gittag0}.wolfy%{?dist}
Summary:        A replacement Yahoo prpl (protocol plugin) for Pidgin/libpurple

Group:          Applications/Internet
License:        GPLv2+
URL:            https://github.com/dequis/purple-facebook/

#Source0:        hgps://github.com/dequis/%{name}/archive/GIT-TAG.tar.gz#/%{name}-%{version}.tar.gz
Source0:        https://github.com/dequis/%{name}/releases/download/%{gittag0}/%{name}-%{gittag0}.tar.gz
BuildRequires:  json-glib-devel libpurple-devel zlib-devel
#BuildRequires:  automake autoconf

Requires:       libpurple >= 2.10.11 

%description

The purple-facebook plugin is a replacement for the builtin Facebook XMPP plugin

%prep
%autosetup -n %{name}-%{gittag0}

%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/purple-2/
#mv libyahoo-plusplus.so $RPM_BUILD_ROOT/%{_libdir}/purple-2/
mv pidgin/libpurple/protocols/facebook/.libs/libfacebook.so $RPM_BUILD_ROOT/%{_libdir}/purple-2/

%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README ChangeLog AUTHORS VERSION
%license COPYING 
%{_libdir}/purple-2/libfacebook.so

%changelog
* Mon Sep 12 2016 Manuel "lonely wolf" Wolfshant <wolfy@fedoraproject.org> - 0-20160409git66ee77378d82.wolfy.el6
Initial package
