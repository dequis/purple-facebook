%if 0%{?suse_version}
%define _group Productivity/Networking/Instant Messenger
%else
%define _group Applications/Internet
%endif

Name: purple-facebook
Version: 0.0.0
Release: 0
Summary: Facebook protocol plugin for libpurple
Group: %{_group}
License: GPL-2.0+
URL: https://github.com/dequis/purple-facebook
Source0: %{name}-%{version}.tar.gz

BuildRequires: autoconf >= 2.64
BuildRequires: automake
BuildRequires: glib2-devel >= 2.28.0
BuildRequires: json-glib-devel >= 0.14
BuildRequires: libpurple-devel < 3
BuildRequires: libtool
BuildRequires: pkg-config

Requires: glib2 >= 2.28.0
Requires: json-glib >= 0.14
Requires: libpurple < 3

%description
Purple Facebook implements the Facebook Messenger protocol into pidgin,
finch, and libpurple. While the primary implementation is for purple3,
this plugin is back-ported for purple2.

%prep
%setup -q

%build
autoreconf -fi
%configure
make %{?_smp_mflags}

%install
%make_install
find %{buildroot} -name '*.la' -print -delete

%files
%doc AUTHORS COPYING ChangeLog NEWS README
%{_libdir}/purple-2/libfacebook.so

%changelog
