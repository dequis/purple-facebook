project(
  'purple-facebook',
  'c',
  default_options : ['c_std=c17', 'warning_level=2'],
  license : 'LGPL-2.1-or-later',
  meson_version : '>=1.1.0',
  version: '0.9.6')

glib_dep = dependency('glib-2.0', version : '>=2.28.0')
gio_dep = dependency('gio-2.0')
gobject_dep = dependency('gobject-2.0')
json_glib_dep = dependency('json-glib-1.0', version : '>=0.14.0')
purple_dep = dependency('purple')
zlib_dep = dependency('zlib')

facebook_dependencies = [glib_dep, gio_dep, gobject_dep, json_glib_dep, purple_dep, zlib_dep]

facebook_install_directory = get_option('prefix') / get_option('libdir') / 'purple'
if get_option('use-purple-prefix')
  facebook_install_directory = purple_dep.get_variable(
    pkgconfig : 'plugindir',
    default_value : facebook_install_directory)
endif

subdir('facebook')

