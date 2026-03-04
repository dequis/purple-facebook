facebook_sources = [
  'api.c',
  'api.h',
  'data.c',
  'data.h',
  'facebook.c',
  'facebook.h',
  'glibcompat.h',
  'http.c',
  'http.h',
  'id.h',
  'json.c',
  'json.h',
  'mqtt.c',
  'mqtt.h',
  'purple-compat.h',
  'purple-http.c',
  'purple-http.h',
  'purple-socket.c',
  'purple-socket.h',
  'thrift.c',
  'thrift.h',
  'util.c',
  'util.h',
]

facebook_built_sources = []

gnome = import('gnome')
facebook_built_sources = gnome.genmarshal(
  'marshal',
  sources: ['marshaller.list'],
  prefix: 'fb_marshal',
)

shared_library(
  'facebook',
  facebook_sources,
  facebook_built_sources,
  dependencies: facebook_dependencies,
  install: true,
  install_dir: facebook_install_directory,
  c_args : [
    '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
    '-DPACKAGE_URL="https://github.com/dequis/purple-facebook"',
    '-DGLIB_DISABLE_DEPRECATION_WARNINGS',
  ]
)

