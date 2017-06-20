FACEBOOKSOURCES = [
	'api.c',
	'api.h',
	'data.c',
	'data.h',
	'facebook.h',
	'facebook.c',
	'http.c',
	'http.h',
	'id.h',
	'json.c',
	'json.h',
	'mqtt.c',
	'mqtt.h',
	'thrift.c',
	'thrift.h',
	'util.c',
	'util.h'
]

if STATIC_FACEBOOK
	facebook_prpl = static_library('facebook', FACEBOOKSOURCES,
	    c_args : '-DPURPLE_STATIC_PRPL',
	    dependencies : [json, libpurple_dep, glib])
elif DYNAMIC_FACEBOOK
	facebook_prpl = shared_library('facebook', FACEBOOKSOURCES,
	    dependencies : [json, libpurple_dep, glib],
	    install : true, install_dir : PURPLE_PLUGINDIR)
endif

# Used to produce docs.
facebook_inc = include_directories('.')
facebook_dep = declare_dependency(
    link_with : facebook_prpl,
    dependencies : [json, libpurple_dep, glib])
