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

marshallers = gnome.genmarshal('marshal',
    sources : 'marshal.list',
    prefix : 'fb_marshal')
FACEBOOKSOURCES += marshallers

if STATIC_FACEBOOK
	facebook_prpl = static_library('facebook', FACEBOOKSOURCES,
	    c_args : '-DPURPLE_STATIC_PRPL',
	    dependencies : [json, libpurple_dep, glib])
elif DYNAMIC_FACEBOOK
	facebook_prpl = shared_library('facebook', FACEBOOKSOURCES,
	    dependencies : [json, libpurple_dep, glib],
	    install : true, install_dir : PURPLE_PLUGINDIR)
endif
