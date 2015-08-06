/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include <json-glib/json-glib.h>
#include <stdarg.h>
#include <string.h>

#include "glibcompat.h"

#include "api.h"
#include "http.h"
#include "json.h"
#include "marshal.h"
#include "thrift.h"
#include "util.h"

enum
{
	PROP_0,

	PROP_CID,
	PROP_DID,
	PROP_MID,
	PROP_STOKEN,
	PROP_TOKEN,
	PROP_UID,

	PROP_N
};

struct _FbApiPrivate
{
	PurpleConnection *gc;
	FbMqtt *mqtt;

	FbId uid;
	gint64 sid;
	guint64 mid;
	gchar *cid;
	gchar *did;
	gchar *stoken;
	gchar *token;

	GHashTable *msgids;

};

static void
fb_api_contacts_after(FbApi *api, const gchar *writeid);

G_DEFINE_TYPE(FbApi, fb_api, G_TYPE_OBJECT);

static void
fb_api_set_property(GObject *obj, guint prop, const GValue *val,
                    GParamSpec *pspec)
{
	FbApiPrivate *priv = FB_API(obj)->priv;

	switch (prop) {
	case PROP_CID:
		g_free(priv->cid);
		priv->cid = g_value_dup_string(val);
		break;
	case PROP_DID:
		g_free(priv->did);
		priv->did = g_value_dup_string(val);
		break;
	case PROP_MID:
		priv->mid = g_value_get_uint64(val);
		break;
	case PROP_STOKEN:
		g_free(priv->stoken);
		priv->stoken = g_value_dup_string(val);
		break;
	case PROP_TOKEN:
		g_free(priv->token);
		priv->token = g_value_dup_string(val);
		break;
	case PROP_UID:
		priv->uid = g_value_get_int64(val);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop, pspec);
		break;
	}
}

static void
fb_api_get_property(GObject *obj, guint prop, GValue *val, GParamSpec *pspec)
{
	FbApiPrivate *priv = FB_API(obj)->priv;

	switch (prop) {
	case PROP_CID:
		g_value_set_string(val, priv->cid);
		break;
	case PROP_DID:
		g_value_set_string(val, priv->did);
		break;
	case PROP_MID:
		g_value_set_uint64(val, priv->mid);
		break;
	case PROP_STOKEN:
		g_value_set_string(val, priv->stoken);
		break;
	case PROP_TOKEN:
		g_value_set_string(val, priv->token);
		break;
	case PROP_UID:
		g_value_set_int64(val, priv->uid);
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop, pspec);
		break;
	}
}


static void
fb_api_dispose(GObject *obj)
{
	FbApiPrivate *priv = FB_API(obj)->priv;

	if (G_LIKELY(priv->gc != NULL)) {
		purple_http_conn_cancel_all(priv->gc);
	}

	if (G_UNLIKELY(priv->mqtt != NULL)) {
		g_object_unref(priv->mqtt);
	}

	g_hash_table_destroy(priv->msgids);

	g_free(priv->cid);
	g_free(priv->did);
	g_free(priv->stoken);
	g_free(priv->token);
}

static void
fb_api_class_init(FbApiClass *klass)
{
	GObjectClass *gklass = G_OBJECT_CLASS(klass);
	GParamSpec *props[PROP_N] = {NULL};

	gklass->set_property = fb_api_set_property;
	gklass->get_property = fb_api_get_property;
	gklass->dispose = fb_api_dispose;
	g_type_class_add_private(klass, sizeof (FbApiPrivate));

	props[PROP_CID] = g_param_spec_string(
		"cid",
		"Client ID",
		"Client identifier for MQTT",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_DID] = g_param_spec_string(
		"did",
		"Device ID",
		"Device identifier",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_MID] = g_param_spec_uint64(
		"mid",
		"MQTT ID",
		"MQTT identifier for the MQTT queuer",
		0, G_MAXUINT64, 0,
		G_PARAM_READWRITE);
	props[PROP_STOKEN] = g_param_spec_string(
		"stoken",
		"Sync Token",
		"Synchronization token for the MQTT queue",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_TOKEN] = g_param_spec_string(
		"token",
		"Access Token",
		"Access token from authenticating",
		NULL,
		G_PARAM_READWRITE);
	props[PROP_UID] = g_param_spec_int64(
		"uid",
		"User ID",
		"User identifier",
		0, G_MAXINT64, 0,
		G_PARAM_READWRITE);
	g_object_class_install_properties(gklass, PROP_N, props);

	g_signal_new("auth",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__VOID,
	             G_TYPE_NONE,
	             0);
	g_signal_new("connect",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__VOID,
	             G_TYPE_NONE,
	             0);
	g_signal_new("contacts",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER_BOOLEAN,
	             G_TYPE_NONE,
	             2, G_TYPE_POINTER, G_TYPE_BOOLEAN);
	g_signal_new("error",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__OBJECT,
	             G_TYPE_NONE,
	             1, G_TYPE_ERROR);
	g_signal_new("message",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("presence",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("thread-create",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__INT64,
	             G_TYPE_NONE,
	             1, FB_TYPE_ID);
	g_signal_new("thread-info",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("thread-list",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
	g_signal_new("typing",
	             G_TYPE_FROM_CLASS(klass),
	             G_SIGNAL_ACTION,
	             0,
	             NULL, NULL,
	             fb_marshal_VOID__POINTER,
	             G_TYPE_NONE,
	             1, G_TYPE_POINTER);
}

static void
fb_api_init(FbApi *api)
{
	FbApiPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE(api, FB_TYPE_API, FbApiPrivate);
	api->priv = priv;

	priv->msgids = g_hash_table_new_full(g_int64_hash, g_int64_equal,
	                                     g_free, NULL);
}

GQuark
fb_api_error_quark(void)
{
	static GQuark q = 0;

	if (G_UNLIKELY(q == 0)) {
		q = g_quark_from_static_string("fb-api-error-quark");
	}

	return q;
}

static gboolean
fb_api_json_chk(FbApi *api, gconstpointer data, gssize size, JsonNode **node)
{
	const gchar *str;
	FbApiError errc = FB_API_ERROR_GENERAL;
	FbApiPrivate *priv;
	FbJsonValues *values;
	gboolean success = TRUE;
	gchar *msg;
	GError *err = NULL;
	gint64 code;
	guint i;
	JsonNode *root;

	static const gchar *exprs[] = {
		"$.error.message",
		"$.error.summary",
		"$.error_msg",
		"$.errorCode",
		"$.failedSend.errorMessage",
	};

	g_return_val_if_fail(FB_IS_API(api), FALSE);
	priv = api->priv;

	if (G_UNLIKELY(size == 0)) {
		fb_api_error(api, FB_API_ERROR_GENERAL, _("Empty JSON data"));
		return FALSE;
	}

	root = fb_json_node_new(data, size, &err);
	FB_API_ERROR_EMIT(api, err, return FALSE);

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE, "$.error_code");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.error.type");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.errorCode");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return FALSE
	);

	code = fb_json_values_next_int(values, 0);
	str = fb_json_values_next_str(values, 0);

	if (purple_strequal(str, "OAuthException") || (code == 401)) {
		errc = FB_API_ERROR_AUTH;
		success = FALSE;

		g_free(priv->stoken);
		priv->stoken = NULL;

		g_free(priv->token);
		priv->token = NULL;
	}

	str = fb_json_values_next_str(values, 0);

	if (purple_strequal(str, "ERROR_QUEUE_NOT_FOUND") ||
	    purple_strequal(str, "ERROR_QUEUE_LOST"))
	{
		errc = FB_API_ERROR_AUTH;
		success = FALSE;

		g_free(priv->stoken);
		priv->stoken = NULL;
	}

	fb_json_values_free(values);

	for (msg = NULL, i = 0; i < G_N_ELEMENTS(exprs); i++) {
		msg = fb_json_node_get_str(root, exprs[i], NULL);

		if (msg != NULL) {
			success = FALSE;
			break;
		}
	}

	if (!success && (msg == NULL)) {
		msg = g_strdup(_("Unknown error"));
	}

	if (msg != NULL) {
		fb_api_error(api, errc, "%s", msg);
		json_node_free(root);
		g_free(msg);
		return FALSE;
	}

	if (node != NULL) {
		*node = root;
	} else {
		json_node_free(root);
	}

	return TRUE;
}

static gboolean
fb_api_http_chk(FbApi *api, PurpleHttpConnection *con, PurpleHttpResponse *res,
                JsonNode **root)
{
	const gchar *data;
	const gchar *msg;
	gchar *emsg;
	GError *err = NULL;
	gint code;
	gsize size;

	msg = purple_http_response_get_error(res);
	code = purple_http_response_get_code(res);
	data = purple_http_response_get_data(res, &size);

	if (msg != NULL) {
		emsg = g_strdup_printf("%s (%d)", msg, code);
	} else {
		emsg = g_strdup_printf("%d", code);
	}

	fb_util_debug(FB_UTIL_DEBUG_INFO, "HTTP Response (%p):", con);
	fb_util_debug(FB_UTIL_DEBUG_INFO, "  Response Error: %s", emsg);
	g_free(emsg);

	if (G_LIKELY(size > 0)) {
		fb_util_debug(FB_UTIL_DEBUG_INFO, "  Response Data: %.*s",
		              (gint) size, data);
	}

	if ((root == NULL) && fb_http_error_chk(res, &err)) {
		return TRUE;
	}

	/* Rudimentary check to prevent wrongful error parsing */
	if ((size < 2) || (data[0] != '{') || (data[size - 1] != '}')) {
		FB_API_ERROR_EMIT(api, err, return FALSE);
	}

	if (fb_api_json_chk(api, data, size, root)) {
		FB_API_ERROR_EMIT(api, err, return FALSE);
		return TRUE;
	}

	return FALSE;
}

static PurpleHttpConnection *
fb_api_http_req(FbApi *api, const FbApiHttpInfo *info,
                FbHttpParams *params, const gchar *url)
{
	FbApiPrivate *priv = api->priv;
	gchar *data;
	gchar *key;
	gchar *val;
	GList *keys;
	GList *l;
	GString *gstr;
	PurpleHttpConnection *ret;
	PurpleHttpRequest *req;

	fb_http_params_set_str(params, "api_key", FB_API_KEY);
	fb_http_params_set_str(params, "device_id", priv->did);
	fb_http_params_set_str(params, "fb_api_caller_class", info->klass);
	fb_http_params_set_str(params, "fb_api_req_friendly_name", info->name);
	fb_http_params_set_str(params, "format", "json");
	fb_http_params_set_str(params, "method", info->method);

	val = fb_util_locale_str();
	fb_http_params_set_str(params, "locale", val);
	g_free(val);

	req = purple_http_request_new(url);
	purple_http_request_set_max_len(req, -1);
	purple_http_request_set_method(req, "POST");

	/* Ensure an old signature is not computed */
	g_hash_table_remove(params, "sig");

	gstr = g_string_new(NULL);
	keys = g_hash_table_get_keys(params);
	keys = g_list_sort(keys, (GCompareFunc) g_ascii_strcasecmp);

	for (l = keys; l != NULL; l = l->next) {
		key = l->data;
		val = g_hash_table_lookup(params, key);
		g_string_append_printf(gstr, "%s=%s", key, val);
	}

	g_string_append(gstr, FB_API_SECRET);
	data = g_compute_checksum_for_string(G_CHECKSUM_MD5, gstr->str,
	                                     gstr->len);
	fb_http_params_set_str(params, "sig", data);
	g_string_free(gstr, TRUE);
	g_list_free(keys);
	g_free(data);

	if (priv->token != NULL) {
		data = g_strdup_printf("OAuth %s", priv->token);
		purple_http_request_header_set(req, "Authorization", data);
		g_free(data);
	}

	data = fb_http_params_close(params, NULL);
	purple_http_request_set_contents(req, data, -1);
	ret = purple_http_request(priv->gc, req, info->callback, api);
	purple_http_request_unref(req);

	fb_util_debug(FB_UTIL_DEBUG_INFO, "HTTP Request (%p):", ret);
	fb_util_debug(FB_UTIL_DEBUG_INFO, "  Request URL: %s", url);
	fb_util_debug(FB_UTIL_DEBUG_INFO, "  Request Data: %s", data);

	g_free(data);
	return ret;
}

static void
fb_api_http_graph(FbApi *api, const FbApiHttpInfo *info, JsonBuilder *builder,
                  const gchar *qid)
{
	FbHttpParams *prms;
	gchar *json;

	prms = fb_http_params_new();
	json = fb_json_bldr_close(builder, JSON_NODE_OBJECT, NULL);

	fb_http_params_set_str(prms, "query_id", qid);
	fb_http_params_set_str(prms, "query_params", json);
	fb_api_http_req(api, info, prms, FB_API_URL_GQL);

	g_free(json);
}

static void
fb_api_cb_http_bool(PurpleHttpConnection *con, PurpleHttpResponse *res,
                    gpointer data)
{
	const gchar *hata;
	FbApi *api = data;

	if (!fb_api_http_chk(api, con, res, NULL)) {
		return;
	}

	hata = purple_http_response_get_data(res, NULL);

	if (g_ascii_strcasecmp(hata, "true") != 0) {
		fb_api_error(api, FB_API_ERROR,
		             _("Failed generic API operation"));
	}
}

static void
fb_api_cb_mqtt_error(FbMqtt *mqtt, GError *error, gpointer data)
{
	FbApi *api = data;
	g_signal_emit_by_name(api, "error", error);
}

static void
fb_api_cb_mqtt_open(FbMqtt *mqtt, gpointer data)
{
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	gchar *json;
	JsonBuilder *bldr;

	static guint8 flags = FB_MQTT_CONNECT_FLAG_USER |
	                      FB_MQTT_CONNECT_FLAG_PASS |
	                      FB_MQTT_CONNECT_FLAG_CLR;

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_bool(bldr, "chat_on", TRUE);
	fb_json_bldr_add_bool(bldr, "fg", FALSE);
	fb_json_bldr_add_bool(bldr, "no_auto_fg", TRUE);
	fb_json_bldr_add_int(bldr, "mqtt_sid", priv->mid);
	fb_json_bldr_add_int(bldr, "nwt", 1);
	fb_json_bldr_add_int(bldr, "nwst", 0);
	fb_json_bldr_add_str(bldr, "a", FB_API_AGENT);
	fb_json_bldr_add_str(bldr, "d", priv->did);
	fb_json_bldr_add_str(bldr, "pf", "jz");
	fb_json_bldr_add_strf(bldr, "u", "%" FB_ID_FORMAT, priv->uid);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_mqtt_connect(mqtt,
		flags,       /* Flags */
		priv->cid,   /* Client identifier */
		json,        /* Will message */
		priv->token, /* Username */
		NULL);

	g_free(json);
}

static void
fb_api_cb_seqid(PurpleHttpConnection *con, PurpleHttpResponse *res,
                gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	FbJsonValues *values;
	gchar *json;
	GError *err = NULL;
	JsonBuilder *bldr;
	JsonNode *root;

	if (!fb_api_http_chk(api, con, res, &root)) {
		return;
	}

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.viewer.message_threads.sync_sequence_id");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return;
	);

	str = fb_json_values_next_str(values, "0");
	priv->sid = g_ascii_strtoll(str, NULL, 10);
	fb_json_values_free(values);
	json_node_free(root);

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_int(bldr, "delta_batch_size", 125);
	fb_json_bldr_add_int(bldr, "max_deltas_able_to_process", 1250);
	fb_json_bldr_add_int(bldr, "sync_api_version", 3);
	fb_json_bldr_add_str(bldr, "encoding", "JSON");

	if (priv->stoken == NULL) {
		fb_json_bldr_add_int(bldr, "initial_titan_sequence_id",
		                     priv->sid);
		fb_json_bldr_add_str(bldr, "device_id", priv->did);
		fb_json_bldr_add_int(bldr, "entity_fbid", priv->uid);

		fb_json_bldr_obj_begin(bldr, "device_params");
		fb_json_bldr_add_str(bldr, "animated_image_format", "GIF");

		fb_json_bldr_obj_begin(bldr, "animated_image_sizes");
		fb_json_bldr_add_str(bldr, "0", "9001x9001");
		fb_json_bldr_obj_end(bldr);

		fb_json_bldr_obj_begin(bldr, "image_sizes");
		fb_json_bldr_add_str(bldr, "0", "9001x9001");
		fb_json_bldr_obj_end(bldr);
		fb_json_bldr_obj_end(bldr);

		fb_json_bldr_obj_begin(bldr, "queue_params");
		fb_json_bldr_add_str(bldr, "buzz_on_deltas_enabled", "false");

		fb_json_bldr_obj_begin(bldr, "graphql_query_hashes");
		fb_json_bldr_add_str(bldr, "xma_query_id", FB_API_QRYID_XMA);
		fb_json_bldr_obj_end(bldr);

		fb_json_bldr_obj_begin(bldr, "graphql_query_params");
		fb_json_bldr_obj_begin(bldr, FB_API_QRYID_XMA);
		fb_json_bldr_add_str(bldr, "xma_id", "<ID>");
		fb_json_bldr_add_str(bldr, "small_preview_size", "9001");
		fb_json_bldr_add_str(bldr, "large_preview_size", "9001");
		fb_json_bldr_obj_end(bldr);
		fb_json_bldr_obj_end(bldr);
		fb_json_bldr_obj_end(bldr);

		json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
		fb_api_publish(api, "/messenger_sync_create_queue", "%s",
		               json);
		g_free(json);
		return;
	}

	fb_json_bldr_add_int(bldr, "last_seq_id", priv->sid);
	fb_json_bldr_add_str(bldr, "sync_token", priv->stoken);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/messenger_sync_get_diffs", "%s", json);
	g_signal_emit_by_name(api, "connect");
	g_free(json);
}

static void
fb_api_cb_mqtt_connect(FbMqtt *mqtt, gpointer data)
{
	FbApi *api = data;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_seqid,
		"com.facebook.orca.e.y",
		"ThreadListQuery",
		"get"
	};

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_bool(bldr, "foreground", TRUE);
	fb_json_bldr_add_int(bldr, "keepalive_timeout", FB_MQTT_KA);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/foreground_state", "%s", json);
	g_free(json);

	fb_mqtt_subscribe(mqtt,
		"/inbox", 0,
		"/mercury", 0,
		"/messaging_events", 0,
		"/orca_presence", 0,
		"/orca_typing_notifications", 0,
		"/pp", 0,
		"/t_ms", 0,
		"/t_p", 0,
		"/t_rtc", 0,
		"/webrtc", 0,
		"/webrtc_response", 0,
		NULL
	);

	/* Notifications seem to lead to some sort of sending rate limit */
	fb_mqtt_unsubscribe(mqtt, "/orca_message_notifications", NULL);

	/* See fb_api_thread_list() for key mapping */
	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_str(bldr, "1", "0");
	fb_api_http_graph(api, &info, bldr, FB_API_QRYID_THREAD_LIST);
}

static void
fb_api_cb_publish_mark(FbApi *api, const GByteArray *pload)
{
	FbJsonValues *values;
	GError *err = NULL;
	JsonNode *root;

	if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
		return;
	}

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_BOOL, FALSE, "$.succeeded");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return;
	);

	if (!fb_json_values_next_bool(values, TRUE)) {
		fb_api_error(api, FB_API_ERROR_GENERAL,
		             _("Failed to mark thread as read"));
	}

	fb_json_values_free(values);
	json_node_free(root);
}

static void
fb_api_cb_publish_typing(FbApi *api, const GByteArray *pload)
{
	const gchar *str;
	FbApiPrivate *priv = api->priv;
	FbApiTyping typg;
	FbJsonValues *values;
	GError *err = NULL;
	JsonNode *root;

	if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
		return;
	}

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.type");
	fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.sender_fbid");
	fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.state");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return;
	);

	str = fb_json_values_next_str(values, NULL);

	if (g_ascii_strcasecmp(str, "typ") == 0) {
		typg.uid = fb_json_values_next_int(values, 0);

		if (typg.uid != priv->uid) {
			typg.state = fb_json_values_next_int(values, 0);
			g_signal_emit_by_name(api, "typing", &typg);
		}
	}

	fb_json_values_free(values);
	json_node_free(root);
}

static gchar *
fb_api_message_parse_xma(FbApi *api, const gchar *json, GError **error)
{
	const gchar *str;
	FbHttpParams *params;
	FbJsonValues *values;
	gchar *ret;
	GError *err = NULL;
	JsonNode *node;
	JsonNode *root;

	if (!fb_api_json_chk(api, json, -1, &root)) {
		return NULL;
	}

	node = fb_json_node_get_nth(root, 0);
	values = fb_json_values_new(node, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.story_attachment.target.__type__.name");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.story_attachment.url");
	fb_json_values_update(values, &err);

	if (G_UNLIKELY(err != NULL)) {
		g_propagate_error(error, err);
		fb_json_values_free(values);
		json_node_free(root);
		return NULL;
	}

	str = fb_json_values_next_str(values, NULL);

	if (!purple_strequal(str, "ExternalUrl")) {
		fb_util_debug_warning("Unknown XMA type %s", str);
		fb_json_values_free(values);
		json_node_free(root);
		return NULL;
	}

	str = fb_json_values_next_str(values, NULL);
	params = fb_http_params_new_parse(str, TRUE);
	ret = fb_http_params_dup_str(params, "u", NULL);
	fb_http_params_free(params);

	fb_json_values_free(values);
	json_node_free(root);
	return ret;
}

static GSList *
fb_api_message_parse_attach(FbApi *api, FbApiMessage *msg, GSList *msgs,
                            JsonNode *root, GError **error)
{
	const gchar *body = msg->text;
	const gchar *str;
	FbJsonValues *values;
	GError *err = NULL;
	gpointer mptr;

	values = fb_json_values_new(root, "$.deltaNewMessage.attachments");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
	                   "$.imageMetadata.imageURIMap.0");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.xmaGraphQL");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.filename");

	while (fb_json_values_update(values, &err)) {
		msg->text = fb_json_values_next_str_dup(values, NULL);

		if (msg->text != NULL) {
			mptr = fb_api_message_dup(msg, FALSE);
			msgs = g_slist_prepend(msgs, mptr);
			continue;
		}

		str = fb_json_values_next_str(values, NULL);

		if (str != NULL) {
			msg->text = fb_api_message_parse_xma(api, str, &err);

			if (err != NULL) {
				g_propagate_error(error, err);
				fb_json_values_free(values);
				return msgs;
			}

			if (purple_strequal(msg->text, body)) {
				g_free(msg->text);
				continue;
			}

			mptr = fb_api_message_dup(msg, FALSE);
			msgs = g_slist_prepend(msgs, mptr);
			continue;
		}

		str = fb_json_values_next_str(values, NULL);

		if (G_UNLIKELY(str == NULL)) {
			str = _("unknown attachment");
		}

		msg->text = g_strdup_printf("%s/%" FB_ID_FORMAT " [%s]",
					    FB_API_URL_MESSAGES,
					    msg->uid, str);
		mptr = fb_api_message_dup(msg, FALSE);
		msgs = g_slist_prepend(msgs, mptr);
	}

	if (G_UNLIKELY(err != NULL)) {
		g_propagate_error(error, err);
	}

	fb_json_values_free(values);
	return msgs;
}

static void
fb_api_cb_publish_ms(FbApi *api, const GByteArray *pload)
{
	const gchar *data;
	FbApiMessage msg;
	FbApiPrivate *priv = api->priv;
	FbHttpParams *params;
	FbId oid;
	FbId uid;
	FbJsonValues *values;
	FbThrift *thft;
	gchar *json;
	gchar *stoken;
	GError *err = NULL;
	gint64 id;
	gpointer mptr;
	GRegex *regex;
	GSList *msgs = NULL;
	guint size;
	JsonNode *root;
	JsonNode *node;

	thft = fb_thrift_new((GByteArray*) pload, 0, TRUE);
	fb_thrift_read_str(thft, NULL);
	size = fb_thrift_get_pos(thft);
	g_object_unref(thft);

	g_return_if_fail(size < pload->len);

	data = (gchar *) pload->data + size;
	size = pload->len - size;

	/* Ugly hack to fix broken JSON from Facebook */
	regex = g_regex_new("(\\d+)(:\")", 0, 0, &err);
	json = g_regex_replace(regex, data, size, 0, "\"\\1\"\\2", 0, &err);
	g_regex_unref(regex);
	FB_API_ERROR_EMIT(api, err, return);

	if (!fb_api_json_chk(api, json, -1, &root)) {
		g_free(json);
		return;
	}

	g_free(json);
	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
	                   "$.lastIssuedSeqId");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.syncToken");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return;
	);

	priv->sid = fb_json_values_next_int(values, 0);
	stoken = fb_json_values_next_str_dup(values, NULL);
	fb_json_values_free(values);

	if (G_UNLIKELY(stoken != NULL)) {
		g_free(priv->stoken);
		priv->stoken = stoken;
		g_signal_emit_by_name(api, "connect");
		json_node_free(root);
		return;
	}

	values = fb_json_values_new(root, "$.deltas");
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
	                   "$.deltaNewMessage.messageMetadata"
			    ".offlineThreadingId");
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
	                   "$.deltaNewMessage.messageMetadata.actorFbId");
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
	                   "$.deltaNewMessage.messageMetadata"
	                    ".threadKey.otherUserFbId");
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
	                   "$.deltaNewMessage.messageMetadata"
	                    ".threadKey.threadFbId");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
	                   "$.deltaNewMessage.body");
	fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
	                   "$.deltaNewMessage.stickerId");

	while (fb_json_values_update(values, &err)) {
		id = fb_json_values_next_int(values, 0);

		if (g_hash_table_remove(priv->msgids, &id)) {
			g_print("GOT OUR OWN MESSAGE!\n");
			continue;
		}

		fb_api_message_reset(&msg, FALSE);
		uid = fb_json_values_next_int(values, 0);
		oid = fb_json_values_next_int(values, 0);
		msg.tid = fb_json_values_next_int(values, 0);

		if (uid != priv->uid) {
			msg.isself = FALSE;
			msg.uid = uid;
		} else {
			msg.isself = TRUE;
			msg.uid = oid;
		}

		if (msg.uid == 0) {
			continue;
		}

		msg.text = fb_json_values_next_str_dup(values, NULL);

		if (msg.text != NULL) {
			mptr = fb_api_message_dup(&msg, FALSE);
			msgs = g_slist_prepend(msgs, mptr);
		}

		id = fb_json_values_next_int(values, 0);

		if (id != 0) {
			params = fb_http_params_new();
			fb_http_params_set_int(params, "sticker_id", id);
			msg.text = fb_http_params_close(params,
			                                FB_API_URL_STICKER);
			mptr = fb_api_message_dup(&msg, FALSE);
			msgs = g_slist_prepend(msgs, mptr);
			continue;
		}

		node = fb_json_values_get_root(values);
		msgs = fb_api_message_parse_attach(api, &msg, msgs, node,
		                                   &err);

		if (G_UNLIKELY(err != NULL)) {
			break;
		}
	}

	if (G_LIKELY(err == NULL)) {
		msgs = g_slist_reverse(msgs);
		g_signal_emit_by_name(api, "message", msgs);
	} else {
		fb_api_error_emit(api, err);
	}

	g_slist_free_full(msgs, (GDestroyNotify) fb_api_message_free);
	fb_json_values_free(values);
	json_node_free(root);
}

static void
fb_api_cb_publish_p(FbApi *api, const GByteArray *pload)
{
	FbApiPresence pres;
	FbThrift *thft;
	FbThriftType type;
	gint32 i32;
	gint64 i64;
	gpointer mptr;
	GSList *press;
	guint i;
	guint size;

	/* Start at 1 to skip the NULL byte */
	thft  = fb_thrift_new((GByteArray*) pload, 1, TRUE);
	press = NULL;

	/* Skip the full list boolean field */
	fb_thrift_read_field(thft, &type, NULL);
	g_warn_if_fail(type == FB_THRIFT_TYPE_BOOL);
	fb_thrift_read_bool(thft, NULL);

	/* Read the list field */
	fb_thrift_read_field(thft, &type, NULL);
	g_warn_if_fail(type == FB_THRIFT_TYPE_LIST);

	/* Read the list */
	fb_thrift_read_list(thft, &type, &size);
	g_warn_if_fail(type == FB_THRIFT_TYPE_STRUCT);

	for (i = 0; i < size; i++) {
		/* Read the user identifier field */
		fb_thrift_read_field(thft, &type, NULL);
		g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
		fb_thrift_read_i64(thft, &i64);

		/* Read the active field */
		fb_thrift_read_field(thft, &type, NULL);
		g_warn_if_fail(type == FB_THRIFT_TYPE_I32);
		fb_thrift_read_i32(thft, &i32);

		pres.uid = i64;
		pres.active = i32 != 0;

		mptr = fb_api_presence_dup(&pres);
		press = g_slist_prepend(press, mptr);
		fb_util_debug_info("Presence: %" FB_ID_FORMAT " (%d)",
		                   i64, i32 != 0);

		/* Skip the last active timestamp field */
		if (!fb_thrift_read_field(thft, &type, NULL)) {
			continue;
		}

		g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
		fb_thrift_read_i64(thft, NULL);

		/* Skip the active client bits field */
		if (!fb_thrift_read_field(thft, &type, NULL)) {
			continue;
		}

		g_warn_if_fail(type == FB_THRIFT_TYPE_I16);
		fb_thrift_read_i16(thft, NULL);

		/* Skip the VoIP compatibility bits field */
		if (!fb_thrift_read_field(thft, &type, NULL)) {
			continue;
		}

		g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
		fb_thrift_read_i64(thft, NULL);

		/* Read the field stop */
		fb_thrift_read_stop(thft);
	}

	/* Read the field stop */
	fb_thrift_read_stop(thft);
	g_object_unref(thft);

	press = g_slist_reverse(press);
	g_signal_emit_by_name(api, "presence", press);
	g_slist_free_full(press, (GDestroyNotify) fb_api_presence_free);
}

static void
fb_api_cb_mqtt_publish(FbMqtt *mqtt, const gchar *topic,
                       const GByteArray *pload, gpointer data)
{
	FbApi *api = data;
	gboolean comp;
	GByteArray *bytes;
	guint i;

	static const struct {
		const gchar *topic;
		void (*func) (FbApi *api, const GByteArray *pload);
	} parsers[] = {
		{"/mark_thread_response", fb_api_cb_publish_mark},
		{"/orca_typing_notifications", fb_api_cb_publish_typing},
		{"/t_ms", fb_api_cb_publish_ms},
		{"/t_p", fb_api_cb_publish_p}
	};

	comp = fb_util_zcompressed(pload);

	if (G_LIKELY(comp)) {
		bytes = fb_util_zuncompress(pload);

		if (G_UNLIKELY(bytes == NULL)) {
			fb_api_error(api, FB_API_ERROR,
			             _("Failed to decompress"));
			return;
		}
	} else {
		bytes = (GByteArray*) pload;
	}

	fb_util_debug_hexdump(FB_UTIL_DEBUG_INFO, bytes,
	                      "Reading message (topic: %s)",
			      topic);

	for (i = 0; i < G_N_ELEMENTS(parsers); i++) {
		if (g_ascii_strcasecmp(topic, parsers[i].topic) == 0) {
			parsers[i].func(api, bytes);
			break;
		}
	}

	if (G_LIKELY(comp)) {
		g_byte_array_free(bytes, TRUE);
	}
}

FbApi *
fb_api_new(PurpleConnection *gc)
{
	FbApi *api;
	FbApiPrivate *priv;

	api = g_object_new(FB_TYPE_API, NULL);
	priv = api->priv;

	priv->gc = gc;
	priv->mqtt = fb_mqtt_new(gc);

	g_signal_connect(priv->mqtt,
	                 "connect",
	                 G_CALLBACK(fb_api_cb_mqtt_connect),
	                 api);
	g_signal_connect(priv->mqtt,
	                 "error",
	                 G_CALLBACK(fb_api_cb_mqtt_error),
	                 api);
	g_signal_connect(priv->mqtt,
	                 "open",
	                 G_CALLBACK(fb_api_cb_mqtt_open),
	                 api);
	g_signal_connect(priv->mqtt,
	                 "publish",
	                 G_CALLBACK(fb_api_cb_mqtt_publish),
	                 api);

	return api;
}

void
fb_api_rehash(FbApi *api)
{
	FbApiPrivate *priv;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	if (priv->cid == NULL) {
		priv->cid = fb_util_randstr(32);
	}

	if (priv->did == NULL) {
		priv->did = purple_uuid_random();
	}

	if (priv->mid == 0) {
		priv->mid = g_random_int();
	}

	if (strlen(priv->cid) > 20) {
		priv->cid = g_realloc_n(priv->cid , 21, sizeof *priv->cid);
		priv->cid[20] = 0;
	}
}

void
fb_api_error(FbApi *api, FbApiError error, const gchar *format, ...)
{
	GError *err;
	va_list ap;

	g_return_if_fail(FB_IS_API(api));

	va_start(ap, format);
	err = g_error_new_valist(FB_API_ERROR, error, format, ap);
	va_end(ap);

	fb_api_error_emit(api, err);
}

void
fb_api_error_emit(FbApi *api, GError *error)
{
	g_return_if_fail(FB_IS_API(api));
	g_return_if_fail(error != NULL);

	g_signal_emit_by_name(api, "error", error);
	g_error_free(error);
}

static void
fb_api_cb_auth(PurpleHttpConnection *con, PurpleHttpResponse *res,
               gpointer data)
{
	FbApi *api = data;
	FbApiPrivate *priv = api->priv;
	FbJsonValues *values;
	GError *err = NULL;
	JsonNode *root;

	if (!fb_api_http_chk(api, con, res, &root)) {
		return;
	}

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.access_token");
	fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.uid");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return;
	);

	g_free(priv->token);
	priv->token = fb_json_values_next_str_dup(values, NULL);
	priv->uid = fb_json_values_next_int(values, 0);

	g_signal_emit_by_name(api, "auth");
	fb_json_values_free(values);
	json_node_free(root);
}

void
fb_api_auth(FbApi *api, const gchar *user, const gchar *pass)
{
	FbHttpParams *prms;

	static const FbApiHttpInfo info = {
		fb_api_cb_auth,
		"com.facebook.auth.protocol.d",
		"authenticate",
		"auth.login"
	};

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "email", user);
	fb_http_params_set_str(prms, "password", pass);
	fb_api_http_req(api, &info, prms, FB_API_URL_AUTH);
}

static void
fb_api_cb_contacts(PurpleHttpConnection *con, PurpleHttpResponse *res,
                   gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbApiUser user;
	FbHttpParams *params;
	FbJsonValues *values;
	gchar *writeid = NULL;
	GError *err = NULL;
	gpointer mptr;
	GSList *users = NULL;
	JsonNode *root;

	if (!fb_api_http_chk(api, con, res, &root)) {
		return;
	}

	values = fb_json_values_new(root, "$.viewer.messenger_contacts.nodes");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.graph_api_write_id");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.represented_profile.friendship_status");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.represented_profile.id");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.structured_name.text");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.hugePictureUrl.uri");

	while (fb_json_values_update(values, &err)) {
		g_free(writeid);
		writeid = fb_json_values_next_str_dup(values, NULL);
		str = fb_json_values_next_str(values, NULL);

		if (!purple_strequal(str, "ARE_FRIENDS")) {
			continue;
		}

		fb_api_user_reset(&user, FALSE);
		str = fb_json_values_next_str(values, NULL);
		user.uid = FB_ID_FROM_STR(str);

		user.name = fb_json_values_next_str_dup(values, NULL);
		user.icon = fb_json_values_next_str_dup(values, NULL);

		params = fb_http_params_new_parse(user.icon, TRUE);
		str = fb_http_params_get_str(params, "oh", &err);
		user.csum = g_strdup(str);
		fb_http_params_free(params);

		mptr = fb_api_user_dup(&user, FALSE);
		users = g_slist_prepend(users, mptr);
	}

	if (G_UNLIKELY(err == NULL)) {
		g_signal_emit_by_name(api, "contacts", users, writeid == NULL);

		if (writeid != NULL) {
			fb_api_contacts_after(api, writeid);
		}
	} else {
		fb_api_error_emit(api, err);
	}

	g_free(writeid);
	g_slist_free_full(users, (GDestroyNotify) fb_api_user_free);
	fb_json_values_free(values);
	json_node_free(root);
}

void
fb_api_contacts(FbApi *api)
{
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_contacts,
		"com.facebook.contacts.service.c",
		"FetchContactsFullQuery",
		"get"
	};

	/* Object key mapping:
	 *   0: profile_types
	 *   1: limit
	 *   2: small_img_size
	 *   3: big_img_size
	 *   4: huge_img_size
	 *   5: low_res_cover_size
	 *   6: media_type
	 *   7: high_res_cover_size
	 */

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_arr_begin(bldr, "0");
	fb_json_bldr_add_str(bldr, NULL, "user");
	fb_json_bldr_arr_end(bldr);

	fb_json_bldr_add_str(bldr, "1", FB_API_CONTACTS_COUNT);
	fb_api_http_graph(api, &info, bldr, FB_API_QRYID_CONTACTS);
}

static void
fb_api_contacts_after(FbApi *api, const gchar *writeid)
{
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_contacts,
		"com.facebook.contacts.service.c",
		"FetchContactsFullWithAfterQuery",
		"get"
	};

	/* Object key mapping:
	 *   0: profile_types
	 *   1: after
	 *   2: limit
	 *   3: small_img_size
	 *   4: big_img_size
	 *   5: huge_img_size
	 *   6: low_res_cover_size
	 *   7: media_type
	 *   8: high_res_cover_size
	 */

	if (g_str_has_prefix(writeid, "contact_")) {
		writeid += 8;
	}

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_arr_begin(bldr, "0");
	fb_json_bldr_add_str(bldr, NULL, "user");
	fb_json_bldr_arr_end(bldr);

	fb_json_bldr_add_str(bldr, "1", writeid);
	fb_json_bldr_add_str(bldr, "2", FB_API_CONTACTS_COUNT);
	fb_api_http_graph(api, &info, bldr, FB_API_QRYID_CONTACTS_AFTER);
}

void
fb_api_connect(FbApi *api)
{
	FbApiPrivate *priv;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	fb_mqtt_open(priv->mqtt, FB_MQTT_HOST, FB_MQTT_PORT);
}

void
fb_api_disconnect(FbApi *api)
{
	FbApiPrivate *priv;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	fb_mqtt_disconnect(priv->mqtt);
}

void
fb_api_message(FbApi *api, FbId id, gboolean thread, const gchar *msg)
{
	const gchar *tpfx;
	FbApiPrivate *priv;
	gchar *json;
	gpointer mptr;
	guint64 msgid;
	JsonBuilder *bldr;

	g_return_if_fail(FB_IS_API(api));
	g_return_if_fail(msg != NULL);
	priv = api->priv;

	msgid = FB_API_MSGID(g_get_real_time() / 1000, g_random_int());
	tpfx = thread ? "tfbid_" : "";

	mptr = g_memdup(&msgid, sizeof msgid);
	g_hash_table_replace(priv->msgids, mptr, mptr);

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_int(bldr, "msgid", msgid);
	fb_json_bldr_add_str(bldr, "body", msg);
	fb_json_bldr_add_strf(bldr, "sender_fbid", "%" FB_ID_FORMAT, priv->uid);
	fb_json_bldr_add_strf(bldr, "to", "%s%" FB_ID_FORMAT, tpfx, id);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/send_message2", "%s", json);
	g_free(json);
}

void
fb_api_publish(FbApi *api, const gchar *topic, const gchar *fmt, ...)
{
	FbApiPrivate *priv;
	GByteArray *bytes;
	GByteArray *cytes;
	gchar *msg;
	va_list ap;

	g_return_if_fail(FB_IS_API(api));
	g_return_if_fail(topic != NULL);
	g_return_if_fail(fmt != NULL);
	priv = api->priv;

	va_start(ap, fmt);
	msg = g_strdup_vprintf(fmt, ap);
	va_end(ap);

	bytes = g_byte_array_new_take((guint8*) msg, strlen(msg));
	cytes = fb_util_zcompress(bytes);

	fb_util_debug_hexdump(FB_UTIL_DEBUG_INFO, bytes,
	                      "Writing message (topic: %s)",
			      topic);

	fb_mqtt_publish(priv->mqtt, topic, cytes);
	g_byte_array_free(cytes, TRUE);
	g_byte_array_free(bytes, TRUE);
}

void
fb_api_read(FbApi *api, FbId id, gboolean thread)
{
	const gchar *key;
	FbApiPrivate *priv;
	gchar *json;
	JsonBuilder *bldr;

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_bool(bldr, "state", TRUE);
	fb_json_bldr_add_int(bldr, "syncSeqId", priv->sid);
	fb_json_bldr_add_str(bldr, "mark", "read");

	key = thread ? "threadFbId" : "otherUserFbId";
	fb_json_bldr_add_strf(bldr, key, "%" FB_ID_FORMAT, id);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/mark_thread", "%s", json);
	g_free(json);
}

static void
fb_api_cb_thread_create(PurpleHttpConnection *con, PurpleHttpResponse *res,
                        gpointer data)
{
	const gchar *str;
	FbApi *api = data;
	FbId tid;
	FbJsonValues *values;
	GError *err = NULL;
	JsonNode *root;

	if (!fb_api_http_chk(api, con, res, &root)) {
		return;
	}

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.thread_fbid");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		json_node_free(root);
		return;
	);

	str = fb_json_values_next_str(values, "0");
	tid = FB_ID_FROM_STR(str);
	g_signal_emit_by_name(api, "thread-create", tid);

	fb_json_values_free(values);
	json_node_free(root);
}

void
fb_api_thread_create(FbApi *api, GSList *uids)
{
	FbApiPrivate *priv;
	FbHttpParams *prms;
	FbId *uid;
	gchar *json;
	GSList *l;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_thread_create,
		"ccom.facebook.orca.send.service.l",
		"createThread",
		"POST"
	};

	g_return_if_fail(FB_IS_API(api));
	g_warn_if_fail(g_slist_length(uids) > 1);
	priv = api->priv;

	bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
	fb_json_bldr_obj_begin(bldr, NULL);
	fb_json_bldr_add_str(bldr, "type", "id");
	fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, priv->uid);
	fb_json_bldr_obj_end(bldr);

	for (l = uids; l != NULL; l = l->next) {
		uid = l->data;
		fb_json_bldr_obj_begin(bldr, NULL);
		fb_json_bldr_add_str(bldr, "type", "id");
		fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, *uid);
		fb_json_bldr_obj_end(bldr);
	}

	json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);
	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "to", json);
	fb_api_http_req(api, &info, prms, FB_API_URL_THRDS);
	g_free(json);
}

static gboolean
fb_api_thread_parse(FbApi *api, FbApiThread *thrd, JsonNode *root,
                    GError **error)
{
	const gchar *str;
	FbApiPrivate *priv = api->priv;
	FbApiUser user;
	FbJsonValues *values;
	gboolean haself = FALSE;
	GError *err = NULL;
	gpointer mptr;

	values = fb_json_values_new(root, NULL);
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
	                   "$.thread_key.thread_fbid");
	fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.name");
	fb_json_values_update(values, &err);

	FB_API_ERROR_EMIT(api, err,
		fb_json_values_free(values);
		return FALSE;
	);

	str = fb_json_values_next_str(values, NULL);

	if (str == NULL) {
		fb_json_values_free(values);
		return FALSE;
	}

	thrd->tid = FB_ID_FROM_STR(str);
	thrd->topic = fb_json_values_next_str_dup(values, NULL);
	fb_json_values_free(values);

	values = fb_json_values_new(root, "$.all_participants.nodes");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.messaging_actor.id");
	fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
	                   "$.messaging_actor.name");

	while (fb_json_values_update(values, &err)) {
		fb_api_user_reset(&user, FALSE);
		str = fb_json_values_next_str(values, "0");
		user.uid = FB_ID_FROM_STR(str);

		if (user.uid != priv->uid) {
			user.name = fb_json_values_next_str_dup(values, NULL);
			mptr = fb_api_user_dup(&user, FALSE);
			thrd->users = g_slist_prepend(thrd->users, mptr);
		} else {
			haself = TRUE;
		}
	}

	if ((g_slist_length(thrd->users) < 2) || !haself) {
		fb_api_thread_reset(thrd, FALSE);
		return FALSE;
	}

	if (G_UNLIKELY(err != NULL)) {
		g_propagate_error(error, err);
	}

	fb_json_values_free(values);
	return TRUE;
}

static void
fb_api_cb_thread_info(PurpleHttpConnection *con, PurpleHttpResponse *res,
                      gpointer data)
{
	FbApi *api = data;
	FbApiThread thrd;
	GError *err = NULL;
	JsonNode *node;
	JsonNode *root;

	if (!fb_api_http_chk(api, con, res, &root)) {
		return;
	}

	node = fb_json_node_get_nth(root, 0);

	if (node == NULL) {
		fb_api_error(api, FB_API_ERROR_GENERAL,
		             _("Failed to obtain thread information"));
		json_node_free(root);
		return;
	}

	fb_api_thread_reset(&thrd, FALSE);

	if (!fb_api_thread_parse(api, &thrd, node, &err)) {
		fb_api_error(api, FB_API_ERROR_GENERAL,
		             _("Failed to parse thread information"));
		json_node_free(root);
		return;
	}

	if (G_LIKELY(err == NULL)) {
		g_signal_emit_by_name(api, "thread-info", &thrd);
	} else {
		fb_api_error_emit(api, err);
	}

	fb_api_thread_reset(&thrd, TRUE);
	json_node_free(root);
}

void
fb_api_thread_info(FbApi *api, FbId tid)
{
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_thread_info,
		"com.facebook.orca.e.m",
		"ThreadQuery",
		"get"
	};

	/* Object key mapping:
	 *   0: thread_ids
	 *   1: verification_type
	 *   2: hash_key
	 *   3: medium_preview_size
	 *   4: item_count
	 *   5: itemCount
	 *   6: full_screen_height
	 *   7: full_screen_width
	 *   8: small_preview_size
	 *   9: large_preview_size
	 *   10: fetch_users_separately
	 *   11: include_message_info
	 *   12: msg_count
	 *   13: include_full_user_info
	 *   14: profile_pic_small_size
	 *   15: profile_pic_medium_size
	 *   16: profile_pic_large_size
	 */

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_arr_begin(bldr, "0");
	fb_json_bldr_add_strf(bldr, NULL, "%" FB_ID_FORMAT, tid);
	fb_json_bldr_arr_end(bldr);

	fb_json_bldr_add_str(bldr, "10", "false");
	fb_json_bldr_add_str(bldr, "11", "false");
	fb_json_bldr_add_str(bldr, "12", "false");
	fb_json_bldr_add_str(bldr, "13", "false");
	fb_api_http_graph(api, &info, bldr, FB_API_QRYID_THREAD_INFO);
}

void
fb_api_thread_invite(FbApi *api, FbId tid, FbId uid)
{
	FbHttpParams *prms;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_http_bool,
		"com.facebook.orca.protocol.a",
		"addMembers",
		"POST"
	};

	bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
	fb_json_bldr_obj_begin(bldr, NULL);
	fb_json_bldr_add_str(bldr, "type", "id");
	fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, uid);
	fb_json_bldr_obj_end(bldr);
	json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "to", json);
	fb_http_params_set_strf(prms, "id", "t_id.%" FB_ID_FORMAT, tid);
	fb_api_http_req(api, &info, prms, FB_API_URL_PARTS);
	g_free(json);
}

static void
fb_api_cb_thread_list(PurpleHttpConnection *con, PurpleHttpResponse *res,
                      gpointer data)
{
	FbApi *api = data;
	FbApiThread thrd;
	GError *err = NULL;
	GList *elms;
	GList *l;
	GSList *thrds = NULL;
	gpointer mptr;
	JsonArray *arr;
	JsonNode *root;

	if (!fb_api_http_chk(api, con, res, &root)) {
		return;
	}

	arr = fb_json_node_get_arr(root, "$.viewer.message_threads.nodes",
	                           &err);
	FB_API_ERROR_EMIT(api, err,
		json_node_free(root);
		return;
	);

	elms = json_array_get_elements(arr);
	fb_api_thread_reset(&thrd, FALSE);

	for (l = elms; l != NULL; l = l->next) {
		if (fb_api_thread_parse(api, &thrd, l->data, &err)) {
			mptr = fb_api_thread_dup(&thrd, TRUE);
			thrds = g_slist_prepend(thrds, mptr);
		}

		if (G_UNLIKELY(err != NULL)) {
			break;
		}

		fb_api_thread_reset(&thrd, TRUE);
	}

	if (G_LIKELY(err == NULL)) {
		thrds = g_slist_reverse(thrds);
		g_signal_emit_by_name(api, "thread-list", thrds);
	} else {
		fb_api_error_emit(api, err);
	}

	g_slist_free_full(thrds, (GDestroyNotify) fb_api_thread_free);
	g_list_free(elms);
	json_array_unref(arr);
	json_node_free(root);
}

void
fb_api_thread_list(FbApi *api)
{
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_thread_list,
		"com.facebook.orca.e.y",
		"ThreadListQuery",
		"get"
	};

	/* Object key mapping:
	 *   0: folder_tag
	 *   1: thread_count
	 *   2: include_thread_info
	 *   3: verification_type
	 *   4: hash_key
	 *   5: medium_preview_size
	 *   6: item_count
	 *   7: itemCount
	 *   8: full_screen_height
	 *   9: full_screen_width
	 *   10: small_preview_size
	 *   11: large_preview_size
	 *   12: fetch_users_separately
	 *   13: include_message_info
	 *   14: msg_count
	 *   15: include_full_user_info
	 *   16: profile_pic_small_size
	 *   17: profile_pic_medium_size
	 *   18: profile_pic_large_size
	 */

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_str(bldr, "2", "true");
	fb_json_bldr_add_str(bldr, "12", "false");
	fb_json_bldr_add_str(bldr, "13", "false");
	fb_json_bldr_add_str(bldr, "14", "false");
	fb_json_bldr_add_str(bldr, "15", "false");
	fb_api_http_graph(api, &info, bldr, FB_API_QRYID_THREAD_LIST);
}

void
fb_api_thread_remove(FbApi *api, FbId tid, FbId uid)
{
	FbApiPrivate *priv;
	FbHttpParams *prms;
	gchar *json;
	JsonBuilder *bldr;

	static const FbApiHttpInfo info = {
		fb_api_cb_http_bool,
		"com.facebook.orca.protocol.a",
		"removeMembers",
		"DELETE"
	};

	g_return_if_fail(FB_IS_API(api));
	priv = api->priv;

	prms = fb_http_params_new();
	fb_http_params_set_strf(prms, "id", "t_id.%" FB_ID_FORMAT, tid);

	if (uid == 0) {
		uid = priv->uid;
	}

	if (uid != priv->uid) {
		bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
		fb_json_bldr_add_strf(bldr, NULL, "%" FB_ID_FORMAT, uid);
		json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);
		fb_http_params_set_str(prms, "to", json);
		g_free(json);
	}

	fb_api_http_req(api, &info, prms, FB_API_URL_PARTS);
}

void
fb_api_thread_topic(FbApi *api, FbId tid, const gchar *topic)
{
	FbHttpParams *prms;

	static const FbApiHttpInfo info = {
		fb_api_cb_http_bool,
		"com.facebook.orca.protocol.a",
		"setThreadName",
		"messaging.setthreadname"
	};

	prms = fb_http_params_new();
	fb_http_params_set_str(prms, "name", topic);
	fb_http_params_set_strf(prms, "tid", "t_id.%" FB_ID_FORMAT, tid);
	fb_api_http_req(api, &info, prms, FB_API_URL_TOPIC);
}

void
fb_api_typing(FbApi *api, FbId uid, gboolean state)
{
	gchar *json;
	JsonBuilder *bldr;

	bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
	fb_json_bldr_add_int(bldr, "state", state != 0);
	fb_json_bldr_add_strf(bldr, "to", "%" FB_ID_FORMAT, uid);

	json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
	fb_api_publish(api, "/typing", "%s", json);
	g_free(json);
}

FbApiMessage *
fb_api_message_new(FbId uid, FbId tid, const gchar *text, gboolean isself)
{
	FbApiMessage *msg;

	msg = g_new(FbApiMessage, 1);
	msg->uid = uid;
	msg->tid = tid;
	msg->text = g_strdup(text);
	msg->isself = isself;

	return msg;
}

FbApiMessage *
fb_api_message_dup(FbApiMessage *msg, gboolean deep)
{
	FbApiMessage *ret;

	g_return_val_if_fail(msg != NULL, NULL);
	ret = fb_api_message_new(msg->uid, msg->tid, NULL, msg->isself);

	if (deep) {
		ret->text = g_strdup(msg->text);
	} else {
		ret->text = msg->text;
	}

	return ret;
}

void
fb_api_message_reset(FbApiMessage *msg, gboolean deep)
{
	g_return_if_fail(msg != NULL);

	if (deep) {
		g_free(msg->text);
	}

	memset(msg, 0, sizeof *msg);
}

void
fb_api_message_free(FbApiMessage *msg)
{
	if (G_UNLIKELY(msg == NULL)) {
		return;
	}

	g_free(msg->text);
	g_free(msg);
}

FbApiPresence *
fb_api_presence_new(FbId uid, gboolean active)
{
	FbApiPresence *pres;

	pres = g_new(FbApiPresence, 1);
	pres->uid = uid;
	pres->active = active;

	return pres;
}

FbApiPresence *
fb_api_presence_dup(FbApiPresence *pres)
{
	g_return_val_if_fail(pres != NULL, NULL);
	return fb_api_presence_new(pres->uid, pres->active);
}

void
fb_api_presence_reset(FbApiPresence *pres)
{
	g_return_if_fail(pres != NULL);
	memset(pres, 0, sizeof *pres);
}

void
fb_api_presence_free(FbApiPresence *pres)
{
	if (G_UNLIKELY(pres == NULL)) {
		return;
	}

	g_free(pres);
}

FbApiThread *
fb_api_thread_new(FbId tid, const gchar *topic, GSList *users)
{
	FbApiThread *thrd;

	thrd = g_new(FbApiThread, 1);
	thrd->tid = tid;
	thrd->topic = g_strdup(topic);
	thrd->users = users;

	return thrd;
}

FbApiThread *
fb_api_thread_dup(FbApiThread *thrd, gboolean deep)
{
	FbApiThread *ret;

	g_return_val_if_fail(thrd != NULL, NULL);
	ret = fb_api_thread_new(thrd->tid, NULL, NULL);

	if (deep) {
		ret->topic = g_strdup(thrd->topic);
		ret->users = g_slist_copy_deep(thrd->users,
		                               (GCopyFunc) fb_api_user_dup,
		                               GINT_TO_POINTER(deep));
	} else {
		ret->topic = thrd->topic;
		ret->users = thrd->users;
	}

	return ret;
}

void
fb_api_thread_reset(FbApiThread *thrd, gboolean deep)
{
	g_return_if_fail(thrd != NULL);

	if (deep) {
		g_slist_free_full(thrd->users, (GDestroyNotify) fb_api_user_free);
		g_free(thrd->topic);
	}

	memset(thrd, 0, sizeof *thrd);
}

void
fb_api_thread_free(FbApiThread *thrd)
{
	if (G_UNLIKELY(thrd == NULL)) {
		return;
	}

	g_slist_free_full(thrd->users, (GDestroyNotify) fb_api_user_free);
	g_free(thrd->topic);
	g_free(thrd);
}

FbApiTyping *
fb_api_typing_new(FbId uid, gboolean state)
{
	FbApiTyping *typg;

	typg = g_new(FbApiTyping, 1);
	typg->uid = uid;
	typg->state = state;

	return typg;
}

FbApiTyping *
fb_api_typing_dup(FbApiTyping *typg)
{
	g_return_val_if_fail(typg != NULL, NULL);
	return fb_api_typing_new(typg->uid, typg->state);
}

void
fb_api_typing_reset(FbApiTyping *typg)
{
	g_return_if_fail(typg != NULL);
	memset(typg, 0, sizeof *typg);
}

void
fb_api_typing_free(FbApiTyping *typg)
{
	if (G_UNLIKELY(typg == NULL)) {
		return;
	}

	g_free(typg);
}

FbApiUser *
fb_api_user_new(FbId uid, const gchar *name, const gchar *icon,
                const gchar *csum)
{
	FbApiUser *user;

	user = g_new(FbApiUser, 1);
	user->uid = uid;

	return user;
}

FbApiUser *
fb_api_user_dup(FbApiUser *user, gboolean deep)
{
	FbApiUser *ret;

	g_return_val_if_fail(user != NULL, NULL);
	ret = fb_api_user_new(user->uid, NULL, NULL, NULL);

	if (deep) {
		ret->name = g_strdup(user->name);
		ret->icon = g_strdup(user->icon);
		ret->csum = g_strdup(user->csum);
	} else {
		ret->name = user->name;
		ret->icon = user->icon;
		ret->csum = user->csum;
	}

	return ret;
}

void
fb_api_user_reset(FbApiUser *user, gboolean deep)
{
	g_return_if_fail(user != NULL);

	if (deep) {
		g_free(user->name);
		g_free(user->icon);
		g_free(user->csum);
	}

	memset(user, 0, sizeof *user);
}

void
fb_api_user_free(FbApiUser *user)
{
	if (G_UNLIKELY(user == NULL)) {
		return;
	}

	g_free(user->name);
	g_free(user->icon);
	g_free(user->csum);
	g_free(user);
}
