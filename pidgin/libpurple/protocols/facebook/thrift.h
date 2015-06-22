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

#ifndef _FACEBOOK_THRIFT_H_
#define _FACEBOOK_THRIFT_H_

#include <glib.h>
#include <glib-object.h>

#define FB_TYPE_THRIFT             (fb_thrift_get_type())
#define FB_THRIFT(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_THRIFT, FbThrift))
#define FB_THRIFT(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_THRIFT, FbThrift))
#define FB_THRIFT_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_THRIFT, FbThriftClass))
#define FB_IS_THRIFT(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_THRIFT))
#define FB_IS_THRIFT_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_THRIFT))
#define FB_THRIFT_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_THRIFT, FbThriftClass))

typedef enum _FbThriftFlags FbThriftFlags;
typedef enum _FbThriftType FbThriftType;
typedef struct _FbThrift FbThrift;
typedef struct _FbThriftClass FbThriftClass;
typedef struct _FbThriftPrivate FbThriftPrivate;

enum _FbThriftFlags
{
	FB_THRIFT_FLAG_COMPACT  = 1 << 0,
	FB_THRIFT_FLAG_INTERNAL = 1 << 1
};

enum _FbThriftType
{
	FB_THRIFT_TYPE_STOP   = 0,
	FB_THRIFT_TYPE_VOID   = 1,
	FB_THRIFT_TYPE_BOOL   = 2,
	FB_THRIFT_TYPE_BYTE   = 3,
	FB_THRIFT_TYPE_DOUBLE = 4,
	FB_THRIFT_TYPE_I16    = 6,
	FB_THRIFT_TYPE_I32    = 8,
	FB_THRIFT_TYPE_I64    = 10,
	FB_THRIFT_TYPE_STRING = 11,
	FB_THRIFT_TYPE_STRUCT = 12,
	FB_THRIFT_TYPE_MAP    = 13,
	FB_THRIFT_TYPE_SET    = 14,
	FB_THRIFT_TYPE_LIST   = 15,
	FB_THRIFT_TYPE_ENUM   = 16,

	FB_THRIFT_TYPE_UNKNOWN

};

struct _FbThrift
{
	GObject parent;
	FbThriftPrivate *priv;
};

struct _FbThriftClass
{
	GObjectClass parent_class;
};


GType
fb_thrift_get_type(void);

FbThrift *
fb_thrift_new(GByteArray *bytes, guint offset, gboolean compact);

guint
fb_thrift_get_pos(FbThrift *thft);

void
fb_thrift_set_pos(FbThrift *thft, guint pos);

void
fb_thrift_reset(FbThrift *thft);

gboolean
fb_thrift_read(FbThrift *thft, gpointer data, guint size);

gboolean
fb_thrift_read_bool(FbThrift *thft, gboolean *bln);

gboolean
fb_thrift_read_byte(FbThrift *thft, guint8 *byte);

gboolean
fb_thrift_read_dbl(FbThrift *thft, gdouble *dbl);

gboolean
fb_thrift_read_i16(FbThrift *thft, gint16 *i16);

gboolean
fb_thrift_read_vi16(FbThrift *thft, guint16 *u16);

gboolean
fb_thrift_read_i32(FbThrift *thft, gint32 *i32);

gboolean
fb_thrift_read_vi32(FbThrift *thft, guint32 *u32);

gboolean
fb_thrift_read_i64(FbThrift *thft, gint64 *i64);

gboolean
fb_thrift_read_vi64(FbThrift *thft, guint64 *u64);

gboolean
fb_thrift_read_str(FbThrift *thft, gchar **str);

gboolean
fb_thrift_read_field(FbThrift *thft, FbThriftType *type, gint16 *id);

gboolean
fb_thrift_read_stop(FbThrift *thft);

gboolean
fb_thrift_read_isstop(FbThrift *thft);

gboolean
fb_thrift_read_list(FbThrift *thft, FbThriftType *type, guint *size);

gboolean
fb_thrift_read_map(FbThrift *thft, FbThriftType *ktype, FbThriftType *vtype,
                   guint *size);

gboolean
fb_thrift_read_set(FbThrift *thft, FbThriftType *type, guint *size);

void
fb_thrift_write(FbThrift *thft, gconstpointer data, guint size);

void
fb_thrift_write_bool(FbThrift *thft, gboolean bln);

void
fb_thrift_write_byte(FbThrift *thft, guint8 byte);

void
fb_thrift_write_dbl(FbThrift *thft, gdouble dbl);

void
fb_thrift_write_i16(FbThrift *thft, gint16 i16);

void
fb_thrift_write_vi16(FbThrift *thft, guint16 u16);

void
fb_thrift_write_i32(FbThrift *thft, gint32 i32);

void
fb_thrift_write_vi32(FbThrift *thft, guint32 u32);

void
fb_thrift_write_i64(FbThrift *thft, gint64 i64);

void
fb_thrift_write_vi64(FbThrift *thft, guint64 u64);

void
fb_thrift_write_str(FbThrift *thft, const gchar *str);

void
fb_thrift_write_field(FbThrift *thft, FbThriftType type, gint16 id);

void
fb_thrift_write_stop(FbThrift *thft);

void
fb_thrift_write_list(FbThrift *thft, FbThriftType type, guint size);

void
fb_thrift_write_map(FbThrift *thft, FbThriftType ktype, FbThriftType vtype,
                    guint size);

void
fb_thrift_write_set(FbThrift *thft, FbThriftType type, guint size);

guint8
fb_thrift_t2ct(FbThriftType type);

FbThriftType
fb_thrift_ct2t(guint8 type);

#endif /* _FACEBOOK_THRIFT_H_ */
