#ifndef _PACKET_ZWAVE_NET_H_
#define _PACKET_ZWAVE_NET_H_

#define ZWAVE_NET_SR_FORMAT_QUIET 0x00
#define ZWAVE_NET_SR_FORMAT_DEFAULT 0x02
#define ZWAVE_NET_SR_FORMAT_DELUXE 0x03

#define ZWAVE_NET_SR_FORMAT_COL_TXT 0x01
#define ZWAVE_NET_SR_FORMAT_TREE_TXT 0x02
#define ZWAVE_NET_SR_STRLEN 50

extern guint8
dissect_zwave_net_sr(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 offset, guint8 format);

/*
struct source_rt{
	guint8 net_type,
	guint8 sr_lenhop,
	guint8 *route
}(__attribute__((packed));

struct neighbor_list{
	guint8 length,
	guint8 *nl
}(__attribute__((packed));

struct route_entry{
	guint destID,
	struct source_rt route,
	guint status
}(__attribute__((packed));
*/

#endif
