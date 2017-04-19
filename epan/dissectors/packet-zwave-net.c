#include "config.h"
#include <epan/packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "packet-zwave-net.h"

static int proto_zwave_net = -1;

static int hf_zwave_net_type = -1;

static int hf_zwave_net_len = -1;
static int hf_zwave_net_athop = -1;
static int hf_zwave_net_sr = -1;

//static int hf_zwave_net_config_type = -1;
//static int hf_zwave_net_config_status = -1;
//static int hf_zwave_net_config_nl_size = -1;
//static int hf_zwave_net_config_nl = -1;

//static int hf_zwave_net_config_rt_dest_id = -1;
//static int hf_zwave_net_config_rt_status = -1;
//static int hf_zwave_net_config_rt_entry = -1;

#define ZWAVE_NET_CONFIG_RT_STATUS_OK 0x10
#define ZWAVE_NET_CONFIG_RT_STATUS_EMPTY 0x08

#define ZWAVE_NET_HIGH_NIBBLE_MASK 0xF0
#define ZWAVE_NET_LOW_NIBBLE_MASK 0x0F

static gint ett_zwave_net = -1;
static dissector_handle_t data_handle;
static dissector_handle_t app_handle;

#define ZWAVE_NET_SR 0x00
#define ZWAVE_NET_CFG 0x01
#define ZWAVE_NET_RT_ACK 0x03
#define ZWAVE_NET_RT_NACK 0x15

static const value_string zwave_net_header_type[] = {
	{	 ZWAVE_NET_SR	,	"SR"	 },
	{	 ZWAVE_NET_RT_ACK	,	"ACK"	 },
	{	 ZWAVE_NET_RT_NACK	,	"NACK"	 }
};

guint8
dissect_zwave_net_sr(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 offset, guint8 format){
	guint len = -1;
	guint athop = -1;
	guint8 *bytes = NULL;
	guint8 *sr = NULL;
    guint8 strbuf[256];
	guint8 singleHop[5];
	guint8 i=-1;

	//If you want this to be in a subtree, you must create one and pass to this function

	memset(strbuf,0,256);

	len = ((tvb_get_guint8 (tvb, offset)) & ZWAVE_NET_HIGH_NIBBLE_MASK) >> 4;
	athop = ((tvb_get_guint8 (tvb, offset)) & ZWAVE_NET_LOW_NIBBLE_MASK);
	bytes = tvb_get_string(wmem_packet_scope(),tvb, offset+1, len);
	
	sr = (guint8*)calloc(sizeof(guint8),ZWAVE_NET_SR_STRLEN);
	
	for (i=0;i<len;i++){
		
		if(i==0){
			snprintf(sr, ZWAVE_NET_SR_STRLEN,"%u", bytes[i]);
		}else{
			memset(singleHop,0,5);
			snprintf(singleHop, 5, ",%u", bytes[i]);
			strncat(sr, singleHop, ZWAVE_NET_SR_STRLEN);
		}
	}

/*
	if (len == 0)
		snprintf(sr, ZWAVE_NET_SR_STRLEN, "''");
	else if(len == 1)
		snprintf(sr, ZWAVE_NET_SR_STRLEN,"%u", bytes[0]);
	else if(len == 2)
		snprintf(sr, ZWAVE_NET_SR_STRLEN,"%u,%u", bytes[0], bytes[1]);
	else if(len == 3)
		snprintf(sr, ZWAVE_NET_SR_STRLEN,"%u,%u,%u", bytes[0], bytes[1], bytes[2]);
	else if(len == 4)
		snprintf(sr, ZWAVE_NET_SR_STRLEN,"%u,%u,%u,%u", bytes[0], bytes[1], bytes[2], bytes[3]);
*/

	if((format & ZWAVE_NET_SR_FORMAT_COL_TXT) > 0){
		snprintf(strbuf,255," [%s]@%x", sr, athop);
		col_append_str(pinfo->cinfo,COL_INFO,strbuf);
	}

	if((format & ZWAVE_NET_SR_FORMAT_TREE_TXT) > 0){
		proto_item_append_text (ti, " [%s]@%x", sr, athop);
	}

	// Do the field stuff
	proto_tree_add_item( tree, hf_zwave_net_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item( tree, hf_zwave_net_athop, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
		
	proto_tree_add_string( tree, hf_zwave_net_sr, tvb, offset, len,sr);
	offset += len;

	// I hope the source route gets copied rather than referenced...
	if(sr){
		free(sr);
	}

	return offset;
}


static void
dissect_zwave_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	tvbuff_t *next_tvb;	
	proto_item* ti = NULL;
	proto_tree* zwave_net_tree = NULL;

	guint type = -1;
    guint8 strbuf[256];

	if(app_handle <= 0){
		app_handle = find_dissector("zwave_app");
	}

	if(data_handle <= 0){	
		data_handle = find_dissector("data");
	}

	memset(strbuf,0,256);
	if(tree){
		type = tvb_get_guint8 (tvb, offset);

		ti = proto_tree_add_item (tree, proto_zwave_net, tvb, 0, -1, ENC_NA);
		zwave_net_tree = proto_item_add_subtree (ti, ett_zwave_net);

		proto_tree_add_item (zwave_net_tree, hf_zwave_net_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		
		//col_clear (pinfo->cinfo, COL_INFO);
		snprintf(strbuf,255," | NET: %s",val_to_str(type, zwave_net_header_type, "Unknown(0x%02x)"));
		col_append_str(pinfo->cinfo,COL_INFO,strbuf);

		proto_item_append_text (ti, " %s", val_to_str(type, zwave_net_header_type, "Unknown (0x%02x)"));

		offset = dissect_zwave_net_sr(ti, tvb, pinfo, zwave_net_tree, offset, ZWAVE_NET_SR_FORMAT_DELUXE);
		
		next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset), tvb_reported_length(tvb));


		if((app_handle > 0)&&(type == ZWAVE_NET_SR)){			
			call_dissector(app_handle, next_tvb, pinfo, tree);
			
		}else{
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	}

	return;
}

void
proto_register_zwave_net (void)
{
 

	static hf_register_info hf[] = {
		{ &hf_zwave_net_type,
			{
				"Network Message Type", "zwave_net.type",
				FT_UINT8, BASE_HEX, VALS(zwave_net_header_type), 0x0, NULL, HFILL
			}
		},
		{ &hf_zwave_net_len,
			{
				"Source Route Length", "zwave_net.sr.len",
				FT_UINT8, BASE_HEX, NULL, ZWAVE_NET_HIGH_NIBBLE_MASK, NULL, HFILL
			}
		},
		{ &hf_zwave_net_athop,
			{
				"Current Index of Hop Count", "zwave_net.athop",
				FT_UINT8, BASE_HEX, NULL, ZWAVE_NET_LOW_NIBBLE_MASK, NULL, HFILL
			}
		},
		{ &hf_zwave_net_sr,
			{
				"Source Route", "zwave_net.sr",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		}

/*
		{ &hf_zwave_net_config_type,
			{
				"Config Msg Type", "zwave_net.cfg.type",
				FT_UINT8, BASE_HEX, VALS(zwave_net_config_header_type), 0x00, NULL, HFILL
			}
		},
		{ &hf_zwave_net_config_status,
			{
				"Status", "zwave_net.cfg.status",
				FT_UINT8, BASE_HEX, VALS(zwave_net_config_header_type), 0x00, NULL, HFILL
			}
		},
		{ &hf_zwave_net_config_nl_size,
			{
				"Neighbor List Size", "zwave_net.cfg.nl.size",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_zwave_net_config_nl,
			{
				"Neighbor List", "zwave_net.nl.bitfield",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_zwave_net_config_rt_dest_id,
			{
				"Destination Node ID", "zwave_net.cfg.rt.dst",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_zwave_net_config_rt_status,
			{
				"Destination Node ID", "zwave_net.cfg.rt.status",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL
			}
		},
		{ &hf_zwave_net_config_rt_entry,
			{
				"Destination Node ID", "zwave_net.cfg.rt.entry",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL
			}
		} */
		
	};

	static gint *ett[] = {
			&ett_zwave_net
		
	};
	
	proto_zwave_net = proto_register_protocol (
			"Z-Wave Network Layer",
			"ZWAVE-NET",
			"zwave_net"
	);

	proto_register_field_array (proto_zwave_net, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	
}

void
proto_reg_handoff_zwave_net (void)
{
	static dissector_handle_t zwave_net_handle;

	zwave_net_handle = create_dissector_handle (dissect_zwave_net, proto_zwave_net);
	register_dissector("zwave_net", dissect_zwave_net, proto_zwave_net);
	
	//dissector_add_uint("zwave_mac.frame_ctrl.routed_flag", 0x1, zwave_net_handle);

	
	
}
