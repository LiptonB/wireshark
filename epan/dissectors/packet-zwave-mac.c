/* packet-zwave.c
 * Routines for PROTONAME dissection
 * Copyright 201x, YOUR_NAME <YOUR_EMAIL_ADDRESS>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include "config.h"
#include <epan/packet.h>
#include "packet-afit-encapse.h"

#define ZWAVE_MAX_MSDU_SIZE 54
#define ZWAVE_MIN_MSDU_SIZE 10

static int proto_zwave_mac = -1;
static int hf_zwave_mac_home_id = -1;
static int hf_zwave_mac_source_id = -1;
static int hf_zwave_mac_length = -1;
static int hf_zwave_mac_destination_id = -1;
static int hf_zwave_mac_frame_type = -1;
static int hf_zwave_mac_ack_req_flag = -1;
static int hf_zwave_mac_low_power_flag = -1;
static int hf_zwave_mac_speed_mod_flag = -1;
static int hf_zwave_mac_routed_flag = -1;
static int hf_zwave_mac_beam_control = -1;
static int hf_zwave_mac_seq_nbr = -1;
static int hf_zwave_mac_checksum = -1;

//const char * hf_zwave_mac_info_fmt = " %s %u [0x%x %u->%u|%s]";

static gint ett_zwave_mac = -1;
static dissector_handle_t zwave_app_handle = NULL;
static dissector_handle_t zwave_net_handle = NULL;
static dissector_handle_t data_handle = NULL;


//static dissector_table_t zwave_mac_dissector_table;


// Only for channel config 1 and 2
// MSB of frame control
#define ZWAVE_MAC_FRAME_CONTROL_FRAME_TYPE_MASK 0x0F
#define ZWAVE_MAC_FRAME_CONTROL_ROUTED_FLAG 0x80
#define ZWAVE_MAC_FRAME_CONTROL_ACK_REQ_FLAG 0x40
#define ZWAVE_MAC_FRAME_CONTROL_LOW_POWER_FLAG 0x20
#define ZWAVE_MAC_FRAME_CONTROL_SPEED_MOD_FLAG 0x10

// LSB of frame control
#define ZWAVE_MAC_FRAME_CONTROL_BEAM_MASK 0x60
#define ZWAVE_MAC_FRAME_CONTROL_SEQNBR_MASK 0x0F

/*
struct zwave_mpdu_hdr{
	guint32 homeID,
	guint8 srcID,
	guint16 frameCtl,
	guint8	len,
	guint8	dstID
}(__attribute__((packed));
*/

static const value_string zwave_mac_frame_type_names[] = {
	{	0x1, "Singlecast" },
	{	0x2, "Multicast" },
	{	0x3, "ACK" },
	{	0x8, "Routed" }
};

guint8 calc_checksum_tvb (tvbuff_t *tvb, size_t offset, size_t len)
{
	size_t i=0;
	guint8 sum=0xFF;
	for (i=offset;i<len-1;i++)
		sum ^= tvb_get_guint8(tvb, i);  // XOR (from ITU G9959)

	return sum;
}

static void
dissect_zwave_mac (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
	guint offset = 0;
	
	tvbuff_t *next_tvb;
	guint src = -1;
	guint dst = -1;
	guint type = -1;
	guint len = -1;
	guint seq_nbr = -1;

	guint8 routed = -1;

	guint8 checksum_calc = -1;
	guint8 checksum = -1;
	guint32 checksum_passed = -1;
	guint homeid = -1;
	proto_item* ti = NULL;

	if(data_handle == NULL){
		data_handle = find_dissector("data");
	}

	if(zwave_net_handle == NULL){	
		zwave_net_handle = find_dissector("zwave_net");
	}	

	if(zwave_app_handle == NULL){
		//zwave_app_handle = find_dissector("zwave_app");
	}

	col_set_str (pinfo->cinfo, COL_PROTOCOL, "Zwave");
	/* Clear out stuff in the info column to make way for zwave*/
	col_clear (pinfo->cinfo, COL_INFO);
	
	// Check length correctness
	len = tvb_get_guint8 (tvb, 7);
	if(len < ZWAVE_MIN_MSDU_SIZE){
		col_append_str(pinfo->cinfo, COL_INFO, "Frame is too SHORT to be Zwave");
		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}else if(len > ZWAVE_MAX_MSDU_SIZE){
		col_append_str(pinfo->cinfo, COL_INFO, "Frame is too LONG to be Zwave");
		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}

	//Checksum
	checksum = tvb_get_guint8 (tvb, len-1);
	checksum_calc = calc_checksum_tvb(tvb, 0, len);
	if (checksum_calc != checksum)
		{
				checksum_passed = 0x00;
				col_append_str(pinfo->cinfo, COL_INFO, " [CHKSM ERR]");
				call_dissector(data_handle, tvb, pinfo, tree);
				return;
		}
	
	checksum_passed = 0x01;
	
	if (tree)
	{
		proto_tree* zwave_mac_tree = NULL;
		ti = proto_tree_add_item (tree, proto_zwave_mac, tvb, 0, -1, ENC_NA);
		
	// For Col info field
		homeid = tvb_get_ntohl (tvb, 0);
		src = tvb_get_guint8 (tvb, 4);
		dst = tvb_get_guint8 (tvb, 8);
		type = tvb_get_guint8 (tvb, 5) & ZWAVE_MAC_FRAME_CONTROL_FRAME_TYPE_MASK;
		routed = tvb_get_guint8 (tvb, 5) & ZWAVE_MAC_FRAME_CONTROL_ROUTED_FLAG;
		seq_nbr = tvb_get_guint8 (tvb, 6) & ZWAVE_MAC_FRAME_CONTROL_SEQNBR_MASK;
		col_add_fstr (pinfo->cinfo,COL_INFO, "MAC: %s(%u) [0x%x %u->%u]", val_to_str(type, zwave_mac_frame_type_names, "Unknown (0x%02x)"), seq_nbr, homeid, src,dst);

		proto_item_append_text (ti, "%s(%u) [0x%x %u->%u]", val_to_str(type, zwave_mac_frame_type_names, "Unknown (0x%02x)"), seq_nbr, homeid, src,dst);
		
		zwave_mac_tree = proto_item_add_subtree (ti, ett_zwave_mac);
		
		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_home_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_source_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_routed_flag, tvb, offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_ack_req_flag, tvb, offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_low_power_flag, tvb, offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_speed_mod_flag, tvb,offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_frame_type, tvb, offset,1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_beam_control, tvb,offset,1, ENC_BIG_ENDIAN);
		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_seq_nbr, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item (zwave_mac_tree, hf_zwave_mac_destination_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_uint(zwave_mac_tree, hf_zwave_mac_checksum, tvb, len-1, 1, checksum_passed);	
	}

	
	
	next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset), len-2);

	if(type == 0x3){
		// THis is an ack packet, don't pass to app layer	
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}else if(routed > 0){
		call_dissector(zwave_net_handle, next_tvb, pinfo, tree);
	}else{
		call_dissector(data_handle, next_tvb, pinfo, tree);
	}
	//call_dissector(data_handle, next_tvb, pinfo, tree);
	
}

void
proto_register_zwave_mac (void)
{
 
	static hf_register_info hf[] = {
		{ &hf_zwave_mac_home_id,
			{ "Home Id", "zwave_mac.homeid",
			  FT_UINT32, BASE_HEX, NULL,
				0x0, NULL, HFILL
			}
		},

	{ &hf_zwave_mac_source_id,
		{ "Source Node Id", "zwave_mac.src_id",
			FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL
		}
	},

	{ &hf_zwave_mac_frame_type,
		{ "Frame Type", "zwave_mac.frame_ctrl.frame_type",
			 FT_UINT8, BASE_DEC, VALS (zwave_mac_frame_type_names),
			 ZWAVE_MAC_FRAME_CONTROL_FRAME_TYPE_MASK, NULL, HFILL
		}
	},

	{ &hf_zwave_mac_routed_flag,
		{ "Routed", "zwave_mac.frame_ctrl.routed_flag",
			 FT_BOOLEAN, 8, NULL,
			 ZWAVE_MAC_FRAME_CONTROL_ROUTED_FLAG, NULL, HFILL
		}
	},

 	   { &hf_zwave_mac_ack_req_flag,
		   { "ACK Req", "zwave_mac.frame_ctrl.ack_req_flag",
				   FT_BOOLEAN, 8, NULL,
				   ZWAVE_MAC_FRAME_CONTROL_ACK_REQ_FLAG, NULL, HFILL
		   }
 	   },

	/*{ &hf_zwave_frame_control,
		{ "Frame Control", "zwave.frame_ctrl",
			FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
		}
	},*/ 

 	   { &hf_zwave_mac_low_power_flag,
		   { "Low Power", "zwave_mac.frame_ctrl.low_power_flag",
				   FT_BOOLEAN, 8, NULL,
				   ZWAVE_MAC_FRAME_CONTROL_LOW_POWER_FLAG, NULL, HFILL
		   }
 	   },

 	   { &hf_zwave_mac_speed_mod_flag,
		   { "Speed Modified", "zwave_mac.frame_ctrl.speed_mod_flag",
			   FT_BOOLEAN, 8, NULL,
			   ZWAVE_MAC_FRAME_CONTROL_SPEED_MOD_FLAG, NULL, HFILL
		   }
 	   },

		 { &hf_zwave_mac_beam_control,
			 { "Beam Control", "zwave_mac.frame_ctrl.beam_ctrl",
					FT_UINT8, BASE_DEC, NULL,
					ZWAVE_MAC_FRAME_CONTROL_BEAM_MASK, NULL, HFILL
			 }
			},

		{ &hf_zwave_mac_seq_nbr, 
			{
			"Sequence Number", "zwave_mac.frame_ctrl.seq_nbr",
			FT_UINT8, BASE_DEC, NULL,
			ZWAVE_MAC_FRAME_CONTROL_SEQNBR_MASK, NULL, HFILL
			}
		},

	   { &hf_zwave_mac_length,
			   { "MPDU Length in Bytes", "zwave_mac.len",
					   FT_UINT8, BASE_DEC, NULL,
					   0x0, NULL, HFILL
			   }
	   },

	   { &hf_zwave_mac_destination_id,
			   { "Destination Node Id", "zwave_mac.dst_id",
					   FT_UINT8, BASE_HEX, NULL,
					   0x0, NULL, HFILL
			   }
	   },

		{ &hf_zwave_mac_checksum,
			{ "Checksum", "zwave_mac.checksum",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		}
		
	};

	static gint *ett[] = {
			&ett_zwave_mac
		
	};
	
	proto_zwave_mac = proto_register_protocol (
			"Z-Wave Frame Header",
			"ZWAVE-MAC",
			"zwave_mac"
	);

	//zwave_mac_dissector_table = register_dissector_table("zwave_mac.frame_ctrl.routed_flag", "Handle case when network layer exists",
  //                                              FT_BOOLEAN, 8);	
	proto_register_field_array (proto_zwave_mac, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	
}

void
proto_reg_handoff_zwave_mac (void)
{
	static dissector_handle_t zwave_mac_handle;


	zwave_mac_handle = create_dissector_handle (dissect_zwave_mac, proto_zwave_mac);
	register_dissector("zwave_mac", dissect_zwave_mac, proto_zwave_mac);

	dissector_add_uint ("afit_encap.encap_type", 0x1, zwave_mac_handle);
	dissector_add_uint ("afit_encap.encap_type", 0x3, zwave_mac_handle);

	

}


