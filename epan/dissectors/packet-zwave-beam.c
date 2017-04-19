/* packet-zwave-beam.c
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

#define ZWAVE_MAX_MSDU_SIZE 64
#define ZWAVE_MIN_MSDU_SIZE 10

static int proto_zwave_beam = -1;
static int hf_zwave_beam_tag = -1;
static int hf_zwave_beam_node_id = -1;

static gint ett_zwave_beam = -1;
static dissector_handle_t data_handle = NULL;

static void
dissect_zwave_beam (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
	guint offset = 0;
	guint nodeid; 
	tvbuff_t *next_tvb;
	proto_item* ti = NULL;

	if(data_handle == NULL){
		data_handle = find_dissector("data");
	}

	col_set_str (pinfo->cinfo, COL_PROTOCOL, "Zwave");
	/* Clear out stuff in the info column to make way for zwave*/
	col_clear (pinfo->cinfo, COL_INFO);
	
	if (tree)
	{
		proto_tree* zwave_beam_tree = NULL;
		ti = proto_tree_add_item (tree, proto_zwave_beam, tvb, 0, -1, ENC_NA);
		
	// For Col info field
		nodeid = tvb_get_guint8 (tvb, 1);
		col_add_fstr (pinfo->cinfo,COL_INFO, "Beam Frame: %u", nodeid);
		proto_item_append_text (ti, "Beam Frame: %u", nodeid);
		
		zwave_beam_tree = proto_item_add_subtree (ti, ett_zwave_beam);
		
		proto_tree_add_item (zwave_beam_tree, hf_zwave_beam_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset ++;
		proto_tree_add_item (zwave_beam_tree, hf_zwave_beam_node_id, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;	
	}

	next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset), tvb_reported_length(tvb));
	call_dissector(data_handle, next_tvb, pinfo, tree);
	
}

void
proto_register_zwave_beam (void)
{
 
	static hf_register_info hf[] = {
		{ &hf_zwave_beam_tag,
			{ "Beam Tag", "zwave_beam.beam_tag",
			  FT_UINT8, BASE_HEX, NULL,
				0x0, NULL, HFILL
			}
		},

	{ &hf_zwave_beam_node_id,
		{ "Node Id", "zwave_beam.node_id",
			FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL
		}
	}

	};

	static gint *ett[] = {
			&ett_zwave_beam
		
	};
	
	proto_zwave_beam = proto_register_protocol (
			"Z-Wave Beam Frame",
			"ZWAVE-BEAM",
			"zwave_beam"
	);

	//zwave_mac_dissector_table = register_dissector_table("zwave_mac.frame_ctrl.routed_flag", "Handle case when network layer exists",
  //                                              FT_BOOLEAN, 8);	
	proto_register_field_array (proto_zwave_beam, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	
}

void
proto_reg_handoff_zwave_beam (void)
{
	static dissector_handle_t zwave_beam_handle;


	zwave_beam_handle = create_dissector_handle (dissect_zwave_beam, proto_zwave_beam);
	register_dissector("zwave_beam", dissect_zwave_beam, proto_zwave_beam);

}

