#include "config.h"
#include <epan/packet.h>

#define AFIT_ENCAP_UDP_PORT 52002

static gint ett_afit_encap = -1;
static gint proto_afit_encap = -1;
static gint hf_afit_encap_type_ext = -1;
//static gint hf_sfd_timestamp_sec = -1;
//static gint hf_sfd_timestamp_usec = -1;

static dissector_handle_t data_handle;

static dissector_table_t afit_encap_dissector_table;

static const value_string afit_encap_packet_type_names[] = {
	{	0x1, "Scapy Radio Zwave" },
	{	0x2, "Scapy Radio Zigbee" },
	{	0x3, "AFIT Sniffer Zwave" }
};  

static void
dissect_afit_encap (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	int type = tvb_get_guint8 (tvb, 0);
	tvbuff_t *next_tvb;

	col_clear (pinfo->cinfo, COL_INFO);
	col_add_fstr (pinfo->cinfo,COL_INFO, ": %s len=(%i)", val_to_str(type, afit_encap_packet_type_names, "Unknown (0x%02x)"), tvb_reported_length(tvb));

	if (tree)
	{
		proto_item* ti = NULL;
		proto_tree* afit_encap_tree = NULL;

		ti = proto_tree_add_item (tree, proto_afit_encap, tvb, 0, -1, ENC_NA);
		proto_item_append_text (ti, ": %s len=(%i)", val_to_str(type, afit_encap_packet_type_names, "Unknown (0x%02x)"), tvb_reported_length(tvb));
		
		afit_encap_tree = proto_item_add_subtree (ti, ett_afit_encap);
		proto_tree_add_item (afit_encap_tree, hf_afit_encap_type_ext, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 8;		
		//offset++;
		
		// These values are set by the host system and not converted to network order before packet over localhost
		//proto_tree_add_item (afit_encap_tree, hf_sfd_timestamp_sec, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		//offset += 8;
		
		//proto_tree_add_item (afit_encap_tree, hf_sfd_timestamp_usec, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		//offset += 8;
		
		next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset), tvb_reported_length(tvb));
		
		if (!dissector_try_uint(afit_encap_dissector_table, type, next_tvb, pinfo, tree))
		{
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}

	}

}

void
proto_register_afit_encap (void)
{
	static hf_register_info hf[] = {
		{ &hf_afit_encap_type_ext,
			{ "Encapsulation Type", "afit_encap.encap_type",
				 FT_UINT8, BASE_DEC, VALS (afit_encap_packet_type_names),
			 	0x0, NULL, HFILL
			}
		},
/*
		{ &hf_sfd_timestamp_sec,
			{ "Seconds portion of Timestamp when SFD is detected", "afit_encap.sfd_timestamp_sec",
				 FT_UINT64, BASE_DEC, NULL,
			 	0x0, NULL, HFILL
			}
		},

		{ &hf_sfd_timestamp_usec,
			{ "Microseconds portion Timestamp when SFD is detected", "afit_encap.sfd_timestamp_usec",
				 FT_UINT64, BASE_DEC, NULL,
			 	0x0, NULL, HFILL
			}
		}, */
	};

	static gint *ett[] = {
			&ett_afit_encap
		
	};


	proto_afit_encap = proto_register_protocol (
			"AFIT Encapsulation",
			"afit_encap",
			"afit_encap"
	);

	
  	afit_encap_dissector_table = register_dissector_table("afit_encap.encap_type", "Temporary Encapsulation Type for ZWAVE dissector",
                                                FT_UINT8, BASE_DEC);	
	proto_register_field_array (proto_afit_encap, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_afit_encap (void)
{
	static dissector_handle_t afit_encap_handle;
 	
	data_handle = find_dissector("data");
	afit_encap_handle = create_dissector_handle (dissect_afit_encap, proto_afit_encap);
	dissector_add_uint("udp.port", AFIT_ENCAP_UDP_PORT, afit_encap_handle);

}
