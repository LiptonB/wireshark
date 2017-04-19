#include "config.h"
#include <epan/packet.h>
#include <stdio.h>
#include <string.h>
#include "packet-zwave-net.h"

static int proto_zwave_app = -1;
static int hf_zwave_app_cmd_class = -1;
static int hf_zwave_app_net_type = -1;

static int hf_zwave_app_rt_dest = -1;
static int hf_zwave_app_rt_status = -1;
static int hf_zwave_app_nl = -1;
static int hf_zwave_app_nl_len = -1;

static gint ett_zwave_app = -1;
static dissector_handle_t data_handle;

#define ZWAVE_APP_NETWORK_CONFIG_REQ 0x02
#define ZWAVE_APP_NETWORK_CONT_NL 0x04
#define ZWAVE_APP_NETWORK_DEV_NL 0x06
#define ZWAVE_APP_NETWORK_REV_RT 0x0C
#define ZWAVE_APP_NETWORK_NL_RT 0x14

static const value_string zwave_app_net_types[] = {
	{	 ZWAVE_APP_NETWORK_CONFIG_REQ 		,	"Controller Config Request"	 },
	{	 ZWAVE_APP_NETWORK_CONT_NL	,	"NL Update (Controller)"	 },
	{	 ZWAVE_APP_NETWORK_DEV_NL	,	"NL Update (Device)" 	 },
	{	 ZWAVE_APP_NETWORK_REV_RT	,	"Reverse Route Assignment"	 },
	{	 ZWAVE_APP_NETWORK_NL_RT		,	"Route Assignment"	 }
	
};

static const value_string zwave_app_route_statuses[] = {
	{	0x08	,	"Empty Route Entry"},
	{	0x10	,	"Valid Route Entry"}
};


static const value_string zwave_app_cmd_classes[] = {
	{	 0x00	,	"Hello / NOOP"	 },
	{	 0x01	,	"Network"},
	{	 0x20	,	"Basic"	 },
	{	 0x21	,	"Controller Replication"	 },
	{	 0x22	,	"app Status"	 },
	{	 0x25	,	"Switch Binary"	 },
	{	 0x26	,	"Switch Multilevel"	 },
	{	 0x27	,	"Switch All"	 },
	{	 0x28	,	"Switch Toggle Binary"	 },
	{	 0x29	,	"Switch Toggle Multilevel"	 },
	{	 0x2B	,	"Scene Activation"	 },
	{	 0x30	,	"Sensor Binary"	 },
	{	 0x31	,	"Sensor Multilevel" },
	{	 0x32	,	"Meter"	 },
	{	 0x35	,	"Meter Pulse"	 },
	{	 0x40	,	"Thermostat Mode"	 },
	{	 0x42	,	"Thermostat Operating State"	 },
	{	 0x43	,	"Thermostat Setpoint"	 },
	{	 0x44	,	"Thermostat Fan Mode"	 },
	{	 0x45	,	"Thermostat Fan State"	 },
	{	 0x46	,	"Climate Control Schedule"	 },
	{	 0x4c	,	"Door Lock Logging"	 },
	{	 0x50	,	"Basic Window Covering"	 },
	{	 0x56	,	"CRC16 Encap"	 },
	{	 0x60	,	"Multi Instance"	 },
	{	 0x62	,	"Door Lock"	 },
	{	 0x63	,	"User Code"	 },
	{	 0x70	,	"Configuration"	 },
	{	 0x71	,	"Alarm"	 },
	{	 0x72	,	"Manufacturer Specific"	 },
	{	 0x73	,	"Power Level"	 },
	{	 0x75	,	"Protection"	 },
	{	 0x76	,	"Lock"	 },
	{	 0x77	,	"Node Naming"	 },
	{	 0x80	,	"Battery"	 },
	{	 0x81	,	"Clock"	 },
	{	 0x82	,	"Hail"	 },
	{	 0x84	,	"WakeUp"	 },
	{	 0x85	,	"Association"	 },
	{	 0x86	,	"Version"	 },
	{	 0x87	,	"Indicator"	 },
	{	 0x88	,	"Proprietary"	 },
	{	 0x89	,	"Language"	 },
	{	 0x8B	,	"Time Parameters"	 },
	{	 0x8e	,	"Multi Instance Association"	 },
	{	 0x8f	,	"Multi Command"	 },
	{	 0x90	,	"Energy Production"	 },
	{	 0x98	,	"Security"	 },
	{	 0x9b	,	"Association Command Configuration"	 },
	{	 0x9c	,	"Sensor Alarm"	 }
};

#define ZWAVE_APP_NET_NL_STRLEN (2*232 + 1)
#define ZWAVE_APP_NET_BIN_STRLEN (8*2+1)

static guint8* getBinary8(guint8 data){
	static guint8 result[ZWAVE_APP_NET_BIN_STRLEN];
	gint i;
	guint8 mask = 0x80;
	memset(result, 0, ZWAVE_APP_NET_BIN_STRLEN);
	
	snprintf(result, ZWAVE_APP_NET_BIN_STRLEN, "%u,", ((data & mask) >> 7));

	for(i=6; i >= 0;i--){
		mask = mask >> 1;
	
		snprintf(result, ZWAVE_APP_NET_BIN_STRLEN, "%s,%u", result, ((data & mask) >> i));
	}

	return result;
}

guint
dissect_zwave_app_nl_update(tvbuff_t *tvb, proto_tree *tree, guint offset){

	guint8 nl_len = -1;
	guint8* nl = NULL;
	guint8* bytes = NULL;
	gint i;
	
	proto_tree* zwave_app_nl_tree = NULL;
	guint8 nodeId, current, mask;

	nl = (guint8*)calloc(sizeof(guint8),ZWAVE_APP_NET_NL_STRLEN);
	memset(nl,0,ZWAVE_APP_NET_NL_STRLEN);
	nl_len = tvb_get_guint8 (tvb, offset);
	bytes = tvb_get_string(wmem_packet_scope(),tvb, offset+1, nl_len);

	// CWB: What if instead of printing every byte, I just list the nodes names that are adjacent (will usually be smaller than not adjacent list)
	// This might be easier to read than a list of 232 values of 1 or 0
/*
	for (i=0;i<nl_len;i++){
		if(i==0){
			snprintf(nl, ZWAVE_APP_NET_NL_STRLEN,"%s", getBinary8(bytes[i]));
		}else{
			snprintf(nl, ZWAVE_APP_NET_NL_STRLEN,"%s\n%s", nl, getBinary8(bytes[i]));
		}
	}	
	*/


	zwave_app_nl_tree = proto_item_add_subtree (tree, ett_zwave_app);
	nodeId = 1;
	for (i=0;i<nl_len;i++) {
		mask = 0x80;

		for (j=0;j<8;j++) {
			if ((bytes[i] & mask) != 0){
				snprintf(nl, ZWAVE_APP_NET_NL_STRLEN, "Node 0x%x", nodeId);
				proto_tree_add_string (zwave_app_nl_tree, hf_zwave_app_nl, tvb, offset, strlen(nl), nl); //TODO: I need to look at these params again. Don't think it is correct
			}
			nodeId++;
			mask = mask >> 1;
		}
	}
	//proto_tree_add_item( tree, hf_zwave_app_nl_len, tvb, offset, 1, ENC_BIG_ENDIAN);
	//offset++;

	//proto_tree_add_string(tree, hf_zwave_app_nl, tvb, offset, nl_len,nl);
	offset += nl_len;
	
	return offset;
}

guint
dissect_zwave_app_route_assignment(proto_item *ti, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset){
	guint8 destID;

	//CWB: The observed behavior for this is strange. The last byte and first byte both change when a route entry is empty. 
	// Even when empty the protocol has the controller send an empty route, but the len/athop byte does not reflect the length of the remaining message.
	// I'd like to have read the last byte to determine the state of the route but I can't find it unless I check if the first byte is non-zero (this may mean the first byte is not a destination ID, but a state variable and the last byte is something else).

	destID = tvb_get_guint8 (tvb, offset);
	proto_tree_add_item( tree, hf_zwave_app_rt_dest, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	if(destID > 0){
		offset = dissect_zwave_net_sr(ti, tvb, pinfo, tree, offset, ZWAVE_NET_SR_FORMAT_QUIET);
	}else{
		// CWB: I'm skipping this byte. We could print it out if we really need to but it will just be a hop len of 0,1,2,3 and athop of 0 for an invalid
		offset++;	
	}

	proto_tree_add_item( tree, hf_zwave_app_rt_status, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	
	return offset;
}

static void
dissect_zwave_app(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint offset = 0;
	tvbuff_t *next_tvb;	
	proto_item* ti = NULL;
	proto_tree* zwave_app_tree = NULL;

	guint8 strbuf[256];
	guint cmd_type = -1;
	guint msg_type = -1;
	//guint nl_len = -1;
	//guint rt_len = -1;

	//proto_tree* zwave_app_tree = NULL;

	if(data_handle <= 0){
		data_handle = find_dissector("data");
	}
	
	memset(strbuf,0,256);	

	if(tree){

		ti = proto_tree_add_item (tree, proto_zwave_app, tvb, 0, -1, ENC_NA);

		cmd_type = tvb_get_guint8 (tvb, 0);
		snprintf(strbuf,255," | APP: %s", val_to_str(cmd_type, zwave_app_cmd_classes, "Unknown (0x%02x)"));
		col_append_str(pinfo->cinfo,COL_INFO,strbuf);

		proto_item_append_text (ti, " cmd_class=%s", val_to_str(cmd_type, zwave_app_cmd_classes, "Unknown (0x%02x)"));
		
		zwave_app_tree = proto_item_add_subtree (ti, ett_zwave_app);
		proto_tree_add_item (zwave_app_tree, hf_zwave_app_cmd_class, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		// Handle network configuration message case
		if(cmd_type == 0x1){
			msg_type = tvb_get_guint8 (tvb,1);
			snprintf(strbuf,255,": %s", val_to_str(msg_type, zwave_app_net_types, "Unknown (0x%02x)"));
			col_append_str(pinfo->cinfo,COL_INFO,strbuf);
			proto_item_append_text (ti, " net_msg_type=%s", val_to_str(msg_type, zwave_app_net_types, "Unknown (0x%02x)"));

			proto_tree_add_item(zwave_app_tree, hf_zwave_app_net_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;

			// Check for NL update primitive
			if((msg_type == ZWAVE_APP_NETWORK_DEV_NL) || (msg_type == ZWAVE_APP_NETWORK_CONT_NL)){
				offset = dissect_zwave_app_nl_update(tvb, zwave_app_tree, offset);

			// Check for Route assignment primitive
			}else if((msg_type == ZWAVE_APP_NETWORK_REV_RT) || (msg_type == ZWAVE_APP_NETWORK_NL_RT)){
				offset = dissect_zwave_app_route_assignment(ti, tvb, pinfo, zwave_app_tree, offset);
			}
		}

		next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb,offset), tvb_reported_length(tvb));
		
		call_dissector(data_handle, next_tvb, pinfo, tree);

	}

	return;
}

void
proto_register_zwave_app (void)
{
 
	static hf_register_info hf[] = {
		{ &hf_zwave_app_cmd_class,
			{
				"Command Class", "zwave_app.cmd_class",
				FT_UINT8, BASE_HEX, VALS(zwave_app_cmd_classes), 0x0, NULL, HFILL
			}
		},
		
		{ &hf_zwave_app_net_type,
			{	"Network Message Type", "zwave_app.net_msg_type",
				FT_UINT8, BASE_HEX, VALS(zwave_app_net_types),0x0, NULL, HFILL
			}
		},

		{ &hf_zwave_app_nl_len,
			{
				"Neighbor List Length", "zwave_app.net.nl.len",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},

		{ &hf_zwave_app_nl,
			{
				"Neighbor List", "zwave_app.net.nl",
				FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},

		{ &hf_zwave_app_rt_dest,
			{
				"Destination Node ID", "zwave_app.net.rt.dest",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},

		{ &hf_zwave_app_rt_status,
			{
				"Route Status", "zwave_app.net.rt.status",
				FT_UINT8, BASE_HEX, VALS(zwave_app_route_statuses), 0x0, NULL, HFILL
			}
		}
	};

	static gint *ett[] = {
			&ett_zwave_app
		
	};
	
	proto_zwave_app = proto_register_protocol (
			"Z-Wave Application Payload",
			"ZWAVE-APP",
			"zwave_app"
	);

	proto_register_field_array (proto_zwave_app, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	
}

void
proto_reg_handoff_zwave_app (void)
{
	//static dissector_handle_t zwave_app_handle;

	create_dissector_handle (dissect_zwave_app, proto_zwave_app);
	register_dissector("zwave_app", dissect_zwave_app, proto_zwave_app);

	
	
}
