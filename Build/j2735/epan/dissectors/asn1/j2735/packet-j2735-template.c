/* packet-j2735.c
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-per.h"
#include "packet-ieee1609dot2.h"

#define PNAME  "SAE J2735 DSRC Message Set Dictionary"
#define PSNAME "J2735"
#define PFNAME "j2735"

void proto_register_j2735(void);
void proto_reg_handoff_j2735(void);

static dissector_handle_t j2735_handle;

#if defined(__GNUC__)
/*
 *
 * DIAG_OFF doesn't work with llvm-gcc, for some unknown reason, so
 * we just use the pragma directly.
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-const-variable"
#endif

/* Initialize the protocol and registered fields */
int proto_j2735 = -1;
#include "packet-j2735-hf.c"

/* Initialize the subtree pointers */
static int ett_j2735 = -1;
#include "packet-j2735-ett.c"

/* Global variables */
static guint32 DSRCmsgID;
static guint32 PartII_Id;

static dissector_table_t dsrcmsgid_dissector_table;
static dissector_table_t j2735_partii_id_dissector_table;

#include "packet-j2735-val.h"

static int dissect_j2735_DSRCmsgID_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return (dissector_try_uint_new(dsrcmsgid_dissector_table, DSRCmsgID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_j2735_partii_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return (dissector_try_uint_new(j2735_partii_id_dissector_table, PartII_Id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

#include "packet-j2735-fn.c"


static int
dissect_j2735(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *j2735_item = NULL;
    proto_tree *j2735_tree = NULL;

    int offset = -1;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SAE j2735");
    //col_set_str(pinfo->cinfo, COL_INFO, "DSRC Message Set Dictionary");

    j2735_item = proto_tree_add_item(tree, proto_j2735, tvb, 0, -1, FALSE);
    j2735_tree = proto_item_add_subtree(j2735_item, ett_j2735);

    offset = dissect_MessageFrame_PDU(tvb, pinfo, j2735_tree, data);

    return offset;
}

/*--- proto_register_j2735 ----------------------------------------------*/

void proto_register_j2735(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-j2735-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
      &ett_j2735,
#include "packet-j2735-ettarr.c"
  };

  /* Register protocol */
  proto_j2735 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_j2735, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  j2735_handle = register_dissector("j2735", dissect_j2735, proto_j2735);

  dsrcmsgid_dissector_table       = register_dissector_table("j2735.msg", "J2735 DSRC Message dissector table ", proto_j2735, FT_UINT32, BASE_DEC);
  j2735_partii_id_dissector_table = register_dissector_table("j2735.partii-id", "J2735 PARTII-EXT-ID table ", proto_j2735, FT_UINT32, BASE_DEC);

}


/*--- proto_reg_handoff_j2735 -------------------------------------------*/
void proto_reg_handoff_j2735(void) {

#include "packet-j2735-dis-tab.c"

  // based on 1609.12

  // V2V
  dissector_add_uint("ieee1609dot2.psid", psid_vehicle_to_vehicle_safety_and_awarenesss, j2735_handle); // BSM
  dissector_add_uint("ieee1609dot2.psid", psid_emergency_and_erratic_vehicles_present_in_roadway, j2735_handle);
  dissector_add_uint("ieee1609dot2.psid", psid_limited_sensor_vehicle_to_vehicle_safety_and_awarenesss, j2735_handle);

  // V2I
  // MAP+SPAT
  dissector_add_uint("ieee1609dot2.psid", psid_intersection_safety_and_awareness, j2735_handle);
  // SRM+SSM?

  // RSM (BIM)?

  // TIM
  dissector_add_uint("ieee1609dot2.psid", psid_traveller_information_and_roadside_signage, j2735_handle);   // TIM

  // V2P
  dissector_add_uint("ieee1609dot2.psid", psid_vulnerable_road_users_safety_applications, j2735_handle);

  // GNSS
  dissector_add_uint("ieee1609dot2.psid", psid_differential_gps_corrections_compressed, j2735_handle);
  dissector_add_uint("ieee1609dot2.psid", psid_differential_gps_corrections_uncompressed, j2735_handle);

  // Other
  dissector_add_uint("ieee1609dot2.psid", psid_mobile_probe_exchanges, j2735_handle);
  dissector_add_uint("ieee1609dot2.psid", 2113687, j2735_handle); // CV-Pilot

  // UDP
}

