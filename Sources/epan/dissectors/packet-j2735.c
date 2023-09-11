/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-j2735.c                                                             */
/* asn2wrs.py -u -L -p j2735 -c ./j2735.cnf -s ./packet-j2735-template -D . -O ../.. J2735-AddGrpB.asn J2735-AddGrpC.asn J2735-BasicSafetyMessage.asn J2735-Common.asn J2735-CommonSafetyRequest.asn J2735-EmergencyVehicleAlert.asn J2735-IntersectionCollision.asn J2735-ITIS.asn J2735-MapData.asn J2735-MessageFrame.asn J2735-NMEAcorrections.asn J2735-NTCIP.asn J2735-PersonalSafetyMessage.asn J2735-ProbeDataManagement.asn J2735-ProbeVehicleData.asn J2735-REGION.asn J2735-RoadSideAlert.asn J2735-RTCMcorrections.asn J2735-SignalRequestMessage.asn J2735-SignalStatusMessage.asn J2735-SPAT.asn J2735-TestMessage00.asn J2735-TestMessage01.asn J2735-TestMessage02.asn J2735-TestMessage03.asn J2735-TestMessage04.asn J2735-TestMessage05.asn J2735-TestMessage06.asn J2735-TestMessage07.asn J2735-TestMessage08.asn J2735-TestMessage09.asn J2735-TestMessage10.asn J2735-TestMessage11.asn J2735-TestMessage12.asn J2735-TestMessage13.asn J2735-TestMessage14.asn J2735-TestMessage15.asn J2735-TravelerInformation.asn */

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
static int hf_j2735_BasicSafetyMessage_PDU = -1;  /* BasicSafetyMessage */
static int hf_j2735_SpecialVehicleExtensions_PDU = -1;  /* SpecialVehicleExtensions */
static int hf_j2735_SupplementalVehicleExtensions_PDU = -1;  /* SupplementalVehicleExtensions */
static int hf_j2735_VehicleSafetyExtensions_PDU = -1;  /* VehicleSafetyExtensions */
static int hf_j2735_CommonSafetyRequest_PDU = -1;  /* CommonSafetyRequest */
static int hf_j2735_EmergencyVehicleAlert_PDU = -1;  /* EmergencyVehicleAlert */
static int hf_j2735_IntersectionCollision_PDU = -1;  /* IntersectionCollision */
static int hf_j2735_MapData_PDU = -1;             /* MapData */
static int hf_j2735_MessageFrame_PDU = -1;        /* MessageFrame */
static int hf_j2735_NMEAcorrections_PDU = -1;     /* NMEAcorrections */
static int hf_j2735_PersonalSafetyMessage_PDU = -1;  /* PersonalSafetyMessage */
static int hf_j2735_ProbeDataManagement_PDU = -1;  /* ProbeDataManagement */
static int hf_j2735_ProbeVehicleData_PDU = -1;    /* ProbeVehicleData */
static int hf_j2735_RoadSideAlert_PDU = -1;       /* RoadSideAlert */
static int hf_j2735_RTCMcorrections_PDU = -1;     /* RTCMcorrections */
static int hf_j2735_SignalRequestMessage_PDU = -1;  /* SignalRequestMessage */
static int hf_j2735_SignalStatusMessage_PDU = -1;  /* SignalStatusMessage */
static int hf_j2735_SPAT_PDU = -1;                /* SPAT */
static int hf_j2735_TravelerInformation_PDU = -1;  /* TravelerInformation */
static int hf_j2735_d = -1;                       /* DegreesLat */
static int hf_j2735_m = -1;                       /* MinutesAngle */
static int hf_j2735_s = -1;                       /* SecondsAngle */
static int hf_j2735_d_01 = -1;                    /* DegreesLong */
static int hf_j2735_lon = -1;                     /* LongitudeDMS */
static int hf_j2735_lat = -1;                     /* LatitudeDMS */
static int hf_j2735_lon_01 = -1;                  /* LongitudeDMS2 */
static int hf_j2735_lat_01 = -1;                  /* LatitudeDMS2 */
static int hf_j2735_startTime = -1;               /* TimeRemaining */
static int hf_j2735_minEndTime = -1;              /* MinTimetoChange */
static int hf_j2735_maxEndTime = -1;              /* MaxTimetoChange */
static int hf_j2735_likelyTime = -1;              /* TimeRemaining */
static int hf_j2735_confidence = -1;              /* TimeIntervalConfidence */
static int hf_j2735_nextTime = -1;                /* TimeRemaining */
static int hf_j2735_posA = -1;                    /* Node_LLdms_48b */
static int hf_j2735_posB = -1;                    /* Node_LLdms_80b */
static int hf_j2735_latitude = -1;                /* LatitudeDMS2 */
static int hf_j2735_longitude = -1;               /* LongitudeDMS2 */
static int hf_j2735_elevation = -1;               /* ElevationB */
static int hf_j2735_year = -1;                    /* Year */
static int hf_j2735_month = -1;                   /* Month */
static int hf_j2735_day = -1;                     /* Day */
static int hf_j2735_summerTime = -1;              /* SummerTime */
static int hf_j2735_holiday = -1;                 /* Holiday */
static int hf_j2735_dayofWeek = -1;               /* DayOfWeek */
static int hf_j2735_hour = -1;                    /* Hour */
static int hf_j2735_minute = -1;                  /* Minute */
static int hf_j2735_second = -1;                  /* Second */
static int hf_j2735_tenthSecond = -1;             /* TenthSecond */
static int hf_j2735_value = -1;                   /* AltitudeValue */
static int hf_j2735_confidence_01 = -1;           /* AltitudeConfidence */
static int hf_j2735_stationID = -1;               /* StationID */
static int hf_j2735_priorState = -1;              /* PrioritizationResponseStatus */
static int hf_j2735_signalGroup = -1;             /* SignalGroupID */
static int hf_j2735_PrioritizationResponseList_item = -1;  /* PrioritizationResponse */
static int hf_j2735_vehicleToLanePositions = -1;  /* VehicleToLanePositionList */
static int hf_j2735_rsuDistanceFromAnchor = -1;   /* NodeOffsetPointXY */
static int hf_j2735_activePrioritizations = -1;   /* PrioritizationResponseList */
static int hf_j2735_signalHeadLocations = -1;     /* SignalHeadLocationList */
static int hf_j2735_altitude = -1;                /* Altitude */
static int hf_j2735_emission = -1;                /* EmissionType */
static int hf_j2735_node = -1;                    /* NodeOffsetPointXY */
static int hf_j2735_signalGroupID = -1;           /* SignalGroupID */
static int hf_j2735_SignalHeadLocationList_item = -1;  /* SignalHeadLocation */
static int hf_j2735_laneID = -1;                  /* LaneID */
static int hf_j2735_VehicleToLanePositionList_item = -1;  /* VehicleToLanePosition */
static int hf_j2735_coreData = -1;                /* BSMcoreData */
static int hf_j2735_partII = -1;                  /* SEQUENCE_SIZE_1_8_OF_PartIIcontent */
static int hf_j2735_partII_item = -1;             /* PartIIcontent */
static int hf_j2735_regional = -1;                /* SEQUENCE_SIZE_1_4_OF_RegionalExtension */
static int hf_j2735_regional_item = -1;           /* RegionalExtension */
static int hf_j2735_partII_Id = -1;               /* PartII_Id */
static int hf_j2735_partII_Value = -1;            /* T_partII_Value */
static int hf_j2735_statusDetails = -1;           /* ITIScodes */
static int hf_j2735_locationDetails = -1;         /* GenericLocations */
static int hf_j2735_typeEvent = -1;               /* ITIScodes */
static int hf_j2735_description = -1;             /* SEQUENCE_SIZE_1_8_OF_ITIScodes */
static int hf_j2735_description_item = -1;        /* ITIScodes */
static int hf_j2735_priority = -1;                /* Priority */
static int hf_j2735_heading = -1;                 /* HeadingSlice */
static int hf_j2735_extent = -1;                  /* Extent */
static int hf_j2735_obDist = -1;                  /* ObstacleDistance */
static int hf_j2735_obDirect = -1;                /* ObstacleDirection */
static int hf_j2735_description_01 = -1;          /* ITIScodes */
static int hf_j2735_dateTime = -1;                /* DDateTime */
static int hf_j2735_vertEvent = -1;               /* VerticalAccelerationThreshold */
static int hf_j2735_pivotOffset = -1;             /* Offset_B11 */
static int hf_j2735_pivotAngle = -1;              /* Angle */
static int hf_j2735_pivots = -1;                  /* PivotingAllowed */
static int hf_j2735_rtcmHeader = -1;              /* RTCMheader */
static int hf_j2735_msgs = -1;                    /* RTCMmessageList */
static int hf_j2735_vehicleAlerts = -1;           /* EmergencyDetails */
static int hf_j2735_description_02 = -1;          /* EventDescription */
static int hf_j2735_trailers = -1;                /* TrailerData */
static int hf_j2735_SpeedProfileMeasurementList_item = -1;  /* SpeedProfileMeasurement */
static int hf_j2735_speedReports = -1;            /* SpeedProfileMeasurementList */
static int hf_j2735_classification = -1;          /* BasicVehicleClass */
static int hf_j2735_classDetails = -1;            /* VehicleClassification */
static int hf_j2735_vehicleData = -1;             /* VehicleData */
static int hf_j2735_weatherReport = -1;           /* WeatherReport */
static int hf_j2735_weatherProbe = -1;            /* WeatherProbe */
static int hf_j2735_obstacle = -1;                /* ObstacleDetection */
static int hf_j2735_status = -1;                  /* DisabledVehicle */
static int hf_j2735_speedProfile = -1;            /* SpeedProfile */
static int hf_j2735_theRTCM = -1;                 /* RTCMPackage */
static int hf_j2735_notUsed = -1;                 /* SSPindex */
static int hf_j2735_connection = -1;              /* PivotPointDescription */
static int hf_j2735_units = -1;                   /* TrailerUnitDescriptionList */
static int hf_j2735_TrailerHistoryPointList_item = -1;  /* TrailerHistoryPoint */
static int hf_j2735_timeOffset = -1;              /* TimeOffset */
static int hf_j2735_positionOffset = -1;          /* Node_XY_24b */
static int hf_j2735_elevationOffset = -1;         /* VertOffset_B07 */
static int hf_j2735_heading_01 = -1;              /* CoarseHeading */
static int hf_j2735_TrailerUnitDescriptionList_item = -1;  /* TrailerUnitDescription */
static int hf_j2735_isDolly = -1;                 /* IsDolly */
static int hf_j2735_width = -1;                   /* VehicleWidth */
static int hf_j2735_length = -1;                  /* VehicleLength */
static int hf_j2735_height = -1;                  /* VehicleHeight */
static int hf_j2735_mass = -1;                    /* TrailerMass */
static int hf_j2735_bumperHeights = -1;           /* BumperHeights */
static int hf_j2735_centerOfGravity = -1;         /* VehicleHeight */
static int hf_j2735_frontPivot = -1;              /* PivotPointDescription */
static int hf_j2735_rearPivot = -1;               /* PivotPointDescription */
static int hf_j2735_rearWheelOffset = -1;         /* Offset_B12 */
static int hf_j2735_crumbData = -1;               /* TrailerHistoryPointList */
static int hf_j2735_bumpers = -1;                 /* BumperHeights */
static int hf_j2735_mass_01 = -1;                 /* VehicleMass */
static int hf_j2735_trailerWeight = -1;           /* TrailerWeight */
static int hf_j2735_airTemp = -1;                 /* AmbientAirTemperature */
static int hf_j2735_airPressure = -1;             /* AmbientAirPressure */
static int hf_j2735_rainRates = -1;               /* WiperSet */
static int hf_j2735_isRaining = -1;               /* EssPrecipYesNo */
static int hf_j2735_rainRate = -1;                /* EssPrecipRate */
static int hf_j2735_precipSituation = -1;         /* EssPrecipSituation */
static int hf_j2735_solarRadiation = -1;          /* EssSolarRadiation */
static int hf_j2735_friction = -1;                /* EssMobileFriction */
static int hf_j2735_roadFriction = -1;            /* CoefficientOfFriction */
static int hf_j2735_regionId = -1;                /* RegionId */
static int hf_j2735_regExtValue = -1;             /* T_regExtValue */
static int hf_j2735_long = -1;                    /* Acceleration */
static int hf_j2735_lat_02 = -1;                  /* Acceleration */
static int hf_j2735_vert = -1;                    /* VerticalAcceleration */
static int hf_j2735_yaw = -1;                     /* YawRate */
static int hf_j2735_antOffsetX = -1;              /* Offset_B12 */
static int hf_j2735_antOffsetY = -1;              /* Offset_B09 */
static int hf_j2735_antOffsetZ = -1;              /* Offset_B10 */
static int hf_j2735_wheelBrakes = -1;             /* BrakeAppliedStatus */
static int hf_j2735_traction = -1;                /* TractionControlStatus */
static int hf_j2735_abs = -1;                     /* AntiLockBrakeStatus */
static int hf_j2735_scs = -1;                     /* StabilityControlStatus */
static int hf_j2735_brakeBoost = -1;              /* BrakeBoostApplied */
static int hf_j2735_auxBrakes = -1;               /* AuxiliaryBrakeStatus */
static int hf_j2735_msgCnt = -1;                  /* MsgCount */
static int hf_j2735_id = -1;                      /* TemporaryID */
static int hf_j2735_secMark = -1;                 /* DSecond */
static int hf_j2735_lat_03 = -1;                  /* Latitude */
static int hf_j2735_long_01 = -1;                 /* Longitude */
static int hf_j2735_elev = -1;                    /* Elevation */
static int hf_j2735_accuracy = -1;                /* PositionalAccuracy */
static int hf_j2735_transmission = -1;            /* TransmissionState */
static int hf_j2735_speed = -1;                   /* Speed */
static int hf_j2735_heading_02 = -1;              /* Heading */
static int hf_j2735_angle = -1;                   /* SteeringWheelAngle */
static int hf_j2735_accelSet = -1;                /* AccelerationSet4Way */
static int hf_j2735_brakes = -1;                  /* BrakeSystemStatus */
static int hf_j2735_size = -1;                    /* VehicleSize */
static int hf_j2735_front = -1;                   /* BumperHeight */
static int hf_j2735_rear = -1;                    /* BumperHeight */
static int hf_j2735_referenceLaneId = -1;         /* LaneID */
static int hf_j2735_offsetXaxis = -1;             /* T_offsetXaxis */
static int hf_j2735_small = -1;                   /* DrivenLineOffsetSm */
static int hf_j2735_large = -1;                   /* DrivenLineOffsetLg */
static int hf_j2735_offsetYaxis = -1;             /* T_offsetYaxis */
static int hf_j2735_rotateXY = -1;                /* Angle */
static int hf_j2735_scaleXaxis = -1;              /* Scale_B12 */
static int hf_j2735_scaleYaxis = -1;              /* Scale_B12 */
static int hf_j2735_year_01 = -1;                 /* DYear */
static int hf_j2735_month_01 = -1;                /* DMonth */
static int hf_j2735_day_01 = -1;                  /* DDay */
static int hf_j2735_hour_01 = -1;                 /* DHour */
static int hf_j2735_minute_01 = -1;               /* DMinute */
static int hf_j2735_second_01 = -1;               /* DSecond */
static int hf_j2735_offset = -1;                  /* DOffset */
static int hf_j2735_sirenUse = -1;                /* SirenInUse */
static int hf_j2735_lightsUse = -1;               /* LightbarInUse */
static int hf_j2735_multi = -1;                   /* MultiVehicleResponse */
static int hf_j2735_events = -1;                  /* PrivilegedEvents */
static int hf_j2735_responseType = -1;            /* ResponseType */
static int hf_j2735_utcTime = -1;                 /* DDateTime */
static int hf_j2735_elevation_01 = -1;            /* Elevation */
static int hf_j2735_speed_01 = -1;                /* TransmissionAndSpeed */
static int hf_j2735_posAccuracy = -1;             /* PositionalAccuracy */
static int hf_j2735_timeConfidence = -1;          /* TimeConfidence */
static int hf_j2735_posConfidence = -1;           /* PositionConfidenceSet */
static int hf_j2735_speedConfidence = -1;         /* SpeedandHeadingandThrottleConfidence */
static int hf_j2735_timeStamp = -1;               /* MinuteOfTheYear */
static int hf_j2735_msgIssueRevision = -1;        /* MsgCount */
static int hf_j2735_lane = -1;                    /* LaneID */
static int hf_j2735_approach = -1;                /* ApproachID */
static int hf_j2735_connection_01 = -1;           /* LaneConnectionID */
static int hf_j2735_region = -1;                  /* RoadRegulatorID */
static int hf_j2735_id_01 = -1;                   /* IntersectionID */
static int hf_j2735_pathEndPointAngle = -1;       /* DeltaAngle */
static int hf_j2735_laneCrownPointCenter = -1;    /* RoadwayCrownAngle */
static int hf_j2735_laneCrownPointLeft = -1;      /* RoadwayCrownAngle */
static int hf_j2735_laneCrownPointRight = -1;     /* RoadwayCrownAngle */
static int hf_j2735_laneAngle = -1;               /* MergeDivergeNodeAngle */
static int hf_j2735_speedLimits = -1;             /* SpeedLimitList */
static int hf_j2735_LaneDataAttributeList_item = -1;  /* LaneDataAttribute */
static int hf_j2735_lon_02 = -1;                  /* Longitude */
static int hf_j2735_x = -1;                       /* Offset_B10 */
static int hf_j2735_y = -1;                       /* Offset_B10 */
static int hf_j2735_x_01 = -1;                    /* Offset_B11 */
static int hf_j2735_y_01 = -1;                    /* Offset_B11 */
static int hf_j2735_x_02 = -1;                    /* Offset_B12 */
static int hf_j2735_y_02 = -1;                    /* Offset_B12 */
static int hf_j2735_x_03 = -1;                    /* Offset_B13 */
static int hf_j2735_y_03 = -1;                    /* Offset_B13 */
static int hf_j2735_x_04 = -1;                    /* Offset_B14 */
static int hf_j2735_y_04 = -1;                    /* Offset_B14 */
static int hf_j2735_x_05 = -1;                    /* Offset_B16 */
static int hf_j2735_y_05 = -1;                    /* Offset_B16 */
static int hf_j2735_localNode = -1;               /* NodeAttributeXYList */
static int hf_j2735_disabled = -1;                /* SegmentAttributeXYList */
static int hf_j2735_enabled = -1;                 /* SegmentAttributeXYList */
static int hf_j2735_data = -1;                    /* LaneDataAttributeList */
static int hf_j2735_dWidth = -1;                  /* Offset_B10 */
static int hf_j2735_dElevation = -1;              /* Offset_B10 */
static int hf_j2735_NodeAttributeXYList_item = -1;  /* NodeAttributeXY */
static int hf_j2735_nodes = -1;                   /* NodeSetXY */
static int hf_j2735_computed = -1;                /* ComputedLane */
static int hf_j2735_node_XY1 = -1;                /* Node_XY_20b */
static int hf_j2735_node_XY2 = -1;                /* Node_XY_22b */
static int hf_j2735_node_XY3 = -1;                /* Node_XY_24b */
static int hf_j2735_node_XY4 = -1;                /* Node_XY_26b */
static int hf_j2735_node_XY5 = -1;                /* Node_XY_28b */
static int hf_j2735_node_XY6 = -1;                /* Node_XY_32b */
static int hf_j2735_node_LatLon = -1;             /* Node_LLmD_64b */
static int hf_j2735_regional_01 = -1;             /* RegionalExtension */
static int hf_j2735_NodeSetXY_item = -1;          /* NodeXY */
static int hf_j2735_delta = -1;                   /* NodeOffsetPointXY */
static int hf_j2735_attributes = -1;              /* NodeAttributeSetXY */
static int hf_j2735_initialPosition = -1;         /* FullPositionVector */
static int hf_j2735_currGNSSstatus = -1;          /* GNSSstatus */
static int hf_j2735_crumbData_01 = -1;            /* PathHistoryPointList */
static int hf_j2735_PathHistoryPointList_item = -1;  /* PathHistoryPoint */
static int hf_j2735_latOffset = -1;               /* OffsetLL_B18 */
static int hf_j2735_lonOffset = -1;               /* OffsetLL_B18 */
static int hf_j2735_elevationOffset_01 = -1;      /* VertOffset_B12 */
static int hf_j2735_radiusOfCurve = -1;           /* RadiusOfCurvature */
static int hf_j2735_confidence_02 = -1;           /* Confidence */
static int hf_j2735_semiMajor = -1;               /* SemiMajorAxisAccuracy */
static int hf_j2735_semiMinor = -1;               /* SemiMinorAxisAccuracy */
static int hf_j2735_orientation = -1;             /* SemiMajorAxisOrientation */
static int hf_j2735_pos = -1;                     /* PositionConfidence */
static int hf_j2735_elevation_02 = -1;            /* ElevationConfidence */
static int hf_j2735_event = -1;                   /* PrivilegedEventFlags */
static int hf_j2735_type = -1;                    /* SpeedLimitType */
static int hf_j2735_speed_02 = -1;                /* Velocity */
static int hf_j2735_role = -1;                    /* BasicVehicleRole */
static int hf_j2735_subrole = -1;                 /* RequestSubRole */
static int hf_j2735_request = -1;                 /* RequestImportanceLevel */
static int hf_j2735_iso3883 = -1;                 /* Iso3833VehicleType */
static int hf_j2735_hpmsType = -1;                /* VehicleType */
static int hf_j2735_id_02 = -1;                   /* RoadSegmentID */
static int hf_j2735_status_01 = -1;               /* GNSSstatus */
static int hf_j2735_offsetSet = -1;               /* AntennaOffsetSet */
static int hf_j2735_RTCMmessageList_item = -1;    /* RTCMmessage */
static int hf_j2735_SegmentAttributeXYList_item = -1;  /* SegmentAttributeXY */
static int hf_j2735_heading_03 = -1;              /* HeadingConfidence */
static int hf_j2735_speed_03 = -1;                /* SpeedConfidence */
static int hf_j2735_throttle = -1;                /* ThrottleConfidence */
static int hf_j2735_SpeedLimitList_item = -1;     /* RegulatorySpeedLimit */
static int hf_j2735_transmisson = -1;             /* TransmissionState */
static int hf_j2735_keyType = -1;                 /* BasicVehicleClass */
static int hf_j2735_vehicleType = -1;             /* VehicleGroupAffected */
static int hf_j2735_responseEquip = -1;           /* IncidentResponseEquipment */
static int hf_j2735_responderType = -1;           /* ResponderGroupAffected */
static int hf_j2735_fuelType = -1;                /* FuelType */
static int hf_j2735_entityID = -1;                /* TemporaryID */
static int hf_j2735_events_01 = -1;               /* VehicleEventFlags */
static int hf_j2735_pathHistory = -1;             /* PathHistory */
static int hf_j2735_pathPrediction = -1;          /* PathPrediction */
static int hf_j2735_lights = -1;                  /* ExteriorLights */
static int hf_j2735_offset1 = -1;                 /* VertOffset_B07 */
static int hf_j2735_offset2 = -1;                 /* VertOffset_B08 */
static int hf_j2735_offset3 = -1;                 /* VertOffset_B09 */
static int hf_j2735_offset4 = -1;                 /* VertOffset_B10 */
static int hf_j2735_offset5 = -1;                 /* VertOffset_B11 */
static int hf_j2735_offset6 = -1;                 /* VertOffset_B12 */
static int hf_j2735_statusFront = -1;             /* WiperStatus */
static int hf_j2735_rateFront = -1;               /* WiperRate */
static int hf_j2735_statusRear = -1;              /* WiperStatus */
static int hf_j2735_rateRear = -1;                /* WiperRate */
static int hf_j2735_requests = -1;                /* RequestedItemList */
static int hf_j2735_RequestedItemList_item = -1;  /* RequestedItem */
static int hf_j2735_rsaMsg = -1;                  /* RoadSideAlert */
static int hf_j2735_details = -1;                 /* EmergencyDetails */
static int hf_j2735_basicType = -1;               /* VehicleType */
static int hf_j2735_partOne = -1;                 /* BSMcoreData */
static int hf_j2735_path = -1;                    /* PathHistory */
static int hf_j2735_intersectionID = -1;          /* IntersectionReferenceID */
static int hf_j2735_laneNumber = -1;              /* ApproachOrLane */
static int hf_j2735_eventFlag = -1;               /* VehicleEventFlags */
static int hf_j2735_ITIScodesAndText_item = -1;   /* ITIScodesAndText_item */
static int hf_j2735_item = -1;                    /* T_item */
static int hf_j2735_itis = -1;                    /* ITIScodes */
static int hf_j2735_text = -1;                    /* ITIStext */
static int hf_j2735_layerType = -1;               /* LayerType */
static int hf_j2735_layerID = -1;                 /* LayerID */
static int hf_j2735_intersections = -1;           /* IntersectionGeometryList */
static int hf_j2735_roadSegments = -1;            /* RoadSegmentList */
static int hf_j2735_dataParameters = -1;          /* DataParameters */
static int hf_j2735_restrictionList = -1;         /* RestrictionClassList */
static int hf_j2735_maneuver = -1;                /* AllowedManeuvers */
static int hf_j2735_connectingLane = -1;          /* ConnectingLane */
static int hf_j2735_remoteIntersection = -1;      /* IntersectionReferenceID */
static int hf_j2735_userClass = -1;               /* RestrictionClassID */
static int hf_j2735_connectionID = -1;            /* LaneConnectionID */
static int hf_j2735_ConnectsToList_item = -1;     /* Connection */
static int hf_j2735_processMethod = -1;           /* IA5String_SIZE_1_255 */
static int hf_j2735_processAgency = -1;           /* IA5String_SIZE_1_255 */
static int hf_j2735_lastCheckedDate = -1;         /* IA5String_SIZE_1_255 */
static int hf_j2735_geoidUsed = -1;               /* IA5String_SIZE_1_255 */
static int hf_j2735_name = -1;                    /* DescriptiveName */
static int hf_j2735_ingressApproach = -1;         /* ApproachID */
static int hf_j2735_egressApproach = -1;          /* ApproachID */
static int hf_j2735_laneAttributes = -1;          /* LaneAttributes */
static int hf_j2735_maneuvers = -1;               /* AllowedManeuvers */
static int hf_j2735_nodeList = -1;                /* NodeListXY */
static int hf_j2735_connectsTo = -1;              /* ConnectsToList */
static int hf_j2735_overlays = -1;                /* OverlayLaneList */
static int hf_j2735_id_03 = -1;                   /* IntersectionReferenceID */
static int hf_j2735_revision = -1;                /* MsgCount */
static int hf_j2735_refPoint = -1;                /* Position3D */
static int hf_j2735_laneWidth = -1;               /* LaneWidth */
static int hf_j2735_laneSet = -1;                 /* LaneList */
static int hf_j2735_preemptPriorityData = -1;     /* PreemptPriorityList */
static int hf_j2735_IntersectionGeometryList_item = -1;  /* IntersectionGeometry */
static int hf_j2735_directionalUse = -1;          /* LaneDirection */
static int hf_j2735_sharedWith = -1;              /* LaneSharing */
static int hf_j2735_laneType = -1;                /* LaneTypeAttributes */
static int hf_j2735_LaneList_item = -1;           /* GenericLane */
static int hf_j2735_vehicle = -1;                 /* LaneAttributes_Vehicle */
static int hf_j2735_crosswalk = -1;               /* LaneAttributes_Crosswalk */
static int hf_j2735_bikeLane = -1;                /* LaneAttributes_Bike */
static int hf_j2735_sidewalk = -1;                /* LaneAttributes_Sidewalk */
static int hf_j2735_median = -1;                  /* LaneAttributes_Barrier */
static int hf_j2735_striping = -1;                /* LaneAttributes_Striping */
static int hf_j2735_trackedVehicle = -1;          /* LaneAttributes_TrackedVehicle */
static int hf_j2735_parking = -1;                 /* LaneAttributes_Parking */
static int hf_j2735_OverlayLaneList_item = -1;    /* LaneID */
static int hf_j2735_PreemptPriorityList_item = -1;  /* SignalControlZone */
static int hf_j2735_zone = -1;                    /* RegionalExtension */
static int hf_j2735_id_04 = -1;                   /* RestrictionClassID */
static int hf_j2735_users = -1;                   /* RestrictionUserTypeList */
static int hf_j2735_RestrictionClassList_item = -1;  /* RestrictionClassAssignment */
static int hf_j2735_RestrictionUserTypeList_item = -1;  /* RestrictionUserType */
static int hf_j2735_basicType_01 = -1;            /* RestrictionAppliesTo */
static int hf_j2735_RoadLaneSetList_item = -1;    /* GenericLane */
static int hf_j2735_RoadSegmentList_item = -1;    /* RoadSegment */
static int hf_j2735_id_05 = -1;                   /* RoadSegmentReferenceID */
static int hf_j2735_roadLaneSet = -1;             /* RoadLaneSetList */
static int hf_j2735_messageId = -1;               /* DSRCmsgID */
static int hf_j2735_value_01 = -1;                /* T_value */
static int hf_j2735_rev = -1;                     /* NMEA_Revision */
static int hf_j2735_msg = -1;                     /* NMEA_MsgType */
static int hf_j2735_wdCount = -1;                 /* ObjectCount */
static int hf_j2735_payload = -1;                 /* NMEA_Payload */
static int hf_j2735_basicType_02 = -1;            /* PersonalDeviceUserType */
static int hf_j2735_position = -1;                /* Position3D */
static int hf_j2735_propulsion = -1;              /* PropelledInformation */
static int hf_j2735_useState = -1;                /* PersonalDeviceUsageState */
static int hf_j2735_crossRequest = -1;            /* PersonalCrossingRequest */
static int hf_j2735_crossState = -1;              /* PersonalCrossingInProgress */
static int hf_j2735_clusterSize = -1;             /* NumberOfParticipantsInCluster */
static int hf_j2735_clusterRadius = -1;           /* PersonalClusterRadius */
static int hf_j2735_eventResponderType = -1;      /* PublicSafetyEventResponderWorkerType */
static int hf_j2735_activityType = -1;            /* PublicSafetyAndRoadWorkerActivity */
static int hf_j2735_activitySubType = -1;         /* PublicSafetyDirectingTrafficSubType */
static int hf_j2735_assistType = -1;              /* PersonalAssistive */
static int hf_j2735_sizing = -1;                  /* UserSizeAndBehaviour */
static int hf_j2735_attachment = -1;              /* Attachment */
static int hf_j2735_attachmentRadius = -1;        /* AttachmentRadius */
static int hf_j2735_animalType = -1;              /* AnimalType */
static int hf_j2735_human = -1;                   /* HumanPropelledType */
static int hf_j2735_animal = -1;                  /* AnimalPropelledType */
static int hf_j2735_motor = -1;                   /* MotorizedPropelledType */
static int hf_j2735_sample = -1;                  /* Sample */
static int hf_j2735_directions = -1;              /* HeadingSlice */
static int hf_j2735_term = -1;                    /* T_term */
static int hf_j2735_termtime = -1;                /* TermTime */
static int hf_j2735_termDistance = -1;            /* TermDistance */
static int hf_j2735_snapshot = -1;                /* T_snapshot */
static int hf_j2735_snapshotTime = -1;            /* SnapshotTime */
static int hf_j2735_snapshotDistance = -1;        /* SnapshotDistance */
static int hf_j2735_txInterval = -1;              /* SecondOfTime */
static int hf_j2735_dataElements = -1;            /* VehicleStatusRequestList */
static int hf_j2735_sampleStart = -1;             /* INTEGER_0_255 */
static int hf_j2735_sampleEnd = -1;               /* INTEGER_0_255 */
static int hf_j2735_distance1 = -1;               /* GrossDistance */
static int hf_j2735_speed1 = -1;                  /* GrossSpeed */
static int hf_j2735_distance2 = -1;               /* GrossDistance */
static int hf_j2735_speed2 = -1;                  /* GrossSpeed */
static int hf_j2735_time1 = -1;                   /* SecondOfTime */
static int hf_j2735_time2 = -1;                   /* SecondOfTime */
static int hf_j2735_dataType = -1;                /* VehicleStatusDeviceTypeTag */
static int hf_j2735_subType = -1;                 /* INTEGER_1_15 */
static int hf_j2735_sendOnLessThenValue = -1;     /* INTEGER_M32767_32767 */
static int hf_j2735_sendOnMoreThenValue = -1;     /* INTEGER_M32767_32767 */
static int hf_j2735_sendAll = -1;                 /* BOOLEAN */
static int hf_j2735_VehicleStatusRequestList_item = -1;  /* VehicleStatusRequest */
static int hf_j2735_segNum = -1;                  /* ProbeSegmentNumber */
static int hf_j2735_probeID = -1;                 /* VehicleIdent */
static int hf_j2735_startVector = -1;             /* FullPositionVector */
static int hf_j2735_vehicleType_01 = -1;          /* VehicleClassification */
static int hf_j2735_snapshots = -1;               /* SEQUENCE_SIZE_1_32_OF_Snapshot */
static int hf_j2735_snapshots_item = -1;          /* Snapshot */
static int hf_j2735_yawRate = -1;                 /* YawRateConfidence */
static int hf_j2735_acceleration = -1;            /* AccelerationConfidence */
static int hf_j2735_steeringWheelAngle = -1;      /* SteeringWheelAngleConfidence */
static int hf_j2735_accelConfidence = -1;         /* AccelSteerYawRateConfidence */
static int hf_j2735_steerConfidence = -1;         /* SteeringWheelAngleConfidence */
static int hf_j2735_headingConfidence = -1;       /* HeadingConfidence */
static int hf_j2735_throttleConfidence = -1;      /* ThrottleConfidence */
static int hf_j2735_tires = -1;                   /* TireDataList */
static int hf_j2735_axles = -1;                   /* AxleWeightList */
static int hf_j2735_cargoWeight = -1;             /* CargoWeight */
static int hf_j2735_steeringAxleTemperature = -1;  /* SteeringAxleTemperature */
static int hf_j2735_driveAxleLocation = -1;       /* DriveAxleLocation */
static int hf_j2735_driveAxleLiftAirPressure = -1;  /* DriveAxleLiftAirPressure */
static int hf_j2735_driveAxleTemperature = -1;    /* DriveAxleTemperature */
static int hf_j2735_driveAxleLubePressure = -1;   /* DriveAxleLubePressure */
static int hf_j2735_steeringAxleLubePressure = -1;  /* SteeringAxleLubePressure */
static int hf_j2735_TireDataList_item = -1;       /* TireData */
static int hf_j2735_location = -1;                /* TireLocation */
static int hf_j2735_pressure = -1;                /* TirePressure */
static int hf_j2735_temp = -1;                    /* TireTemp */
static int hf_j2735_wheelSensorStatus = -1;       /* WheelSensorStatus */
static int hf_j2735_wheelEndElectFault = -1;      /* WheelEndElectFault */
static int hf_j2735_leakageRate = -1;             /* TireLeakageRate */
static int hf_j2735_detection = -1;               /* TirePressureThresholdDetection */
static int hf_j2735_AxleWeightList_item = -1;     /* AxleWeightSet */
static int hf_j2735_location_01 = -1;             /* AxleLocation */
static int hf_j2735_weight = -1;                  /* AxleWeight */
static int hf_j2735_thePosition = -1;             /* FullPositionVector */
static int hf_j2735_safetyExt = -1;               /* VehicleSafetyExtensions */
static int hf_j2735_dataSet = -1;                 /* VehicleStatus */
static int hf_j2735_vin = -1;                     /* VINstring */
static int hf_j2735_ownerCode = -1;               /* IA5String_SIZE_1_32 */
static int hf_j2735_id_06 = -1;                   /* VehicleID */
static int hf_j2735_vehicleType_02 = -1;          /* VehicleType */
static int hf_j2735_vehicleClass = -1;            /* T_vehicleClass */
static int hf_j2735_vGroup = -1;                  /* VehicleGroupAffected */
static int hf_j2735_rGroup = -1;                  /* ResponderGroupAffected */
static int hf_j2735_rEquip = -1;                  /* IncidentResponseEquipment */
static int hf_j2735_lightBar = -1;                /* LightbarInUse */
static int hf_j2735_wipers = -1;                  /* WiperSet */
static int hf_j2735_brakeStatus = -1;             /* BrakeSystemStatus */
static int hf_j2735_brakePressure = -1;           /* BrakeAppliedPressure */
static int hf_j2735_sunData = -1;                 /* SunSensor */
static int hf_j2735_rainData = -1;                /* RainSensor */
static int hf_j2735_airPres = -1;                 /* AmbientAirPressure */
static int hf_j2735_steering = -1;                /* T_steering */
static int hf_j2735_confidence_03 = -1;           /* SteeringWheelAngleConfidence */
static int hf_j2735_rate = -1;                    /* SteeringWheelAngleRateOfChange */
static int hf_j2735_wheels = -1;                  /* DrivingWheelAngle */
static int hf_j2735_accelSets = -1;               /* T_accelSets */
static int hf_j2735_accel4way = -1;               /* AccelerationSet4Way */
static int hf_j2735_vertAccelThres = -1;          /* VerticalAccelerationThreshold */
static int hf_j2735_yawRateCon = -1;              /* YawRateConfidence */
static int hf_j2735_hozAccelCon = -1;             /* AccelerationConfidence */
static int hf_j2735_confidenceSet = -1;           /* ConfidenceSet */
static int hf_j2735_object = -1;                  /* T_object */
static int hf_j2735_obDirect_01 = -1;             /* Angle */
static int hf_j2735_fullPos = -1;                 /* FullPositionVector */
static int hf_j2735_throttlePos = -1;             /* ThrottlePosition */
static int hf_j2735_speedHeadC = -1;              /* SpeedandHeadingandThrottleConfidence */
static int hf_j2735_speedC = -1;                  /* SpeedConfidence */
static int hf_j2735_vehicleData_01 = -1;          /* T_vehicleData */
static int hf_j2735_type_01 = -1;                 /* VehicleType */
static int hf_j2735_vehicleIdent = -1;            /* VehicleIdent */
static int hf_j2735_j1939data = -1;               /* J1939data */
static int hf_j2735_weatherReport_01 = -1;        /* T_weatherReport */
static int hf_j2735_gnssStatus = -1;              /* GNSSstatus */
static int hf_j2735_position_01 = -1;             /* FullPositionVector */
static int hf_j2735_furtherInfoID = -1;           /* FurtherInfoID */
static int hf_j2735_rev_01 = -1;                  /* RTCM_Revision */
static int hf_j2735_anchorPoint = -1;             /* FullPositionVector */
static int hf_j2735_sequenceNumber = -1;          /* MsgCount */
static int hf_j2735_requests_01 = -1;             /* SignalRequestList */
static int hf_j2735_requestor = -1;               /* RequestorDescription */
static int hf_j2735_type_02 = -1;                 /* RequestorType */
static int hf_j2735_position_02 = -1;             /* RequestorPositionVector */
static int hf_j2735_routeName = -1;               /* DescriptiveName */
static int hf_j2735_transitStatus = -1;           /* TransitVehicleStatus */
static int hf_j2735_transitOccupancy = -1;        /* TransitVehicleOccupancy */
static int hf_j2735_transitSchedule = -1;         /* DeltaTime */
static int hf_j2735_heading_04 = -1;              /* Angle */
static int hf_j2735_SignalRequestList_item = -1;  /* SignalRequestPackage */
static int hf_j2735_request_01 = -1;              /* SignalRequest */
static int hf_j2735_minute_02 = -1;               /* MinuteOfTheYear */
static int hf_j2735_duration = -1;                /* DSecond */
static int hf_j2735_requestID = -1;               /* RequestID */
static int hf_j2735_requestType = -1;             /* PriorityRequestType */
static int hf_j2735_inBoundLane = -1;             /* IntersectionAccessPoint */
static int hf_j2735_outBoundLane = -1;            /* IntersectionAccessPoint */
static int hf_j2735_status_02 = -1;               /* SignalStatusList */
static int hf_j2735_request_02 = -1;              /* RequestID */
static int hf_j2735_typeData = -1;                /* RequestorType */
static int hf_j2735_SignalStatusList_item = -1;   /* SignalStatus */
static int hf_j2735_SignalStatusPackageList_item = -1;  /* SignalStatusPackage */
static int hf_j2735_requester = -1;               /* SignalRequesterInfo */
static int hf_j2735_inboundOn = -1;               /* IntersectionAccessPoint */
static int hf_j2735_outboundOn = -1;              /* IntersectionAccessPoint */
static int hf_j2735_status_03 = -1;               /* PrioritizationResponseStatus */
static int hf_j2735_sigStatus = -1;               /* SignalStatusPackageList */
static int hf_j2735_intersections_01 = -1;        /* IntersectionStateList */
static int hf_j2735_type_03 = -1;                 /* AdvisorySpeedType */
static int hf_j2735_speed_04 = -1;                /* SpeedAdvice */
static int hf_j2735_confidence_04 = -1;           /* SpeedConfidence */
static int hf_j2735_distance = -1;                /* ZoneLength */
static int hf_j2735_class = -1;                   /* RestrictionClassID */
static int hf_j2735_AdvisorySpeedList_item = -1;  /* AdvisorySpeed */
static int hf_j2735_queueLength = -1;             /* ZoneLength */
static int hf_j2735_availableStorageLength = -1;  /* ZoneLength */
static int hf_j2735_waitOnStop = -1;              /* WaitOnStopline */
static int hf_j2735_pedBicycleDetect = -1;        /* PedestrianBicycleDetect */
static int hf_j2735_EnabledLaneList_item = -1;    /* LaneID */
static int hf_j2735_status_04 = -1;               /* IntersectionStatusObject */
static int hf_j2735_moy = -1;                     /* MinuteOfTheYear */
static int hf_j2735_timeStamp_01 = -1;            /* DSecond */
static int hf_j2735_enabledLanes = -1;            /* EnabledLaneList */
static int hf_j2735_states = -1;                  /* MovementList */
static int hf_j2735_maneuverAssistList = -1;      /* ManeuverAssistList */
static int hf_j2735_IntersectionStateList_item = -1;  /* IntersectionState */
static int hf_j2735_ManeuverAssistList_item = -1;  /* ConnectionManeuverAssist */
static int hf_j2735_MovementEventList_item = -1;  /* MovementEvent */
static int hf_j2735_eventState = -1;              /* MovementPhaseState */
static int hf_j2735_timing = -1;                  /* TimeChangeDetails */
static int hf_j2735_speeds = -1;                  /* AdvisorySpeedList */
static int hf_j2735_MovementList_item = -1;       /* MovementState */
static int hf_j2735_movementName = -1;            /* DescriptiveName */
static int hf_j2735_state_time_speed = -1;        /* MovementEventList */
static int hf_j2735_startTime_01 = -1;            /* TimeMark */
static int hf_j2735_minEndTime_01 = -1;           /* TimeMark */
static int hf_j2735_maxEndTime_01 = -1;           /* TimeMark */
static int hf_j2735_likelyTime_01 = -1;           /* TimeMark */
static int hf_j2735_nextTime_01 = -1;             /* TimeMark */
static int hf_j2735_header = -1;                  /* Header */
static int hf_j2735_packetID = -1;                /* UniqueMSGID */
static int hf_j2735_urlB = -1;                    /* URL_Base */
static int hf_j2735_dataFrames = -1;              /* TravelerDataFrameList */
static int hf_j2735_center = -1;                  /* Position3D */
static int hf_j2735_radius = -1;                  /* Radius_B12 */
static int hf_j2735_units_01 = -1;                /* DistanceUnits */
static int hf_j2735_anchor = -1;                  /* Position3D */
static int hf_j2735_directionality = -1;          /* DirectionOfUse */
static int hf_j2735_closedPath = -1;              /* BOOLEAN */
static int hf_j2735_direction = -1;               /* HeadingSlice */
static int hf_j2735_description_03 = -1;          /* T_description */
static int hf_j2735_path_01 = -1;                 /* OffsetSystem */
static int hf_j2735_geometry = -1;                /* GeometricProjection */
static int hf_j2735_oldRegion = -1;               /* ValidRegion */
static int hf_j2735_circle = -1;                  /* Circle */
static int hf_j2735_ExitService_item = -1;        /* ExitService_item */
static int hf_j2735_item_01 = -1;                 /* T_item_01 */
static int hf_j2735_text_01 = -1;                 /* ITIStextPhrase */
static int hf_j2735_GenericSignage_item = -1;     /* GenericSignage_item */
static int hf_j2735_item_02 = -1;                 /* T_item_02 */
static int hf_j2735_SpeedLimit_item = -1;         /* SpeedLimit_item */
static int hf_j2735_item_03 = -1;                 /* T_item_03 */
static int hf_j2735_WorkZone_item = -1;           /* WorkZone_item */
static int hf_j2735_item_04 = -1;                 /* T_item_04 */
static int hf_j2735_lon_03 = -1;                  /* OffsetLL_B12 */
static int hf_j2735_lat_04 = -1;                  /* OffsetLL_B12 */
static int hf_j2735_lon_04 = -1;                  /* OffsetLL_B14 */
static int hf_j2735_lat_05 = -1;                  /* OffsetLL_B14 */
static int hf_j2735_lon_05 = -1;                  /* OffsetLL_B16 */
static int hf_j2735_lat_06 = -1;                  /* OffsetLL_B16 */
static int hf_j2735_lon_06 = -1;                  /* OffsetLL_B18 */
static int hf_j2735_lat_07 = -1;                  /* OffsetLL_B18 */
static int hf_j2735_lon_07 = -1;                  /* OffsetLL_B22 */
static int hf_j2735_lat_08 = -1;                  /* OffsetLL_B22 */
static int hf_j2735_lon_08 = -1;                  /* OffsetLL_B24 */
static int hf_j2735_lat_09 = -1;                  /* OffsetLL_B24 */
static int hf_j2735_NodeAttributeLLList_item = -1;  /* NodeAttributeLL */
static int hf_j2735_localNode_01 = -1;            /* NodeAttributeLLList */
static int hf_j2735_disabled_01 = -1;             /* SegmentAttributeLLList */
static int hf_j2735_enabled_01 = -1;              /* SegmentAttributeLLList */
static int hf_j2735_nodes_01 = -1;                /* NodeSetLL */
static int hf_j2735_delta_01 = -1;                /* NodeOffsetPointLL */
static int hf_j2735_attributes_01 = -1;           /* NodeAttributeSetLL */
static int hf_j2735_node_LL1 = -1;                /* Node_LL_24B */
static int hf_j2735_node_LL2 = -1;                /* Node_LL_28B */
static int hf_j2735_node_LL3 = -1;                /* Node_LL_32B */
static int hf_j2735_node_LL4 = -1;                /* Node_LL_36B */
static int hf_j2735_node_LL5 = -1;                /* Node_LL_44B */
static int hf_j2735_node_LL6 = -1;                /* Node_LL_48B */
static int hf_j2735_NodeSetLL_item = -1;          /* NodeLL */
static int hf_j2735_scale = -1;                   /* Zoom */
static int hf_j2735_offset_01 = -1;               /* T_offset */
static int hf_j2735_xy = -1;                      /* NodeListXY */
static int hf_j2735_ll = -1;                      /* NodeListLL */
static int hf_j2735_RegionList_item = -1;         /* RegionOffsets */
static int hf_j2735_xOffset = -1;                 /* OffsetLL_B16 */
static int hf_j2735_yOffset = -1;                 /* OffsetLL_B16 */
static int hf_j2735_zOffset = -1;                 /* OffsetLL_B16 */
static int hf_j2735_nodeList_01 = -1;             /* RegionList */
static int hf_j2735_viewAngle = -1;               /* HeadingSlice */
static int hf_j2735_mutcdCode = -1;               /* MUTCDCode */
static int hf_j2735_crc = -1;                     /* MsgCRC */
static int hf_j2735_SegmentAttributeLLList_item = -1;  /* SegmentAttributeLL */
static int hf_j2735_TravelerDataFrameList_item = -1;  /* TravelerDataFrame */
static int hf_j2735_frameType = -1;               /* TravelerInfoType */
static int hf_j2735_msgId = -1;                   /* T_msgId */
static int hf_j2735_roadSignID = -1;              /* RoadSignID */
static int hf_j2735_startYear = -1;               /* DYear */
static int hf_j2735_startTime_02 = -1;            /* MinuteOfTheYear */
static int hf_j2735_durationTime = -1;            /* MinutesDuration */
static int hf_j2735_priority_01 = -1;             /* SignPrority */
static int hf_j2735_notUsed1 = -1;                /* SSPindex */
static int hf_j2735_regions = -1;                 /* SEQUENCE_SIZE_1_16_OF_GeographicalPath */
static int hf_j2735_regions_item = -1;            /* GeographicalPath */
static int hf_j2735_notUsed2 = -1;                /* SSPindex */
static int hf_j2735_notUsed3 = -1;                /* SSPindex */
static int hf_j2735_content = -1;                 /* T_content */
static int hf_j2735_advisory = -1;                /* ITIScodesAndText */
static int hf_j2735_workZone = -1;                /* WorkZone */
static int hf_j2735_genericSign = -1;             /* GenericSignage */
static int hf_j2735_speedLimit = -1;              /* SpeedLimit */
static int hf_j2735_exitService = -1;             /* ExitService */
static int hf_j2735_url = -1;                     /* URL_Short */
static int hf_j2735_area = -1;                    /* T_area */
static int hf_j2735_shapePointSet = -1;           /* ShapePointSet */
static int hf_j2735_regionPointSet = -1;          /* RegionPointSet */
/* named bits */
static int hf_j2735_BrakeAppliedStatus_unavailable = -1;
static int hf_j2735_BrakeAppliedStatus_leftFront = -1;
static int hf_j2735_BrakeAppliedStatus_leftRear = -1;
static int hf_j2735_BrakeAppliedStatus_rightFront = -1;
static int hf_j2735_BrakeAppliedStatus_rightRear = -1;
static int hf_j2735_ExteriorLights_lowBeamHeadlightsOn = -1;
static int hf_j2735_ExteriorLights_highBeamHeadlightsOn = -1;
static int hf_j2735_ExteriorLights_leftTurnSignalOn = -1;
static int hf_j2735_ExteriorLights_rightTurnSignalOn = -1;
static int hf_j2735_ExteriorLights_hazardSignalOn = -1;
static int hf_j2735_ExteriorLights_automaticLightControlOn = -1;
static int hf_j2735_ExteriorLights_daytimeRunningLightsOn = -1;
static int hf_j2735_ExteriorLights_fogLightOn = -1;
static int hf_j2735_ExteriorLights_parkingLightsOn = -1;
static int hf_j2735_GNSSstatus_unavailable = -1;
static int hf_j2735_GNSSstatus_isHealthy = -1;
static int hf_j2735_GNSSstatus_isMonitored = -1;
static int hf_j2735_GNSSstatus_baseStationType = -1;
static int hf_j2735_GNSSstatus_aPDOPofUnder5 = -1;
static int hf_j2735_GNSSstatus_inViewOfUnder5 = -1;
static int hf_j2735_GNSSstatus_localCorrectionsPresent = -1;
static int hf_j2735_GNSSstatus_networkCorrectionsPresent = -1;
static int hf_j2735_HeadingSlice_from000_0to022_5degrees = -1;
static int hf_j2735_HeadingSlice_from022_5to045_0degrees = -1;
static int hf_j2735_HeadingSlice_from045_0to067_5degrees = -1;
static int hf_j2735_HeadingSlice_from067_5to090_0degrees = -1;
static int hf_j2735_HeadingSlice_from090_0to112_5degrees = -1;
static int hf_j2735_HeadingSlice_from112_5to135_0degrees = -1;
static int hf_j2735_HeadingSlice_from135_0to157_5degrees = -1;
static int hf_j2735_HeadingSlice_from157_5to180_0degrees = -1;
static int hf_j2735_HeadingSlice_from180_0to202_5degrees = -1;
static int hf_j2735_HeadingSlice_from202_5to225_0degrees = -1;
static int hf_j2735_HeadingSlice_from225_0to247_5degrees = -1;
static int hf_j2735_HeadingSlice_from247_5to270_0degrees = -1;
static int hf_j2735_HeadingSlice_from270_0to292_5degrees = -1;
static int hf_j2735_HeadingSlice_from292_5to315_0degrees = -1;
static int hf_j2735_HeadingSlice_from315_0to337_5degrees = -1;
static int hf_j2735_HeadingSlice_from337_5to360_0degrees = -1;
static int hf_j2735_PrivilegedEventFlags_peUnavailable = -1;
static int hf_j2735_PrivilegedEventFlags_peEmergencyResponse = -1;
static int hf_j2735_PrivilegedEventFlags_peEmergencyLightsActive = -1;
static int hf_j2735_PrivilegedEventFlags_peEmergencySoundActive = -1;
static int hf_j2735_PrivilegedEventFlags_peNonEmergencyLightsActive = -1;
static int hf_j2735_PrivilegedEventFlags_peNonEmergencySoundActive = -1;
static int hf_j2735_TransitStatus_none = -1;
static int hf_j2735_TransitStatus_anADAuse = -1;
static int hf_j2735_TransitStatus_aBikeLoad = -1;
static int hf_j2735_TransitStatus_doorOpen = -1;
static int hf_j2735_TransitStatus_occM = -1;
static int hf_j2735_TransitStatus_occL = -1;
static int hf_j2735_VehicleEventFlags_eventHazardLights = -1;
static int hf_j2735_VehicleEventFlags_eventStopLineViolation = -1;
static int hf_j2735_VehicleEventFlags_eventABSactivated = -1;
static int hf_j2735_VehicleEventFlags_eventTractionControlLoss = -1;
static int hf_j2735_VehicleEventFlags_eventStabilityControlactivated = -1;
static int hf_j2735_VehicleEventFlags_eventHazardousMaterials = -1;
static int hf_j2735_VehicleEventFlags_eventReserved1 = -1;
static int hf_j2735_VehicleEventFlags_eventHardBraking = -1;
static int hf_j2735_VehicleEventFlags_eventLightsChanged = -1;
static int hf_j2735_VehicleEventFlags_eventWipersChanged = -1;
static int hf_j2735_VehicleEventFlags_eventFlatTire = -1;
static int hf_j2735_VehicleEventFlags_eventDisabledVehicle = -1;
static int hf_j2735_VehicleEventFlags_eventAirBagDeployment = -1;
static int hf_j2735_VerticalAccelerationThreshold_notEquipped = -1;
static int hf_j2735_VerticalAccelerationThreshold_leftFront = -1;
static int hf_j2735_VerticalAccelerationThreshold_leftRear = -1;
static int hf_j2735_VerticalAccelerationThreshold_rightFront = -1;
static int hf_j2735_VerticalAccelerationThreshold_rightRear = -1;
static int hf_j2735_AllowedManeuvers_maneuverStraightAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverLeftAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverRightAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverUTurnAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverLeftTurnOnRedAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverRightTurnOnRedAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverLaneChangeAllowed = -1;
static int hf_j2735_AllowedManeuvers_maneuverNoStoppingAllowed = -1;
static int hf_j2735_AllowedManeuvers_yieldAllwaysRequired = -1;
static int hf_j2735_AllowedManeuvers_goWithHalt = -1;
static int hf_j2735_AllowedManeuvers_caution = -1;
static int hf_j2735_AllowedManeuvers_reserved1 = -1;
static int hf_j2735_LaneAttributes_Barrier_median_RevocableLane = -1;
static int hf_j2735_LaneAttributes_Barrier_median = -1;
static int hf_j2735_LaneAttributes_Barrier_whiteLineHashing = -1;
static int hf_j2735_LaneAttributes_Barrier_stripedLines = -1;
static int hf_j2735_LaneAttributes_Barrier_doubleStripedLines = -1;
static int hf_j2735_LaneAttributes_Barrier_trafficCones = -1;
static int hf_j2735_LaneAttributes_Barrier_constructionBarrier = -1;
static int hf_j2735_LaneAttributes_Barrier_trafficChannels = -1;
static int hf_j2735_LaneAttributes_Barrier_lowCurbs = -1;
static int hf_j2735_LaneAttributes_Barrier_highCurbs = -1;
static int hf_j2735_LaneAttributes_Bike_bikeRevocableLane = -1;
static int hf_j2735_LaneAttributes_Bike_pedestrianUseAllowed = -1;
static int hf_j2735_LaneAttributes_Bike_isBikeFlyOverLane = -1;
static int hf_j2735_LaneAttributes_Bike_fixedCycleTime = -1;
static int hf_j2735_LaneAttributes_Bike_biDirectionalCycleTimes = -1;
static int hf_j2735_LaneAttributes_Bike_isolatedByBarrier = -1;
static int hf_j2735_LaneAttributes_Bike_unsignalizedSegmentsPresent = -1;
static int hf_j2735_LaneAttributes_Crosswalk_crosswalkRevocableLane = -1;
static int hf_j2735_LaneAttributes_Crosswalk_bicyleUseAllowed = -1;
static int hf_j2735_LaneAttributes_Crosswalk_isXwalkFlyOverLane = -1;
static int hf_j2735_LaneAttributes_Crosswalk_fixedCycleTime = -1;
static int hf_j2735_LaneAttributes_Crosswalk_biDirectionalCycleTimes = -1;
static int hf_j2735_LaneAttributes_Crosswalk_hasPushToWalkButton = -1;
static int hf_j2735_LaneAttributes_Crosswalk_audioSupport = -1;
static int hf_j2735_LaneAttributes_Crosswalk_rfSignalRequestPresent = -1;
static int hf_j2735_LaneAttributes_Crosswalk_unsignalizedSegmentsPresent = -1;
static int hf_j2735_LaneAttributes_Parking_parkingRevocableLane = -1;
static int hf_j2735_LaneAttributes_Parking_parallelParkingInUse = -1;
static int hf_j2735_LaneAttributes_Parking_headInParkingInUse = -1;
static int hf_j2735_LaneAttributes_Parking_doNotParkZone = -1;
static int hf_j2735_LaneAttributes_Parking_parkingForBusUse = -1;
static int hf_j2735_LaneAttributes_Parking_parkingForTaxiUse = -1;
static int hf_j2735_LaneAttributes_Parking_noPublicParkingUse = -1;
static int hf_j2735_LaneAttributes_Sidewalk_sidewalk_RevocableLane = -1;
static int hf_j2735_LaneAttributes_Sidewalk_bicyleUseAllowed = -1;
static int hf_j2735_LaneAttributes_Sidewalk_isSidewalkFlyOverLane = -1;
static int hf_j2735_LaneAttributes_Sidewalk_walkBikes = -1;
static int hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesRevocableLane = -1;
static int hf_j2735_LaneAttributes_Striping_stripeDrawOnLeft = -1;
static int hf_j2735_LaneAttributes_Striping_stripeDrawOnRight = -1;
static int hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesLeft = -1;
static int hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesRight = -1;
static int hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesAhead = -1;
static int hf_j2735_LaneAttributes_TrackedVehicle_spec_RevocableLane = -1;
static int hf_j2735_LaneAttributes_TrackedVehicle_spec_commuterRailRoadTrack = -1;
static int hf_j2735_LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack = -1;
static int hf_j2735_LaneAttributes_TrackedVehicle_spec_heavyRailRoadTrack = -1;
static int hf_j2735_LaneAttributes_TrackedVehicle_spec_otherRailType = -1;
static int hf_j2735_LaneAttributes_Vehicle_isVehicleRevocableLane = -1;
static int hf_j2735_LaneAttributes_Vehicle_isVehicleFlyOverLane = -1;
static int hf_j2735_LaneAttributes_Vehicle_hovLaneUseOnly = -1;
static int hf_j2735_LaneAttributes_Vehicle_restrictedToBusUse = -1;
static int hf_j2735_LaneAttributes_Vehicle_restrictedToTaxiUse = -1;
static int hf_j2735_LaneAttributes_Vehicle_restrictedFromPublicUse = -1;
static int hf_j2735_LaneAttributes_Vehicle_hasIRbeaconCoverage = -1;
static int hf_j2735_LaneAttributes_Vehicle_permissionOnRequest = -1;
static int hf_j2735_LaneDirection_ingressPath = -1;
static int hf_j2735_LaneDirection_egressPath = -1;
static int hf_j2735_LaneSharing_overlappingLaneDescriptionProvided = -1;
static int hf_j2735_LaneSharing_multipleLanesTreatedAsOneLane = -1;
static int hf_j2735_LaneSharing_otherNonMotorizedTrafficTypes = -1;
static int hf_j2735_LaneSharing_individualMotorizedVehicleTraffic = -1;
static int hf_j2735_LaneSharing_busVehicleTraffic = -1;
static int hf_j2735_LaneSharing_taxiVehicleTraffic = -1;
static int hf_j2735_LaneSharing_pedestriansTraffic = -1;
static int hf_j2735_LaneSharing_cyclistVehicleTraffic = -1;
static int hf_j2735_LaneSharing_trackedVehicleTraffic = -1;
static int hf_j2735_LaneSharing_reserved = -1;
static int hf_j2735_PersonalAssistive_unavailable = -1;
static int hf_j2735_PersonalAssistive_otherType = -1;
static int hf_j2735_PersonalAssistive_vision = -1;
static int hf_j2735_PersonalAssistive_hearing = -1;
static int hf_j2735_PersonalAssistive_movement = -1;
static int hf_j2735_PersonalAssistive_cognition = -1;
static int hf_j2735_PersonalDeviceUsageState_unavailable = -1;
static int hf_j2735_PersonalDeviceUsageState_other = -1;
static int hf_j2735_PersonalDeviceUsageState_idle = -1;
static int hf_j2735_PersonalDeviceUsageState_listeningToAudio = -1;
static int hf_j2735_PersonalDeviceUsageState_typing = -1;
static int hf_j2735_PersonalDeviceUsageState_calling = -1;
static int hf_j2735_PersonalDeviceUsageState_playingGames = -1;
static int hf_j2735_PersonalDeviceUsageState_reading = -1;
static int hf_j2735_PersonalDeviceUsageState_viewing = -1;
static int hf_j2735_PublicSafetyAndRoadWorkerActivity_unavailable = -1;
static int hf_j2735_PublicSafetyAndRoadWorkerActivity_workingOnRoad = -1;
static int hf_j2735_PublicSafetyAndRoadWorkerActivity_settingUpClosures = -1;
static int hf_j2735_PublicSafetyAndRoadWorkerActivity_respondingToEvents = -1;
static int hf_j2735_PublicSafetyAndRoadWorkerActivity_directingTraffic = -1;
static int hf_j2735_PublicSafetyAndRoadWorkerActivity_otherActivities = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_unavailable = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_policeAndTrafficOfficers = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_trafficControlPersons = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_railroadCrossingGuards = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_civilDefenseNationalGuardMilitaryPolice = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_emergencyOrganizationPersonnel = -1;
static int hf_j2735_PublicSafetyDirectingTrafficSubType_highwayServiceVehiclePersonnel = -1;
static int hf_j2735_UserSizeAndBehaviour_unavailable = -1;
static int hf_j2735_UserSizeAndBehaviour_smallStature = -1;
static int hf_j2735_UserSizeAndBehaviour_largeStature = -1;
static int hf_j2735_UserSizeAndBehaviour_erraticMoving = -1;
static int hf_j2735_UserSizeAndBehaviour_slowMoving = -1;
static int hf_j2735_TransitVehicleStatus_loading = -1;
static int hf_j2735_TransitVehicleStatus_anADAuse = -1;
static int hf_j2735_TransitVehicleStatus_aBikeLoad = -1;
static int hf_j2735_TransitVehicleStatus_doorOpen = -1;
static int hf_j2735_TransitVehicleStatus_charging = -1;
static int hf_j2735_TransitVehicleStatus_atStopLine = -1;
static int hf_j2735_IntersectionStatusObject_manualControlIsEnabled = -1;
static int hf_j2735_IntersectionStatusObject_stopTimeIsActivated = -1;
static int hf_j2735_IntersectionStatusObject_failureFlash = -1;
static int hf_j2735_IntersectionStatusObject_preemptIsActive = -1;
static int hf_j2735_IntersectionStatusObject_signalPriorityIsActive = -1;
static int hf_j2735_IntersectionStatusObject_fixedTimeOperation = -1;
static int hf_j2735_IntersectionStatusObject_trafficDependentOperation = -1;
static int hf_j2735_IntersectionStatusObject_standbyOperation = -1;
static int hf_j2735_IntersectionStatusObject_failureMode = -1;
static int hf_j2735_IntersectionStatusObject_off = -1;
static int hf_j2735_IntersectionStatusObject_recentMAPmessageUpdate = -1;
static int hf_j2735_IntersectionStatusObject_recentChangeInMAPassignedLanesIDsUsed = -1;
static int hf_j2735_IntersectionStatusObject_noValidMAPisAvailableAtThisTime = -1;
static int hf_j2735_IntersectionStatusObject_noValidSPATisAvailableAtThisTime = -1;

/* Initialize the subtree pointers */
static int ett_j2735 = -1;
static gint ett_j2735_LatitudeDMS2 = -1;
static gint ett_j2735_LongitudeDMS2 = -1;
static gint ett_j2735_Node_LLdms_48b = -1;
static gint ett_j2735_Node_LLdms_80b = -1;
static gint ett_j2735_LaneDataAttribute_addGrpB = -1;
static gint ett_j2735_MovementEvent_addGrpB = -1;
static gint ett_j2735_NodeOffsetPointXY_addGrpB = -1;
static gint ett_j2735_Position3D_addGrpB = -1;
static gint ett_j2735_TimeMark_addGrpB = -1;
static gint ett_j2735_Altitude = -1;
static gint ett_j2735_PrioritizationResponse = -1;
static gint ett_j2735_PrioritizationResponseList = -1;
static gint ett_j2735_ConnectionManeuverAssist_addGrpC = -1;
static gint ett_j2735_IntersectionState_addGrpC = -1;
static gint ett_j2735_MapData_addGrpC = -1;
static gint ett_j2735_Position3D_addGrpC = -1;
static gint ett_j2735_RestrictionUserType_addGrpC = -1;
static gint ett_j2735_SignalHeadLocation = -1;
static gint ett_j2735_SignalHeadLocationList = -1;
static gint ett_j2735_VehicleToLanePosition = -1;
static gint ett_j2735_VehicleToLanePositionList = -1;
static gint ett_j2735_BasicSafetyMessage = -1;
static gint ett_j2735_SEQUENCE_SIZE_1_8_OF_PartIIcontent = -1;
static gint ett_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension = -1;
static gint ett_j2735_PartIIcontent = -1;
static gint ett_j2735_DisabledVehicle = -1;
static gint ett_j2735_EventDescription = -1;
static gint ett_j2735_SEQUENCE_SIZE_1_8_OF_ITIScodes = -1;
static gint ett_j2735_ObstacleDetection = -1;
static gint ett_j2735_PivotPointDescription = -1;
static gint ett_j2735_RTCMPackage = -1;
static gint ett_j2735_SpecialVehicleExtensions = -1;
static gint ett_j2735_SpeedProfileMeasurementList = -1;
static gint ett_j2735_SpeedProfile = -1;
static gint ett_j2735_SupplementalVehicleExtensions = -1;
static gint ett_j2735_TrailerData = -1;
static gint ett_j2735_TrailerHistoryPointList = -1;
static gint ett_j2735_TrailerHistoryPoint = -1;
static gint ett_j2735_TrailerUnitDescriptionList = -1;
static gint ett_j2735_TrailerUnitDescription = -1;
static gint ett_j2735_VehicleData = -1;
static gint ett_j2735_WeatherProbe = -1;
static gint ett_j2735_WeatherReport = -1;
static gint ett_j2735_RegionalExtension = -1;
static gint ett_j2735_AccelerationSet4Way = -1;
static gint ett_j2735_AntennaOffsetSet = -1;
static gint ett_j2735_BrakeSystemStatus = -1;
static gint ett_j2735_BSMcoreData = -1;
static gint ett_j2735_BumperHeights = -1;
static gint ett_j2735_ComputedLane = -1;
static gint ett_j2735_T_offsetXaxis = -1;
static gint ett_j2735_T_offsetYaxis = -1;
static gint ett_j2735_DDate = -1;
static gint ett_j2735_DDateTime = -1;
static gint ett_j2735_DFullTime = -1;
static gint ett_j2735_DMonthDay = -1;
static gint ett_j2735_DTime = -1;
static gint ett_j2735_DYearMonth = -1;
static gint ett_j2735_EmergencyDetails = -1;
static gint ett_j2735_FullPositionVector = -1;
static gint ett_j2735_Header = -1;
static gint ett_j2735_IntersectionAccessPoint = -1;
static gint ett_j2735_IntersectionReferenceID = -1;
static gint ett_j2735_LaneDataAttribute = -1;
static gint ett_j2735_LaneDataAttributeList = -1;
static gint ett_j2735_Node_LLmD_64b = -1;
static gint ett_j2735_Node_XY_20b = -1;
static gint ett_j2735_Node_XY_22b = -1;
static gint ett_j2735_Node_XY_24b = -1;
static gint ett_j2735_Node_XY_26b = -1;
static gint ett_j2735_Node_XY_28b = -1;
static gint ett_j2735_Node_XY_32b = -1;
static gint ett_j2735_NodeAttributeSetXY = -1;
static gint ett_j2735_NodeAttributeXYList = -1;
static gint ett_j2735_NodeListXY = -1;
static gint ett_j2735_NodeOffsetPointXY = -1;
static gint ett_j2735_NodeSetXY = -1;
static gint ett_j2735_NodeXY = -1;
static gint ett_j2735_PathHistory = -1;
static gint ett_j2735_PathHistoryPointList = -1;
static gint ett_j2735_PathHistoryPoint = -1;
static gint ett_j2735_PathPrediction = -1;
static gint ett_j2735_Position3D = -1;
static gint ett_j2735_PositionalAccuracy = -1;
static gint ett_j2735_PositionConfidenceSet = -1;
static gint ett_j2735_PrivilegedEvents = -1;
static gint ett_j2735_RegulatorySpeedLimit = -1;
static gint ett_j2735_RequestorType = -1;
static gint ett_j2735_RoadSegmentReferenceID = -1;
static gint ett_j2735_RTCMheader = -1;
static gint ett_j2735_RTCMmessageList = -1;
static gint ett_j2735_SegmentAttributeXYList = -1;
static gint ett_j2735_SpeedandHeadingandThrottleConfidence = -1;
static gint ett_j2735_SpeedLimitList = -1;
static gint ett_j2735_TransmissionAndSpeed = -1;
static gint ett_j2735_VehicleClassification = -1;
static gint ett_j2735_VehicleID = -1;
static gint ett_j2735_VehicleSafetyExtensions = -1;
static gint ett_j2735_VehicleSize = -1;
static gint ett_j2735_VerticalOffset = -1;
static gint ett_j2735_WiperSet = -1;
static gint ett_j2735_BrakeAppliedStatus = -1;
static gint ett_j2735_ExteriorLights = -1;
static gint ett_j2735_GNSSstatus = -1;
static gint ett_j2735_HeadingSlice = -1;
static gint ett_j2735_PrivilegedEventFlags = -1;
static gint ett_j2735_TransitStatus = -1;
static gint ett_j2735_VehicleEventFlags = -1;
static gint ett_j2735_VerticalAccelerationThreshold = -1;
static gint ett_j2735_CommonSafetyRequest = -1;
static gint ett_j2735_RequestedItemList = -1;
static gint ett_j2735_EmergencyVehicleAlert = -1;
static gint ett_j2735_IntersectionCollision = -1;
static gint ett_j2735_ApproachOrLane = -1;
static gint ett_j2735_ITIScodesAndText = -1;
static gint ett_j2735_ITIScodesAndText_item = -1;
static gint ett_j2735_T_item = -1;
static gint ett_j2735_MapData = -1;
static gint ett_j2735_ConnectingLane = -1;
static gint ett_j2735_Connection = -1;
static gint ett_j2735_ConnectsToList = -1;
static gint ett_j2735_DataParameters = -1;
static gint ett_j2735_GenericLane = -1;
static gint ett_j2735_IntersectionGeometry = -1;
static gint ett_j2735_IntersectionGeometryList = -1;
static gint ett_j2735_LaneAttributes = -1;
static gint ett_j2735_LaneList = -1;
static gint ett_j2735_LaneTypeAttributes = -1;
static gint ett_j2735_OverlayLaneList = -1;
static gint ett_j2735_PreemptPriorityList = -1;
static gint ett_j2735_SignalControlZone = -1;
static gint ett_j2735_RestrictionClassAssignment = -1;
static gint ett_j2735_RestrictionClassList = -1;
static gint ett_j2735_RestrictionUserTypeList = -1;
static gint ett_j2735_RestrictionUserType = -1;
static gint ett_j2735_RoadLaneSetList = -1;
static gint ett_j2735_RoadSegmentList = -1;
static gint ett_j2735_RoadSegment = -1;
static gint ett_j2735_AllowedManeuvers = -1;
static gint ett_j2735_LaneAttributes_Barrier = -1;
static gint ett_j2735_LaneAttributes_Bike = -1;
static gint ett_j2735_LaneAttributes_Crosswalk = -1;
static gint ett_j2735_LaneAttributes_Parking = -1;
static gint ett_j2735_LaneAttributes_Sidewalk = -1;
static gint ett_j2735_LaneAttributes_Striping = -1;
static gint ett_j2735_LaneAttributes_TrackedVehicle = -1;
static gint ett_j2735_LaneAttributes_Vehicle = -1;
static gint ett_j2735_LaneDirection = -1;
static gint ett_j2735_LaneSharing = -1;
static gint ett_j2735_MessageFrame = -1;
static gint ett_j2735_NMEAcorrections = -1;
static gint ett_j2735_PersonalSafetyMessage = -1;
static gint ett_j2735_PropelledInformation = -1;
static gint ett_j2735_PersonalAssistive = -1;
static gint ett_j2735_PersonalDeviceUsageState = -1;
static gint ett_j2735_PublicSafetyAndRoadWorkerActivity = -1;
static gint ett_j2735_PublicSafetyDirectingTrafficSubType = -1;
static gint ett_j2735_UserSizeAndBehaviour = -1;
static gint ett_j2735_ProbeDataManagement = -1;
static gint ett_j2735_T_term = -1;
static gint ett_j2735_T_snapshot = -1;
static gint ett_j2735_Sample = -1;
static gint ett_j2735_SnapshotDistance = -1;
static gint ett_j2735_SnapshotTime = -1;
static gint ett_j2735_VehicleStatusRequest = -1;
static gint ett_j2735_VehicleStatusRequestList = -1;
static gint ett_j2735_ProbeVehicleData = -1;
static gint ett_j2735_SEQUENCE_SIZE_1_32_OF_Snapshot = -1;
static gint ett_j2735_AccelSteerYawRateConfidence = -1;
static gint ett_j2735_ConfidenceSet = -1;
static gint ett_j2735_J1939data = -1;
static gint ett_j2735_TireDataList = -1;
static gint ett_j2735_TireData = -1;
static gint ett_j2735_AxleWeightList = -1;
static gint ett_j2735_AxleWeightSet = -1;
static gint ett_j2735_Snapshot = -1;
static gint ett_j2735_VehicleIdent = -1;
static gint ett_j2735_T_vehicleClass = -1;
static gint ett_j2735_VehicleStatus = -1;
static gint ett_j2735_T_steering = -1;
static gint ett_j2735_T_accelSets = -1;
static gint ett_j2735_T_object = -1;
static gint ett_j2735_T_vehicleData = -1;
static gint ett_j2735_T_weatherReport = -1;
static gint ett_j2735_RoadSideAlert = -1;
static gint ett_j2735_RTCMcorrections = -1;
static gint ett_j2735_SignalRequestMessage = -1;
static gint ett_j2735_RequestorDescription = -1;
static gint ett_j2735_RequestorPositionVector = -1;
static gint ett_j2735_SignalRequestList = -1;
static gint ett_j2735_SignalRequestPackage = -1;
static gint ett_j2735_SignalRequest = -1;
static gint ett_j2735_TransitVehicleStatus = -1;
static gint ett_j2735_SignalStatusMessage = -1;
static gint ett_j2735_SignalRequesterInfo = -1;
static gint ett_j2735_SignalStatusList = -1;
static gint ett_j2735_SignalStatusPackageList = -1;
static gint ett_j2735_SignalStatusPackage = -1;
static gint ett_j2735_SignalStatus = -1;
static gint ett_j2735_SPAT = -1;
static gint ett_j2735_AdvisorySpeed = -1;
static gint ett_j2735_AdvisorySpeedList = -1;
static gint ett_j2735_ConnectionManeuverAssist = -1;
static gint ett_j2735_EnabledLaneList = -1;
static gint ett_j2735_IntersectionState = -1;
static gint ett_j2735_IntersectionStateList = -1;
static gint ett_j2735_ManeuverAssistList = -1;
static gint ett_j2735_MovementEventList = -1;
static gint ett_j2735_MovementEvent = -1;
static gint ett_j2735_MovementList = -1;
static gint ett_j2735_MovementState = -1;
static gint ett_j2735_TimeChangeDetails = -1;
static gint ett_j2735_IntersectionStatusObject = -1;
static gint ett_j2735_TestMessage00 = -1;
static gint ett_j2735_TestMessage01 = -1;
static gint ett_j2735_TestMessage02 = -1;
static gint ett_j2735_TestMessage03 = -1;
static gint ett_j2735_TestMessage04 = -1;
static gint ett_j2735_TestMessage05 = -1;
static gint ett_j2735_TestMessage06 = -1;
static gint ett_j2735_TestMessage07 = -1;
static gint ett_j2735_TestMessage08 = -1;
static gint ett_j2735_TestMessage09 = -1;
static gint ett_j2735_TestMessage10 = -1;
static gint ett_j2735_TestMessage11 = -1;
static gint ett_j2735_TestMessage12 = -1;
static gint ett_j2735_TestMessage13 = -1;
static gint ett_j2735_TestMessage14 = -1;
static gint ett_j2735_TestMessage15 = -1;
static gint ett_j2735_TravelerInformation = -1;
static gint ett_j2735_Circle = -1;
static gint ett_j2735_GeographicalPath = -1;
static gint ett_j2735_T_description = -1;
static gint ett_j2735_GeometricProjection = -1;
static gint ett_j2735_ExitService = -1;
static gint ett_j2735_ExitService_item = -1;
static gint ett_j2735_T_item_01 = -1;
static gint ett_j2735_GenericSignage = -1;
static gint ett_j2735_GenericSignage_item = -1;
static gint ett_j2735_T_item_02 = -1;
static gint ett_j2735_SpeedLimit = -1;
static gint ett_j2735_SpeedLimit_item = -1;
static gint ett_j2735_T_item_03 = -1;
static gint ett_j2735_WorkZone = -1;
static gint ett_j2735_WorkZone_item = -1;
static gint ett_j2735_T_item_04 = -1;
static gint ett_j2735_Node_LL_24B = -1;
static gint ett_j2735_Node_LL_28B = -1;
static gint ett_j2735_Node_LL_32B = -1;
static gint ett_j2735_Node_LL_36B = -1;
static gint ett_j2735_Node_LL_44B = -1;
static gint ett_j2735_Node_LL_48B = -1;
static gint ett_j2735_NodeAttributeLLList = -1;
static gint ett_j2735_NodeAttributeSetLL = -1;
static gint ett_j2735_NodeListLL = -1;
static gint ett_j2735_NodeLL = -1;
static gint ett_j2735_NodeOffsetPointLL = -1;
static gint ett_j2735_NodeSetLL = -1;
static gint ett_j2735_OffsetSystem = -1;
static gint ett_j2735_T_offset = -1;
static gint ett_j2735_RegionList = -1;
static gint ett_j2735_RegionOffsets = -1;
static gint ett_j2735_RegionPointSet = -1;
static gint ett_j2735_RoadSignID = -1;
static gint ett_j2735_SegmentAttributeLLList = -1;
static gint ett_j2735_ShapePointSet = -1;
static gint ett_j2735_TravelerDataFrameList = -1;
static gint ett_j2735_TravelerDataFrame = -1;
static gint ett_j2735_T_msgId = -1;
static gint ett_j2735_SEQUENCE_SIZE_1_16_OF_GeographicalPath = -1;
static gint ett_j2735_T_content = -1;
static gint ett_j2735_ValidRegion = -1;
static gint ett_j2735_T_area = -1;

/* Global variables */
static guint32 DSRCmsgID;
static guint32 PartII_Id;

static dissector_table_t dsrcmsgid_dissector_table;
static dissector_table_t j2735_partii_id_dissector_table;


typedef enum _PartII_Id_enum {
  vehicleSafetyExt =   0,
  specialVehicleExt =   1,
  supplementalVehicleExt =   2
} PartII_Id_enum;

typedef enum _DSRCmsgID_enum {
  reservedMessageId_D =   0,
  alaCarteMessage_D =   1,
  basicSafetyMessage_D =   2,
  basicSafetyMessageVerbose_D =   3,
  commonSafetyRequest_D =   4,
  emergencyVehicleAlert_D =   5,
  intersectionCollision_D =   6,
  mapData_D    =   7,
  nmeaCorrections_D =   8,
  probeDataManagement_D =   9,
  probeVehicleData_D =  10,
  roadSideAlert_D =  11,
  rtcmCorrections_D =  12,
  signalPhaseAndTimingMessage_D =  13,
  signalRequestMessage_D =  14,
  signalStatusMessage_D =  15,
  travelerInformation_D =  16,
  uperFrame_D  =  17,
  mapData      =  18,
  signalPhaseAndTimingMessage =  19,
  basicSafetyMessage =  20,
  commonSafetyRequest =  21,
  emergencyVehicleAlert =  22,
  intersectionCollision =  23,
  nmeaCorrections =  24,
  probeDataManagement =  25,
  probeVehicleData =  26,
  roadSideAlert =  27,
  rtcmCorrections =  28,
  signalRequestMessage =  29,
  signalStatusMessage =  30,
  travelerInformation =  31,
  personalSafetyMessage =  32,
  testMessage00 = 240,
  testMessage01 = 241,
  testMessage02 = 242,
  testMessage03 = 243,
  testMessage04 = 244,
  testMessage05 = 245,
  testMessage06 = 246,
  testMessage07 = 247,
  testMessage08 = 248,
  testMessage09 = 249,
  testMessage10 = 250,
  testMessage11 = 251,
  testMessage12 = 252,
  testMessage13 = 253,
  testMessage14 = 254,
  testMessage15 = 255
} DSRCmsgID_enum;

static int dissect_j2735_DSRCmsgID_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return (dissector_try_uint_new(dsrcmsgid_dissector_table, DSRCmsgID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_j2735_partii_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return (dissector_try_uint_new(j2735_partii_id_dissector_table, PartII_Id, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}



static int
dissect_j2735_AngleB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 239U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Day(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string j2735_DayOfWeek_vals[] = {
  {   0, "unknown" },
  {   1, "monday" },
  {   2, "tuesday" },
  {   3, "wednesday" },
  {   4, "thursday" },
  {   5, "friday" },
  {   6, "saturday" },
  {   7, "sunday" },
  { 0, NULL }
};


static int
dissect_j2735_DayOfWeek(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_DegreesLat(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -90, 90U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DegreesLong(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -180, 180U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_ElevationB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const value_string j2735_Holiday_vals[] = {
  {   0, "weekday" },
  {   1, "holiday" },
  { 0, NULL }
};


static int
dissect_j2735_Holiday(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_Hour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_LatitudeDMS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32400000, 32400000U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_LongitudeDMS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64800000, 64800000U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_MaxTimetoChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2402U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_MinTimetoChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2402U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Minute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_MinutesAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Month(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_MsgCountB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Second(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 60U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SecondsAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5999U, NULL, FALSE);

  return offset;
}


static const value_string j2735_SummerTime_vals[] = {
  {   0, "notInSummerTime" },
  {   1, "inSummerTime" },
  { 0, NULL }
};


static int
dissect_j2735_SummerTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_TenthSecond(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TimeRemaining(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9001U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Year(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t LatitudeDMS2_sequence[] = {
  { &hf_j2735_d             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DegreesLat },
  { &hf_j2735_m             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_MinutesAngle },
  { &hf_j2735_s             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SecondsAngle },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_LatitudeDMS2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_LatitudeDMS2, LatitudeDMS2_sequence);

  return offset;
}


static const per_sequence_t LongitudeDMS2_sequence[] = {
  { &hf_j2735_d_01          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DegreesLong },
  { &hf_j2735_m             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_MinutesAngle },
  { &hf_j2735_s             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SecondsAngle },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_LongitudeDMS2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_LongitudeDMS2, LongitudeDMS2_sequence);

  return offset;
}


static const per_sequence_t Node_LLdms_48b_sequence[] = {
  { &hf_j2735_lon           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LongitudeDMS },
  { &hf_j2735_lat           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LatitudeDMS },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LLdms_48b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LLdms_48b, Node_LLdms_48b_sequence);

  return offset;
}


static const per_sequence_t Node_LLdms_80b_sequence[] = {
  { &hf_j2735_lon_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LongitudeDMS2 },
  { &hf_j2735_lat_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LatitudeDMS2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LLdms_80b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LLdms_80b, Node_LLdms_80b_sequence);

  return offset;
}


static const per_sequence_t LaneDataAttribute_addGrpB_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_j2735_LaneDataAttribute_addGrpB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_LaneDataAttribute_addGrpB, LaneDataAttribute_addGrpB_sequence);

  return offset;
}



static int
dissect_j2735_TimeIntervalConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MovementEvent_addGrpB_sequence[] = {
  { &hf_j2735_startTime     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeRemaining },
  { &hf_j2735_minEndTime    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MinTimetoChange },
  { &hf_j2735_maxEndTime    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MaxTimetoChange },
  { &hf_j2735_likelyTime    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeRemaining },
  { &hf_j2735_confidence    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeIntervalConfidence },
  { &hf_j2735_nextTime      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeRemaining },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_MovementEvent_addGrpB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_MovementEvent_addGrpB, MovementEvent_addGrpB_sequence);

  return offset;
}


static const value_string j2735_NodeOffsetPointXY_addGrpB_vals[] = {
  {   0, "posA" },
  {   1, "posB" },
  { 0, NULL }
};

static const per_choice_t NodeOffsetPointXY_addGrpB_choice[] = {
  {   0, &hf_j2735_posA          , ASN1_EXTENSION_ROOT    , dissect_j2735_Node_LLdms_48b },
  {   1, &hf_j2735_posB          , ASN1_EXTENSION_ROOT    , dissect_j2735_Node_LLdms_80b },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_NodeOffsetPointXY_addGrpB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_NodeOffsetPointXY_addGrpB, NodeOffsetPointXY_addGrpB_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Position3D_addGrpB_sequence[] = {
  { &hf_j2735_latitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LatitudeDMS2 },
  { &hf_j2735_longitude     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LongitudeDMS2 },
  { &hf_j2735_elevation     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ElevationB },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Position3D_addGrpB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Position3D_addGrpB, Position3D_addGrpB_sequence);

  return offset;
}


static const per_sequence_t TimeMark_addGrpB_sequence[] = {
  { &hf_j2735_year          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Year },
  { &hf_j2735_month         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Month },
  { &hf_j2735_day           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Day },
  { &hf_j2735_summerTime    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SummerTime },
  { &hf_j2735_holiday       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Holiday },
  { &hf_j2735_dayofWeek     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DayOfWeek },
  { &hf_j2735_hour          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Hour },
  { &hf_j2735_minute        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Minute },
  { &hf_j2735_second        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Second },
  { &hf_j2735_tenthSecond   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TenthSecond },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TimeMark_addGrpB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TimeMark_addGrpB, TimeMark_addGrpB_sequence);

  return offset;
}


static const value_string j2735_AltitudeConfidence_vals[] = {
  {   0, "alt-000-01" },
  {   1, "alt-000-02" },
  {   2, "alt-000-05" },
  {   3, "alt-000-10" },
  {   4, "alt-000-20" },
  {   5, "alt-000-50" },
  {   6, "alt-001-00" },
  {   7, "alt-002-00" },
  {   8, "alt-005-00" },
  {   9, "alt-010-00" },
  {  10, "alt-020-00" },
  {  11, "alt-050-00" },
  {  12, "alt-100-00" },
  {  13, "alt-200-00" },
  {  14, "outOfRange" },
  {  15, "unavailable" },
  { 0, NULL }
};


static int
dissect_j2735_AltitudeConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_AltitudeValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100000, 800001U, NULL, FALSE);

  return offset;
}


static const value_string j2735_EmissionType_vals[] = {
  {   0, "typeA" },
  {   1, "typeB" },
  {   2, "typeC" },
  {   3, "typeD" },
  {   4, "typeE" },
  { 0, NULL }
};


static int
dissect_j2735_EmissionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Altitude_sequence[] = {
  { &hf_j2735_value         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AltitudeValue },
  { &hf_j2735_confidence_01 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AltitudeConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Altitude, Altitude_sequence);

  return offset;
}



static int
dissect_j2735_StationID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const value_string j2735_PrioritizationResponseStatus_vals[] = {
  {   0, "unknown" },
  {   1, "requested" },
  {   2, "processing" },
  {   3, "watchOtherTraffic" },
  {   4, "granted" },
  {   5, "rejected" },
  {   6, "maxPresence" },
  {   7, "reserviceLocked" },
  { 0, NULL }
};


static int
dissect_j2735_PrioritizationResponseStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_SignalGroupID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PrioritizationResponse_sequence[] = {
  { &hf_j2735_stationID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_StationID },
  { &hf_j2735_priorState    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PrioritizationResponseStatus },
  { &hf_j2735_signalGroup   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignalGroupID },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PrioritizationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PrioritizationResponse, PrioritizationResponse_sequence);

  return offset;
}


static const per_sequence_t PrioritizationResponseList_sequence_of[1] = {
  { &hf_j2735_PrioritizationResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_PrioritizationResponse },
};

static int
dissect_j2735_PrioritizationResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_PrioritizationResponseList, PrioritizationResponseList_sequence_of,
                                                  1, 10, FALSE);

  return offset;
}



static int
dissect_j2735_LaneID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleToLanePosition_sequence[] = {
  { &hf_j2735_stationID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_StationID },
  { &hf_j2735_laneID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LaneID },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleToLanePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleToLanePosition, VehicleToLanePosition_sequence);

  return offset;
}


static const per_sequence_t VehicleToLanePositionList_sequence_of[1] = {
  { &hf_j2735_VehicleToLanePositionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleToLanePosition },
};

static int
dissect_j2735_VehicleToLanePositionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_VehicleToLanePositionList, VehicleToLanePositionList_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}



static int
dissect_j2735_Offset_B10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -512, 511U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_20b_sequence[] = {
  { &hf_j2735_x             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B10 },
  { &hf_j2735_y             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_XY_20b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_XY_20b, Node_XY_20b_sequence);

  return offset;
}



static int
dissect_j2735_Offset_B11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1024, 1023U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_22b_sequence[] = {
  { &hf_j2735_x_01          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B11 },
  { &hf_j2735_y_01          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_XY_22b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_XY_22b, Node_XY_22b_sequence);

  return offset;
}



static int
dissect_j2735_Offset_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_24b_sequence[] = {
  { &hf_j2735_x_02          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B12 },
  { &hf_j2735_y_02          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B12 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_XY_24b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_XY_24b, Node_XY_24b_sequence);

  return offset;
}



static int
dissect_j2735_Offset_B13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4096, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_26b_sequence[] = {
  { &hf_j2735_x_03          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B13 },
  { &hf_j2735_y_03          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B13 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_XY_26b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_XY_26b, Node_XY_26b_sequence);

  return offset;
}



static int
dissect_j2735_Offset_B14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8192, 8191U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_28b_sequence[] = {
  { &hf_j2735_x_04          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B14 },
  { &hf_j2735_y_04          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B14 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_XY_28b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_XY_28b, Node_XY_28b_sequence);

  return offset;
}



static int
dissect_j2735_Offset_B16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_XY_32b_sequence[] = {
  { &hf_j2735_x_05          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B16 },
  { &hf_j2735_y_05          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_XY_32b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_XY_32b, Node_XY_32b_sequence);

  return offset;
}



static int
dissect_j2735_Longitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1799999999, 1800000001U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Latitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -900000000, 900000001U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_LLmD_64b_sequence[] = {
  { &hf_j2735_lon_02        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Longitude },
  { &hf_j2735_lat_03        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Latitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LLmD_64b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LLmD_64b, Node_LLmD_64b_sequence);

  return offset;
}


static const value_string j2735_RegionId_vals[] = {
  {   0, "noRegion" },
  {   1, "addGrpA" },
  {   2, "addGrpB" },
  {   3, "addGrpC" },
  { 0, NULL }
};


static int
dissect_j2735_RegionId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_T_regExtValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t RegionalExtension_sequence[] = {
  { &hf_j2735_regionId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RegionId },
  { &hf_j2735_regExtValue   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_regExtValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RegionalExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RegionalExtension, RegionalExtension_sequence);

  return offset;
}


static const value_string j2735_NodeOffsetPointXY_vals[] = {
  {   0, "node-XY1" },
  {   1, "node-XY2" },
  {   2, "node-XY3" },
  {   3, "node-XY4" },
  {   4, "node-XY5" },
  {   5, "node-XY6" },
  {   6, "node-LatLon" },
  {   7, "regional" },
  { 0, NULL }
};

static const per_choice_t NodeOffsetPointXY_choice[] = {
  {   0, &hf_j2735_node_XY1      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_XY_20b },
  {   1, &hf_j2735_node_XY2      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_XY_22b },
  {   2, &hf_j2735_node_XY3      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_XY_24b },
  {   3, &hf_j2735_node_XY4      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_XY_26b },
  {   4, &hf_j2735_node_XY5      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_XY_28b },
  {   5, &hf_j2735_node_XY6      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_XY_32b },
  {   6, &hf_j2735_node_LatLon   , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LLmD_64b },
  {   7, &hf_j2735_regional_01   , ASN1_NO_EXTENSIONS     , dissect_j2735_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_NodeOffsetPointXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_NodeOffsetPointXY, NodeOffsetPointXY_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ConnectionManeuverAssist_addGrpC_sequence[] = {
  { &hf_j2735_vehicleToLanePositions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleToLanePositionList },
  { &hf_j2735_rsuDistanceFromAnchor, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_NodeOffsetPointXY },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ConnectionManeuverAssist_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ConnectionManeuverAssist_addGrpC, ConnectionManeuverAssist_addGrpC_sequence);

  return offset;
}


static const per_sequence_t IntersectionState_addGrpC_sequence[] = {
  { &hf_j2735_activePrioritizations, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PrioritizationResponseList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_IntersectionState_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_IntersectionState_addGrpC, IntersectionState_addGrpC_sequence);

  return offset;
}


static const per_sequence_t SignalHeadLocation_sequence[] = {
  { &hf_j2735_node          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_NodeOffsetPointXY },
  { &hf_j2735_signalGroupID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignalGroupID },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalHeadLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalHeadLocation, SignalHeadLocation_sequence);

  return offset;
}


static const per_sequence_t SignalHeadLocationList_sequence_of[1] = {
  { &hf_j2735_SignalHeadLocationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SignalHeadLocation },
};

static int
dissect_j2735_SignalHeadLocationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SignalHeadLocationList, SignalHeadLocationList_sequence_of,
                                                  1, 20, FALSE);

  return offset;
}


static const per_sequence_t MapData_addGrpC_sequence[] = {
  { &hf_j2735_signalHeadLocations, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SignalHeadLocationList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_MapData_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_MapData_addGrpC, MapData_addGrpC_sequence);

  return offset;
}


static const per_sequence_t Position3D_addGrpC_sequence[] = {
  { &hf_j2735_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Position3D_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Position3D_addGrpC, Position3D_addGrpC_sequence);

  return offset;
}


static const per_sequence_t RestrictionUserType_addGrpC_sequence[] = {
  { &hf_j2735_emission      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EmissionType },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RestrictionUserType_addGrpC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RestrictionUserType_addGrpC, RestrictionUserType_addGrpC_sequence);

  return offset;
}



static int
dissect_j2735_MsgCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TemporaryID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_DSecond(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Elevation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4096, 61439U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SemiMajorAxisAccuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SemiMinorAxisAccuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SemiMajorAxisOrientation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PositionalAccuracy_sequence[] = {
  { &hf_j2735_semiMajor     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SemiMajorAxisAccuracy },
  { &hf_j2735_semiMinor     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SemiMinorAxisAccuracy },
  { &hf_j2735_orientation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SemiMajorAxisOrientation },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PositionalAccuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PositionalAccuracy, PositionalAccuracy_sequence);

  return offset;
}


static const value_string j2735_TransmissionState_vals[] = {
  {   0, "neutral" },
  {   1, "park" },
  {   2, "forwardGears" },
  {   3, "reverseGears" },
  {   4, "reserved1" },
  {   5, "reserved2" },
  {   6, "reserved3" },
  {   7, "unavailable" },
  { 0, NULL }
};


static int
dissect_j2735_TransmissionState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_Speed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Heading(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 28800U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SteeringWheelAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -126, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Acceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2000, 2001U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VerticalAcceleration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_YawRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32767, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AccelerationSet4Way_sequence[] = {
  { &hf_j2735_long          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Acceleration },
  { &hf_j2735_lat_02        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Acceleration },
  { &hf_j2735_vert          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VerticalAcceleration },
  { &hf_j2735_yaw           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_YawRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_AccelerationSet4Way(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_AccelerationSet4Way, AccelerationSet4Way_sequence);

  return offset;
}


static int * const BrakeAppliedStatus_bits[] = {
  &hf_j2735_BrakeAppliedStatus_unavailable,
  &hf_j2735_BrakeAppliedStatus_leftFront,
  &hf_j2735_BrakeAppliedStatus_leftRear,
  &hf_j2735_BrakeAppliedStatus_rightFront,
  &hf_j2735_BrakeAppliedStatus_rightRear,
  NULL
};

static int
dissect_j2735_BrakeAppliedStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, FALSE, BrakeAppliedStatus_bits, 5, NULL, NULL);

  return offset;
}


static const value_string j2735_TractionControlStatus_vals[] = {
  {   0, "unavailable" },
  {   1, "off" },
  {   2, "on" },
  {   3, "engaged" },
  { 0, NULL }
};


static int
dissect_j2735_TractionControlStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_AntiLockBrakeStatus_vals[] = {
  {   0, "unavailable" },
  {   1, "off" },
  {   2, "on" },
  {   3, "engaged" },
  { 0, NULL }
};


static int
dissect_j2735_AntiLockBrakeStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_StabilityControlStatus_vals[] = {
  {   0, "unavailable" },
  {   1, "off" },
  {   2, "on" },
  {   3, "engaged" },
  { 0, NULL }
};


static int
dissect_j2735_StabilityControlStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_BrakeBoostApplied_vals[] = {
  {   0, "unavailable" },
  {   1, "off" },
  {   2, "on" },
  { 0, NULL }
};


static int
dissect_j2735_BrakeBoostApplied(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_AuxiliaryBrakeStatus_vals[] = {
  {   0, "unavailable" },
  {   1, "off" },
  {   2, "on" },
  {   3, "reserved" },
  { 0, NULL }
};


static int
dissect_j2735_AuxiliaryBrakeStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t BrakeSystemStatus_sequence[] = {
  { &hf_j2735_wheelBrakes   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_BrakeAppliedStatus },
  { &hf_j2735_traction      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TractionControlStatus },
  { &hf_j2735_abs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AntiLockBrakeStatus },
  { &hf_j2735_scs           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_StabilityControlStatus },
  { &hf_j2735_brakeBoost    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_BrakeBoostApplied },
  { &hf_j2735_auxBrakes     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AuxiliaryBrakeStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_BrakeSystemStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_BrakeSystemStatus, BrakeSystemStatus_sequence);

  return offset;
}



static int
dissect_j2735_VehicleWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VehicleLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleSize_sequence[] = {
  { &hf_j2735_width         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleWidth },
  { &hf_j2735_length        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleLength },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleSize, VehicleSize_sequence);

  return offset;
}


static const per_sequence_t BSMcoreData_sequence[] = {
  { &hf_j2735_msgCnt        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TemporaryID },
  { &hf_j2735_secMark       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DSecond },
  { &hf_j2735_lat_03        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Latitude },
  { &hf_j2735_long_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Longitude },
  { &hf_j2735_elev          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Elevation },
  { &hf_j2735_accuracy      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_PositionalAccuracy },
  { &hf_j2735_transmission  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TransmissionState },
  { &hf_j2735_speed         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Speed },
  { &hf_j2735_heading_02    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Heading },
  { &hf_j2735_angle         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SteeringWheelAngle },
  { &hf_j2735_accelSet      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AccelerationSet4Way },
  { &hf_j2735_brakes        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_BrakeSystemStatus },
  { &hf_j2735_size          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleSize },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_BSMcoreData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_BSMcoreData, BSMcoreData_sequence);

  return offset;
}


static const value_string j2735_PartII_Id_vals[] = {
  { vehicleSafetyExt, "vehicleSafetyExt" },
  { specialVehicleExt, "specialVehicleExt" },
  { supplementalVehicleExt, "supplementalVehicleExt" },
  { 0, NULL }
};


static int
dissect_j2735_PartII_Id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, &PartII_Id, FALSE);

  return offset;
}



static int
dissect_j2735_T_partII_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_j2735_partii_value);

  return offset;
}


static const per_sequence_t PartIIcontent_sequence[] = {
  { &hf_j2735_partII_Id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_PartII_Id },
  { &hf_j2735_partII_Value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_partII_Value },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PartIIcontent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PartIIcontent, PartIIcontent_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8_OF_PartIIcontent_sequence_of[1] = {
  { &hf_j2735_partII_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_PartIIcontent },
};

static int
dissect_j2735_SEQUENCE_SIZE_1_8_OF_PartIIcontent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SEQUENCE_SIZE_1_8_OF_PartIIcontent, SEQUENCE_SIZE_1_8_OF_PartIIcontent_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_4_OF_RegionalExtension_sequence_of[1] = {
  { &hf_j2735_regional_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RegionalExtension },
};

static int
dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension, SEQUENCE_SIZE_1_4_OF_RegionalExtension_sequence_of,
                                                  1, 4, FALSE);

  return offset;
}


static const per_sequence_t BasicSafetyMessage_sequence[] = {
  { &hf_j2735_coreData      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_BSMcoreData },
  { &hf_j2735_partII        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_8_OF_PartIIcontent },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_BasicSafetyMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_BasicSafetyMessage, BasicSafetyMessage_sequence);

  return offset;
}



static int
dissect_j2735_ITIScodes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string j2735_GenericLocations_vals[] = {
  { 7937, "on-bridges" },
  { 7938, "in-tunnels" },
  { 7939, "entering-or-leaving-tunnels" },
  { 7940, "on-ramps" },
  { 7941, "in-road-construction-area" },
  { 7942, "around-a-curve" },
  { 8026, "on-curve" },
  { 8009, "on-tracks" },
  { 8025, "in-street" },
  { 8027, "shoulder" },
  { 7943, "on-minor-roads" },
  { 7944, "in-the-opposing-lanes" },
  { 7945, "adjacent-to-roadway" },
  { 8024, "across-tracks" },
  { 7946, "on-bend" },
  { 8032, "intersection" },
  { 7947, "entire-intersection" },
  { 7948, "in-the-median" },
  { 7949, "moved-to-side-of-road" },
  { 7950, "moved-to-shoulder" },
  { 7951, "on-the-roadway" },
  { 8010, "dip" },
  { 8011, "traffic-circle" },
  { 8028, "crossover" },
  { 8029, "cross-road" },
  { 8030, "side-road" },
  { 8014, "to" },
  { 8015, "by" },
  { 8016, "through" },
  { 8017, "area-of" },
  { 8018, "under" },
  { 8019, "over" },
  { 8020, "from" },
  { 8021, "approaching" },
  { 8022, "entering-at" },
  { 8023, "exiting-at" },
  { 7952, "in-shaded-areas" },
  { 7953, "in-low-lying-areas" },
  { 7954, "in-the-downtown-area" },
  { 7955, "in-the-inner-city-area" },
  { 7956, "in-parts" },
  { 7957, "in-some-places" },
  { 7958, "in-the-ditch" },
  { 7959, "in-the-valley" },
  { 7960, "on-hill-top" },
  { 7961, "near-the-foothills" },
  { 7962, "at-high-altitudes" },
  { 7963, "near-the-lake" },
  { 7964, "near-the-shore" },
  { 8008, "nearby-basin" },
  { 7965, "over-the-crest-of-a-hill" },
  { 7966, "other-than-on-the-roadway" },
  { 7967, "near-the-beach" },
  { 7968, "near-beach-access-point" },
  { 8006, "mountain-pass" },
  { 7969, "lower-level" },
  { 7970, "upper-level" },
  { 7971, "airport" },
  { 7972, "concourse" },
  { 7973, "gate" },
  { 7974, "baggage-claim" },
  { 7975, "customs-point" },
  { 8007, "reservation-center" },
  { 7976, "station" },
  { 7977, "platform" },
  { 7978, "dock" },
  { 7979, "depot" },
  { 7980, "ev-charging-point" },
  { 7981, "information-welcome-point" },
  { 7982, "at-rest-area" },
  { 7983, "at-service-area" },
  { 7984, "at-weigh-station" },
  { 8033, "roadside-park" },
  { 7985, "picnic-areas" },
  { 7986, "rest-area" },
  { 7987, "service-stations" },
  { 7988, "toilets" },
  { 8031, "bus-stop" },
  { 8012, "park-and-ride-lot" },
  { 7989, "on-the-right" },
  { 7990, "on-the-left" },
  { 7991, "in-the-center" },
  { 7992, "in-the-opposite-direction" },
  { 7993, "cross-traffic" },
  { 7994, "northbound-traffic" },
  { 7995, "eastbound-traffic" },
  { 7996, "southbound-traffic" },
  { 7997, "westbound-traffic" },
  { 7998, "north" },
  { 7999, "south" },
  { 8000, "east" },
  { 8001, "west" },
  { 8002, "northeast" },
  { 8003, "northwest" },
  { 8004, "southeast" },
  { 8005, "southwest" },
  { 0, NULL }
};

static guint32 GenericLocations_value_map[96+0] = {7937, 7938, 7939, 7940, 7941, 7942, 8026, 8009, 8025, 8027, 7943, 7944, 7945, 8024, 7946, 8032, 7947, 7948, 7949, 7950, 7951, 8010, 8011, 8028, 8029, 8030, 8014, 8015, 8016, 8017, 8018, 8019, 8020, 8021, 8022, 8023, 7952, 7953, 7954, 7955, 7956, 7957, 7958, 7959, 7960, 7961, 7962, 7963, 7964, 8008, 7965, 7966, 7967, 7968, 8006, 7969, 7970, 7971, 7972, 7973, 7974, 7975, 8007, 7976, 7977, 7978, 7979, 7980, 7981, 7982, 7983, 7984, 8033, 7985, 7986, 7987, 7988, 8031, 8012, 7989, 7990, 7991, 7992, 7993, 7994, 7995, 7996, 7997, 7998, 7999, 8000, 8001, 8002, 8003, 8004, 8005};

static int
dissect_j2735_GenericLocations(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     96, NULL, TRUE, 0, GenericLocations_value_map);

  return offset;
}


static const per_sequence_t DisabledVehicle_sequence[] = {
  { &hf_j2735_statusDetails , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ITIScodes },
  { &hf_j2735_locationDetails, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_GenericLocations },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DisabledVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DisabledVehicle, DisabledVehicle_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_8_OF_ITIScodes_sequence_of[1] = {
  { &hf_j2735_description_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ITIScodes },
};

static int
dissect_j2735_SEQUENCE_SIZE_1_8_OF_ITIScodes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SEQUENCE_SIZE_1_8_OF_ITIScodes, SEQUENCE_SIZE_1_8_OF_ITIScodes_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}



static int
dissect_j2735_Priority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static int * const HeadingSlice_bits[] = {
  &hf_j2735_HeadingSlice_from000_0to022_5degrees,
  &hf_j2735_HeadingSlice_from022_5to045_0degrees,
  &hf_j2735_HeadingSlice_from045_0to067_5degrees,
  &hf_j2735_HeadingSlice_from067_5to090_0degrees,
  &hf_j2735_HeadingSlice_from090_0to112_5degrees,
  &hf_j2735_HeadingSlice_from112_5to135_0degrees,
  &hf_j2735_HeadingSlice_from135_0to157_5degrees,
  &hf_j2735_HeadingSlice_from157_5to180_0degrees,
  &hf_j2735_HeadingSlice_from180_0to202_5degrees,
  &hf_j2735_HeadingSlice_from202_5to225_0degrees,
  &hf_j2735_HeadingSlice_from225_0to247_5degrees,
  &hf_j2735_HeadingSlice_from247_5to270_0degrees,
  &hf_j2735_HeadingSlice_from270_0to292_5degrees,
  &hf_j2735_HeadingSlice_from292_5to315_0degrees,
  &hf_j2735_HeadingSlice_from315_0to337_5degrees,
  &hf_j2735_HeadingSlice_from337_5to360_0degrees,
  NULL
};

static int
dissect_j2735_HeadingSlice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, HeadingSlice_bits, 16, NULL, NULL);

  return offset;
}


static const value_string j2735_Extent_vals[] = {
  {   0, "useInstantlyOnly" },
  {   1, "useFor3meters" },
  {   2, "useFor10meters" },
  {   3, "useFor50meters" },
  {   4, "useFor100meters" },
  {   5, "useFor500meters" },
  {   6, "useFor1000meters" },
  {   7, "useFor5000meters" },
  {   8, "useFor10000meters" },
  {   9, "useFor50000meters" },
  {  10, "useFor100000meters" },
  {  11, "useFor500000meters" },
  {  12, "useFor1000000meters" },
  {  13, "useFor5000000meters" },
  {  14, "useFor10000000meters" },
  {  15, "forever" },
  { 0, NULL }
};


static int
dissect_j2735_Extent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t EventDescription_sequence[] = {
  { &hf_j2735_typeEvent     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ITIScodes },
  { &hf_j2735_description   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_8_OF_ITIScodes },
  { &hf_j2735_priority      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Priority },
  { &hf_j2735_heading       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_HeadingSlice },
  { &hf_j2735_extent        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Extent },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_EventDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_EventDescription, EventDescription_sequence);

  return offset;
}



static int
dissect_j2735_ObstacleDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Angle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 28800U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_ObstacleDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_j2735_Angle(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_j2735_DYear(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DMonth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 12U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DDay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DHour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DMinute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 60U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -840, 840U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DDateTime_sequence[] = {
  { &hf_j2735_year_01       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DYear },
  { &hf_j2735_month_01      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DMonth },
  { &hf_j2735_day_01        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DDay },
  { &hf_j2735_hour_01       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DHour },
  { &hf_j2735_minute_01     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DMinute },
  { &hf_j2735_second_01     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_offset        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DOffset },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DDateTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DDateTime, DDateTime_sequence);

  return offset;
}


static int * const VerticalAccelerationThreshold_bits[] = {
  &hf_j2735_VerticalAccelerationThreshold_notEquipped,
  &hf_j2735_VerticalAccelerationThreshold_leftFront,
  &hf_j2735_VerticalAccelerationThreshold_leftRear,
  &hf_j2735_VerticalAccelerationThreshold_rightFront,
  &hf_j2735_VerticalAccelerationThreshold_rightRear,
  NULL
};

static int
dissect_j2735_VerticalAccelerationThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, FALSE, VerticalAccelerationThreshold_bits, 5, NULL, NULL);

  return offset;
}


static const per_sequence_t ObstacleDetection_sequence[] = {
  { &hf_j2735_obDist        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ObstacleDistance },
  { &hf_j2735_obDirect      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ObstacleDirection },
  { &hf_j2735_description_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ITIScodes },
  { &hf_j2735_locationDetails, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_GenericLocations },
  { &hf_j2735_dateTime      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_DDateTime },
  { &hf_j2735_vertEvent     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VerticalAccelerationThreshold },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ObstacleDetection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ObstacleDetection, ObstacleDetection_sequence);

  return offset;
}



static int
dissect_j2735_PivotingAllowed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PivotPointDescription_sequence[] = {
  { &hf_j2735_pivotOffset   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B11 },
  { &hf_j2735_pivotAngle    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Angle },
  { &hf_j2735_pivots        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PivotingAllowed },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PivotPointDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PivotPointDescription, PivotPointDescription_sequence);

  return offset;
}


static int * const GNSSstatus_bits[] = {
  &hf_j2735_GNSSstatus_unavailable,
  &hf_j2735_GNSSstatus_isHealthy,
  &hf_j2735_GNSSstatus_isMonitored,
  &hf_j2735_GNSSstatus_baseStationType,
  &hf_j2735_GNSSstatus_aPDOPofUnder5,
  &hf_j2735_GNSSstatus_inViewOfUnder5,
  &hf_j2735_GNSSstatus_localCorrectionsPresent,
  &hf_j2735_GNSSstatus_networkCorrectionsPresent,
  NULL
};

static int
dissect_j2735_GNSSstatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, GNSSstatus_bits, 8, NULL, NULL);

  return offset;
}



static int
dissect_j2735_Offset_B09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -256, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AntennaOffsetSet_sequence[] = {
  { &hf_j2735_antOffsetX    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B12 },
  { &hf_j2735_antOffsetY    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B09 },
  { &hf_j2735_antOffsetZ    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Offset_B10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_AntennaOffsetSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_AntennaOffsetSet, AntennaOffsetSet_sequence);

  return offset;
}


static const per_sequence_t RTCMheader_sequence[] = {
  { &hf_j2735_status_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GNSSstatus },
  { &hf_j2735_offsetSet     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AntennaOffsetSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RTCMheader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RTCMheader, RTCMheader_sequence);

  return offset;
}



static int
dissect_j2735_RTCMmessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1023, FALSE, NULL);

  return offset;
}


static const per_sequence_t RTCMmessageList_sequence_of[1] = {
  { &hf_j2735_RTCMmessageList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RTCMmessage },
};

static int
dissect_j2735_RTCMmessageList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RTCMmessageList, RTCMmessageList_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t RTCMPackage_sequence[] = {
  { &hf_j2735_rtcmHeader    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RTCMheader },
  { &hf_j2735_msgs          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RTCMmessageList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RTCMPackage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RTCMPackage, RTCMPackage_sequence);

  return offset;
}



static int
dissect_j2735_SSPindex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}


static const value_string j2735_SirenInUse_vals[] = {
  {   0, "unavailable" },
  {   1, "notInUse" },
  {   2, "inUse" },
  {   3, "reserved" },
  { 0, NULL }
};


static int
dissect_j2735_SirenInUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_LightbarInUse_vals[] = {
  {   0, "unavailable" },
  {   1, "notInUse" },
  {   2, "inUse" },
  {   3, "yellowCautionLights" },
  {   4, "schooldBusLights" },
  {   5, "arrowSignsActive" },
  {   6, "slowMovingVehicle" },
  {   7, "freqStops" },
  { 0, NULL }
};


static int
dissect_j2735_LightbarInUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_MultiVehicleResponse_vals[] = {
  {   0, "unavailable" },
  {   1, "singleVehicle" },
  {   2, "multiVehicle" },
  {   3, "reserved" },
  { 0, NULL }
};


static int
dissect_j2735_MultiVehicleResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static int * const PrivilegedEventFlags_bits[] = {
  &hf_j2735_PrivilegedEventFlags_peUnavailable,
  &hf_j2735_PrivilegedEventFlags_peEmergencyResponse,
  &hf_j2735_PrivilegedEventFlags_peEmergencyLightsActive,
  &hf_j2735_PrivilegedEventFlags_peEmergencySoundActive,
  &hf_j2735_PrivilegedEventFlags_peNonEmergencyLightsActive,
  &hf_j2735_PrivilegedEventFlags_peNonEmergencySoundActive,
  NULL
};

static int
dissect_j2735_PrivilegedEventFlags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, PrivilegedEventFlags_bits, 6, NULL, NULL);

  return offset;
}


static const per_sequence_t PrivilegedEvents_sequence[] = {
  { &hf_j2735_notUsed       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_event         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PrivilegedEventFlags },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PrivilegedEvents(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PrivilegedEvents, PrivilegedEvents_sequence);

  return offset;
}


static const value_string j2735_ResponseType_vals[] = {
  {   0, "notInUseOrNotEquipped" },
  {   1, "emergency" },
  {   2, "nonEmergency" },
  {   3, "pursuit" },
  {   4, "stationary" },
  {   5, "slowMoving" },
  {   6, "stopAndGoMovement" },
  { 0, NULL }
};


static int
dissect_j2735_ResponseType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t EmergencyDetails_sequence[] = {
  { &hf_j2735_notUsed       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_sirenUse      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SirenInUse },
  { &hf_j2735_lightsUse     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LightbarInUse },
  { &hf_j2735_multi         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MultiVehicleResponse },
  { &hf_j2735_events        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PrivilegedEvents },
  { &hf_j2735_responseType  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ResponseType },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_EmergencyDetails(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_EmergencyDetails, EmergencyDetails_sequence);

  return offset;
}



static int
dissect_j2735_IsDolly(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_j2735_VehicleHeight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TrailerMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_BumperHeight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t BumperHeights_sequence[] = {
  { &hf_j2735_front         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_BumperHeight },
  { &hf_j2735_rear          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_BumperHeight },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_BumperHeights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_BumperHeights, BumperHeights_sequence);

  return offset;
}



static int
dissect_j2735_VertOffset_B07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TimeOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_CoarseHeading(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 240U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TrailerHistoryPoint_sequence[] = {
  { &hf_j2735_pivotAngle    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Angle },
  { &hf_j2735_timeOffset    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TimeOffset },
  { &hf_j2735_positionOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Node_XY_24b },
  { &hf_j2735_elevationOffset, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VertOffset_B07 },
  { &hf_j2735_heading_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_CoarseHeading },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TrailerHistoryPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TrailerHistoryPoint, TrailerHistoryPoint_sequence);

  return offset;
}


static const per_sequence_t TrailerHistoryPointList_sequence_of[1] = {
  { &hf_j2735_TrailerHistoryPointList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TrailerHistoryPoint },
};

static int
dissect_j2735_TrailerHistoryPointList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_TrailerHistoryPointList, TrailerHistoryPointList_sequence_of,
                                                  1, 23, FALSE);

  return offset;
}


static const per_sequence_t TrailerUnitDescription_sequence[] = {
  { &hf_j2735_isDolly       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IsDolly },
  { &hf_j2735_width         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleWidth },
  { &hf_j2735_length        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleLength },
  { &hf_j2735_height        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleHeight },
  { &hf_j2735_mass          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TrailerMass },
  { &hf_j2735_bumperHeights , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BumperHeights },
  { &hf_j2735_centerOfGravity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleHeight },
  { &hf_j2735_frontPivot    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PivotPointDescription },
  { &hf_j2735_rearPivot     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PivotPointDescription },
  { &hf_j2735_rearWheelOffset, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Offset_B12 },
  { &hf_j2735_positionOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Node_XY_24b },
  { &hf_j2735_elevationOffset, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VertOffset_B07 },
  { &hf_j2735_crumbData     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TrailerHistoryPointList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TrailerUnitDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TrailerUnitDescription, TrailerUnitDescription_sequence);

  return offset;
}


static const per_sequence_t TrailerUnitDescriptionList_sequence_of[1] = {
  { &hf_j2735_TrailerUnitDescriptionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TrailerUnitDescription },
};

static int
dissect_j2735_TrailerUnitDescriptionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_TrailerUnitDescriptionList, TrailerUnitDescriptionList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t TrailerData_sequence[] = {
  { &hf_j2735_notUsed       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_connection    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PivotPointDescription },
  { &hf_j2735_units         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TrailerUnitDescriptionList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TrailerData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TrailerData, TrailerData_sequence);

  return offset;
}


static const per_sequence_t SpecialVehicleExtensions_sequence[] = {
  { &hf_j2735_vehicleAlerts , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EmergencyDetails },
  { &hf_j2735_description_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EventDescription },
  { &hf_j2735_trailers      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TrailerData },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SpecialVehicleExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SpecialVehicleExtensions, SpecialVehicleExtensions_sequence);

  return offset;
}



static int
dissect_j2735_GrossSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SpeedProfileMeasurement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_j2735_GrossSpeed(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SpeedProfileMeasurementList_sequence_of[1] = {
  { &hf_j2735_SpeedProfileMeasurementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SpeedProfileMeasurement },
};

static int
dissect_j2735_SpeedProfileMeasurementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SpeedProfileMeasurementList, SpeedProfileMeasurementList_sequence_of,
                                                  1, 20, FALSE);

  return offset;
}


static const per_sequence_t SpeedProfile_sequence[] = {
  { &hf_j2735_speedReports  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SpeedProfileMeasurementList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SpeedProfile(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SpeedProfile, SpeedProfile_sequence);

  return offset;
}


static const value_string j2735_BasicVehicleClass_vals[] = {
  {   0, "unknownVehicleClass" },
  {   1, "specialVehicleClass" },
  {  10, "passenger-Vehicle-TypeUnknown" },
  {  11, "passenger-Vehicle-TypeOther" },
  {  20, "lightTruck-Vehicle-TypeUnknown" },
  {  21, "lightTruck-Vehicle-TypeOther" },
  {  25, "truck-Vehicle-TypeUnknown" },
  {  26, "truck-Vehicle-TypeOther" },
  {  27, "truck-axleCnt2" },
  {  28, "truck-axleCnt3" },
  {  29, "truck-axleCnt4" },
  {  30, "truck-axleCnt4Trailer" },
  {  31, "truck-axleCnt5Trailer" },
  {  32, "truck-axleCnt6Trailer" },
  {  33, "truck-axleCnt5MultiTrailer" },
  {  34, "truck-axleCnt6MultiTrailer" },
  {  35, "truck-axleCnt7MultiTrailer" },
  {  40, "motorcycle-TypeUnknown" },
  {  41, "motorcycle-TypeOther" },
  {  42, "motorcycle-Cruiser-Standard" },
  {  43, "motorcycle-SportUnclad" },
  {  44, "motorcycle-SportTouring" },
  {  45, "motorcycle-SuperSport" },
  {  46, "motorcycle-Touring" },
  {  47, "motorcycle-Trike" },
  {  48, "motorcycle-wPassengers" },
  {  50, "transit-TypeUnknown" },
  {  51, "transit-TypeOther" },
  {  52, "transit-BRT" },
  {  53, "transit-ExpressBus" },
  {  54, "transit-LocalBus" },
  {  55, "transit-SchoolBus" },
  {  56, "transit-FixedGuideway" },
  {  57, "transit-Paratransit" },
  {  58, "transit-Paratransit-Ambulance" },
  {  60, "emergency-TypeUnknown" },
  {  61, "emergency-TypeOther" },
  {  62, "emergency-Fire-Light-Vehicle" },
  {  63, "emergency-Fire-Heavy-Vehicle" },
  {  64, "emergency-Fire-Paramedic-Vehicle" },
  {  65, "emergency-Fire-Ambulance-Vehicle" },
  {  66, "emergency-Police-Light-Vehicle" },
  {  67, "emergency-Police-Heavy-Vehicle" },
  {  68, "emergency-Other-Responder" },
  {  69, "emergency-Other-Ambulance" },
  {  80, "otherTraveler-TypeUnknown" },
  {  81, "otherTraveler-TypeOther" },
  {  82, "otherTraveler-Pedestrian" },
  {  83, "otherTraveler-Visually-Disabled" },
  {  84, "otherTraveler-Physically-Disabled" },
  {  85, "otherTraveler-Bicycle" },
  {  86, "otherTraveler-Vulnerable-Roadworker" },
  {  90, "infrastructure-TypeUnknown" },
  {  91, "infrastructure-Fixed" },
  {  92, "infrastructure-Movable" },
  {  93, "equipped-CargoTrailer" },
  { 0, NULL }
};


static int
dissect_j2735_BasicVehicleClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string j2735_BasicVehicleRole_vals[] = {
  {   0, "basicVehicle" },
  {   1, "publicTransport" },
  {   2, "specialTransport" },
  {   3, "dangerousGoods" },
  {   4, "roadWork" },
  {   5, "roadRescue" },
  {   6, "emergency" },
  {   7, "safetyCar" },
  {   8, "none-unknown" },
  {   9, "truck" },
  {  10, "motorcycle" },
  {  11, "roadSideSource" },
  {  12, "police" },
  {  13, "fire" },
  {  14, "ambulance" },
  {  15, "dot" },
  {  16, "transit" },
  {  17, "slowMoving" },
  {  18, "stopNgo" },
  {  19, "cyclist" },
  {  20, "pedestrian" },
  {  21, "nonMotorized" },
  {  22, "military" },
  { 0, NULL }
};


static int
dissect_j2735_BasicVehicleRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     23, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_Iso3833VehicleType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const value_string j2735_VehicleType_vals[] = {
  {   0, "none" },
  {   1, "unknown" },
  {   2, "special" },
  {   3, "moto" },
  {   4, "car" },
  {   5, "carOther" },
  {   6, "bus" },
  {   7, "axleCnt2" },
  {   8, "axleCnt3" },
  {   9, "axleCnt4" },
  {  10, "axleCnt4Trailer" },
  {  11, "axleCnt5Trailer" },
  {  12, "axleCnt6Trailer" },
  {  13, "axleCnt5MultiTrailer" },
  {  14, "axleCnt6MultiTrailer" },
  {  15, "axleCnt7MultiTrailer" },
  { 0, NULL }
};


static int
dissect_j2735_VehicleType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_VehicleGroupAffected_vals[] = {
  { 9217, "all-vehicles" },
  { 9218, "bicycles" },
  { 9219, "motorcycles" },
  { 9220, "cars" },
  { 9221, "light-vehicles" },
  { 9222, "cars-and-light-vehicles" },
  { 9223, "cars-with-trailers" },
  { 9224, "cars-with-recreational-trailers" },
  { 9225, "vehicles-with-trailers" },
  { 9226, "heavy-vehicles" },
  { 9227, "trucks" },
  { 9228, "buses" },
  { 9229, "articulated-buses" },
  { 9230, "school-buses" },
  { 9231, "vehicles-with-semi-trailers" },
  { 9232, "vehicles-with-double-trailers" },
  { 9233, "high-profile-vehicles" },
  { 9234, "wide-vehicles" },
  { 9235, "long-vehicles" },
  { 9236, "hazardous-loads" },
  { 9237, "exceptional-loads" },
  { 9238, "abnormal-loads" },
  { 9239, "convoys" },
  { 9240, "maintenance-vehicles" },
  { 9241, "delivery-vehicles" },
  { 9242, "vehicles-with-even-numbered-license-plates" },
  { 9243, "vehicles-with-odd-numbered-license-plates" },
  { 9244, "vehicles-with-parking-permits" },
  { 9245, "vehicles-with-catalytic-converters" },
  { 9246, "vehicles-without-catalytic-converters" },
  { 9247, "gas-powered-vehicles" },
  { 9248, "diesel-powered-vehicles" },
  { 9249, "lPG-vehicles" },
  { 9250, "military-convoys" },
  { 9251, "military-vehicles" },
  { 0, NULL }
};

static guint32 VehicleGroupAffected_value_map[35+0] = {9217, 9218, 9219, 9220, 9221, 9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229, 9230, 9231, 9232, 9233, 9234, 9235, 9236, 9237, 9238, 9239, 9240, 9241, 9242, 9243, 9244, 9245, 9246, 9247, 9248, 9249, 9250, 9251};

static int
dissect_j2735_VehicleGroupAffected(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     35, NULL, TRUE, 0, VehicleGroupAffected_value_map);

  return offset;
}


static const value_string j2735_IncidentResponseEquipment_vals[] = {
  { 9985, "ground-fire-suppression" },
  { 9986, "heavy-ground-equipment" },
  { 9988, "aircraft" },
  { 9989, "marine-equipment" },
  { 9990, "support-equipment" },
  { 9991, "medical-rescue-unit" },
  { 9993, "other" },
  { 9994, "ground-fire-suppression-other" },
  { 9995, "engine" },
  { 9996, "truck-or-aerial" },
  { 9997, "quint" },
  { 9998, "tanker-pumper-combination" },
  { 10000, "brush-truck" },
  { 10001, "aircraft-rescue-firefighting" },
  { 10004, "heavy-ground-equipment-other" },
  { 10005, "dozer-or-plow" },
  { 10006, "tractor" },
  { 10008, "tanker-or-tender" },
  { 10024, "aircraft-other" },
  { 10025, "aircraft-fixed-wing-tanker" },
  { 10026, "helitanker" },
  { 10027, "helicopter" },
  { 10034, "marine-equipment-other" },
  { 10035, "fire-boat-with-pump" },
  { 10036, "boat-no-pump" },
  { 10044, "support-apparatus-other" },
  { 10045, "breathing-apparatus-support" },
  { 10046, "light-and-air-unit" },
  { 10054, "medical-rescue-unit-other" },
  { 10055, "rescue-unit" },
  { 10056, "urban-search-rescue-unit" },
  { 10057, "high-angle-rescue" },
  { 10058, "crash-fire-rescue" },
  { 10059, "bLS-unit" },
  { 10060, "aLS-unit" },
  { 10075, "mobile-command-post" },
  { 10076, "chief-officer-car" },
  { 10077, "hAZMAT-unit" },
  { 10078, "type-i-hand-crew" },
  { 10079, "type-ii-hand-crew" },
  { 10083, "privately-owned-vehicle" },
  { 10084, "other-apparatus-resource" },
  { 10085, "ambulance" },
  { 10086, "bomb-squad-van" },
  { 10087, "combine-harvester" },
  { 10088, "construction-vehicle" },
  { 10089, "farm-tractor" },
  { 10090, "grass-cutting-machines" },
  { 10091, "hAZMAT-containment-tow" },
  { 10092, "heavy-tow" },
  { 10094, "light-tow" },
  { 10114, "flatbed-tow" },
  { 10093, "hedge-cutting-machines" },
  { 10095, "mobile-crane" },
  { 10096, "refuse-collection-vehicle" },
  { 10097, "resurfacing-vehicle" },
  { 10098, "road-sweeper" },
  { 10099, "roadside-litter-collection-crews" },
  { 10100, "salvage-vehicle" },
  { 10101, "sand-truck" },
  { 10102, "snowplow" },
  { 10103, "steam-roller" },
  { 10104, "swat-team-van" },
  { 10105, "track-laying-vehicle" },
  { 10106, "unknown-vehicle" },
  { 10107, "white-lining-vehicle" },
  { 10108, "dump-truck" },
  { 10109, "supervisor-vehicle" },
  { 10110, "snow-blower" },
  { 10111, "rotary-snow-blower" },
  { 10112, "road-grader" },
  { 10113, "steam-truck" },
  { 0, NULL }
};

static guint32 IncidentResponseEquipment_value_map[72+0] = {9985, 9986, 9988, 9989, 9990, 9991, 9993, 9994, 9995, 9996, 9997, 9998, 10000, 10001, 10004, 10005, 10006, 10008, 10024, 10025, 10026, 10027, 10034, 10035, 10036, 10044, 10045, 10046, 10054, 10055, 10056, 10057, 10058, 10059, 10060, 10075, 10076, 10077, 10078, 10079, 10083, 10084, 10085, 10086, 10087, 10088, 10089, 10090, 10091, 10092, 10094, 10114, 10093, 10095, 10096, 10097, 10098, 10099, 10100, 10101, 10102, 10103, 10104, 10105, 10106, 10107, 10108, 10109, 10110, 10111, 10112, 10113};

static int
dissect_j2735_IncidentResponseEquipment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     72, NULL, TRUE, 0, IncidentResponseEquipment_value_map);

  return offset;
}


static const value_string j2735_ResponderGroupAffected_vals[] = {
  { 9729, "emergency-vehicle-units" },
  { 9730, "federal-law-enforcement-units" },
  { 9731, "state-police-units" },
  { 9732, "county-police-units" },
  { 9733, "local-police-units" },
  { 9734, "ambulance-units" },
  { 9735, "rescue-units" },
  { 9736, "fire-units" },
  { 9737, "hAZMAT-units" },
  { 9738, "light-tow-unit" },
  { 9739, "heavy-tow-unit" },
  { 9740, "freeway-service-patrols" },
  { 9741, "transportation-response-units" },
  { 9742, "private-contractor-response-units" },
  { 0, NULL }
};

static guint32 ResponderGroupAffected_value_map[14+0] = {9729, 9730, 9731, 9732, 9733, 9734, 9735, 9736, 9737, 9738, 9739, 9740, 9741, 9742};

static int
dissect_j2735_ResponderGroupAffected(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, TRUE, 0, ResponderGroupAffected_value_map);

  return offset;
}


static const value_string j2735_FuelType_vals[] = {
  {   0, "unknownFuel" },
  {   1, "gasoline" },
  {   2, "ethanol" },
  {   3, "diesel" },
  {   4, "electric" },
  {   5, "hybrid" },
  {   6, "hydrogen" },
  {   7, "natGasLiquid" },
  {   8, "natGasComp" },
  {   9, "propane" },
  { 0, NULL }
};


static int
dissect_j2735_FuelType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleClassification_sequence[] = {
  { &hf_j2735_keyType       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BasicVehicleClass },
  { &hf_j2735_role          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BasicVehicleRole },
  { &hf_j2735_iso3883       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Iso3833VehicleType },
  { &hf_j2735_hpmsType      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleType },
  { &hf_j2735_vehicleType   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleGroupAffected },
  { &hf_j2735_responseEquip , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IncidentResponseEquipment },
  { &hf_j2735_responderType , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ResponderGroupAffected },
  { &hf_j2735_fuelType      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_FuelType },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleClassification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleClassification, VehicleClassification_sequence);

  return offset;
}



static int
dissect_j2735_VehicleMass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TrailerWeight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 64255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t VehicleData_sequence[] = {
  { &hf_j2735_height        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleHeight },
  { &hf_j2735_bumpers       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BumperHeights },
  { &hf_j2735_mass_01       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleMass },
  { &hf_j2735_trailerWeight , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TrailerWeight },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleData, VehicleData_sequence);

  return offset;
}


static const value_string j2735_EssPrecipYesNo_vals[] = {
  {   1, "precip" },
  {   2, "noPrecip" },
  {   3, "error" },
  { 0, NULL }
};

static guint32 EssPrecipYesNo_value_map[3+0] = {1, 2, 3};

static int
dissect_j2735_EssPrecipYesNo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, EssPrecipYesNo_value_map);

  return offset;
}



static int
dissect_j2735_EssPrecipRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string j2735_EssPrecipSituation_vals[] = {
  {   1, "other" },
  {   2, "unknown" },
  {   3, "noPrecipitation" },
  {   4, "unidentifiedSlight" },
  {   5, "unidentifiedModerate" },
  {   6, "unidentifiedHeavy" },
  {   7, "snowSlight" },
  {   8, "snowModerate" },
  {   9, "snowHeavy" },
  {  10, "rainSlight" },
  {  11, "rainModerate" },
  {  12, "rainHeavy" },
  {  13, "frozenPrecipitationSlight" },
  {  14, "frozenPrecipitationModerate" },
  {  15, "frozenPrecipitationHeavy" },
  { 0, NULL }
};

static guint32 EssPrecipSituation_value_map[15+0] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static int
dissect_j2735_EssPrecipSituation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, FALSE, 0, EssPrecipSituation_value_map);

  return offset;
}



static int
dissect_j2735_EssSolarRadiation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_EssMobileFriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 101U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_CoefficientOfFriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 50U, NULL, FALSE);

  return offset;
}


static const per_sequence_t WeatherReport_sequence[] = {
  { &hf_j2735_isRaining     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_EssPrecipYesNo },
  { &hf_j2735_rainRate      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EssPrecipRate },
  { &hf_j2735_precipSituation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EssPrecipSituation },
  { &hf_j2735_solarRadiation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EssSolarRadiation },
  { &hf_j2735_friction      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EssMobileFriction },
  { &hf_j2735_roadFriction  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_CoefficientOfFriction },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_WeatherReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_WeatherReport, WeatherReport_sequence);

  return offset;
}



static int
dissect_j2735_AmbientAirTemperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 191U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_AmbientAirPressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string j2735_WiperStatus_vals[] = {
  {   0, "unavailable" },
  {   1, "off" },
  {   2, "intermittent" },
  {   3, "low" },
  {   4, "high" },
  {   5, "washerInUse" },
  {   6, "automaticPresent" },
  { 0, NULL }
};


static int
dissect_j2735_WiperStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_WiperRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t WiperSet_sequence[] = {
  { &hf_j2735_statusFront   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_WiperStatus },
  { &hf_j2735_rateFront     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_WiperRate },
  { &hf_j2735_statusRear    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_WiperStatus },
  { &hf_j2735_rateRear      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_WiperRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_WiperSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_WiperSet, WiperSet_sequence);

  return offset;
}


static const per_sequence_t WeatherProbe_sequence[] = {
  { &hf_j2735_airTemp       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AmbientAirTemperature },
  { &hf_j2735_airPressure   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AmbientAirPressure },
  { &hf_j2735_rainRates     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WiperSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_WeatherProbe(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_WeatherProbe, WeatherProbe_sequence);

  return offset;
}


static const per_sequence_t SupplementalVehicleExtensions_sequence[] = {
  { &hf_j2735_classification, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BasicVehicleClass },
  { &hf_j2735_classDetails  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleClassification },
  { &hf_j2735_vehicleData   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleData },
  { &hf_j2735_weatherReport , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WeatherReport },
  { &hf_j2735_weatherProbe  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WeatherProbe },
  { &hf_j2735_obstacle      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ObstacleDetection },
  { &hf_j2735_status        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DisabledVehicle },
  { &hf_j2735_speedProfile  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedProfile },
  { &hf_j2735_theRTCM       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RTCMPackage },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SupplementalVehicleExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SupplementalVehicleExtensions, SupplementalVehicleExtensions_sequence);

  return offset;
}



static int
dissect_j2735_DrivenLineOffsetSm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2047, 2047U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DrivenLineOffsetLg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32767, 32767U, NULL, FALSE);

  return offset;
}


static const value_string j2735_T_offsetXaxis_vals[] = {
  {   0, "small" },
  {   1, "large" },
  { 0, NULL }
};

static const per_choice_t T_offsetXaxis_choice[] = {
  {   0, &hf_j2735_small         , ASN1_NO_EXTENSIONS     , dissect_j2735_DrivenLineOffsetSm },
  {   1, &hf_j2735_large         , ASN1_NO_EXTENSIONS     , dissect_j2735_DrivenLineOffsetLg },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_offsetXaxis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_offsetXaxis, T_offsetXaxis_choice,
                                 NULL);

  return offset;
}


static const value_string j2735_T_offsetYaxis_vals[] = {
  {   0, "small" },
  {   1, "large" },
  { 0, NULL }
};

static const per_choice_t T_offsetYaxis_choice[] = {
  {   0, &hf_j2735_small         , ASN1_NO_EXTENSIONS     , dissect_j2735_DrivenLineOffsetSm },
  {   1, &hf_j2735_large         , ASN1_NO_EXTENSIONS     , dissect_j2735_DrivenLineOffsetLg },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_offsetYaxis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_offsetYaxis, T_offsetYaxis_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_Scale_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t ComputedLane_sequence[] = {
  { &hf_j2735_referenceLaneId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LaneID },
  { &hf_j2735_offsetXaxis   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_offsetXaxis },
  { &hf_j2735_offsetYaxis   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_offsetYaxis },
  { &hf_j2735_rotateXY      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Angle },
  { &hf_j2735_scaleXaxis    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Scale_B12 },
  { &hf_j2735_scaleYaxis    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Scale_B12 },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ComputedLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ComputedLane, ComputedLane_sequence);

  return offset;
}


static const per_sequence_t DDate_sequence[] = {
  { &hf_j2735_year_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DYear },
  { &hf_j2735_month_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DMonth },
  { &hf_j2735_day_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DDay },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DDate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DDate, DDate_sequence);

  return offset;
}


static const per_sequence_t DFullTime_sequence[] = {
  { &hf_j2735_year_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DYear },
  { &hf_j2735_month_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DMonth },
  { &hf_j2735_day_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DDay },
  { &hf_j2735_hour_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DHour },
  { &hf_j2735_minute_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DMinute },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DFullTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DFullTime, DFullTime_sequence);

  return offset;
}


static const per_sequence_t DMonthDay_sequence[] = {
  { &hf_j2735_month_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DMonth },
  { &hf_j2735_day_01        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DDay },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DMonthDay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DMonthDay, DMonthDay_sequence);

  return offset;
}


static const per_sequence_t DTime_sequence[] = {
  { &hf_j2735_hour_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DHour },
  { &hf_j2735_minute_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DMinute },
  { &hf_j2735_second_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DSecond },
  { &hf_j2735_offset        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DOffset },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DTime, DTime_sequence);

  return offset;
}


static const per_sequence_t DYearMonth_sequence[] = {
  { &hf_j2735_year_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DYear },
  { &hf_j2735_month_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DMonth },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DYearMonth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DYearMonth, DYearMonth_sequence);

  return offset;
}



static int
dissect_j2735_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TransmissionAndSpeed_sequence[] = {
  { &hf_j2735_transmisson   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TransmissionState },
  { &hf_j2735_speed_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TransmissionAndSpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TransmissionAndSpeed, TransmissionAndSpeed_sequence);

  return offset;
}


static const value_string j2735_TimeConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "time-100-000" },
  {   2, "time-050-000" },
  {   3, "time-020-000" },
  {   4, "time-010-000" },
  {   5, "time-002-000" },
  {   6, "time-001-000" },
  {   7, "time-000-500" },
  {   8, "time-000-200" },
  {   9, "time-000-100" },
  {  10, "time-000-050" },
  {  11, "time-000-020" },
  {  12, "time-000-010" },
  {  13, "time-000-005" },
  {  14, "time-000-002" },
  {  15, "time-000-001" },
  {  16, "time-000-000-5" },
  {  17, "time-000-000-2" },
  {  18, "time-000-000-1" },
  {  19, "time-000-000-05" },
  {  20, "time-000-000-02" },
  {  21, "time-000-000-01" },
  {  22, "time-000-000-005" },
  {  23, "time-000-000-002" },
  {  24, "time-000-000-001" },
  {  25, "time-000-000-000-5" },
  {  26, "time-000-000-000-2" },
  {  27, "time-000-000-000-1" },
  {  28, "time-000-000-000-05" },
  {  29, "time-000-000-000-02" },
  {  30, "time-000-000-000-01" },
  {  31, "time-000-000-000-005" },
  {  32, "time-000-000-000-002" },
  {  33, "time-000-000-000-001" },
  {  34, "time-000-000-000-000-5" },
  {  35, "time-000-000-000-000-2" },
  {  36, "time-000-000-000-000-1" },
  {  37, "time-000-000-000-000-05" },
  {  38, "time-000-000-000-000-02" },
  {  39, "time-000-000-000-000-01" },
  { 0, NULL }
};


static int
dissect_j2735_TimeConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     40, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_PositionConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "a500m" },
  {   2, "a200m" },
  {   3, "a100m" },
  {   4, "a50m" },
  {   5, "a20m" },
  {   6, "a10m" },
  {   7, "a5m" },
  {   8, "a2m" },
  {   9, "a1m" },
  {  10, "a50cm" },
  {  11, "a20cm" },
  {  12, "a10cm" },
  {  13, "a5cm" },
  {  14, "a2cm" },
  {  15, "a1cm" },
  { 0, NULL }
};


static int
dissect_j2735_PositionConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_ElevationConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "elev-500-00" },
  {   2, "elev-200-00" },
  {   3, "elev-100-00" },
  {   4, "elev-050-00" },
  {   5, "elev-020-00" },
  {   6, "elev-010-00" },
  {   7, "elev-005-00" },
  {   8, "elev-002-00" },
  {   9, "elev-001-00" },
  {  10, "elev-000-50" },
  {  11, "elev-000-20" },
  {  12, "elev-000-10" },
  {  13, "elev-000-05" },
  {  14, "elev-000-02" },
  {  15, "elev-000-01" },
  { 0, NULL }
};


static int
dissect_j2735_ElevationConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PositionConfidenceSet_sequence[] = {
  { &hf_j2735_pos           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_PositionConfidence },
  { &hf_j2735_elevation_02  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ElevationConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PositionConfidenceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PositionConfidenceSet, PositionConfidenceSet_sequence);

  return offset;
}


static const value_string j2735_HeadingConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "prec10deg" },
  {   2, "prec05deg" },
  {   3, "prec01deg" },
  {   4, "prec0-1deg" },
  {   5, "prec0-05deg" },
  {   6, "prec0-01deg" },
  {   7, "prec0-0125deg" },
  { 0, NULL }
};


static int
dissect_j2735_HeadingConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_SpeedConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "prec100ms" },
  {   2, "prec10ms" },
  {   3, "prec5ms" },
  {   4, "prec1ms" },
  {   5, "prec0-1ms" },
  {   6, "prec0-05ms" },
  {   7, "prec0-01ms" },
  { 0, NULL }
};


static int
dissect_j2735_SpeedConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_ThrottleConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "prec10percent" },
  {   2, "prec1percent" },
  {   3, "prec0-5percent" },
  { 0, NULL }
};


static int
dissect_j2735_ThrottleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SpeedandHeadingandThrottleConfidence_sequence[] = {
  { &hf_j2735_heading_03    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_HeadingConfidence },
  { &hf_j2735_speed_03      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SpeedConfidence },
  { &hf_j2735_throttle      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ThrottleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SpeedandHeadingandThrottleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SpeedandHeadingandThrottleConfidence, SpeedandHeadingandThrottleConfidence_sequence);

  return offset;
}


static const per_sequence_t FullPositionVector_sequence[] = {
  { &hf_j2735_utcTime       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DDateTime },
  { &hf_j2735_long_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Longitude },
  { &hf_j2735_lat_03        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Latitude },
  { &hf_j2735_elevation_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Elevation },
  { &hf_j2735_heading_02    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Heading },
  { &hf_j2735_speed_01      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TransmissionAndSpeed },
  { &hf_j2735_posAccuracy   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PositionalAccuracy },
  { &hf_j2735_timeConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeConfidence },
  { &hf_j2735_posConfidence , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PositionConfidenceSet },
  { &hf_j2735_speedConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedandHeadingandThrottleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_FullPositionVector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_FullPositionVector, FullPositionVector_sequence);

  return offset;
}



static int
dissect_j2735_MinuteOfTheYear(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 527040U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Header_sequence[] = {
  { &hf_j2735_year_01       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DYear },
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_secMark       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_msgIssueRevision, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MsgCount },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Header(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Header, Header_sequence);

  return offset;
}



static int
dissect_j2735_ApproachID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_LaneConnectionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string j2735_IntersectionAccessPoint_vals[] = {
  {   0, "lane" },
  {   1, "approach" },
  {   2, "connection" },
  { 0, NULL }
};

static const per_choice_t IntersectionAccessPoint_choice[] = {
  {   0, &hf_j2735_lane          , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneID },
  {   1, &hf_j2735_approach      , ASN1_EXTENSION_ROOT    , dissect_j2735_ApproachID },
  {   2, &hf_j2735_connection_01 , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneConnectionID },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_IntersectionAccessPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_IntersectionAccessPoint, IntersectionAccessPoint_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_RoadRegulatorID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_IntersectionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t IntersectionReferenceID_sequence[] = {
  { &hf_j2735_region        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_RoadRegulatorID },
  { &hf_j2735_id_01         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_IntersectionReferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_IntersectionReferenceID, IntersectionReferenceID_sequence);

  return offset;
}



static int
dissect_j2735_DeltaAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -150, 150U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_RoadwayCrownAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_MergeDivergeNodeAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -180, 180U, NULL, FALSE);

  return offset;
}


static const value_string j2735_SpeedLimitType_vals[] = {
  {   0, "unknown" },
  {   1, "maxSpeedInSchoolZone" },
  {   2, "maxSpeedInSchoolZoneWhenChildrenArePresent" },
  {   3, "maxSpeedInConstructionZone" },
  {   4, "vehicleMinSpeed" },
  {   5, "vehicleMaxSpeed" },
  {   6, "vehicleNightMaxSpeed" },
  {   7, "truckMinSpeed" },
  {   8, "truckMaxSpeed" },
  {   9, "truckNightMaxSpeed" },
  {  10, "vehiclesWithTrailersMinSpeed" },
  {  11, "vehiclesWithTrailersMaxSpeed" },
  {  12, "vehiclesWithTrailersNightMaxSpeed" },
  { 0, NULL }
};


static int
dissect_j2735_SpeedLimitType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RegulatorySpeedLimit_sequence[] = {
  { &hf_j2735_type          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SpeedLimitType },
  { &hf_j2735_speed_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RegulatorySpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RegulatorySpeedLimit, RegulatorySpeedLimit_sequence);

  return offset;
}


static const per_sequence_t SpeedLimitList_sequence_of[1] = {
  { &hf_j2735_SpeedLimitList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RegulatorySpeedLimit },
};

static int
dissect_j2735_SpeedLimitList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SpeedLimitList, SpeedLimitList_sequence_of,
                                                  1, 9, FALSE);

  return offset;
}


static const value_string j2735_LaneDataAttribute_vals[] = {
  {   0, "pathEndPointAngle" },
  {   1, "laneCrownPointCenter" },
  {   2, "laneCrownPointLeft" },
  {   3, "laneCrownPointRight" },
  {   4, "laneAngle" },
  {   5, "speedLimits" },
  {   6, "regional" },
  { 0, NULL }
};

static const per_choice_t LaneDataAttribute_choice[] = {
  {   0, &hf_j2735_pathEndPointAngle, ASN1_EXTENSION_ROOT    , dissect_j2735_DeltaAngle },
  {   1, &hf_j2735_laneCrownPointCenter, ASN1_EXTENSION_ROOT    , dissect_j2735_RoadwayCrownAngle },
  {   2, &hf_j2735_laneCrownPointLeft, ASN1_EXTENSION_ROOT    , dissect_j2735_RoadwayCrownAngle },
  {   3, &hf_j2735_laneCrownPointRight, ASN1_EXTENSION_ROOT    , dissect_j2735_RoadwayCrownAngle },
  {   4, &hf_j2735_laneAngle     , ASN1_EXTENSION_ROOT    , dissect_j2735_MergeDivergeNodeAngle },
  {   5, &hf_j2735_speedLimits   , ASN1_EXTENSION_ROOT    , dissect_j2735_SpeedLimitList },
  {   6, &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_LaneDataAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_LaneDataAttribute, LaneDataAttribute_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LaneDataAttributeList_sequence_of[1] = {
  { &hf_j2735_LaneDataAttributeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneDataAttribute },
};

static int
dissect_j2735_LaneDataAttributeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_LaneDataAttributeList, LaneDataAttributeList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const value_string j2735_NodeAttributeXY_vals[] = {
  {   0, "reserved" },
  {   1, "stopLine" },
  {   2, "roundedCapStyleA" },
  {   3, "roundedCapStyleB" },
  {   4, "mergePoint" },
  {   5, "divergePoint" },
  {   6, "downstreamStopLine" },
  {   7, "downstreamStartNode" },
  {   8, "closedToTraffic" },
  {   9, "safeIsland" },
  {  10, "curbPresentAtStepOff" },
  {  11, "hydrantPresent" },
  { 0, NULL }
};


static int
dissect_j2735_NodeAttributeXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NodeAttributeXYList_sequence_of[1] = {
  { &hf_j2735_NodeAttributeXYList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_NodeAttributeXY },
};

static int
dissect_j2735_NodeAttributeXYList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_NodeAttributeXYList, NodeAttributeXYList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const value_string j2735_SegmentAttributeXY_vals[] = {
  {   0, "reserved" },
  {   1, "doNotBlock" },
  {   2, "whiteLine" },
  {   3, "mergingLaneLeft" },
  {   4, "mergingLaneRight" },
  {   5, "curbOnLeft" },
  {   6, "curbOnRight" },
  {   7, "loadingzoneOnLeft" },
  {   8, "loadingzoneOnRight" },
  {   9, "turnOutPointOnLeft" },
  {  10, "turnOutPointOnRight" },
  {  11, "adjacentParkingOnLeft" },
  {  12, "adjacentParkingOnRight" },
  {  13, "adjacentBikeLaneOnLeft" },
  {  14, "adjacentBikeLaneOnRight" },
  {  15, "sharedBikeLane" },
  {  16, "bikeBoxInFront" },
  {  17, "transitStopOnLeft" },
  {  18, "transitStopOnRight" },
  {  19, "transitStopInLane" },
  {  20, "sharedWithTrackedVehicle" },
  {  21, "safeIsland" },
  {  22, "lowCurbsPresent" },
  {  23, "rumbleStripPresent" },
  {  24, "audibleSignalingPresent" },
  {  25, "adaptiveTimingPresent" },
  {  26, "rfSignalRequestPresent" },
  {  27, "partialCurbIntrusion" },
  {  28, "taperToLeft" },
  {  29, "taperToRight" },
  {  30, "taperToCenterLine" },
  {  31, "parallelParking" },
  {  32, "headInParking" },
  {  33, "freeParking" },
  {  34, "timeRestrictionsOnParking" },
  {  35, "costToPark" },
  {  36, "midBlockCurbPresent" },
  {  37, "unEvenPavementPresent" },
  { 0, NULL }
};


static int
dissect_j2735_SegmentAttributeXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     38, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SegmentAttributeXYList_sequence_of[1] = {
  { &hf_j2735_SegmentAttributeXYList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SegmentAttributeXY },
};

static int
dissect_j2735_SegmentAttributeXYList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SegmentAttributeXYList, SegmentAttributeXYList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t NodeAttributeSetXY_sequence[] = {
  { &hf_j2735_localNode     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NodeAttributeXYList },
  { &hf_j2735_disabled      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SegmentAttributeXYList },
  { &hf_j2735_enabled       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SegmentAttributeXYList },
  { &hf_j2735_data          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneDataAttributeList },
  { &hf_j2735_dWidth        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Offset_B10 },
  { &hf_j2735_dElevation    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Offset_B10 },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_NodeAttributeSetXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_NodeAttributeSetXY, NodeAttributeSetXY_sequence);

  return offset;
}


static const per_sequence_t NodeXY_sequence[] = {
  { &hf_j2735_delta         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_NodeOffsetPointXY },
  { &hf_j2735_attributes    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NodeAttributeSetXY },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_NodeXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_NodeXY, NodeXY_sequence);

  return offset;
}


static const per_sequence_t NodeSetXY_sequence_of[1] = {
  { &hf_j2735_NodeSetXY_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_NodeXY },
};

static int
dissect_j2735_NodeSetXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_NodeSetXY, NodeSetXY_sequence_of,
                                                  2, 63, FALSE);

  return offset;
}


static const value_string j2735_NodeListXY_vals[] = {
  {   0, "nodes" },
  {   1, "computed" },
  { 0, NULL }
};

static const per_choice_t NodeListXY_choice[] = {
  {   0, &hf_j2735_nodes         , ASN1_EXTENSION_ROOT    , dissect_j2735_NodeSetXY },
  {   1, &hf_j2735_computed      , ASN1_EXTENSION_ROOT    , dissect_j2735_ComputedLane },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_NodeListXY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_NodeListXY, NodeListXY_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_OffsetLL_B18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131072, 131071U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VertOffset_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PathHistoryPoint_sequence[] = {
  { &hf_j2735_latOffset     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B18 },
  { &hf_j2735_lonOffset     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B18 },
  { &hf_j2735_elevationOffset_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VertOffset_B12 },
  { &hf_j2735_timeOffset    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TimeOffset },
  { &hf_j2735_speed         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Speed },
  { &hf_j2735_posAccuracy   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PositionalAccuracy },
  { &hf_j2735_heading_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_CoarseHeading },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PathHistoryPoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PathHistoryPoint, PathHistoryPoint_sequence);

  return offset;
}


static const per_sequence_t PathHistoryPointList_sequence_of[1] = {
  { &hf_j2735_PathHistoryPointList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_PathHistoryPoint },
};

static int
dissect_j2735_PathHistoryPointList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_PathHistoryPointList, PathHistoryPointList_sequence_of,
                                                  1, 23, FALSE);

  return offset;
}


static const per_sequence_t PathHistory_sequence[] = {
  { &hf_j2735_initialPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_FullPositionVector },
  { &hf_j2735_currGNSSstatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_GNSSstatus },
  { &hf_j2735_crumbData_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PathHistoryPointList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PathHistory(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PathHistory, PathHistory_sequence);

  return offset;
}



static int
dissect_j2735_RadiusOfCurvature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32767, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_Confidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 200U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PathPrediction_sequence[] = {
  { &hf_j2735_radiusOfCurve , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RadiusOfCurvature },
  { &hf_j2735_confidence_02 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Confidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PathPrediction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PathPrediction, PathPrediction_sequence);

  return offset;
}


static const per_sequence_t Position3D_sequence[] = {
  { &hf_j2735_lat_03        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Latitude },
  { &hf_j2735_long_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Longitude },
  { &hf_j2735_elevation_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Elevation },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Position3D(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Position3D, Position3D_sequence);

  return offset;
}


static const value_string j2735_RequestSubRole_vals[] = {
  {   0, "requestSubRoleUnKnown" },
  {   1, "requestSubRole1" },
  {   2, "requestSubRole2" },
  {   3, "requestSubRole3" },
  {   4, "requestSubRole4" },
  {   5, "requestSubRole5" },
  {   6, "requestSubRole6" },
  {   7, "requestSubRole7" },
  {   8, "requestSubRole8" },
  {   9, "requestSubRole9" },
  {  10, "requestSubRole10" },
  {  11, "requestSubRole11" },
  {  12, "requestSubRole12" },
  {  13, "requestSubRole13" },
  {  14, "requestSubRole14" },
  {  15, "requestSubRoleReserved" },
  { 0, NULL }
};


static int
dissect_j2735_RequestSubRole(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_RequestImportanceLevel_vals[] = {
  {   0, "requestImportanceLevelUnKnown" },
  {   1, "requestImportanceLevel1" },
  {   2, "requestImportanceLevel2" },
  {   3, "requestImportanceLevel3" },
  {   4, "requestImportanceLevel4" },
  {   5, "requestImportanceLevel5" },
  {   6, "requestImportanceLevel6" },
  {   7, "requestImportanceLevel7" },
  {   8, "requestImportanceLevel8" },
  {   9, "requestImportanceLevel9" },
  {  10, "requestImportanceLevel10" },
  {  11, "requestImportanceLevel11" },
  {  12, "requestImportanceLevel12" },
  {  13, "requestImportanceLevel13" },
  {  14, "requestImportanceLevel14" },
  {  15, "requestImportanceReserved" },
  { 0, NULL }
};


static int
dissect_j2735_RequestImportanceLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RequestorType_sequence[] = {
  { &hf_j2735_role          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_BasicVehicleRole },
  { &hf_j2735_subrole       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RequestSubRole },
  { &hf_j2735_request       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RequestImportanceLevel },
  { &hf_j2735_iso3883       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Iso3833VehicleType },
  { &hf_j2735_hpmsType      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleType },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RequestorType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RequestorType, RequestorType_sequence);

  return offset;
}



static int
dissect_j2735_RoadSegmentID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RoadSegmentReferenceID_sequence[] = {
  { &hf_j2735_region        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_RoadRegulatorID },
  { &hf_j2735_id_02         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RoadSegmentID },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RoadSegmentReferenceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RoadSegmentReferenceID, RoadSegmentReferenceID_sequence);

  return offset;
}


static const value_string j2735_VehicleID_vals[] = {
  {   0, "entityID" },
  {   1, "stationID" },
  { 0, NULL }
};

static const per_choice_t VehicleID_choice[] = {
  {   0, &hf_j2735_entityID      , ASN1_NO_EXTENSIONS     , dissect_j2735_TemporaryID },
  {   1, &hf_j2735_stationID     , ASN1_NO_EXTENSIONS     , dissect_j2735_StationID },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_VehicleID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_VehicleID, VehicleID_choice,
                                 NULL);

  return offset;
}


static int * const VehicleEventFlags_bits[] = {
  &hf_j2735_VehicleEventFlags_eventHazardLights,
  &hf_j2735_VehicleEventFlags_eventStopLineViolation,
  &hf_j2735_VehicleEventFlags_eventABSactivated,
  &hf_j2735_VehicleEventFlags_eventTractionControlLoss,
  &hf_j2735_VehicleEventFlags_eventStabilityControlactivated,
  &hf_j2735_VehicleEventFlags_eventHazardousMaterials,
  &hf_j2735_VehicleEventFlags_eventReserved1,
  &hf_j2735_VehicleEventFlags_eventHardBraking,
  &hf_j2735_VehicleEventFlags_eventLightsChanged,
  &hf_j2735_VehicleEventFlags_eventWipersChanged,
  &hf_j2735_VehicleEventFlags_eventFlatTire,
  &hf_j2735_VehicleEventFlags_eventDisabledVehicle,
  &hf_j2735_VehicleEventFlags_eventAirBagDeployment,
  NULL
};

static int
dissect_j2735_VehicleEventFlags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     13, 13, TRUE, VehicleEventFlags_bits, 13, NULL, NULL);

  return offset;
}


static int * const ExteriorLights_bits[] = {
  &hf_j2735_ExteriorLights_lowBeamHeadlightsOn,
  &hf_j2735_ExteriorLights_highBeamHeadlightsOn,
  &hf_j2735_ExteriorLights_leftTurnSignalOn,
  &hf_j2735_ExteriorLights_rightTurnSignalOn,
  &hf_j2735_ExteriorLights_hazardSignalOn,
  &hf_j2735_ExteriorLights_automaticLightControlOn,
  &hf_j2735_ExteriorLights_daytimeRunningLightsOn,
  &hf_j2735_ExteriorLights_fogLightOn,
  &hf_j2735_ExteriorLights_parkingLightsOn,
  NULL
};

static int
dissect_j2735_ExteriorLights(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, TRUE, ExteriorLights_bits, 9, NULL, NULL);

  return offset;
}


static const per_sequence_t VehicleSafetyExtensions_sequence[] = {
  { &hf_j2735_events_01     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleEventFlags },
  { &hf_j2735_pathHistory   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PathHistory },
  { &hf_j2735_pathPrediction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PathPrediction },
  { &hf_j2735_lights        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ExteriorLights },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleSafetyExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleSafetyExtensions, VehicleSafetyExtensions_sequence);

  return offset;
}



static int
dissect_j2735_VertOffset_B08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VertOffset_B09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -256, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VertOffset_B10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -512, 511U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VertOffset_B11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1024, 1023U, NULL, FALSE);

  return offset;
}


static const value_string j2735_VerticalOffset_vals[] = {
  {   0, "offset1" },
  {   1, "offset2" },
  {   2, "offset3" },
  {   3, "offset4" },
  {   4, "offset5" },
  {   5, "offset6" },
  {   6, "elevation" },
  {   7, "regional" },
  { 0, NULL }
};

static const per_choice_t VerticalOffset_choice[] = {
  {   0, &hf_j2735_offset1       , ASN1_NO_EXTENSIONS     , dissect_j2735_VertOffset_B07 },
  {   1, &hf_j2735_offset2       , ASN1_NO_EXTENSIONS     , dissect_j2735_VertOffset_B08 },
  {   2, &hf_j2735_offset3       , ASN1_NO_EXTENSIONS     , dissect_j2735_VertOffset_B09 },
  {   3, &hf_j2735_offset4       , ASN1_NO_EXTENSIONS     , dissect_j2735_VertOffset_B10 },
  {   4, &hf_j2735_offset5       , ASN1_NO_EXTENSIONS     , dissect_j2735_VertOffset_B11 },
  {   5, &hf_j2735_offset6       , ASN1_NO_EXTENSIONS     , dissect_j2735_VertOffset_B12 },
  {   6, &hf_j2735_elevation_01  , ASN1_NO_EXTENSIONS     , dissect_j2735_Elevation },
  {   7, &hf_j2735_regional_01   , ASN1_NO_EXTENSIONS     , dissect_j2735_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_VerticalOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_VerticalOffset, VerticalOffset_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_CodeWord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 16, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_Count(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DescriptiveName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 63, FALSE,
                                          NULL);

  return offset;
}



static int
dissect_j2735_Duration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3600U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_FurtherInfoID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_LaneWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const value_string j2735_Location_quality_vals[] = {
  {   0, "loc-qual-bt1m" },
  {   1, "loc-qual-bt5m" },
  {   2, "loc-qual-bt12m" },
  {   3, "loc-qual-bt50m" },
  {   4, "loc-qual-bt125m" },
  {   5, "loc-qual-bt500m" },
  {   6, "loc-qual-bt1250m" },
  {   7, "loc-qual-unknown" },
  { 0, NULL }
};


static int
dissect_j2735_Location_quality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_Location_tech_vals[] = {
  {   0, "loc-tech-unknown" },
  {   1, "loc-tech-GNSS" },
  {   2, "loc-tech-DGPS" },
  {   3, "loc-tech-RTK" },
  {   4, "loc-tech-PPP" },
  {   5, "loc-tech-drGPS" },
  {   6, "loc-tech-drDGPS" },
  {   7, "loc-tech-dr" },
  {   8, "loc-tech-nav" },
  {   9, "loc-tech-fault" },
  { 0, NULL }
};


static int
dissect_j2735_Location_tech(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_MessageBLOB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       10, 2000, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_PayloadData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 2048, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_RequestID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_RestrictionClassID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SignalReqScheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static int * const TransitStatus_bits[] = {
  &hf_j2735_TransitStatus_none,
  &hf_j2735_TransitStatus_anADAuse,
  &hf_j2735_TransitStatus_aBikeLoad,
  &hf_j2735_TransitStatus_doorOpen,
  &hf_j2735_TransitStatus_occM,
  &hf_j2735_TransitStatus_occL,
  NULL
};

static int
dissect_j2735_TransitStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, TransitStatus_bits, 6, NULL, NULL);

  return offset;
}



static int
dissect_j2735_URL_Link(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 255, FALSE,
                                          NULL);

  return offset;
}


static const value_string j2735_RequestedItem_vals[] = {
  {   0, "reserved" },
  {   1, "itemA" },
  {   2, "itemB" },
  {   3, "itemC" },
  {   4, "itemD" },
  {   5, "itemE" },
  {   6, "itemF" },
  {   7, "itemG" },
  {   8, "itemI" },
  {   9, "itemJ" },
  {  10, "itemK" },
  {  11, "itemL" },
  {  12, "itemM" },
  {  13, "itemN" },
  {  14, "itemO" },
  {  15, "itemP" },
  {  16, "itemQ" },
  { 0, NULL }
};


static int
dissect_j2735_RequestedItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     17, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RequestedItemList_sequence_of[1] = {
  { &hf_j2735_RequestedItemList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RequestedItem },
};

static int
dissect_j2735_RequestedItemList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RequestedItemList, RequestedItemList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t CommonSafetyRequest_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_msgCnt        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MsgCount },
  { &hf_j2735_id            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TemporaryID },
  { &hf_j2735_requests      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RequestedItemList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_CommonSafetyRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_CommonSafetyRequest, CommonSafetyRequest_sequence);

  return offset;
}


static const per_sequence_t RoadSideAlert_sequence[] = {
  { &hf_j2735_msgCnt        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_typeEvent     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ITIScodes },
  { &hf_j2735_description   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_8_OF_ITIScodes },
  { &hf_j2735_priority      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Priority },
  { &hf_j2735_heading       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_HeadingSlice },
  { &hf_j2735_extent        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Extent },
  { &hf_j2735_position_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_FullPositionVector },
  { &hf_j2735_furtherInfoID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_FurtherInfoID },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RoadSideAlert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RoadSideAlert, RoadSideAlert_sequence);

  return offset;
}


static const per_sequence_t EmergencyVehicleAlert_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_id            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TemporaryID },
  { &hf_j2735_rsaMsg        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RoadSideAlert },
  { &hf_j2735_responseType  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ResponseType },
  { &hf_j2735_details       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EmergencyDetails },
  { &hf_j2735_mass_01       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleMass },
  { &hf_j2735_basicType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleType },
  { &hf_j2735_vehicleType   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleGroupAffected },
  { &hf_j2735_responseEquip , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IncidentResponseEquipment },
  { &hf_j2735_responderType , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ResponderGroupAffected },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_EmergencyVehicleAlert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_EmergencyVehicleAlert, EmergencyVehicleAlert_sequence);

  return offset;
}


static const value_string j2735_ApproachOrLane_vals[] = {
  {   0, "approach" },
  {   1, "lane" },
  { 0, NULL }
};

static const per_choice_t ApproachOrLane_choice[] = {
  {   0, &hf_j2735_approach      , ASN1_NO_EXTENSIONS     , dissect_j2735_ApproachID },
  {   1, &hf_j2735_lane          , ASN1_NO_EXTENSIONS     , dissect_j2735_LaneID },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_ApproachOrLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_ApproachOrLane, ApproachOrLane_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t IntersectionCollision_sequence[] = {
  { &hf_j2735_msgCnt        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_id            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TemporaryID },
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_partOne       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BSMcoreData },
  { &hf_j2735_path          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PathHistory },
  { &hf_j2735_pathPrediction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PathPrediction },
  { &hf_j2735_intersectionID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionReferenceID },
  { &hf_j2735_laneNumber    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_ApproachOrLane },
  { &hf_j2735_eventFlag     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleEventFlags },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_IntersectionCollision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_IntersectionCollision, IntersectionCollision_sequence);

  return offset;
}



static int
dissect_j2735_ITIStext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 500, FALSE,
                                          NULL);

  return offset;
}


static const value_string j2735_T_item_vals[] = {
  {   0, "itis" },
  {   1, "text" },
  { 0, NULL }
};

static const per_choice_t T_item_choice[] = {
  {   0, &hf_j2735_itis          , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIScodes },
  {   1, &hf_j2735_text          , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIStext },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_item, T_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ITIScodesAndText_item_sequence[] = {
  { &hf_j2735_item          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_item },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ITIScodesAndText_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ITIScodesAndText_item, ITIScodesAndText_item_sequence);

  return offset;
}


static const per_sequence_t ITIScodesAndText_sequence_of[1] = {
  { &hf_j2735_ITIScodesAndText_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ITIScodesAndText_item },
};

static int
dissect_j2735_ITIScodesAndText(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_ITIScodesAndText, ITIScodesAndText_sequence_of,
                                                  1, 100, FALSE);

  return offset;
}


static const value_string j2735_LayerType_vals[] = {
  {   0, "none" },
  {   1, "mixedContent" },
  {   2, "generalMapData" },
  {   3, "intersectionData" },
  {   4, "curveData" },
  {   5, "roadwaySectionData" },
  {   6, "parkingAreaData" },
  {   7, "sharedLaneData" },
  { 0, NULL }
};


static int
dissect_j2735_LayerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_LayerID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static int * const LaneDirection_bits[] = {
  &hf_j2735_LaneDirection_ingressPath,
  &hf_j2735_LaneDirection_egressPath,
  NULL
};

static int
dissect_j2735_LaneDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, LaneDirection_bits, 2, NULL, NULL);

  return offset;
}


static int * const LaneSharing_bits[] = {
  &hf_j2735_LaneSharing_overlappingLaneDescriptionProvided,
  &hf_j2735_LaneSharing_multipleLanesTreatedAsOneLane,
  &hf_j2735_LaneSharing_otherNonMotorizedTrafficTypes,
  &hf_j2735_LaneSharing_individualMotorizedVehicleTraffic,
  &hf_j2735_LaneSharing_busVehicleTraffic,
  &hf_j2735_LaneSharing_taxiVehicleTraffic,
  &hf_j2735_LaneSharing_pedestriansTraffic,
  &hf_j2735_LaneSharing_cyclistVehicleTraffic,
  &hf_j2735_LaneSharing_trackedVehicleTraffic,
  &hf_j2735_LaneSharing_reserved,
  NULL
};

static int
dissect_j2735_LaneSharing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, LaneSharing_bits, 10, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Vehicle_bits[] = {
  &hf_j2735_LaneAttributes_Vehicle_isVehicleRevocableLane,
  &hf_j2735_LaneAttributes_Vehicle_isVehicleFlyOverLane,
  &hf_j2735_LaneAttributes_Vehicle_hovLaneUseOnly,
  &hf_j2735_LaneAttributes_Vehicle_restrictedToBusUse,
  &hf_j2735_LaneAttributes_Vehicle_restrictedToTaxiUse,
  &hf_j2735_LaneAttributes_Vehicle_restrictedFromPublicUse,
  &hf_j2735_LaneAttributes_Vehicle_hasIRbeaconCoverage,
  &hf_j2735_LaneAttributes_Vehicle_permissionOnRequest,
  NULL
};

static int
dissect_j2735_LaneAttributes_Vehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, TRUE, LaneAttributes_Vehicle_bits, 8, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Crosswalk_bits[] = {
  &hf_j2735_LaneAttributes_Crosswalk_crosswalkRevocableLane,
  &hf_j2735_LaneAttributes_Crosswalk_bicyleUseAllowed,
  &hf_j2735_LaneAttributes_Crosswalk_isXwalkFlyOverLane,
  &hf_j2735_LaneAttributes_Crosswalk_fixedCycleTime,
  &hf_j2735_LaneAttributes_Crosswalk_biDirectionalCycleTimes,
  &hf_j2735_LaneAttributes_Crosswalk_hasPushToWalkButton,
  &hf_j2735_LaneAttributes_Crosswalk_audioSupport,
  &hf_j2735_LaneAttributes_Crosswalk_rfSignalRequestPresent,
  &hf_j2735_LaneAttributes_Crosswalk_unsignalizedSegmentsPresent,
  NULL
};

static int
dissect_j2735_LaneAttributes_Crosswalk(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_Crosswalk_bits, 9, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Bike_bits[] = {
  &hf_j2735_LaneAttributes_Bike_bikeRevocableLane,
  &hf_j2735_LaneAttributes_Bike_pedestrianUseAllowed,
  &hf_j2735_LaneAttributes_Bike_isBikeFlyOverLane,
  &hf_j2735_LaneAttributes_Bike_fixedCycleTime,
  &hf_j2735_LaneAttributes_Bike_biDirectionalCycleTimes,
  &hf_j2735_LaneAttributes_Bike_isolatedByBarrier,
  &hf_j2735_LaneAttributes_Bike_unsignalizedSegmentsPresent,
  NULL
};

static int
dissect_j2735_LaneAttributes_Bike(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_Bike_bits, 7, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Sidewalk_bits[] = {
  &hf_j2735_LaneAttributes_Sidewalk_sidewalk_RevocableLane,
  &hf_j2735_LaneAttributes_Sidewalk_bicyleUseAllowed,
  &hf_j2735_LaneAttributes_Sidewalk_isSidewalkFlyOverLane,
  &hf_j2735_LaneAttributes_Sidewalk_walkBikes,
  NULL
};

static int
dissect_j2735_LaneAttributes_Sidewalk(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_Sidewalk_bits, 4, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Barrier_bits[] = {
  &hf_j2735_LaneAttributes_Barrier_median_RevocableLane,
  &hf_j2735_LaneAttributes_Barrier_median,
  &hf_j2735_LaneAttributes_Barrier_whiteLineHashing,
  &hf_j2735_LaneAttributes_Barrier_stripedLines,
  &hf_j2735_LaneAttributes_Barrier_doubleStripedLines,
  &hf_j2735_LaneAttributes_Barrier_trafficCones,
  &hf_j2735_LaneAttributes_Barrier_constructionBarrier,
  &hf_j2735_LaneAttributes_Barrier_trafficChannels,
  &hf_j2735_LaneAttributes_Barrier_lowCurbs,
  &hf_j2735_LaneAttributes_Barrier_highCurbs,
  NULL
};

static int
dissect_j2735_LaneAttributes_Barrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_Barrier_bits, 10, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Striping_bits[] = {
  &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesRevocableLane,
  &hf_j2735_LaneAttributes_Striping_stripeDrawOnLeft,
  &hf_j2735_LaneAttributes_Striping_stripeDrawOnRight,
  &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesLeft,
  &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesRight,
  &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesAhead,
  NULL
};

static int
dissect_j2735_LaneAttributes_Striping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_Striping_bits, 6, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_TrackedVehicle_bits[] = {
  &hf_j2735_LaneAttributes_TrackedVehicle_spec_RevocableLane,
  &hf_j2735_LaneAttributes_TrackedVehicle_spec_commuterRailRoadTrack,
  &hf_j2735_LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack,
  &hf_j2735_LaneAttributes_TrackedVehicle_spec_heavyRailRoadTrack,
  &hf_j2735_LaneAttributes_TrackedVehicle_spec_otherRailType,
  NULL
};

static int
dissect_j2735_LaneAttributes_TrackedVehicle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_TrackedVehicle_bits, 5, NULL, NULL);

  return offset;
}


static int * const LaneAttributes_Parking_bits[] = {
  &hf_j2735_LaneAttributes_Parking_parkingRevocableLane,
  &hf_j2735_LaneAttributes_Parking_parallelParkingInUse,
  &hf_j2735_LaneAttributes_Parking_headInParkingInUse,
  &hf_j2735_LaneAttributes_Parking_doNotParkZone,
  &hf_j2735_LaneAttributes_Parking_parkingForBusUse,
  &hf_j2735_LaneAttributes_Parking_parkingForTaxiUse,
  &hf_j2735_LaneAttributes_Parking_noPublicParkingUse,
  NULL
};

static int
dissect_j2735_LaneAttributes_Parking(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, LaneAttributes_Parking_bits, 7, NULL, NULL);

  return offset;
}


static const value_string j2735_LaneTypeAttributes_vals[] = {
  {   0, "vehicle" },
  {   1, "crosswalk" },
  {   2, "bikeLane" },
  {   3, "sidewalk" },
  {   4, "median" },
  {   5, "striping" },
  {   6, "trackedVehicle" },
  {   7, "parking" },
  { 0, NULL }
};

static const per_choice_t LaneTypeAttributes_choice[] = {
  {   0, &hf_j2735_vehicle       , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Vehicle },
  {   1, &hf_j2735_crosswalk     , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Crosswalk },
  {   2, &hf_j2735_bikeLane      , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Bike },
  {   3, &hf_j2735_sidewalk      , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Sidewalk },
  {   4, &hf_j2735_median        , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Barrier },
  {   5, &hf_j2735_striping      , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Striping },
  {   6, &hf_j2735_trackedVehicle, ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_TrackedVehicle },
  {   7, &hf_j2735_parking       , ASN1_EXTENSION_ROOT    , dissect_j2735_LaneAttributes_Parking },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_LaneTypeAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_LaneTypeAttributes, LaneTypeAttributes_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LaneAttributes_sequence[] = {
  { &hf_j2735_directionalUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneDirection },
  { &hf_j2735_sharedWith    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneSharing },
  { &hf_j2735_laneType      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneTypeAttributes },
  { &hf_j2735_regional_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_LaneAttributes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_LaneAttributes, LaneAttributes_sequence);

  return offset;
}


static int * const AllowedManeuvers_bits[] = {
  &hf_j2735_AllowedManeuvers_maneuverStraightAllowed,
  &hf_j2735_AllowedManeuvers_maneuverLeftAllowed,
  &hf_j2735_AllowedManeuvers_maneuverRightAllowed,
  &hf_j2735_AllowedManeuvers_maneuverUTurnAllowed,
  &hf_j2735_AllowedManeuvers_maneuverLeftTurnOnRedAllowed,
  &hf_j2735_AllowedManeuvers_maneuverRightTurnOnRedAllowed,
  &hf_j2735_AllowedManeuvers_maneuverLaneChangeAllowed,
  &hf_j2735_AllowedManeuvers_maneuverNoStoppingAllowed,
  &hf_j2735_AllowedManeuvers_yieldAllwaysRequired,
  &hf_j2735_AllowedManeuvers_goWithHalt,
  &hf_j2735_AllowedManeuvers_caution,
  &hf_j2735_AllowedManeuvers_reserved1,
  NULL
};

static int
dissect_j2735_AllowedManeuvers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 12, FALSE, AllowedManeuvers_bits, 12, NULL, NULL);

  return offset;
}


static const per_sequence_t ConnectingLane_sequence[] = {
  { &hf_j2735_lane          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneID },
  { &hf_j2735_maneuver      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_AllowedManeuvers },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ConnectingLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ConnectingLane, ConnectingLane_sequence);

  return offset;
}


static const per_sequence_t Connection_sequence[] = {
  { &hf_j2735_connectingLane, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ConnectingLane },
  { &hf_j2735_remoteIntersection, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_IntersectionReferenceID },
  { &hf_j2735_signalGroup   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_SignalGroupID },
  { &hf_j2735_userClass     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_RestrictionClassID },
  { &hf_j2735_connectionID  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_LaneConnectionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Connection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Connection, Connection_sequence);

  return offset;
}


static const per_sequence_t ConnectsToList_sequence_of[1] = {
  { &hf_j2735_ConnectsToList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Connection },
};

static int
dissect_j2735_ConnectsToList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_ConnectsToList, ConnectsToList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t OverlayLaneList_sequence_of[1] = {
  { &hf_j2735_OverlayLaneList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneID },
};

static int
dissect_j2735_OverlayLaneList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_OverlayLaneList, OverlayLaneList_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t GenericLane_sequence[] = {
  { &hf_j2735_laneID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LaneID },
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_ingressApproach, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ApproachID },
  { &hf_j2735_egressApproach, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ApproachID },
  { &hf_j2735_laneAttributes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LaneAttributes },
  { &hf_j2735_maneuvers     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AllowedManeuvers },
  { &hf_j2735_nodeList      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_NodeListXY },
  { &hf_j2735_connectsTo    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ConnectsToList },
  { &hf_j2735_overlays      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_OverlayLaneList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_GenericLane(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_GenericLane, GenericLane_sequence);

  return offset;
}


static const per_sequence_t LaneList_sequence_of[1] = {
  { &hf_j2735_LaneList_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GenericLane },
};

static int
dissect_j2735_LaneList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_LaneList, LaneList_sequence_of,
                                                  1, 255, FALSE);

  return offset;
}


static const per_sequence_t SignalControlZone_sequence[] = {
  { &hf_j2735_zone          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalControlZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalControlZone, SignalControlZone_sequence);

  return offset;
}


static const per_sequence_t PreemptPriorityList_sequence_of[1] = {
  { &hf_j2735_PreemptPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SignalControlZone },
};

static int
dissect_j2735_PreemptPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_PreemptPriorityList, PreemptPriorityList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t IntersectionGeometry_sequence[] = {
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_id_03         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionReferenceID },
  { &hf_j2735_revision      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_refPoint      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Position3D },
  { &hf_j2735_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneWidth },
  { &hf_j2735_speedLimits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedLimitList },
  { &hf_j2735_laneSet       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LaneList },
  { &hf_j2735_preemptPriorityData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PreemptPriorityList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_IntersectionGeometry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_IntersectionGeometry, IntersectionGeometry_sequence);

  return offset;
}


static const per_sequence_t IntersectionGeometryList_sequence_of[1] = {
  { &hf_j2735_IntersectionGeometryList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionGeometry },
};

static int
dissect_j2735_IntersectionGeometryList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_IntersectionGeometryList, IntersectionGeometryList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t RoadLaneSetList_sequence_of[1] = {
  { &hf_j2735_RoadLaneSetList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GenericLane },
};

static int
dissect_j2735_RoadLaneSetList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RoadLaneSetList, RoadLaneSetList_sequence_of,
                                                  1, 255, FALSE);

  return offset;
}


static const per_sequence_t RoadSegment_sequence[] = {
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_id_05         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RoadSegmentReferenceID },
  { &hf_j2735_revision      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_refPoint      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Position3D },
  { &hf_j2735_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneWidth },
  { &hf_j2735_speedLimits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedLimitList },
  { &hf_j2735_roadLaneSet   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RoadLaneSetList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RoadSegment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RoadSegment, RoadSegment_sequence);

  return offset;
}


static const per_sequence_t RoadSegmentList_sequence_of[1] = {
  { &hf_j2735_RoadSegmentList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RoadSegment },
};

static int
dissect_j2735_RoadSegmentList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RoadSegmentList, RoadSegmentList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}



static int
dissect_j2735_IA5String_SIZE_1_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 255, FALSE,
                                          NULL);

  return offset;
}


static const per_sequence_t DataParameters_sequence[] = {
  { &hf_j2735_processMethod , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IA5String_SIZE_1_255 },
  { &hf_j2735_processAgency , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IA5String_SIZE_1_255 },
  { &hf_j2735_lastCheckedDate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IA5String_SIZE_1_255 },
  { &hf_j2735_geoidUsed     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IA5String_SIZE_1_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_DataParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_DataParameters, DataParameters_sequence);

  return offset;
}


static const value_string j2735_RestrictionAppliesTo_vals[] = {
  {   0, "none" },
  {   1, "equippedTransit" },
  {   2, "equippedTaxis" },
  {   3, "equippedOther" },
  {   4, "emissionCompliant" },
  {   5, "equippedBicycle" },
  {   6, "weightCompliant" },
  {   7, "heightCompliant" },
  {   8, "pedestrians" },
  {   9, "slowMovingPersons" },
  {  10, "wheelchairUsers" },
  {  11, "visualDisabilities" },
  {  12, "audioDisabilities" },
  {  13, "otherUnknownDisabilities" },
  { 0, NULL }
};


static int
dissect_j2735_RestrictionAppliesTo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_RestrictionUserType_vals[] = {
  {   0, "basicType" },
  {   1, "regional" },
  { 0, NULL }
};

static const per_choice_t RestrictionUserType_choice[] = {
  {   0, &hf_j2735_basicType_01  , ASN1_EXTENSION_ROOT    , dissect_j2735_RestrictionAppliesTo },
  {   1, &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_RestrictionUserType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_RestrictionUserType, RestrictionUserType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RestrictionUserTypeList_sequence_of[1] = {
  { &hf_j2735_RestrictionUserTypeList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RestrictionUserType },
};

static int
dissect_j2735_RestrictionUserTypeList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RestrictionUserTypeList, RestrictionUserTypeList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t RestrictionClassAssignment_sequence[] = {
  { &hf_j2735_id_04         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RestrictionClassID },
  { &hf_j2735_users         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RestrictionUserTypeList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RestrictionClassAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RestrictionClassAssignment, RestrictionClassAssignment_sequence);

  return offset;
}


static const per_sequence_t RestrictionClassList_sequence_of[1] = {
  { &hf_j2735_RestrictionClassList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RestrictionClassAssignment },
};

static int
dissect_j2735_RestrictionClassList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RestrictionClassList, RestrictionClassList_sequence_of,
                                                  1, 254, FALSE);

  return offset;
}


static const per_sequence_t MapData_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_msgIssueRevision, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_layerType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LayerType },
  { &hf_j2735_layerID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LayerID },
  { &hf_j2735_intersections , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IntersectionGeometryList },
  { &hf_j2735_roadSegments  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RoadSegmentList },
  { &hf_j2735_dataParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DataParameters },
  { &hf_j2735_restrictionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RestrictionClassList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_MapData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_MapData, MapData_sequence);

  return offset;
}


static const value_string j2735_DSRCmsgID_vals[] = {
  { reservedMessageId_D, "reservedMessageId-D" },
  { alaCarteMessage_D, "alaCarteMessage-D" },
  { basicSafetyMessage_D, "basicSafetyMessage-D" },
  { basicSafetyMessageVerbose_D, "basicSafetyMessageVerbose-D" },
  { commonSafetyRequest_D, "commonSafetyRequest-D" },
  { emergencyVehicleAlert_D, "emergencyVehicleAlert-D" },
  { intersectionCollision_D, "intersectionCollision-D" },
  { mapData_D, "mapData-D" },
  { nmeaCorrections_D, "nmeaCorrections-D" },
  { probeDataManagement_D, "probeDataManagement-D" },
  { probeVehicleData_D, "probeVehicleData-D" },
  { roadSideAlert_D, "roadSideAlert-D" },
  { rtcmCorrections_D, "rtcmCorrections-D" },
  { signalPhaseAndTimingMessage_D, "signalPhaseAndTimingMessage-D" },
  { signalRequestMessage_D, "signalRequestMessage-D" },
  { signalStatusMessage_D, "signalStatusMessage-D" },
  { travelerInformation_D, "travelerInformation-D" },
  { uperFrame_D, "uperFrame-D" },
  { mapData, "mapData" },
  { signalPhaseAndTimingMessage, "signalPhaseAndTimingMessage" },
  { basicSafetyMessage, "basicSafetyMessage" },
  { commonSafetyRequest, "commonSafetyRequest" },
  { emergencyVehicleAlert, "emergencyVehicleAlert" },
  { intersectionCollision, "intersectionCollision" },
  { nmeaCorrections, "nmeaCorrections" },
  { probeDataManagement, "probeDataManagement" },
  { probeVehicleData, "probeVehicleData" },
  { roadSideAlert, "roadSideAlert" },
  { rtcmCorrections, "rtcmCorrections" },
  { signalRequestMessage, "signalRequestMessage" },
  { signalStatusMessage, "signalStatusMessage" },
  { travelerInformation, "travelerInformation" },
  { personalSafetyMessage, "personalSafetyMessage" },
  { testMessage00, "testMessage00" },
  { testMessage01, "testMessage01" },
  { testMessage02, "testMessage02" },
  { testMessage03, "testMessage03" },
  { testMessage04, "testMessage04" },
  { testMessage05, "testMessage05" },
  { testMessage06, "testMessage06" },
  { testMessage07, "testMessage07" },
  { testMessage08, "testMessage08" },
  { testMessage09, "testMessage09" },
  { testMessage10, "testMessage10" },
  { testMessage11, "testMessage11" },
  { testMessage12, "testMessage12" },
  { testMessage13, "testMessage13" },
  { testMessage14, "testMessage14" },
  { testMessage15, "testMessage15" },
  { 0, NULL }
};


static int
dissect_j2735_DSRCmsgID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, &DSRCmsgID, FALSE);

  col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s",
    val_to_str_const(DSRCmsgID, j2735_DSRCmsgID_vals, "Unknown"));

  return offset;
}



static int
dissect_j2735_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_j2735_DSRCmsgID_msg);

  return offset;
}


static const per_sequence_t MessageFrame_sequence[] = {
  { &hf_j2735_messageId     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_DSRCmsgID },
  { &hf_j2735_value_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_MessageFrame(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_MessageFrame, MessageFrame_sequence);

  return offset;
}


static const value_string j2735_NMEA_Revision_vals[] = {
  {   0, "unknown" },
  {   1, "reserved" },
  {   2, "rev1" },
  {   3, "rev2" },
  {   4, "rev3" },
  {   5, "rev4" },
  {   6, "rev5" },
  { 0, NULL }
};


static int
dissect_j2735_NMEA_Revision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_NMEA_MsgType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_ObjectCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_NMEA_Payload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1023, FALSE, NULL);

  return offset;
}


static const per_sequence_t NMEAcorrections_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_rev           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NMEA_Revision },
  { &hf_j2735_msg           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NMEA_MsgType },
  { &hf_j2735_wdCount       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ObjectCount },
  { &hf_j2735_payload       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_NMEA_Payload },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_NMEAcorrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_NMEAcorrections, NMEAcorrections_sequence);

  return offset;
}


static const value_string j2735_PersonalDeviceUserType_vals[] = {
  {   0, "unavailable" },
  {   1, "aPEDESTRIAN" },
  {   2, "aPEDALCYCLIST" },
  {   3, "aPUBLICSAFETYWORKER" },
  {   4, "anANIMAL" },
  { 0, NULL }
};


static int
dissect_j2735_PersonalDeviceUserType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_HumanPropelledType_vals[] = {
  {   0, "unavailable" },
  {   1, "otherTypes" },
  {   2, "onFoot" },
  {   3, "skateboard" },
  {   4, "pushOrKickScooter" },
  {   5, "wheelchair" },
  { 0, NULL }
};


static int
dissect_j2735_HumanPropelledType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_AnimalPropelledType_vals[] = {
  {   0, "unavailable" },
  {   1, "otherTypes" },
  {   2, "animalMounted" },
  {   3, "animalDrawnCarriage" },
  { 0, NULL }
};


static int
dissect_j2735_AnimalPropelledType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_MotorizedPropelledType_vals[] = {
  {   0, "unavailable" },
  {   1, "otherTypes" },
  {   2, "wheelChair" },
  {   3, "bicycle" },
  {   4, "scooter" },
  {   5, "selfBalancingDevice" },
  { 0, NULL }
};


static int
dissect_j2735_MotorizedPropelledType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_PropelledInformation_vals[] = {
  {   0, "human" },
  {   1, "animal" },
  {   2, "motor" },
  { 0, NULL }
};

static const per_choice_t PropelledInformation_choice[] = {
  {   0, &hf_j2735_human         , ASN1_EXTENSION_ROOT    , dissect_j2735_HumanPropelledType },
  {   1, &hf_j2735_animal        , ASN1_EXTENSION_ROOT    , dissect_j2735_AnimalPropelledType },
  {   2, &hf_j2735_motor         , ASN1_EXTENSION_ROOT    , dissect_j2735_MotorizedPropelledType },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_PropelledInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_PropelledInformation, PropelledInformation_choice,
                                 NULL);

  return offset;
}


static int * const PersonalDeviceUsageState_bits[] = {
  &hf_j2735_PersonalDeviceUsageState_unavailable,
  &hf_j2735_PersonalDeviceUsageState_other,
  &hf_j2735_PersonalDeviceUsageState_idle,
  &hf_j2735_PersonalDeviceUsageState_listeningToAudio,
  &hf_j2735_PersonalDeviceUsageState_typing,
  &hf_j2735_PersonalDeviceUsageState_calling,
  &hf_j2735_PersonalDeviceUsageState_playingGames,
  &hf_j2735_PersonalDeviceUsageState_reading,
  &hf_j2735_PersonalDeviceUsageState_viewing,
  NULL
};

static int
dissect_j2735_PersonalDeviceUsageState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, TRUE, PersonalDeviceUsageState_bits, 9, NULL, NULL);

  return offset;
}



static int
dissect_j2735_PersonalCrossingRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_j2735_PersonalCrossingInProgress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string j2735_NumberOfParticipantsInCluster_vals[] = {
  {   0, "unavailable" },
  {   1, "small" },
  {   2, "medium" },
  {   3, "large" },
  { 0, NULL }
};


static int
dissect_j2735_NumberOfParticipantsInCluster(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_PersonalClusterRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const value_string j2735_PublicSafetyEventResponderWorkerType_vals[] = {
  {   0, "unavailable" },
  {   1, "towOperater" },
  {   2, "fireAndEMSWorker" },
  {   3, "aDOTWorker" },
  {   4, "lawEnforcement" },
  {   5, "hazmatResponder" },
  {   6, "animalControlWorker" },
  {   7, "otherPersonnel" },
  { 0, NULL }
};


static int
dissect_j2735_PublicSafetyEventResponderWorkerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static int * const PublicSafetyAndRoadWorkerActivity_bits[] = {
  &hf_j2735_PublicSafetyAndRoadWorkerActivity_unavailable,
  &hf_j2735_PublicSafetyAndRoadWorkerActivity_workingOnRoad,
  &hf_j2735_PublicSafetyAndRoadWorkerActivity_settingUpClosures,
  &hf_j2735_PublicSafetyAndRoadWorkerActivity_respondingToEvents,
  &hf_j2735_PublicSafetyAndRoadWorkerActivity_directingTraffic,
  &hf_j2735_PublicSafetyAndRoadWorkerActivity_otherActivities,
  NULL
};

static int
dissect_j2735_PublicSafetyAndRoadWorkerActivity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, TRUE, PublicSafetyAndRoadWorkerActivity_bits, 6, NULL, NULL);

  return offset;
}


static int * const PublicSafetyDirectingTrafficSubType_bits[] = {
  &hf_j2735_PublicSafetyDirectingTrafficSubType_unavailable,
  &hf_j2735_PublicSafetyDirectingTrafficSubType_policeAndTrafficOfficers,
  &hf_j2735_PublicSafetyDirectingTrafficSubType_trafficControlPersons,
  &hf_j2735_PublicSafetyDirectingTrafficSubType_railroadCrossingGuards,
  &hf_j2735_PublicSafetyDirectingTrafficSubType_civilDefenseNationalGuardMilitaryPolice,
  &hf_j2735_PublicSafetyDirectingTrafficSubType_emergencyOrganizationPersonnel,
  &hf_j2735_PublicSafetyDirectingTrafficSubType_highwayServiceVehiclePersonnel,
  NULL
};

static int
dissect_j2735_PublicSafetyDirectingTrafficSubType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, TRUE, PublicSafetyDirectingTrafficSubType_bits, 7, NULL, NULL);

  return offset;
}


static int * const PersonalAssistive_bits[] = {
  &hf_j2735_PersonalAssistive_unavailable,
  &hf_j2735_PersonalAssistive_otherType,
  &hf_j2735_PersonalAssistive_vision,
  &hf_j2735_PersonalAssistive_hearing,
  &hf_j2735_PersonalAssistive_movement,
  &hf_j2735_PersonalAssistive_cognition,
  NULL
};

static int
dissect_j2735_PersonalAssistive(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, TRUE, PersonalAssistive_bits, 6, NULL, NULL);

  return offset;
}


static int * const UserSizeAndBehaviour_bits[] = {
  &hf_j2735_UserSizeAndBehaviour_unavailable,
  &hf_j2735_UserSizeAndBehaviour_smallStature,
  &hf_j2735_UserSizeAndBehaviour_largeStature,
  &hf_j2735_UserSizeAndBehaviour_erraticMoving,
  &hf_j2735_UserSizeAndBehaviour_slowMoving,
  NULL
};

static int
dissect_j2735_UserSizeAndBehaviour(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, TRUE, UserSizeAndBehaviour_bits, 5, NULL, NULL);

  return offset;
}


static const value_string j2735_Attachment_vals[] = {
  {   0, "unavailable" },
  {   1, "stroller" },
  {   2, "bicycleTrailer" },
  {   3, "cart" },
  {   4, "wheelchair" },
  {   5, "otherWalkAssistAttachments" },
  {   6, "pet" },
  { 0, NULL }
};


static int
dissect_j2735_Attachment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_AttachmentRadius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 200U, NULL, FALSE);

  return offset;
}


static const value_string j2735_AnimalType_vals[] = {
  {   0, "unavailable" },
  {   1, "serviceUse" },
  {   2, "pet" },
  {   3, "farm" },
  { 0, NULL }
};


static int
dissect_j2735_AnimalType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t PersonalSafetyMessage_sequence[] = {
  { &hf_j2735_basicType_02  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PersonalDeviceUserType },
  { &hf_j2735_secMark       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_DSecond },
  { &hf_j2735_msgCnt        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_id            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TemporaryID },
  { &hf_j2735_position      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Position3D },
  { &hf_j2735_accuracy      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PositionalAccuracy },
  { &hf_j2735_speed_02      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Velocity },
  { &hf_j2735_heading_02    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Heading },
  { &hf_j2735_accelSet      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AccelerationSet4Way },
  { &hf_j2735_pathHistory   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PathHistory },
  { &hf_j2735_pathPrediction, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PathPrediction },
  { &hf_j2735_propulsion    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PropelledInformation },
  { &hf_j2735_useState      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PersonalDeviceUsageState },
  { &hf_j2735_crossRequest  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PersonalCrossingRequest },
  { &hf_j2735_crossState    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PersonalCrossingInProgress },
  { &hf_j2735_clusterSize   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NumberOfParticipantsInCluster },
  { &hf_j2735_clusterRadius , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PersonalClusterRadius },
  { &hf_j2735_eventResponderType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PublicSafetyEventResponderWorkerType },
  { &hf_j2735_activityType  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PublicSafetyAndRoadWorkerActivity },
  { &hf_j2735_activitySubType, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PublicSafetyDirectingTrafficSubType },
  { &hf_j2735_assistType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PersonalAssistive },
  { &hf_j2735_sizing        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_UserSizeAndBehaviour },
  { &hf_j2735_attachment    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Attachment },
  { &hf_j2735_attachmentRadius, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AttachmentRadius },
  { &hf_j2735_animalType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AnimalType },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_PersonalSafetyMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_PersonalSafetyMessage, PersonalSafetyMessage_sequence);

  return offset;
}



static int
dissect_j2735_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Sample_sequence[] = {
  { &hf_j2735_sampleStart   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_INTEGER_0_255 },
  { &hf_j2735_sampleEnd     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Sample(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Sample, Sample_sequence);

  return offset;
}



static int
dissect_j2735_TermTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1800U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TermDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 30000U, NULL, FALSE);

  return offset;
}


static const value_string j2735_T_term_vals[] = {
  {   0, "termtime" },
  {   1, "termDistance" },
  { 0, NULL }
};

static const per_choice_t T_term_choice[] = {
  {   0, &hf_j2735_termtime      , ASN1_NO_EXTENSIONS     , dissect_j2735_TermTime },
  {   1, &hf_j2735_termDistance  , ASN1_NO_EXTENSIONS     , dissect_j2735_TermDistance },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_term(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_term, T_term_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_SecondOfTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 61U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SnapshotTime_sequence[] = {
  { &hf_j2735_speed1        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GrossSpeed },
  { &hf_j2735_time1         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SecondOfTime },
  { &hf_j2735_speed2        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GrossSpeed },
  { &hf_j2735_time2         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SecondOfTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SnapshotTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SnapshotTime, SnapshotTime_sequence);

  return offset;
}



static int
dissect_j2735_GrossDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SnapshotDistance_sequence[] = {
  { &hf_j2735_distance1     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GrossDistance },
  { &hf_j2735_speed1        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GrossSpeed },
  { &hf_j2735_distance2     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GrossDistance },
  { &hf_j2735_speed2        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GrossSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SnapshotDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SnapshotDistance, SnapshotDistance_sequence);

  return offset;
}


static const value_string j2735_T_snapshot_vals[] = {
  {   0, "snapshotTime" },
  {   1, "snapshotDistance" },
  { 0, NULL }
};

static const per_choice_t T_snapshot_choice[] = {
  {   0, &hf_j2735_snapshotTime  , ASN1_NO_EXTENSIONS     , dissect_j2735_SnapshotTime },
  {   1, &hf_j2735_snapshotDistance, ASN1_NO_EXTENSIONS     , dissect_j2735_SnapshotDistance },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_snapshot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_snapshot, T_snapshot_choice,
                                 NULL);

  return offset;
}


static const value_string j2735_VehicleStatusDeviceTypeTag_vals[] = {
  {   0, "unknown" },
  {   1, "lights" },
  {   2, "wipers" },
  {   3, "brakes" },
  {   4, "stab" },
  {   5, "trac" },
  {   6, "abs" },
  {   7, "sunS" },
  {   8, "rainS" },
  {   9, "airTemp" },
  {  10, "steering" },
  {  11, "vertAccelThres" },
  {  12, "vertAccel" },
  {  13, "hozAccelLong" },
  {  14, "hozAccelLat" },
  {  15, "hozAccelCon" },
  {  16, "accel4way" },
  {  17, "confidenceSet" },
  {  18, "obDist" },
  {  19, "obDirect" },
  {  20, "yaw" },
  {  21, "yawRateCon" },
  {  22, "dateTime" },
  {  23, "fullPos" },
  {  24, "position2D" },
  {  25, "position3D" },
  {  26, "vehicle" },
  {  27, "speedHeadC" },
  {  28, "speedC" },
  { 0, NULL }
};


static int
dissect_j2735_VehicleStatusDeviceTypeTag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     29, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_INTEGER_1_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_INTEGER_M32767_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32767, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t VehicleStatusRequest_sequence[] = {
  { &hf_j2735_dataType      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleStatusDeviceTypeTag },
  { &hf_j2735_subType       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_INTEGER_1_15 },
  { &hf_j2735_sendOnLessThenValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_INTEGER_M32767_32767 },
  { &hf_j2735_sendOnMoreThenValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_INTEGER_M32767_32767 },
  { &hf_j2735_sendAll       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleStatusRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleStatusRequest, VehicleStatusRequest_sequence);

  return offset;
}


static const per_sequence_t VehicleStatusRequestList_sequence_of[1] = {
  { &hf_j2735_VehicleStatusRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleStatusRequest },
};

static int
dissect_j2735_VehicleStatusRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_VehicleStatusRequestList, VehicleStatusRequestList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t ProbeDataManagement_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_sample        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Sample },
  { &hf_j2735_directions    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_HeadingSlice },
  { &hf_j2735_term          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_term },
  { &hf_j2735_snapshot      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_snapshot },
  { &hf_j2735_txInterval    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SecondOfTime },
  { &hf_j2735_dataElements  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleStatusRequestList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ProbeDataManagement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ProbeDataManagement, ProbeDataManagement_sequence);

  return offset;
}



static int
dissect_j2735_ProbeSegmentNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_VINstring(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 17, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_IA5String_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 32, FALSE,
                                          NULL);

  return offset;
}


static const value_string j2735_T_vehicleClass_vals[] = {
  {   0, "vGroup" },
  {   1, "rGroup" },
  {   2, "rEquip" },
  { 0, NULL }
};

static const per_choice_t T_vehicleClass_choice[] = {
  {   0, &hf_j2735_vGroup        , ASN1_NO_EXTENSIONS     , dissect_j2735_VehicleGroupAffected },
  {   1, &hf_j2735_rGroup        , ASN1_NO_EXTENSIONS     , dissect_j2735_ResponderGroupAffected },
  {   2, &hf_j2735_rEquip        , ASN1_NO_EXTENSIONS     , dissect_j2735_IncidentResponseEquipment },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_vehicleClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_vehicleClass, T_vehicleClass_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t VehicleIdent_sequence[] = {
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_vin           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VINstring },
  { &hf_j2735_ownerCode     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IA5String_SIZE_1_32 },
  { &hf_j2735_id_06         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleID },
  { &hf_j2735_vehicleType_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleType },
  { &hf_j2735_vehicleClass  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_vehicleClass },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleIdent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleIdent, VehicleIdent_sequence);

  return offset;
}


static const value_string j2735_BrakeAppliedPressure_vals[] = {
  {   0, "unavailable" },
  {   1, "minPressure" },
  {   2, "bkLvl-2" },
  {   3, "bkLvl-3" },
  {   4, "bkLvl-4" },
  {   5, "bkLvl-5" },
  {   6, "bkLvl-6" },
  {   7, "bkLvl-7" },
  {   8, "bkLvl-8" },
  {   9, "bkLvl-9" },
  {  10, "bkLvl-10" },
  {  11, "bkLvl-11" },
  {  12, "bkLvl-12" },
  {  13, "bkLvl-13" },
  {  14, "bkLvl-14" },
  {  15, "maxPressure" },
  { 0, NULL }
};


static int
dissect_j2735_BrakeAppliedPressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_SunSensor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, FALSE);

  return offset;
}


static const value_string j2735_RainSensor_vals[] = {
  {   0, "none" },
  {   1, "lightMist" },
  {   2, "heavyMist" },
  {   3, "lightRainOrDrizzle" },
  {   4, "rain" },
  {   5, "moderateRain" },
  {   6, "heavyRain" },
  {   7, "heavyDownpour" },
  { 0, NULL }
};


static int
dissect_j2735_RainSensor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_SteeringWheelAngleConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "prec2deg" },
  {   2, "prec1deg" },
  {   3, "prec0-02deg" },
  { 0, NULL }
};


static int
dissect_j2735_SteeringWheelAngleConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_SteeringWheelAngleRateOfChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DrivingWheelAngle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_steering_sequence[] = {
  { &hf_j2735_angle         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SteeringWheelAngle },
  { &hf_j2735_confidence_03 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_SteeringWheelAngleConfidence },
  { &hf_j2735_rate          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_SteeringWheelAngleRateOfChange },
  { &hf_j2735_wheels        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_DrivingWheelAngle },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_T_steering(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_T_steering, T_steering_sequence);

  return offset;
}


static const value_string j2735_YawRateConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "degSec-100-00" },
  {   2, "degSec-010-00" },
  {   3, "degSec-005-00" },
  {   4, "degSec-001-00" },
  {   5, "degSec-000-10" },
  {   6, "degSec-000-05" },
  {   7, "degSec-000-01" },
  { 0, NULL }
};


static int
dissect_j2735_YawRateConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_AccelerationConfidence_vals[] = {
  {   0, "unavailable" },
  {   1, "accl-100-00" },
  {   2, "accl-010-00" },
  {   3, "accl-005-00" },
  {   4, "accl-001-00" },
  {   5, "accl-000-10" },
  {   6, "accl-000-05" },
  {   7, "accl-000-01" },
  { 0, NULL }
};


static int
dissect_j2735_AccelerationConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AccelSteerYawRateConfidence_sequence[] = {
  { &hf_j2735_yawRate       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_YawRateConfidence },
  { &hf_j2735_acceleration  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AccelerationConfidence },
  { &hf_j2735_steeringWheelAngle, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SteeringWheelAngleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_AccelSteerYawRateConfidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_AccelSteerYawRateConfidence, AccelSteerYawRateConfidence_sequence);

  return offset;
}


static const per_sequence_t ConfidenceSet_sequence[] = {
  { &hf_j2735_accelConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AccelSteerYawRateConfidence },
  { &hf_j2735_speedConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedandHeadingandThrottleConfidence },
  { &hf_j2735_timeConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeConfidence },
  { &hf_j2735_posConfidence , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PositionConfidenceSet },
  { &hf_j2735_steerConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SteeringWheelAngleConfidence },
  { &hf_j2735_headingConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_HeadingConfidence },
  { &hf_j2735_throttleConfidence, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ThrottleConfidence },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ConfidenceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ConfidenceSet, ConfidenceSet_sequence);

  return offset;
}


static const per_sequence_t T_accelSets_sequence[] = {
  { &hf_j2735_accel4way     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_AccelerationSet4Way },
  { &hf_j2735_vertAccelThres, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_VerticalAccelerationThreshold },
  { &hf_j2735_yawRateCon    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_YawRateConfidence },
  { &hf_j2735_hozAccelCon   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_AccelerationConfidence },
  { &hf_j2735_confidenceSet , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_ConfidenceSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_T_accelSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_T_accelSets, T_accelSets_sequence);

  return offset;
}


static const per_sequence_t T_object_sequence[] = {
  { &hf_j2735_obDist        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ObstacleDistance },
  { &hf_j2735_obDirect_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Angle },
  { &hf_j2735_dateTime      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DDateTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_T_object(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_T_object, T_object_sequence);

  return offset;
}



static int
dissect_j2735_ThrottlePosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 200U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_vehicleData_sequence[] = {
  { &hf_j2735_height        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleHeight },
  { &hf_j2735_bumpers       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_BumperHeights },
  { &hf_j2735_mass_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleMass },
  { &hf_j2735_trailerWeight , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TrailerWeight },
  { &hf_j2735_type_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleType },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_T_vehicleData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_T_vehicleData, T_vehicleData_sequence);

  return offset;
}



static int
dissect_j2735_TireLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TirePressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 250U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_TireTemp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8736, 55519U, NULL, FALSE);

  return offset;
}


static const value_string j2735_WheelSensorStatus_vals[] = {
  {   0, "off" },
  {   1, "on" },
  {   2, "notDefined" },
  {   3, "notSupported" },
  { 0, NULL }
};


static int
dissect_j2735_WheelSensorStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string j2735_WheelEndElectFault_vals[] = {
  {   0, "isOk" },
  {   1, "isNotDefined" },
  {   2, "isError" },
  {   3, "isNotSupported" },
  { 0, NULL }
};


static int
dissect_j2735_WheelEndElectFault(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_TireLeakageRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 64255U, NULL, FALSE);

  return offset;
}


static const value_string j2735_TirePressureThresholdDetection_vals[] = {
  {   0, "noData" },
  {   1, "overPressure" },
  {   2, "noWarningPressure" },
  {   3, "underPressure" },
  {   4, "extremeUnderPressure" },
  {   5, "undefined" },
  {   6, "errorIndicator" },
  {   7, "notAvailable" },
  { 0, NULL }
};


static int
dissect_j2735_TirePressureThresholdDetection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t TireData_sequence[] = {
  { &hf_j2735_location      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TireLocation },
  { &hf_j2735_pressure      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TirePressure },
  { &hf_j2735_temp          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TireTemp },
  { &hf_j2735_wheelSensorStatus, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WheelSensorStatus },
  { &hf_j2735_wheelEndElectFault, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WheelEndElectFault },
  { &hf_j2735_leakageRate   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TireLeakageRate },
  { &hf_j2735_detection     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TirePressureThresholdDetection },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TireData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TireData, TireData_sequence);

  return offset;
}


static const per_sequence_t TireDataList_sequence_of[1] = {
  { &hf_j2735_TireDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TireData },
};

static int
dissect_j2735_TireDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_TireDataList, TireDataList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_j2735_AxleLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_AxleWeight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 64255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AxleWeightSet_sequence[] = {
  { &hf_j2735_location_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AxleLocation },
  { &hf_j2735_weight        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AxleWeight },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_AxleWeightSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_AxleWeightSet, AxleWeightSet_sequence);

  return offset;
}


static const per_sequence_t AxleWeightList_sequence_of[1] = {
  { &hf_j2735_AxleWeightList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AxleWeightSet },
};

static int
dissect_j2735_AxleWeightList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_AxleWeightList, AxleWeightList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_j2735_CargoWeight(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 64255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SteeringAxleTemperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -40, 210U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DriveAxleLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DriveAxleLiftAirPressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1000U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DriveAxleTemperature(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -40, 210U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_DriveAxleLubePressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 250U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SteeringAxleLubePressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 250U, NULL, FALSE);

  return offset;
}


static const per_sequence_t J1939data_sequence[] = {
  { &hf_j2735_tires         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TireDataList },
  { &hf_j2735_axles         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AxleWeightList },
  { &hf_j2735_trailerWeight , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TrailerWeight },
  { &hf_j2735_cargoWeight   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_CargoWeight },
  { &hf_j2735_steeringAxleTemperature, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SteeringAxleTemperature },
  { &hf_j2735_driveAxleLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DriveAxleLocation },
  { &hf_j2735_driveAxleLiftAirPressure, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DriveAxleLiftAirPressure },
  { &hf_j2735_driveAxleTemperature, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DriveAxleTemperature },
  { &hf_j2735_driveAxleLubePressure, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DriveAxleLubePressure },
  { &hf_j2735_steeringAxleLubePressure, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SteeringAxleLubePressure },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_J1939data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_J1939data, J1939data_sequence);

  return offset;
}


static const per_sequence_t T_weatherReport_sequence[] = {
  { &hf_j2735_isRaining     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_EssPrecipYesNo },
  { &hf_j2735_rainRate      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_EssPrecipRate },
  { &hf_j2735_precipSituation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_EssPrecipSituation },
  { &hf_j2735_solarRadiation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_EssSolarRadiation },
  { &hf_j2735_friction      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_EssMobileFriction },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_T_weatherReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_T_weatherReport, T_weatherReport_sequence);

  return offset;
}


static const per_sequence_t VehicleStatus_sequence[] = {
  { &hf_j2735_lights        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ExteriorLights },
  { &hf_j2735_lightBar      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LightbarInUse },
  { &hf_j2735_wipers        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WiperSet },
  { &hf_j2735_brakeStatus   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BrakeSystemStatus },
  { &hf_j2735_brakePressure , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BrakeAppliedPressure },
  { &hf_j2735_roadFriction  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_CoefficientOfFriction },
  { &hf_j2735_sunData       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SunSensor },
  { &hf_j2735_rainData      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RainSensor },
  { &hf_j2735_airTemp       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AmbientAirTemperature },
  { &hf_j2735_airPres       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AmbientAirPressure },
  { &hf_j2735_steering      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_steering },
  { &hf_j2735_accelSets     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_accelSets },
  { &hf_j2735_object        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_object },
  { &hf_j2735_fullPos       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_FullPositionVector },
  { &hf_j2735_throttlePos   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ThrottlePosition },
  { &hf_j2735_speedHeadC    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedandHeadingandThrottleConfidence },
  { &hf_j2735_speedC        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedConfidence },
  { &hf_j2735_vehicleData_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_vehicleData },
  { &hf_j2735_vehicleIdent  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleIdent },
  { &hf_j2735_j1939data     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_J1939data },
  { &hf_j2735_weatherReport_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_weatherReport },
  { &hf_j2735_gnssStatus    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_GNSSstatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_VehicleStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_VehicleStatus, VehicleStatus_sequence);

  return offset;
}


static const per_sequence_t Snapshot_sequence[] = {
  { &hf_j2735_thePosition   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_FullPositionVector },
  { &hf_j2735_safetyExt     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleSafetyExtensions },
  { &hf_j2735_dataSet       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Snapshot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Snapshot, Snapshot_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_32_OF_Snapshot_sequence_of[1] = {
  { &hf_j2735_snapshots_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Snapshot },
};

static int
dissect_j2735_SEQUENCE_SIZE_1_32_OF_Snapshot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SEQUENCE_SIZE_1_32_OF_Snapshot, SEQUENCE_SIZE_1_32_OF_Snapshot_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t ProbeVehicleData_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_segNum        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ProbeSegmentNumber },
  { &hf_j2735_probeID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_VehicleIdent },
  { &hf_j2735_startVector   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_FullPositionVector },
  { &hf_j2735_vehicleType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleClassification },
  { &hf_j2735_snapshots     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SEQUENCE_SIZE_1_32_OF_Snapshot },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ProbeVehicleData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ProbeVehicleData, ProbeVehicleData_sequence);

  return offset;
}


static const value_string j2735_RTCM_Revision_vals[] = {
  {   0, "unknown" },
  {   1, "rtcmRev2" },
  {   2, "rtcmRev3" },
  {   3, "reserved" },
  { 0, NULL }
};


static int
dissect_j2735_RTCM_Revision(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t RTCMcorrections_sequence[] = {
  { &hf_j2735_msgCnt        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_rev_01        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RTCM_Revision },
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_anchorPoint   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_FullPositionVector },
  { &hf_j2735_rtcmHeader    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RTCMheader },
  { &hf_j2735_msgs          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RTCMmessageList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RTCMcorrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RTCMcorrections, RTCMcorrections_sequence);

  return offset;
}


static const value_string j2735_PriorityRequestType_vals[] = {
  {   0, "priorityRequestTypeReserved" },
  {   1, "priorityRequest" },
  {   2, "priorityRequestUpdate" },
  {   3, "priorityCancellation" },
  { 0, NULL }
};


static int
dissect_j2735_PriorityRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SignalRequest_sequence[] = {
  { &hf_j2735_id_03         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionReferenceID },
  { &hf_j2735_requestID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RequestID },
  { &hf_j2735_requestType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PriorityRequestType },
  { &hf_j2735_inBoundLane   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionAccessPoint },
  { &hf_j2735_outBoundLane  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IntersectionAccessPoint },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalRequest, SignalRequest_sequence);

  return offset;
}


static const per_sequence_t SignalRequestPackage_sequence[] = {
  { &hf_j2735_request_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignalRequest },
  { &hf_j2735_minute_02     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_second_01     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_duration      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalRequestPackage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalRequestPackage, SignalRequestPackage_sequence);

  return offset;
}


static const per_sequence_t SignalRequestList_sequence_of[1] = {
  { &hf_j2735_SignalRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SignalRequestPackage },
};

static int
dissect_j2735_SignalRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SignalRequestList, SignalRequestList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t RequestorPositionVector_sequence[] = {
  { &hf_j2735_position      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Position3D },
  { &hf_j2735_heading_04    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Angle },
  { &hf_j2735_speed_01      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TransmissionAndSpeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RequestorPositionVector(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RequestorPositionVector, RequestorPositionVector_sequence);

  return offset;
}


static int * const TransitVehicleStatus_bits[] = {
  &hf_j2735_TransitVehicleStatus_loading,
  &hf_j2735_TransitVehicleStatus_anADAuse,
  &hf_j2735_TransitVehicleStatus_aBikeLoad,
  &hf_j2735_TransitVehicleStatus_doorOpen,
  &hf_j2735_TransitVehicleStatus_charging,
  &hf_j2735_TransitVehicleStatus_atStopLine,
  NULL
};

static int
dissect_j2735_TransitVehicleStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, TransitVehicleStatus_bits, 6, NULL, NULL);

  return offset;
}


static const value_string j2735_TransitVehicleOccupancy_vals[] = {
  {   0, "occupancyUnknown" },
  {   1, "occupancyEmpty" },
  {   2, "occupancyVeryLow" },
  {   3, "occupancyLow" },
  {   4, "occupancyMed" },
  {   5, "occupancyHigh" },
  {   6, "occupancyNearlyFull" },
  {   7, "occupancyFull" },
  { 0, NULL }
};


static int
dissect_j2735_TransitVehicleOccupancy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_DeltaTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -122, 121U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RequestorDescription_sequence[] = {
  { &hf_j2735_id_06         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleID },
  { &hf_j2735_type_02       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RequestorType },
  { &hf_j2735_position_02   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RequestorPositionVector },
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_routeName     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_transitStatus , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TransitVehicleStatus },
  { &hf_j2735_transitOccupancy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TransitVehicleOccupancy },
  { &hf_j2735_transitSchedule, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DeltaTime },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RequestorDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RequestorDescription, RequestorDescription_sequence);

  return offset;
}


static const per_sequence_t SignalRequestMessage_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_second_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_DSecond },
  { &hf_j2735_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MsgCount },
  { &hf_j2735_requests_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SignalRequestList },
  { &hf_j2735_requestor     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RequestorDescription },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalRequestMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalRequestMessage, SignalRequestMessage_sequence);

  return offset;
}


static const per_sequence_t SignalRequesterInfo_sequence[] = {
  { &hf_j2735_id_06         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_VehicleID },
  { &hf_j2735_request_02    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RequestID },
  { &hf_j2735_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_role          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BasicVehicleRole },
  { &hf_j2735_typeData      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RequestorType },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalRequesterInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalRequesterInfo, SignalRequesterInfo_sequence);

  return offset;
}


static const per_sequence_t SignalStatusPackage_sequence[] = {
  { &hf_j2735_requester     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SignalRequesterInfo },
  { &hf_j2735_inboundOn     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionAccessPoint },
  { &hf_j2735_outboundOn    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_IntersectionAccessPoint },
  { &hf_j2735_minute_02     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_second_01     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_duration      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_status_03     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_PrioritizationResponseStatus },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalStatusPackage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalStatusPackage, SignalStatusPackage_sequence);

  return offset;
}


static const per_sequence_t SignalStatusPackageList_sequence_of[1] = {
  { &hf_j2735_SignalStatusPackageList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SignalStatusPackage },
};

static int
dissect_j2735_SignalStatusPackageList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SignalStatusPackageList, SignalStatusPackageList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t SignalStatus_sequence[] = {
  { &hf_j2735_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_id_03         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionReferenceID },
  { &hf_j2735_sigStatus     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignalStatusPackageList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalStatus, SignalStatus_sequence);

  return offset;
}


static const per_sequence_t SignalStatusList_sequence_of[1] = {
  { &hf_j2735_SignalStatusList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SignalStatus },
};

static int
dissect_j2735_SignalStatusList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SignalStatusList, SignalStatusList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t SignalStatusMessage_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_second_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_DSecond },
  { &hf_j2735_sequenceNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MsgCount },
  { &hf_j2735_status_02     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignalStatusList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SignalStatusMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SignalStatusMessage, SignalStatusMessage_sequence);

  return offset;
}


static int * const IntersectionStatusObject_bits[] = {
  &hf_j2735_IntersectionStatusObject_manualControlIsEnabled,
  &hf_j2735_IntersectionStatusObject_stopTimeIsActivated,
  &hf_j2735_IntersectionStatusObject_failureFlash,
  &hf_j2735_IntersectionStatusObject_preemptIsActive,
  &hf_j2735_IntersectionStatusObject_signalPriorityIsActive,
  &hf_j2735_IntersectionStatusObject_fixedTimeOperation,
  &hf_j2735_IntersectionStatusObject_trafficDependentOperation,
  &hf_j2735_IntersectionStatusObject_standbyOperation,
  &hf_j2735_IntersectionStatusObject_failureMode,
  &hf_j2735_IntersectionStatusObject_off,
  &hf_j2735_IntersectionStatusObject_recentMAPmessageUpdate,
  &hf_j2735_IntersectionStatusObject_recentChangeInMAPassignedLanesIDsUsed,
  &hf_j2735_IntersectionStatusObject_noValidMAPisAvailableAtThisTime,
  &hf_j2735_IntersectionStatusObject_noValidSPATisAvailableAtThisTime,
  NULL
};

static int
dissect_j2735_IntersectionStatusObject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, IntersectionStatusObject_bits, 14, NULL, NULL);

  return offset;
}


static const per_sequence_t EnabledLaneList_sequence_of[1] = {
  { &hf_j2735_EnabledLaneList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_LaneID },
};

static int
dissect_j2735_EnabledLaneList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_EnabledLaneList, EnabledLaneList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string j2735_MovementPhaseState_vals[] = {
  {   0, "unavailable" },
  {   1, "dark" },
  {   2, "stop-Then-Proceed" },
  {   3, "stop-And-Remain" },
  {   4, "pre-Movement" },
  {   5, "permissive-Movement-Allowed" },
  {   6, "protected-Movement-Allowed" },
  {   7, "permissive-clearance" },
  {   8, "protected-clearance" },
  {   9, "caution-Conflicting-Traffic" },
  { 0, NULL }
};


static int
dissect_j2735_MovementPhaseState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_TimeMark(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 36111U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TimeChangeDetails_sequence[] = {
  { &hf_j2735_startTime_01  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_TimeMark },
  { &hf_j2735_minEndTime_01 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TimeMark },
  { &hf_j2735_maxEndTime_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_TimeMark },
  { &hf_j2735_likelyTime_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_TimeMark },
  { &hf_j2735_confidence    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_TimeIntervalConfidence },
  { &hf_j2735_nextTime_01   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_TimeMark },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TimeChangeDetails(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TimeChangeDetails, TimeChangeDetails_sequence);

  return offset;
}


static const value_string j2735_AdvisorySpeedType_vals[] = {
  {   0, "none" },
  {   1, "greenwave" },
  {   2, "ecoDrive" },
  {   3, "transit" },
  { 0, NULL }
};


static int
dissect_j2735_AdvisorySpeedType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_SpeedAdvice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 500U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_ZoneLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10000U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AdvisorySpeed_sequence[] = {
  { &hf_j2735_type_03       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_AdvisorySpeedType },
  { &hf_j2735_speed_04      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedAdvice },
  { &hf_j2735_confidence_04 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SpeedConfidence },
  { &hf_j2735_distance      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ZoneLength },
  { &hf_j2735_class         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RestrictionClassID },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_AdvisorySpeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_AdvisorySpeed, AdvisorySpeed_sequence);

  return offset;
}


static const per_sequence_t AdvisorySpeedList_sequence_of[1] = {
  { &hf_j2735_AdvisorySpeedList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_AdvisorySpeed },
};

static int
dissect_j2735_AdvisorySpeedList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_AdvisorySpeedList, AdvisorySpeedList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t MovementEvent_sequence[] = {
  { &hf_j2735_eventState    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MovementPhaseState },
  { &hf_j2735_timing        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_TimeChangeDetails },
  { &hf_j2735_speeds        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_AdvisorySpeedList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_MovementEvent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_MovementEvent, MovementEvent_sequence);

  return offset;
}


static const per_sequence_t MovementEventList_sequence_of[1] = {
  { &hf_j2735_MovementEventList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_MovementEvent },
};

static int
dissect_j2735_MovementEventList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_MovementEventList, MovementEventList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_j2735_WaitOnStopline(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_j2735_PedestrianBicycleDetect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t ConnectionManeuverAssist_sequence[] = {
  { &hf_j2735_connectionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_LaneConnectionID },
  { &hf_j2735_queueLength   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ZoneLength },
  { &hf_j2735_availableStorageLength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ZoneLength },
  { &hf_j2735_waitOnStop    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_WaitOnStopline },
  { &hf_j2735_pedBicycleDetect, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_PedestrianBicycleDetect },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ConnectionManeuverAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ConnectionManeuverAssist, ConnectionManeuverAssist_sequence);

  return offset;
}


static const per_sequence_t ManeuverAssistList_sequence_of[1] = {
  { &hf_j2735_ManeuverAssistList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ConnectionManeuverAssist },
};

static int
dissect_j2735_ManeuverAssistList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_ManeuverAssistList, ManeuverAssistList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t MovementState_sequence[] = {
  { &hf_j2735_movementName  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_signalGroup   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignalGroupID },
  { &hf_j2735_state_time_speed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MovementEventList },
  { &hf_j2735_maneuverAssistList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ManeuverAssistList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_MovementState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_MovementState, MovementState_sequence);

  return offset;
}


static const per_sequence_t MovementList_sequence_of[1] = {
  { &hf_j2735_MovementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_MovementState },
};

static int
dissect_j2735_MovementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_MovementList, MovementList_sequence_of,
                                                  1, 255, FALSE);

  return offset;
}


static const per_sequence_t IntersectionState_sequence[] = {
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_id_03         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionReferenceID },
  { &hf_j2735_revision      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_status_04     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionStatusObject },
  { &hf_j2735_moy           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_timeStamp_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DSecond },
  { &hf_j2735_enabledLanes  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_EnabledLaneList },
  { &hf_j2735_states        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MovementList },
  { &hf_j2735_maneuverAssistList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_ManeuverAssistList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_IntersectionState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_IntersectionState, IntersectionState_sequence);

  return offset;
}


static const per_sequence_t IntersectionStateList_sequence_of[1] = {
  { &hf_j2735_IntersectionStateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionState },
};

static int
dissect_j2735_IntersectionStateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_IntersectionStateList, IntersectionStateList_sequence_of,
                                                  1, 32, FALSE);

  return offset;
}


static const per_sequence_t SPAT_sequence[] = {
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_intersections_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_IntersectionStateList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SPAT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SPAT, SPAT_sequence);

  return offset;
}


static const per_sequence_t TestMessage00_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage00(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage00, TestMessage00_sequence);

  return offset;
}


static const per_sequence_t TestMessage01_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage01, TestMessage01_sequence);

  return offset;
}


static const per_sequence_t TestMessage02_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage02, TestMessage02_sequence);

  return offset;
}


static const per_sequence_t TestMessage03_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage03, TestMessage03_sequence);

  return offset;
}


static const per_sequence_t TestMessage04_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage04, TestMessage04_sequence);

  return offset;
}


static const per_sequence_t TestMessage05_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage05, TestMessage05_sequence);

  return offset;
}


static const per_sequence_t TestMessage06_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage06, TestMessage06_sequence);

  return offset;
}


static const per_sequence_t TestMessage07_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage07, TestMessage07_sequence);

  return offset;
}


static const per_sequence_t TestMessage08_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage08, TestMessage08_sequence);

  return offset;
}


static const per_sequence_t TestMessage09_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage09, TestMessage09_sequence);

  return offset;
}


static const per_sequence_t TestMessage10_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage10, TestMessage10_sequence);

  return offset;
}


static const per_sequence_t TestMessage11_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage11, TestMessage11_sequence);

  return offset;
}


static const per_sequence_t TestMessage12_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage12, TestMessage12_sequence);

  return offset;
}


static const per_sequence_t TestMessage13_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage13, TestMessage13_sequence);

  return offset;
}


static const per_sequence_t TestMessage14_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage14, TestMessage14_sequence);

  return offset;
}


static const per_sequence_t TestMessage15_sequence[] = {
  { &hf_j2735_header        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Header },
  { &hf_j2735_regional_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TestMessage15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TestMessage15, TestMessage15_sequence);

  return offset;
}



static int
dissect_j2735_UniqueMSGID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       9, 9, FALSE, NULL);

  return offset;
}



static int
dissect_j2735_URL_Base(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 45, FALSE,
                                          NULL);

  return offset;
}


static const value_string j2735_TravelerInfoType_vals[] = {
  {   0, "unknown" },
  {   1, "advisory" },
  {   2, "roadSignage" },
  {   3, "commercialSignage" },
  { 0, NULL }
};


static int
dissect_j2735_TravelerInfoType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string j2735_MUTCDCode_vals[] = {
  {   0, "none" },
  {   1, "regulatory" },
  {   2, "warning" },
  {   3, "maintenance" },
  {   4, "motoristService" },
  {   5, "guide" },
  {   6, "rec" },
  { 0, NULL }
};


static int
dissect_j2735_MUTCDCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_j2735_MsgCRC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t RoadSignID_sequence[] = {
  { &hf_j2735_position      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Position3D },
  { &hf_j2735_viewAngle     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_HeadingSlice },
  { &hf_j2735_mutcdCode     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_MUTCDCode },
  { &hf_j2735_crc           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_MsgCRC },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RoadSignID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RoadSignID, RoadSignID_sequence);

  return offset;
}


static const value_string j2735_T_msgId_vals[] = {
  {   0, "furtherInfoID" },
  {   1, "roadSignID" },
  { 0, NULL }
};

static const per_choice_t T_msgId_choice[] = {
  {   0, &hf_j2735_furtherInfoID , ASN1_NO_EXTENSIONS     , dissect_j2735_FurtherInfoID },
  {   1, &hf_j2735_roadSignID    , ASN1_NO_EXTENSIONS     , dissect_j2735_RoadSignID },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_msgId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_msgId, T_msgId_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_MinutesDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32000U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_SignPrority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const value_string j2735_DirectionOfUse_vals[] = {
  {   0, "unavailable" },
  {   1, "forward" },
  {   2, "reverse" },
  {   3, "both" },
  { 0, NULL }
};


static int
dissect_j2735_DirectionOfUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_j2735_Zoom(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_j2735_OffsetLL_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_LL_24B_sequence[] = {
  { &hf_j2735_lon_03        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B12 },
  { &hf_j2735_lat_04        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B12 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LL_24B(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LL_24B, Node_LL_24B_sequence);

  return offset;
}



static int
dissect_j2735_OffsetLL_B14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8192, 8191U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_LL_28B_sequence[] = {
  { &hf_j2735_lon_04        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B14 },
  { &hf_j2735_lat_05        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B14 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LL_28B(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LL_28B, Node_LL_28B_sequence);

  return offset;
}



static int
dissect_j2735_OffsetLL_B16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_LL_32B_sequence[] = {
  { &hf_j2735_lon_05        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B16 },
  { &hf_j2735_lat_06        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LL_32B(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LL_32B, Node_LL_32B_sequence);

  return offset;
}


static const per_sequence_t Node_LL_36B_sequence[] = {
  { &hf_j2735_lon_06        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B18 },
  { &hf_j2735_lat_07        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B18 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LL_36B(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LL_36B, Node_LL_36B_sequence);

  return offset;
}



static int
dissect_j2735_OffsetLL_B22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2097152, 2097151U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_LL_44B_sequence[] = {
  { &hf_j2735_lon_07        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B22 },
  { &hf_j2735_lat_08        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B22 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LL_44B(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LL_44B, Node_LL_44B_sequence);

  return offset;
}



static int
dissect_j2735_OffsetLL_B24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Node_LL_48B_sequence[] = {
  { &hf_j2735_lon_08        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B24 },
  { &hf_j2735_lat_09        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B24 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Node_LL_48B(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Node_LL_48B, Node_LL_48B_sequence);

  return offset;
}


static const value_string j2735_NodeOffsetPointLL_vals[] = {
  {   0, "node-LL1" },
  {   1, "node-LL2" },
  {   2, "node-LL3" },
  {   3, "node-LL4" },
  {   4, "node-LL5" },
  {   5, "node-LL6" },
  {   6, "node-LatLon" },
  {   7, "regional" },
  { 0, NULL }
};

static const per_choice_t NodeOffsetPointLL_choice[] = {
  {   0, &hf_j2735_node_LL1      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LL_24B },
  {   1, &hf_j2735_node_LL2      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LL_28B },
  {   2, &hf_j2735_node_LL3      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LL_32B },
  {   3, &hf_j2735_node_LL4      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LL_36B },
  {   4, &hf_j2735_node_LL5      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LL_44B },
  {   5, &hf_j2735_node_LL6      , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LL_48B },
  {   6, &hf_j2735_node_LatLon   , ASN1_NO_EXTENSIONS     , dissect_j2735_Node_LLmD_64b },
  {   7, &hf_j2735_regional_01   , ASN1_NO_EXTENSIONS     , dissect_j2735_RegionalExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_NodeOffsetPointLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_NodeOffsetPointLL, NodeOffsetPointLL_choice,
                                 NULL);

  return offset;
}


static const value_string j2735_NodeAttributeLL_vals[] = {
  {   0, "reserved" },
  {   1, "stopLine" },
  {   2, "roundedCapStyleA" },
  {   3, "roundedCapStyleB" },
  {   4, "mergePoint" },
  {   5, "divergePoint" },
  {   6, "downstreamStopLine" },
  {   7, "downstreamStartNode" },
  {   8, "closedToTraffic" },
  {   9, "safeIsland" },
  {  10, "curbPresentAtStepOff" },
  {  11, "hydrantPresent" },
  { 0, NULL }
};


static int
dissect_j2735_NodeAttributeLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     12, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NodeAttributeLLList_sequence_of[1] = {
  { &hf_j2735_NodeAttributeLLList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_NodeAttributeLL },
};

static int
dissect_j2735_NodeAttributeLLList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_NodeAttributeLLList, NodeAttributeLLList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const value_string j2735_SegmentAttributeLL_vals[] = {
  {   0, "reserved" },
  {   1, "doNotBlock" },
  {   2, "whiteLine" },
  {   3, "mergingLaneLeft" },
  {   4, "mergingLaneRight" },
  {   5, "curbOnLeft" },
  {   6, "curbOnRight" },
  {   7, "loadingzoneOnLeft" },
  {   8, "loadingzoneOnRight" },
  {   9, "turnOutPointOnLeft" },
  {  10, "turnOutPointOnRight" },
  {  11, "adjacentParkingOnLeft" },
  {  12, "adjacentParkingOnRight" },
  {  13, "adjacentBikeLaneOnLeft" },
  {  14, "adjacentBikeLaneOnRight" },
  {  15, "sharedBikeLane" },
  {  16, "bikeBoxInFront" },
  {  17, "transitStopOnLeft" },
  {  18, "transitStopOnRight" },
  {  19, "transitStopInLane" },
  {  20, "sharedWithTrackedVehicle" },
  {  21, "safeIsland" },
  {  22, "lowCurbsPresent" },
  {  23, "rumbleStripPresent" },
  {  24, "audibleSignalingPresent" },
  {  25, "adaptiveTimingPresent" },
  {  26, "rfSignalRequestPresent" },
  {  27, "partialCurbIntrusion" },
  {  28, "taperToLeft" },
  {  29, "taperToRight" },
  {  30, "taperToCenterLine" },
  {  31, "parallelParking" },
  {  32, "headInParking" },
  {  33, "freeParking" },
  {  34, "timeRestrictionsOnParking" },
  {  35, "costToPark" },
  {  36, "midBlockCurbPresent" },
  {  37, "unEvenPavementPresent" },
  { 0, NULL }
};


static int
dissect_j2735_SegmentAttributeLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     38, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SegmentAttributeLLList_sequence_of[1] = {
  { &hf_j2735_SegmentAttributeLLList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SegmentAttributeLL },
};

static int
dissect_j2735_SegmentAttributeLLList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SegmentAttributeLLList, SegmentAttributeLLList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t NodeAttributeSetLL_sequence[] = {
  { &hf_j2735_localNode_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NodeAttributeLLList },
  { &hf_j2735_disabled_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SegmentAttributeLLList },
  { &hf_j2735_enabled_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SegmentAttributeLLList },
  { &hf_j2735_data          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneDataAttributeList },
  { &hf_j2735_dWidth        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Offset_B10 },
  { &hf_j2735_dElevation    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Offset_B10 },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_NodeAttributeSetLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_NodeAttributeSetLL, NodeAttributeSetLL_sequence);

  return offset;
}


static const per_sequence_t NodeLL_sequence[] = {
  { &hf_j2735_delta_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_NodeOffsetPointLL },
  { &hf_j2735_attributes_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_NodeAttributeSetLL },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_NodeLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_NodeLL, NodeLL_sequence);

  return offset;
}


static const per_sequence_t NodeSetLL_sequence_of[1] = {
  { &hf_j2735_NodeSetLL_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_NodeLL },
};

static int
dissect_j2735_NodeSetLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_NodeSetLL, NodeSetLL_sequence_of,
                                                  2, 63, FALSE);

  return offset;
}


static const value_string j2735_NodeListLL_vals[] = {
  {   0, "nodes" },
  { 0, NULL }
};

static const per_choice_t NodeListLL_choice[] = {
  {   0, &hf_j2735_nodes_01      , ASN1_EXTENSION_ROOT    , dissect_j2735_NodeSetLL },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_NodeListLL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_NodeListLL, NodeListLL_choice,
                                 NULL);

  return offset;
}


static const value_string j2735_T_offset_vals[] = {
  {   0, "xy" },
  {   1, "ll" },
  { 0, NULL }
};

static const per_choice_t T_offset_choice[] = {
  {   0, &hf_j2735_xy            , ASN1_NO_EXTENSIONS     , dissect_j2735_NodeListXY },
  {   1, &hf_j2735_ll            , ASN1_NO_EXTENSIONS     , dissect_j2735_NodeListLL },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_offset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_offset, T_offset_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OffsetSystem_sequence[] = {
  { &hf_j2735_scale         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_Zoom },
  { &hf_j2735_offset_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_offset },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_OffsetSystem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_OffsetSystem, OffsetSystem_sequence);

  return offset;
}



static int
dissect_j2735_Radius_B12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

  return offset;
}


static const value_string j2735_DistanceUnits_vals[] = {
  {   0, "centimeter" },
  {   1, "cm2-5" },
  {   2, "decimeter" },
  {   3, "meter" },
  {   4, "kilometer" },
  {   5, "foot" },
  {   6, "yard" },
  {   7, "mile" },
  { 0, NULL }
};


static int
dissect_j2735_DistanceUnits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Circle_sequence[] = {
  { &hf_j2735_center        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Position3D },
  { &hf_j2735_radius        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_Radius_B12 },
  { &hf_j2735_units_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_DistanceUnits },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_Circle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_Circle, Circle_sequence);

  return offset;
}


static const per_sequence_t GeometricProjection_sequence[] = {
  { &hf_j2735_direction     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_HeadingSlice },
  { &hf_j2735_extent        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Extent },
  { &hf_j2735_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneWidth },
  { &hf_j2735_circle        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_Circle },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_GeometricProjection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_GeometricProjection, GeometricProjection_sequence);

  return offset;
}


static const per_sequence_t ShapePointSet_sequence[] = {
  { &hf_j2735_anchor        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Position3D },
  { &hf_j2735_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneWidth },
  { &hf_j2735_directionality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DirectionOfUse },
  { &hf_j2735_nodeList      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_NodeListXY },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ShapePointSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ShapePointSet, ShapePointSet_sequence);

  return offset;
}


static const per_sequence_t RegionOffsets_sequence[] = {
  { &hf_j2735_xOffset       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B16 },
  { &hf_j2735_yOffset       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_OffsetLL_B16 },
  { &hf_j2735_zOffset       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_OffsetLL_B16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RegionOffsets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RegionOffsets, RegionOffsets_sequence);

  return offset;
}


static const per_sequence_t RegionList_sequence_of[1] = {
  { &hf_j2735_RegionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_RegionOffsets },
};

static int
dissect_j2735_RegionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_RegionList, RegionList_sequence_of,
                                                  1, 64, FALSE);

  return offset;
}


static const per_sequence_t RegionPointSet_sequence[] = {
  { &hf_j2735_anchor        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Position3D },
  { &hf_j2735_scale         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Zoom },
  { &hf_j2735_nodeList_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_RegionList },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_RegionPointSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_RegionPointSet, RegionPointSet_sequence);

  return offset;
}


static const value_string j2735_T_area_vals[] = {
  {   0, "shapePointSet" },
  {   1, "circle" },
  {   2, "regionPointSet" },
  { 0, NULL }
};

static const per_choice_t T_area_choice[] = {
  {   0, &hf_j2735_shapePointSet , ASN1_NO_EXTENSIONS     , dissect_j2735_ShapePointSet },
  {   1, &hf_j2735_circle        , ASN1_NO_EXTENSIONS     , dissect_j2735_Circle },
  {   2, &hf_j2735_regionPointSet, ASN1_NO_EXTENSIONS     , dissect_j2735_RegionPointSet },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_area(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_area, T_area_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ValidRegion_sequence[] = {
  { &hf_j2735_direction     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_HeadingSlice },
  { &hf_j2735_extent        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_j2735_Extent },
  { &hf_j2735_area          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_area },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ValidRegion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ValidRegion, ValidRegion_sequence);

  return offset;
}


static const value_string j2735_T_description_vals[] = {
  {   0, "path" },
  {   1, "geometry" },
  {   2, "oldRegion" },
  { 0, NULL }
};

static const per_choice_t T_description_choice[] = {
  {   0, &hf_j2735_path_01       , ASN1_EXTENSION_ROOT    , dissect_j2735_OffsetSystem },
  {   1, &hf_j2735_geometry      , ASN1_EXTENSION_ROOT    , dissect_j2735_GeometricProjection },
  {   2, &hf_j2735_oldRegion     , ASN1_EXTENSION_ROOT    , dissect_j2735_ValidRegion },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_description(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_description, T_description_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GeographicalPath_sequence[] = {
  { &hf_j2735_name          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DescriptiveName },
  { &hf_j2735_id_05         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_RoadSegmentReferenceID },
  { &hf_j2735_anchor        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_Position3D },
  { &hf_j2735_laneWidth     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_LaneWidth },
  { &hf_j2735_directionality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DirectionOfUse },
  { &hf_j2735_closedPath    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_BOOLEAN },
  { &hf_j2735_direction     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_HeadingSlice },
  { &hf_j2735_description_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_T_description },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_GeographicalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_GeographicalPath, GeographicalPath_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_16_OF_GeographicalPath_sequence_of[1] = {
  { &hf_j2735_regions_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GeographicalPath },
};

static int
dissect_j2735_SEQUENCE_SIZE_1_16_OF_GeographicalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SEQUENCE_SIZE_1_16_OF_GeographicalPath, SEQUENCE_SIZE_1_16_OF_GeographicalPath_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}



static int
dissect_j2735_ITIStextPhrase(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 16, FALSE,
                                          NULL);

  return offset;
}


static const value_string j2735_T_item_04_vals[] = {
  {   0, "itis" },
  {   1, "text" },
  { 0, NULL }
};

static const per_choice_t T_item_04_choice[] = {
  {   0, &hf_j2735_itis          , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIScodes },
  {   1, &hf_j2735_text_01       , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIStextPhrase },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_item_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_item_04, T_item_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t WorkZone_item_sequence[] = {
  { &hf_j2735_item_04       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_item_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_WorkZone_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_WorkZone_item, WorkZone_item_sequence);

  return offset;
}


static const per_sequence_t WorkZone_sequence_of[1] = {
  { &hf_j2735_WorkZone_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_WorkZone_item },
};

static int
dissect_j2735_WorkZone(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_WorkZone, WorkZone_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string j2735_T_item_02_vals[] = {
  {   0, "itis" },
  {   1, "text" },
  { 0, NULL }
};

static const per_choice_t T_item_02_choice[] = {
  {   0, &hf_j2735_itis          , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIScodes },
  {   1, &hf_j2735_text_01       , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIStextPhrase },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_item_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_item_02, T_item_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GenericSignage_item_sequence[] = {
  { &hf_j2735_item_02       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_item_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_GenericSignage_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_GenericSignage_item, GenericSignage_item_sequence);

  return offset;
}


static const per_sequence_t GenericSignage_sequence_of[1] = {
  { &hf_j2735_GenericSignage_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_GenericSignage_item },
};

static int
dissect_j2735_GenericSignage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_GenericSignage, GenericSignage_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string j2735_T_item_03_vals[] = {
  {   0, "itis" },
  {   1, "text" },
  { 0, NULL }
};

static const per_choice_t T_item_03_choice[] = {
  {   0, &hf_j2735_itis          , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIScodes },
  {   1, &hf_j2735_text_01       , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIStextPhrase },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_item_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_item_03, T_item_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SpeedLimit_item_sequence[] = {
  { &hf_j2735_item_03       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_item_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_SpeedLimit_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_SpeedLimit_item, SpeedLimit_item_sequence);

  return offset;
}


static const per_sequence_t SpeedLimit_sequence_of[1] = {
  { &hf_j2735_SpeedLimit_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_SpeedLimit_item },
};

static int
dissect_j2735_SpeedLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_SpeedLimit, SpeedLimit_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string j2735_T_item_01_vals[] = {
  {   0, "itis" },
  {   1, "text" },
  { 0, NULL }
};

static const per_choice_t T_item_01_choice[] = {
  {   0, &hf_j2735_itis          , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIScodes },
  {   1, &hf_j2735_text_01       , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIStextPhrase },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_item_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_item_01, T_item_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ExitService_item_sequence[] = {
  { &hf_j2735_item_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_T_item_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_ExitService_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_ExitService_item, ExitService_item_sequence);

  return offset;
}


static const per_sequence_t ExitService_sequence_of[1] = {
  { &hf_j2735_ExitService_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_ExitService_item },
};

static int
dissect_j2735_ExitService(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_ExitService, ExitService_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string j2735_T_content_vals[] = {
  {   0, "advisory" },
  {   1, "workZone" },
  {   2, "genericSign" },
  {   3, "speedLimit" },
  {   4, "exitService" },
  { 0, NULL }
};

static const per_choice_t T_content_choice[] = {
  {   0, &hf_j2735_advisory      , ASN1_NO_EXTENSIONS     , dissect_j2735_ITIScodesAndText },
  {   1, &hf_j2735_workZone      , ASN1_NO_EXTENSIONS     , dissect_j2735_WorkZone },
  {   2, &hf_j2735_genericSign   , ASN1_NO_EXTENSIONS     , dissect_j2735_GenericSignage },
  {   3, &hf_j2735_speedLimit    , ASN1_NO_EXTENSIONS     , dissect_j2735_SpeedLimit },
  {   4, &hf_j2735_exitService   , ASN1_NO_EXTENSIONS     , dissect_j2735_ExitService },
  { 0, NULL, 0, NULL }
};

static int
dissect_j2735_T_content(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_j2735_T_content, T_content_choice,
                                 NULL);

  return offset;
}



static int
dissect_j2735_URL_Short(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 15, FALSE,
                                          NULL);

  return offset;
}


static const per_sequence_t TravelerDataFrame_sequence[] = {
  { &hf_j2735_notUsed       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_frameType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TravelerInfoType },
  { &hf_j2735_msgId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_msgId },
  { &hf_j2735_startYear     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_DYear },
  { &hf_j2735_startTime_02  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_durationTime  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MinutesDuration },
  { &hf_j2735_priority_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SignPrority },
  { &hf_j2735_notUsed1      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_regions       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SEQUENCE_SIZE_1_16_OF_GeographicalPath },
  { &hf_j2735_notUsed2      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_notUsed3      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_SSPindex },
  { &hf_j2735_content       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_T_content },
  { &hf_j2735_url           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_URL_Short },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TravelerDataFrame(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TravelerDataFrame, TravelerDataFrame_sequence);

  return offset;
}


static const per_sequence_t TravelerDataFrameList_sequence_of[1] = {
  { &hf_j2735_TravelerDataFrameList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_j2735_TravelerDataFrame },
};

static int
dissect_j2735_TravelerDataFrameList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_j2735_TravelerDataFrameList, TravelerDataFrameList_sequence_of,
                                                  1, 8, FALSE);

  return offset;
}


static const per_sequence_t TravelerInformation_sequence[] = {
  { &hf_j2735_msgCnt        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_MsgCount },
  { &hf_j2735_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_MinuteOfTheYear },
  { &hf_j2735_packetID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_UniqueMSGID },
  { &hf_j2735_urlB          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_URL_Base },
  { &hf_j2735_dataFrames    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_j2735_TravelerDataFrameList },
  { &hf_j2735_regional      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_j2735_TravelerInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_j2735_TravelerInformation, TravelerInformation_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_BasicSafetyMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_BasicSafetyMessage(tvb, offset, &asn1_ctx, tree, hf_j2735_BasicSafetyMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SpecialVehicleExtensions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_SpecialVehicleExtensions(tvb, offset, &asn1_ctx, tree, hf_j2735_SpecialVehicleExtensions_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupplementalVehicleExtensions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_SupplementalVehicleExtensions(tvb, offset, &asn1_ctx, tree, hf_j2735_SupplementalVehicleExtensions_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VehicleSafetyExtensions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_VehicleSafetyExtensions(tvb, offset, &asn1_ctx, tree, hf_j2735_VehicleSafetyExtensions_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonSafetyRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_CommonSafetyRequest(tvb, offset, &asn1_ctx, tree, hf_j2735_CommonSafetyRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EmergencyVehicleAlert_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_EmergencyVehicleAlert(tvb, offset, &asn1_ctx, tree, hf_j2735_EmergencyVehicleAlert_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IntersectionCollision_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_IntersectionCollision(tvb, offset, &asn1_ctx, tree, hf_j2735_IntersectionCollision_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MapData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_MapData(tvb, offset, &asn1_ctx, tree, hf_j2735_MapData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MessageFrame_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_MessageFrame(tvb, offset, &asn1_ctx, tree, hf_j2735_MessageFrame_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NMEAcorrections_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_NMEAcorrections(tvb, offset, &asn1_ctx, tree, hf_j2735_NMEAcorrections_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PersonalSafetyMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_PersonalSafetyMessage(tvb, offset, &asn1_ctx, tree, hf_j2735_PersonalSafetyMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProbeDataManagement_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_ProbeDataManagement(tvb, offset, &asn1_ctx, tree, hf_j2735_ProbeDataManagement_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ProbeVehicleData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_ProbeVehicleData(tvb, offset, &asn1_ctx, tree, hf_j2735_ProbeVehicleData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RoadSideAlert_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_RoadSideAlert(tvb, offset, &asn1_ctx, tree, hf_j2735_RoadSideAlert_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RTCMcorrections_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_RTCMcorrections(tvb, offset, &asn1_ctx, tree, hf_j2735_RTCMcorrections_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SignalRequestMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_SignalRequestMessage(tvb, offset, &asn1_ctx, tree, hf_j2735_SignalRequestMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SignalStatusMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_SignalStatusMessage(tvb, offset, &asn1_ctx, tree, hf_j2735_SignalStatusMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SPAT_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_SPAT(tvb, offset, &asn1_ctx, tree, hf_j2735_SPAT_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TravelerInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_j2735_TravelerInformation(tvb, offset, &asn1_ctx, tree, hf_j2735_TravelerInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



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
    { &hf_j2735_BasicSafetyMessage_PDU,
      { "BasicSafetyMessage", "j2735.BasicSafetyMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SpecialVehicleExtensions_PDU,
      { "SpecialVehicleExtensions", "j2735.SpecialVehicleExtensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SupplementalVehicleExtensions_PDU,
      { "SupplementalVehicleExtensions", "j2735.SupplementalVehicleExtensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_VehicleSafetyExtensions_PDU,
      { "VehicleSafetyExtensions", "j2735.VehicleSafetyExtensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_CommonSafetyRequest_PDU,
      { "CommonSafetyRequest", "j2735.CommonSafetyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_EmergencyVehicleAlert_PDU,
      { "EmergencyVehicleAlert", "j2735.EmergencyVehicleAlert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_IntersectionCollision_PDU,
      { "IntersectionCollision", "j2735.IntersectionCollision_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_MapData_PDU,
      { "MapData", "j2735.MapData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_MessageFrame_PDU,
      { "MessageFrame", "j2735.MessageFrame_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_NMEAcorrections_PDU,
      { "NMEAcorrections", "j2735.NMEAcorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_PersonalSafetyMessage_PDU,
      { "PersonalSafetyMessage", "j2735.PersonalSafetyMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_ProbeDataManagement_PDU,
      { "ProbeDataManagement", "j2735.ProbeDataManagement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_ProbeVehicleData_PDU,
      { "ProbeVehicleData", "j2735.ProbeVehicleData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_RoadSideAlert_PDU,
      { "RoadSideAlert", "j2735.RoadSideAlert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_RTCMcorrections_PDU,
      { "RTCMcorrections", "j2735.RTCMcorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SignalRequestMessage_PDU,
      { "SignalRequestMessage", "j2735.SignalRequestMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SignalStatusMessage_PDU,
      { "SignalStatusMessage", "j2735.SignalStatusMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SPAT_PDU,
      { "SPAT", "j2735.SPAT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_TravelerInformation_PDU,
      { "TravelerInformation", "j2735.TravelerInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_d,
      { "d", "j2735.d",
        FT_INT32, BASE_DEC, NULL, 0,
        "DegreesLat", HFILL }},
    { &hf_j2735_m,
      { "m", "j2735.m",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinutesAngle", HFILL }},
    { &hf_j2735_s,
      { "s", "j2735.s",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecondsAngle", HFILL }},
    { &hf_j2735_d_01,
      { "d", "j2735.d",
        FT_INT32, BASE_DEC, NULL, 0,
        "DegreesLong", HFILL }},
    { &hf_j2735_lon,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "LongitudeDMS", HFILL }},
    { &hf_j2735_lat,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "LatitudeDMS", HFILL }},
    { &hf_j2735_lon_01,
      { "lon", "j2735.lon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LongitudeDMS2", HFILL }},
    { &hf_j2735_lat_01,
      { "lat", "j2735.lat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LatitudeDMS2", HFILL }},
    { &hf_j2735_startTime,
      { "startTime", "j2735.startTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeRemaining", HFILL }},
    { &hf_j2735_minEndTime,
      { "minEndTime", "j2735.minEndTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinTimetoChange", HFILL }},
    { &hf_j2735_maxEndTime,
      { "maxEndTime", "j2735.maxEndTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MaxTimetoChange", HFILL }},
    { &hf_j2735_likelyTime,
      { "likelyTime", "j2735.likelyTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeRemaining", HFILL }},
    { &hf_j2735_confidence,
      { "confidence", "j2735.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeIntervalConfidence", HFILL }},
    { &hf_j2735_nextTime,
      { "nextTime", "j2735.nextTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeRemaining", HFILL }},
    { &hf_j2735_posA,
      { "posA", "j2735.posA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LLdms_48b", HFILL }},
    { &hf_j2735_posB,
      { "posB", "j2735.posB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LLdms_80b", HFILL }},
    { &hf_j2735_latitude,
      { "latitude", "j2735.latitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LatitudeDMS2", HFILL }},
    { &hf_j2735_longitude,
      { "longitude", "j2735.longitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LongitudeDMS2", HFILL }},
    { &hf_j2735_elevation,
      { "elevation", "j2735.elevation",
        FT_INT32, BASE_DEC, NULL, 0,
        "ElevationB", HFILL }},
    { &hf_j2735_year,
      { "year", "j2735.year",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_month,
      { "month", "j2735.month",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_day,
      { "day", "j2735.day",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_summerTime,
      { "summerTime", "j2735.summerTime",
        FT_UINT32, BASE_DEC, VALS(j2735_SummerTime_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_holiday,
      { "holiday", "j2735.holiday",
        FT_UINT32, BASE_DEC, VALS(j2735_Holiday_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_dayofWeek,
      { "dayofWeek", "j2735.dayofWeek",
        FT_UINT32, BASE_DEC, VALS(j2735_DayOfWeek_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_hour,
      { "hour", "j2735.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_minute,
      { "minute", "j2735.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_second,
      { "second", "j2735.second",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_tenthSecond,
      { "tenthSecond", "j2735.tenthSecond",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_value,
      { "value", "j2735.value",
        FT_INT32, BASE_DEC, NULL, 0,
        "AltitudeValue", HFILL }},
    { &hf_j2735_confidence_01,
      { "confidence", "j2735.confidence",
        FT_UINT32, BASE_DEC, VALS(j2735_AltitudeConfidence_vals), 0,
        "AltitudeConfidence", HFILL }},
    { &hf_j2735_stationID,
      { "stationID", "j2735.stationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_priorState,
      { "priorState", "j2735.priorState",
        FT_UINT32, BASE_DEC, VALS(j2735_PrioritizationResponseStatus_vals), 0,
        "PrioritizationResponseStatus", HFILL }},
    { &hf_j2735_signalGroup,
      { "signalGroup", "j2735.signalGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalGroupID", HFILL }},
    { &hf_j2735_PrioritizationResponseList_item,
      { "PrioritizationResponse", "j2735.PrioritizationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_vehicleToLanePositions,
      { "vehicleToLanePositions", "j2735.vehicleToLanePositions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleToLanePositionList", HFILL }},
    { &hf_j2735_rsuDistanceFromAnchor,
      { "rsuDistanceFromAnchor", "j2735.rsuDistanceFromAnchor",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeOffsetPointXY_vals), 0,
        "NodeOffsetPointXY", HFILL }},
    { &hf_j2735_activePrioritizations,
      { "activePrioritizations", "j2735.activePrioritizations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrioritizationResponseList", HFILL }},
    { &hf_j2735_signalHeadLocations,
      { "signalHeadLocations", "j2735.signalHeadLocations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalHeadLocationList", HFILL }},
    { &hf_j2735_altitude,
      { "altitude", "j2735.altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_emission,
      { "emission", "j2735.emission",
        FT_UINT32, BASE_DEC, VALS(j2735_EmissionType_vals), 0,
        "EmissionType", HFILL }},
    { &hf_j2735_node,
      { "node", "j2735.node",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeOffsetPointXY_vals), 0,
        "NodeOffsetPointXY", HFILL }},
    { &hf_j2735_signalGroupID,
      { "signalGroupID", "j2735.signalGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SignalHeadLocationList_item,
      { "SignalHeadLocation", "j2735.SignalHeadLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_laneID,
      { "laneID", "j2735.laneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_VehicleToLanePositionList_item,
      { "VehicleToLanePosition", "j2735.VehicleToLanePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_coreData,
      { "coreData", "j2735.coreData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BSMcoreData", HFILL }},
    { &hf_j2735_partII,
      { "partII", "j2735.partII",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8_OF_PartIIcontent", HFILL }},
    { &hf_j2735_partII_item,
      { "PartIIcontent", "j2735.PartIIcontent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_regional,
      { "regional", "j2735.regional",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_4_OF_RegionalExtension", HFILL }},
    { &hf_j2735_regional_item,
      { "RegionalExtension", "j2735.RegionalExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_partII_Id,
      { "partII-Id", "j2735.partII_Id",
        FT_UINT32, BASE_DEC, VALS(j2735_PartII_Id_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_partII_Value,
      { "partII-Value", "j2735.partII_Value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_statusDetails,
      { "statusDetails", "j2735.statusDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ITIScodes", HFILL }},
    { &hf_j2735_locationDetails,
      { "locationDetails", "j2735.locationDetails",
        FT_UINT32, BASE_DEC, VALS(j2735_GenericLocations_vals), 0,
        "GenericLocations", HFILL }},
    { &hf_j2735_typeEvent,
      { "typeEvent", "j2735.typeEvent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ITIScodes", HFILL }},
    { &hf_j2735_description,
      { "description", "j2735.description",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_8_OF_ITIScodes", HFILL }},
    { &hf_j2735_description_item,
      { "ITIScodes", "j2735.ITIScodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_priority,
      { "priority", "j2735.priority",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_heading,
      { "heading", "j2735.heading",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HeadingSlice", HFILL }},
    { &hf_j2735_extent,
      { "extent", "j2735.extent",
        FT_UINT32, BASE_DEC, VALS(j2735_Extent_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_obDist,
      { "obDist", "j2735.obDist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ObstacleDistance", HFILL }},
    { &hf_j2735_obDirect,
      { "obDirect", "j2735.obDirect",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ObstacleDirection", HFILL }},
    { &hf_j2735_description_01,
      { "description", "j2735.description",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ITIScodes", HFILL }},
    { &hf_j2735_dateTime,
      { "dateTime", "j2735.dateTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DDateTime", HFILL }},
    { &hf_j2735_vertEvent,
      { "vertEvent", "j2735.vertEvent",
        FT_BYTES, BASE_NONE, NULL, 0,
        "VerticalAccelerationThreshold", HFILL }},
    { &hf_j2735_pivotOffset,
      { "pivotOffset", "j2735.pivotOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B11", HFILL }},
    { &hf_j2735_pivotAngle,
      { "pivotAngle", "j2735.pivotAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_j2735_pivots,
      { "pivots", "j2735.pivots",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PivotingAllowed", HFILL }},
    { &hf_j2735_rtcmHeader,
      { "rtcmHeader", "j2735.rtcmHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_msgs,
      { "msgs", "j2735.msgs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RTCMmessageList", HFILL }},
    { &hf_j2735_vehicleAlerts,
      { "vehicleAlerts", "j2735.vehicleAlerts_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EmergencyDetails", HFILL }},
    { &hf_j2735_description_02,
      { "description", "j2735.description_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventDescription", HFILL }},
    { &hf_j2735_trailers,
      { "trailers", "j2735.trailers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TrailerData", HFILL }},
    { &hf_j2735_SpeedProfileMeasurementList_item,
      { "SpeedProfileMeasurement", "j2735.SpeedProfileMeasurement",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_speedReports,
      { "speedReports", "j2735.speedReports",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedProfileMeasurementList", HFILL }},
    { &hf_j2735_classification,
      { "classification", "j2735.classification",
        FT_UINT32, BASE_DEC, VALS(j2735_BasicVehicleClass_vals), 0,
        "BasicVehicleClass", HFILL }},
    { &hf_j2735_classDetails,
      { "classDetails", "j2735.classDetails_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VehicleClassification", HFILL }},
    { &hf_j2735_vehicleData,
      { "vehicleData", "j2735.vehicleData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_weatherReport,
      { "weatherReport", "j2735.weatherReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_weatherProbe,
      { "weatherProbe", "j2735.weatherProbe_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_obstacle,
      { "obstacle", "j2735.obstacle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObstacleDetection", HFILL }},
    { &hf_j2735_status,
      { "status", "j2735.status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DisabledVehicle", HFILL }},
    { &hf_j2735_speedProfile,
      { "speedProfile", "j2735.speedProfile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_theRTCM,
      { "theRTCM", "j2735.theRTCM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTCMPackage", HFILL }},
    { &hf_j2735_notUsed,
      { "notUsed", "j2735.notUsed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SSPindex", HFILL }},
    { &hf_j2735_connection,
      { "connection", "j2735.connection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PivotPointDescription", HFILL }},
    { &hf_j2735_units,
      { "units", "j2735.units",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrailerUnitDescriptionList", HFILL }},
    { &hf_j2735_TrailerHistoryPointList_item,
      { "TrailerHistoryPoint", "j2735.TrailerHistoryPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_timeOffset,
      { "timeOffset", "j2735.timeOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_positionOffset,
      { "positionOffset", "j2735.positionOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_24b", HFILL }},
    { &hf_j2735_elevationOffset,
      { "elevationOffset", "j2735.elevationOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B07", HFILL }},
    { &hf_j2735_heading_01,
      { "heading", "j2735.heading",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CoarseHeading", HFILL }},
    { &hf_j2735_TrailerUnitDescriptionList_item,
      { "TrailerUnitDescription", "j2735.TrailerUnitDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_isDolly,
      { "isDolly", "j2735.isDolly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_width,
      { "width", "j2735.width",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleWidth", HFILL }},
    { &hf_j2735_length,
      { "length", "j2735.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleLength", HFILL }},
    { &hf_j2735_height,
      { "height", "j2735.height",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleHeight", HFILL }},
    { &hf_j2735_mass,
      { "mass", "j2735.mass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrailerMass", HFILL }},
    { &hf_j2735_bumperHeights,
      { "bumperHeights", "j2735.bumperHeights_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_centerOfGravity,
      { "centerOfGravity", "j2735.centerOfGravity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleHeight", HFILL }},
    { &hf_j2735_frontPivot,
      { "frontPivot", "j2735.frontPivot_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PivotPointDescription", HFILL }},
    { &hf_j2735_rearPivot,
      { "rearPivot", "j2735.rearPivot_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PivotPointDescription", HFILL }},
    { &hf_j2735_rearWheelOffset,
      { "rearWheelOffset", "j2735.rearWheelOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B12", HFILL }},
    { &hf_j2735_crumbData,
      { "crumbData", "j2735.crumbData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrailerHistoryPointList", HFILL }},
    { &hf_j2735_bumpers,
      { "bumpers", "j2735.bumpers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BumperHeights", HFILL }},
    { &hf_j2735_mass_01,
      { "mass", "j2735.mass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleMass", HFILL }},
    { &hf_j2735_trailerWeight,
      { "trailerWeight", "j2735.trailerWeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_airTemp,
      { "airTemp", "j2735.airTemp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AmbientAirTemperature", HFILL }},
    { &hf_j2735_airPressure,
      { "airPressure", "j2735.airPressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AmbientAirPressure", HFILL }},
    { &hf_j2735_rainRates,
      { "rainRates", "j2735.rainRates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WiperSet", HFILL }},
    { &hf_j2735_isRaining,
      { "isRaining", "j2735.isRaining",
        FT_UINT32, BASE_DEC, VALS(j2735_EssPrecipYesNo_vals), 0,
        "EssPrecipYesNo", HFILL }},
    { &hf_j2735_rainRate,
      { "rainRate", "j2735.rainRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EssPrecipRate", HFILL }},
    { &hf_j2735_precipSituation,
      { "precipSituation", "j2735.precipSituation",
        FT_UINT32, BASE_DEC, VALS(j2735_EssPrecipSituation_vals), 0,
        "EssPrecipSituation", HFILL }},
    { &hf_j2735_solarRadiation,
      { "solarRadiation", "j2735.solarRadiation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EssSolarRadiation", HFILL }},
    { &hf_j2735_friction,
      { "friction", "j2735.friction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EssMobileFriction", HFILL }},
    { &hf_j2735_roadFriction,
      { "roadFriction", "j2735.roadFriction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CoefficientOfFriction", HFILL }},
    { &hf_j2735_regionId,
      { "regionId", "j2735.regionId",
        FT_UINT32, BASE_DEC, VALS(j2735_RegionId_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_regExtValue,
      { "regExtValue", "j2735.regExtValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_long,
      { "long", "j2735.long",
        FT_INT32, BASE_DEC, NULL, 0,
        "Acceleration", HFILL }},
    { &hf_j2735_lat_02,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "Acceleration", HFILL }},
    { &hf_j2735_vert,
      { "vert", "j2735.vert",
        FT_INT32, BASE_DEC, NULL, 0,
        "VerticalAcceleration", HFILL }},
    { &hf_j2735_yaw,
      { "yaw", "j2735.yaw",
        FT_INT32, BASE_DEC, NULL, 0,
        "YawRate", HFILL }},
    { &hf_j2735_antOffsetX,
      { "antOffsetX", "j2735.antOffsetX",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B12", HFILL }},
    { &hf_j2735_antOffsetY,
      { "antOffsetY", "j2735.antOffsetY",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B09", HFILL }},
    { &hf_j2735_antOffsetZ,
      { "antOffsetZ", "j2735.antOffsetZ",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_j2735_wheelBrakes,
      { "wheelBrakes", "j2735.wheelBrakes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BrakeAppliedStatus", HFILL }},
    { &hf_j2735_traction,
      { "traction", "j2735.traction",
        FT_UINT32, BASE_DEC, VALS(j2735_TractionControlStatus_vals), 0,
        "TractionControlStatus", HFILL }},
    { &hf_j2735_abs,
      { "abs", "j2735.abs",
        FT_UINT32, BASE_DEC, VALS(j2735_AntiLockBrakeStatus_vals), 0,
        "AntiLockBrakeStatus", HFILL }},
    { &hf_j2735_scs,
      { "scs", "j2735.scs",
        FT_UINT32, BASE_DEC, VALS(j2735_StabilityControlStatus_vals), 0,
        "StabilityControlStatus", HFILL }},
    { &hf_j2735_brakeBoost,
      { "brakeBoost", "j2735.brakeBoost",
        FT_UINT32, BASE_DEC, VALS(j2735_BrakeBoostApplied_vals), 0,
        "BrakeBoostApplied", HFILL }},
    { &hf_j2735_auxBrakes,
      { "auxBrakes", "j2735.auxBrakes",
        FT_UINT32, BASE_DEC, VALS(j2735_AuxiliaryBrakeStatus_vals), 0,
        "AuxiliaryBrakeStatus", HFILL }},
    { &hf_j2735_msgCnt,
      { "msgCnt", "j2735.msgCnt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_j2735_id,
      { "id", "j2735.id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TemporaryID", HFILL }},
    { &hf_j2735_secMark,
      { "secMark", "j2735.secMark",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_j2735_lat_03,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "Latitude", HFILL }},
    { &hf_j2735_long_01,
      { "long", "j2735.long",
        FT_INT32, BASE_DEC, NULL, 0,
        "Longitude", HFILL }},
    { &hf_j2735_elev,
      { "elev", "j2735.elev",
        FT_INT32, BASE_DEC, NULL, 0,
        "Elevation", HFILL }},
    { &hf_j2735_accuracy,
      { "accuracy", "j2735.accuracy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionalAccuracy", HFILL }},
    { &hf_j2735_transmission,
      { "transmission", "j2735.transmission",
        FT_UINT32, BASE_DEC, VALS(j2735_TransmissionState_vals), 0,
        "TransmissionState", HFILL }},
    { &hf_j2735_speed,
      { "speed", "j2735.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_heading_02,
      { "heading", "j2735.heading",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_angle,
      { "angle", "j2735.angle",
        FT_INT32, BASE_DEC, NULL, 0,
        "SteeringWheelAngle", HFILL }},
    { &hf_j2735_accelSet,
      { "accelSet", "j2735.accelSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccelerationSet4Way", HFILL }},
    { &hf_j2735_brakes,
      { "brakes", "j2735.brakes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BrakeSystemStatus", HFILL }},
    { &hf_j2735_size,
      { "size", "j2735.size_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VehicleSize", HFILL }},
    { &hf_j2735_front,
      { "front", "j2735.front",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BumperHeight", HFILL }},
    { &hf_j2735_rear,
      { "rear", "j2735.rear",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BumperHeight", HFILL }},
    { &hf_j2735_referenceLaneId,
      { "referenceLaneId", "j2735.referenceLaneId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneID", HFILL }},
    { &hf_j2735_offsetXaxis,
      { "offsetXaxis", "j2735.offsetXaxis",
        FT_UINT32, BASE_DEC, VALS(j2735_T_offsetXaxis_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_small,
      { "small", "j2735.small",
        FT_INT32, BASE_DEC, NULL, 0,
        "DrivenLineOffsetSm", HFILL }},
    { &hf_j2735_large,
      { "large", "j2735.large",
        FT_INT32, BASE_DEC, NULL, 0,
        "DrivenLineOffsetLg", HFILL }},
    { &hf_j2735_offsetYaxis,
      { "offsetYaxis", "j2735.offsetYaxis",
        FT_UINT32, BASE_DEC, VALS(j2735_T_offsetYaxis_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_rotateXY,
      { "rotateXY", "j2735.rotateXY",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_j2735_scaleXaxis,
      { "scaleXaxis", "j2735.scaleXaxis",
        FT_INT32, BASE_DEC, NULL, 0,
        "Scale_B12", HFILL }},
    { &hf_j2735_scaleYaxis,
      { "scaleYaxis", "j2735.scaleYaxis",
        FT_INT32, BASE_DEC, NULL, 0,
        "Scale_B12", HFILL }},
    { &hf_j2735_year_01,
      { "year", "j2735.year",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DYear", HFILL }},
    { &hf_j2735_month_01,
      { "month", "j2735.month",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DMonth", HFILL }},
    { &hf_j2735_day_01,
      { "day", "j2735.day",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DDay", HFILL }},
    { &hf_j2735_hour_01,
      { "hour", "j2735.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DHour", HFILL }},
    { &hf_j2735_minute_01,
      { "minute", "j2735.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DMinute", HFILL }},
    { &hf_j2735_second_01,
      { "second", "j2735.second",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_j2735_offset,
      { "offset", "j2735.offset",
        FT_INT32, BASE_DEC, NULL, 0,
        "DOffset", HFILL }},
    { &hf_j2735_sirenUse,
      { "sirenUse", "j2735.sirenUse",
        FT_UINT32, BASE_DEC, VALS(j2735_SirenInUse_vals), 0,
        "SirenInUse", HFILL }},
    { &hf_j2735_lightsUse,
      { "lightsUse", "j2735.lightsUse",
        FT_UINT32, BASE_DEC, VALS(j2735_LightbarInUse_vals), 0,
        "LightbarInUse", HFILL }},
    { &hf_j2735_multi,
      { "multi", "j2735.multi",
        FT_UINT32, BASE_DEC, VALS(j2735_MultiVehicleResponse_vals), 0,
        "MultiVehicleResponse", HFILL }},
    { &hf_j2735_events,
      { "events", "j2735.events_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivilegedEvents", HFILL }},
    { &hf_j2735_responseType,
      { "responseType", "j2735.responseType",
        FT_UINT32, BASE_DEC, VALS(j2735_ResponseType_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_utcTime,
      { "utcTime", "j2735.utcTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DDateTime", HFILL }},
    { &hf_j2735_elevation_01,
      { "elevation", "j2735.elevation",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_speed_01,
      { "speed", "j2735.speed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransmissionAndSpeed", HFILL }},
    { &hf_j2735_posAccuracy,
      { "posAccuracy", "j2735.posAccuracy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionalAccuracy", HFILL }},
    { &hf_j2735_timeConfidence,
      { "timeConfidence", "j2735.timeConfidence",
        FT_UINT32, BASE_DEC, VALS(j2735_TimeConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_posConfidence,
      { "posConfidence", "j2735.posConfidence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionConfidenceSet", HFILL }},
    { &hf_j2735_speedConfidence,
      { "speedConfidence", "j2735.speedConfidence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpeedandHeadingandThrottleConfidence", HFILL }},
    { &hf_j2735_timeStamp,
      { "timeStamp", "j2735.timeStamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_j2735_msgIssueRevision,
      { "msgIssueRevision", "j2735.msgIssueRevision",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_j2735_lane,
      { "lane", "j2735.lane",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneID", HFILL }},
    { &hf_j2735_approach,
      { "approach", "j2735.approach",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApproachID", HFILL }},
    { &hf_j2735_connection_01,
      { "connection", "j2735.connection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneConnectionID", HFILL }},
    { &hf_j2735_region,
      { "region", "j2735.region",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadRegulatorID", HFILL }},
    { &hf_j2735_id_01,
      { "id", "j2735.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntersectionID", HFILL }},
    { &hf_j2735_pathEndPointAngle,
      { "pathEndPointAngle", "j2735.pathEndPointAngle",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeltaAngle", HFILL }},
    { &hf_j2735_laneCrownPointCenter,
      { "laneCrownPointCenter", "j2735.laneCrownPointCenter",
        FT_INT32, BASE_DEC, NULL, 0,
        "RoadwayCrownAngle", HFILL }},
    { &hf_j2735_laneCrownPointLeft,
      { "laneCrownPointLeft", "j2735.laneCrownPointLeft",
        FT_INT32, BASE_DEC, NULL, 0,
        "RoadwayCrownAngle", HFILL }},
    { &hf_j2735_laneCrownPointRight,
      { "laneCrownPointRight", "j2735.laneCrownPointRight",
        FT_INT32, BASE_DEC, NULL, 0,
        "RoadwayCrownAngle", HFILL }},
    { &hf_j2735_laneAngle,
      { "laneAngle", "j2735.laneAngle",
        FT_INT32, BASE_DEC, NULL, 0,
        "MergeDivergeNodeAngle", HFILL }},
    { &hf_j2735_speedLimits,
      { "speedLimits", "j2735.speedLimits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedLimitList", HFILL }},
    { &hf_j2735_LaneDataAttributeList_item,
      { "LaneDataAttribute", "j2735.LaneDataAttribute",
        FT_UINT32, BASE_DEC, VALS(j2735_LaneDataAttribute_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_lon_02,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "Longitude", HFILL }},
    { &hf_j2735_x,
      { "x", "j2735.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_j2735_y,
      { "y", "j2735.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_j2735_x_01,
      { "x", "j2735.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B11", HFILL }},
    { &hf_j2735_y_01,
      { "y", "j2735.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B11", HFILL }},
    { &hf_j2735_x_02,
      { "x", "j2735.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B12", HFILL }},
    { &hf_j2735_y_02,
      { "y", "j2735.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B12", HFILL }},
    { &hf_j2735_x_03,
      { "x", "j2735.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B13", HFILL }},
    { &hf_j2735_y_03,
      { "y", "j2735.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B13", HFILL }},
    { &hf_j2735_x_04,
      { "x", "j2735.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B14", HFILL }},
    { &hf_j2735_y_04,
      { "y", "j2735.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B14", HFILL }},
    { &hf_j2735_x_05,
      { "x", "j2735.x",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B16", HFILL }},
    { &hf_j2735_y_05,
      { "y", "j2735.y",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B16", HFILL }},
    { &hf_j2735_localNode,
      { "localNode", "j2735.localNode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NodeAttributeXYList", HFILL }},
    { &hf_j2735_disabled,
      { "disabled", "j2735.disabled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SegmentAttributeXYList", HFILL }},
    { &hf_j2735_enabled,
      { "enabled", "j2735.enabled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SegmentAttributeXYList", HFILL }},
    { &hf_j2735_data,
      { "data", "j2735.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneDataAttributeList", HFILL }},
    { &hf_j2735_dWidth,
      { "dWidth", "j2735.dWidth",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_j2735_dElevation,
      { "dElevation", "j2735.dElevation",
        FT_INT32, BASE_DEC, NULL, 0,
        "Offset_B10", HFILL }},
    { &hf_j2735_NodeAttributeXYList_item,
      { "NodeAttributeXY", "j2735.NodeAttributeXY",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeAttributeXY_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_nodes,
      { "nodes", "j2735.nodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NodeSetXY", HFILL }},
    { &hf_j2735_computed,
      { "computed", "j2735.computed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ComputedLane", HFILL }},
    { &hf_j2735_node_XY1,
      { "node-XY1", "j2735.node_XY1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_20b", HFILL }},
    { &hf_j2735_node_XY2,
      { "node-XY2", "j2735.node_XY2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_22b", HFILL }},
    { &hf_j2735_node_XY3,
      { "node-XY3", "j2735.node_XY3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_24b", HFILL }},
    { &hf_j2735_node_XY4,
      { "node-XY4", "j2735.node_XY4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_26b", HFILL }},
    { &hf_j2735_node_XY5,
      { "node-XY5", "j2735.node_XY5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_28b", HFILL }},
    { &hf_j2735_node_XY6,
      { "node-XY6", "j2735.node_XY6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_XY_32b", HFILL }},
    { &hf_j2735_node_LatLon,
      { "node-LatLon", "j2735.node_LatLon_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LLmD_64b", HFILL }},
    { &hf_j2735_regional_01,
      { "regional", "j2735.regional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegionalExtension", HFILL }},
    { &hf_j2735_NodeSetXY_item,
      { "NodeXY", "j2735.NodeXY_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_delta,
      { "delta", "j2735.delta",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeOffsetPointXY_vals), 0,
        "NodeOffsetPointXY", HFILL }},
    { &hf_j2735_attributes,
      { "attributes", "j2735.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NodeAttributeSetXY", HFILL }},
    { &hf_j2735_initialPosition,
      { "initialPosition", "j2735.initialPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FullPositionVector", HFILL }},
    { &hf_j2735_currGNSSstatus,
      { "currGNSSstatus", "j2735.currGNSSstatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GNSSstatus", HFILL }},
    { &hf_j2735_crumbData_01,
      { "crumbData", "j2735.crumbData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PathHistoryPointList", HFILL }},
    { &hf_j2735_PathHistoryPointList_item,
      { "PathHistoryPoint", "j2735.PathHistoryPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_latOffset,
      { "latOffset", "j2735.latOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B18", HFILL }},
    { &hf_j2735_lonOffset,
      { "lonOffset", "j2735.lonOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B18", HFILL }},
    { &hf_j2735_elevationOffset_01,
      { "elevationOffset", "j2735.elevationOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B12", HFILL }},
    { &hf_j2735_radiusOfCurve,
      { "radiusOfCurve", "j2735.radiusOfCurve",
        FT_INT32, BASE_DEC, NULL, 0,
        "RadiusOfCurvature", HFILL }},
    { &hf_j2735_confidence_02,
      { "confidence", "j2735.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_semiMajor,
      { "semiMajor", "j2735.semiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SemiMajorAxisAccuracy", HFILL }},
    { &hf_j2735_semiMinor,
      { "semiMinor", "j2735.semiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SemiMinorAxisAccuracy", HFILL }},
    { &hf_j2735_orientation,
      { "orientation", "j2735.orientation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SemiMajorAxisOrientation", HFILL }},
    { &hf_j2735_pos,
      { "pos", "j2735.pos",
        FT_UINT32, BASE_DEC, VALS(j2735_PositionConfidence_vals), 0,
        "PositionConfidence", HFILL }},
    { &hf_j2735_elevation_02,
      { "elevation", "j2735.elevation",
        FT_UINT32, BASE_DEC, VALS(j2735_ElevationConfidence_vals), 0,
        "ElevationConfidence", HFILL }},
    { &hf_j2735_event,
      { "event", "j2735.event",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PrivilegedEventFlags", HFILL }},
    { &hf_j2735_type,
      { "type", "j2735.type",
        FT_UINT32, BASE_DEC, VALS(j2735_SpeedLimitType_vals), 0,
        "SpeedLimitType", HFILL }},
    { &hf_j2735_speed_02,
      { "speed", "j2735.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Velocity", HFILL }},
    { &hf_j2735_role,
      { "role", "j2735.role",
        FT_UINT32, BASE_DEC, VALS(j2735_BasicVehicleRole_vals), 0,
        "BasicVehicleRole", HFILL }},
    { &hf_j2735_subrole,
      { "subrole", "j2735.subrole",
        FT_UINT32, BASE_DEC, VALS(j2735_RequestSubRole_vals), 0,
        "RequestSubRole", HFILL }},
    { &hf_j2735_request,
      { "request", "j2735.request",
        FT_UINT32, BASE_DEC, VALS(j2735_RequestImportanceLevel_vals), 0,
        "RequestImportanceLevel", HFILL }},
    { &hf_j2735_iso3883,
      { "iso3883", "j2735.iso3883",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Iso3833VehicleType", HFILL }},
    { &hf_j2735_hpmsType,
      { "hpmsType", "j2735.hpmsType",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleType_vals), 0,
        "VehicleType", HFILL }},
    { &hf_j2735_id_02,
      { "id", "j2735.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadSegmentID", HFILL }},
    { &hf_j2735_status_01,
      { "status", "j2735.status",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GNSSstatus", HFILL }},
    { &hf_j2735_offsetSet,
      { "offsetSet", "j2735.offsetSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AntennaOffsetSet", HFILL }},
    { &hf_j2735_RTCMmessageList_item,
      { "RTCMmessage", "j2735.RTCMmessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SegmentAttributeXYList_item,
      { "SegmentAttributeXY", "j2735.SegmentAttributeXY",
        FT_UINT32, BASE_DEC, VALS(j2735_SegmentAttributeXY_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_heading_03,
      { "heading", "j2735.heading",
        FT_UINT32, BASE_DEC, VALS(j2735_HeadingConfidence_vals), 0,
        "HeadingConfidence", HFILL }},
    { &hf_j2735_speed_03,
      { "speed", "j2735.speed",
        FT_UINT32, BASE_DEC, VALS(j2735_SpeedConfidence_vals), 0,
        "SpeedConfidence", HFILL }},
    { &hf_j2735_throttle,
      { "throttle", "j2735.throttle",
        FT_UINT32, BASE_DEC, VALS(j2735_ThrottleConfidence_vals), 0,
        "ThrottleConfidence", HFILL }},
    { &hf_j2735_SpeedLimitList_item,
      { "RegulatorySpeedLimit", "j2735.RegulatorySpeedLimit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_transmisson,
      { "transmisson", "j2735.transmisson",
        FT_UINT32, BASE_DEC, VALS(j2735_TransmissionState_vals), 0,
        "TransmissionState", HFILL }},
    { &hf_j2735_keyType,
      { "keyType", "j2735.keyType",
        FT_UINT32, BASE_DEC, VALS(j2735_BasicVehicleClass_vals), 0,
        "BasicVehicleClass", HFILL }},
    { &hf_j2735_vehicleType,
      { "vehicleType", "j2735.vehicleType",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleGroupAffected_vals), 0,
        "VehicleGroupAffected", HFILL }},
    { &hf_j2735_responseEquip,
      { "responseEquip", "j2735.responseEquip",
        FT_UINT32, BASE_DEC, VALS(j2735_IncidentResponseEquipment_vals), 0,
        "IncidentResponseEquipment", HFILL }},
    { &hf_j2735_responderType,
      { "responderType", "j2735.responderType",
        FT_UINT32, BASE_DEC, VALS(j2735_ResponderGroupAffected_vals), 0,
        "ResponderGroupAffected", HFILL }},
    { &hf_j2735_fuelType,
      { "fuelType", "j2735.fuelType",
        FT_UINT32, BASE_DEC, VALS(j2735_FuelType_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_entityID,
      { "entityID", "j2735.entityID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TemporaryID", HFILL }},
    { &hf_j2735_events_01,
      { "events", "j2735.events",
        FT_BYTES, BASE_NONE, NULL, 0,
        "VehicleEventFlags", HFILL }},
    { &hf_j2735_pathHistory,
      { "pathHistory", "j2735.pathHistory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_pathPrediction,
      { "pathPrediction", "j2735.pathPrediction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_lights,
      { "lights", "j2735.lights",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ExteriorLights", HFILL }},
    { &hf_j2735_offset1,
      { "offset1", "j2735.offset1",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B07", HFILL }},
    { &hf_j2735_offset2,
      { "offset2", "j2735.offset2",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B08", HFILL }},
    { &hf_j2735_offset3,
      { "offset3", "j2735.offset3",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B09", HFILL }},
    { &hf_j2735_offset4,
      { "offset4", "j2735.offset4",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B10", HFILL }},
    { &hf_j2735_offset5,
      { "offset5", "j2735.offset5",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B11", HFILL }},
    { &hf_j2735_offset6,
      { "offset6", "j2735.offset6",
        FT_INT32, BASE_DEC, NULL, 0,
        "VertOffset_B12", HFILL }},
    { &hf_j2735_statusFront,
      { "statusFront", "j2735.statusFront",
        FT_UINT32, BASE_DEC, VALS(j2735_WiperStatus_vals), 0,
        "WiperStatus", HFILL }},
    { &hf_j2735_rateFront,
      { "rateFront", "j2735.rateFront",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WiperRate", HFILL }},
    { &hf_j2735_statusRear,
      { "statusRear", "j2735.statusRear",
        FT_UINT32, BASE_DEC, VALS(j2735_WiperStatus_vals), 0,
        "WiperStatus", HFILL }},
    { &hf_j2735_rateRear,
      { "rateRear", "j2735.rateRear",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WiperRate", HFILL }},
    { &hf_j2735_requests,
      { "requests", "j2735.requests",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestedItemList", HFILL }},
    { &hf_j2735_RequestedItemList_item,
      { "RequestedItem", "j2735.RequestedItem",
        FT_UINT32, BASE_DEC, VALS(j2735_RequestedItem_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_rsaMsg,
      { "rsaMsg", "j2735.rsaMsg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoadSideAlert", HFILL }},
    { &hf_j2735_details,
      { "details", "j2735.details_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EmergencyDetails", HFILL }},
    { &hf_j2735_basicType,
      { "basicType", "j2735.basicType",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleType_vals), 0,
        "VehicleType", HFILL }},
    { &hf_j2735_partOne,
      { "partOne", "j2735.partOne_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BSMcoreData", HFILL }},
    { &hf_j2735_path,
      { "path", "j2735.path_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PathHistory", HFILL }},
    { &hf_j2735_intersectionID,
      { "intersectionID", "j2735.intersectionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntersectionReferenceID", HFILL }},
    { &hf_j2735_laneNumber,
      { "laneNumber", "j2735.laneNumber",
        FT_UINT32, BASE_DEC, VALS(j2735_ApproachOrLane_vals), 0,
        "ApproachOrLane", HFILL }},
    { &hf_j2735_eventFlag,
      { "eventFlag", "j2735.eventFlag",
        FT_BYTES, BASE_NONE, NULL, 0,
        "VehicleEventFlags", HFILL }},
    { &hf_j2735_ITIScodesAndText_item,
      { "ITIScodesAndText item", "j2735.ITIScodesAndText_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_item,
      { "item", "j2735.item",
        FT_UINT32, BASE_DEC, VALS(j2735_T_item_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_itis,
      { "itis", "j2735.itis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ITIScodes", HFILL }},
    { &hf_j2735_text,
      { "text", "j2735.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "ITIStext", HFILL }},
    { &hf_j2735_layerType,
      { "layerType", "j2735.layerType",
        FT_UINT32, BASE_DEC, VALS(j2735_LayerType_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_layerID,
      { "layerID", "j2735.layerID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_intersections,
      { "intersections", "j2735.intersections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntersectionGeometryList", HFILL }},
    { &hf_j2735_roadSegments,
      { "roadSegments", "j2735.roadSegments",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadSegmentList", HFILL }},
    { &hf_j2735_dataParameters,
      { "dataParameters", "j2735.dataParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_restrictionList,
      { "restrictionList", "j2735.restrictionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassList", HFILL }},
    { &hf_j2735_maneuver,
      { "maneuver", "j2735.maneuver",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AllowedManeuvers", HFILL }},
    { &hf_j2735_connectingLane,
      { "connectingLane", "j2735.connectingLane_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_remoteIntersection,
      { "remoteIntersection", "j2735.remoteIntersection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntersectionReferenceID", HFILL }},
    { &hf_j2735_userClass,
      { "userClass", "j2735.userClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassID", HFILL }},
    { &hf_j2735_connectionID,
      { "connectionID", "j2735.connectionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneConnectionID", HFILL }},
    { &hf_j2735_ConnectsToList_item,
      { "Connection", "j2735.Connection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_processMethod,
      { "processMethod", "j2735.processMethod",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_j2735_processAgency,
      { "processAgency", "j2735.processAgency",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_j2735_lastCheckedDate,
      { "lastCheckedDate", "j2735.lastCheckedDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_j2735_geoidUsed,
      { "geoidUsed", "j2735.geoidUsed",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_255", HFILL }},
    { &hf_j2735_name,
      { "name", "j2735.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "DescriptiveName", HFILL }},
    { &hf_j2735_ingressApproach,
      { "ingressApproach", "j2735.ingressApproach",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApproachID", HFILL }},
    { &hf_j2735_egressApproach,
      { "egressApproach", "j2735.egressApproach",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ApproachID", HFILL }},
    { &hf_j2735_laneAttributes,
      { "laneAttributes", "j2735.laneAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_maneuvers,
      { "maneuvers", "j2735.maneuvers",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AllowedManeuvers", HFILL }},
    { &hf_j2735_nodeList,
      { "nodeList", "j2735.nodeList",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeListXY_vals), 0,
        "NodeListXY", HFILL }},
    { &hf_j2735_connectsTo,
      { "connectsTo", "j2735.connectsTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ConnectsToList", HFILL }},
    { &hf_j2735_overlays,
      { "overlays", "j2735.overlays",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OverlayLaneList", HFILL }},
    { &hf_j2735_id_03,
      { "id", "j2735.id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntersectionReferenceID", HFILL }},
    { &hf_j2735_revision,
      { "revision", "j2735.revision",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_j2735_refPoint,
      { "refPoint", "j2735.refPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position3D", HFILL }},
    { &hf_j2735_laneWidth,
      { "laneWidth", "j2735.laneWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_laneSet,
      { "laneSet", "j2735.laneSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LaneList", HFILL }},
    { &hf_j2735_preemptPriorityData,
      { "preemptPriorityData", "j2735.preemptPriorityData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PreemptPriorityList", HFILL }},
    { &hf_j2735_IntersectionGeometryList_item,
      { "IntersectionGeometry", "j2735.IntersectionGeometry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_directionalUse,
      { "directionalUse", "j2735.directionalUse",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneDirection", HFILL }},
    { &hf_j2735_sharedWith,
      { "sharedWith", "j2735.sharedWith",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneSharing", HFILL }},
    { &hf_j2735_laneType,
      { "laneType", "j2735.laneType",
        FT_UINT32, BASE_DEC, VALS(j2735_LaneTypeAttributes_vals), 0,
        "LaneTypeAttributes", HFILL }},
    { &hf_j2735_LaneList_item,
      { "GenericLane", "j2735.GenericLane_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_vehicle,
      { "vehicle", "j2735.vehicle",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Vehicle", HFILL }},
    { &hf_j2735_crosswalk,
      { "crosswalk", "j2735.crosswalk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Crosswalk", HFILL }},
    { &hf_j2735_bikeLane,
      { "bikeLane", "j2735.bikeLane",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Bike", HFILL }},
    { &hf_j2735_sidewalk,
      { "sidewalk", "j2735.sidewalk",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Sidewalk", HFILL }},
    { &hf_j2735_median,
      { "median", "j2735.median",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Barrier", HFILL }},
    { &hf_j2735_striping,
      { "striping", "j2735.striping",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Striping", HFILL }},
    { &hf_j2735_trackedVehicle,
      { "trackedVehicle", "j2735.trackedVehicle",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_TrackedVehicle", HFILL }},
    { &hf_j2735_parking,
      { "parking", "j2735.parking",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LaneAttributes_Parking", HFILL }},
    { &hf_j2735_OverlayLaneList_item,
      { "LaneID", "j2735.LaneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_PreemptPriorityList_item,
      { "SignalControlZone", "j2735.SignalControlZone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_zone,
      { "zone", "j2735.zone_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegionalExtension", HFILL }},
    { &hf_j2735_id_04,
      { "id", "j2735.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassID", HFILL }},
    { &hf_j2735_users,
      { "users", "j2735.users",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionUserTypeList", HFILL }},
    { &hf_j2735_RestrictionClassList_item,
      { "RestrictionClassAssignment", "j2735.RestrictionClassAssignment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_RestrictionUserTypeList_item,
      { "RestrictionUserType", "j2735.RestrictionUserType",
        FT_UINT32, BASE_DEC, VALS(j2735_RestrictionUserType_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_basicType_01,
      { "basicType", "j2735.basicType",
        FT_UINT32, BASE_DEC, VALS(j2735_RestrictionAppliesTo_vals), 0,
        "RestrictionAppliesTo", HFILL }},
    { &hf_j2735_RoadLaneSetList_item,
      { "GenericLane", "j2735.GenericLane_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_RoadSegmentList_item,
      { "RoadSegment", "j2735.RoadSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_id_05,
      { "id", "j2735.id_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoadSegmentReferenceID", HFILL }},
    { &hf_j2735_roadLaneSet,
      { "roadLaneSet", "j2735.roadLaneSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoadLaneSetList", HFILL }},
    { &hf_j2735_messageId,
      { "messageId", "j2735.messageId",
        FT_UINT32, BASE_DEC, VALS(j2735_DSRCmsgID_vals), 0,
        "DSRCmsgID", HFILL }},
    { &hf_j2735_value_01,
      { "value", "j2735.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_rev,
      { "rev", "j2735.rev",
        FT_UINT32, BASE_DEC, VALS(j2735_NMEA_Revision_vals), 0,
        "NMEA_Revision", HFILL }},
    { &hf_j2735_msg,
      { "msg", "j2735.msg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NMEA_MsgType", HFILL }},
    { &hf_j2735_wdCount,
      { "wdCount", "j2735.wdCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ObjectCount", HFILL }},
    { &hf_j2735_payload,
      { "payload", "j2735.payload",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NMEA_Payload", HFILL }},
    { &hf_j2735_basicType_02,
      { "basicType", "j2735.basicType",
        FT_UINT32, BASE_DEC, VALS(j2735_PersonalDeviceUserType_vals), 0,
        "PersonalDeviceUserType", HFILL }},
    { &hf_j2735_position,
      { "position", "j2735.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position3D", HFILL }},
    { &hf_j2735_propulsion,
      { "propulsion", "j2735.propulsion",
        FT_UINT32, BASE_DEC, VALS(j2735_PropelledInformation_vals), 0,
        "PropelledInformation", HFILL }},
    { &hf_j2735_useState,
      { "useState", "j2735.useState",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PersonalDeviceUsageState", HFILL }},
    { &hf_j2735_crossRequest,
      { "crossRequest", "j2735.crossRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PersonalCrossingRequest", HFILL }},
    { &hf_j2735_crossState,
      { "crossState", "j2735.crossState",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PersonalCrossingInProgress", HFILL }},
    { &hf_j2735_clusterSize,
      { "clusterSize", "j2735.clusterSize",
        FT_UINT32, BASE_DEC, VALS(j2735_NumberOfParticipantsInCluster_vals), 0,
        "NumberOfParticipantsInCluster", HFILL }},
    { &hf_j2735_clusterRadius,
      { "clusterRadius", "j2735.clusterRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PersonalClusterRadius", HFILL }},
    { &hf_j2735_eventResponderType,
      { "eventResponderType", "j2735.eventResponderType",
        FT_UINT32, BASE_DEC, VALS(j2735_PublicSafetyEventResponderWorkerType_vals), 0,
        "PublicSafetyEventResponderWorkerType", HFILL }},
    { &hf_j2735_activityType,
      { "activityType", "j2735.activityType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PublicSafetyAndRoadWorkerActivity", HFILL }},
    { &hf_j2735_activitySubType,
      { "activitySubType", "j2735.activitySubType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PublicSafetyDirectingTrafficSubType", HFILL }},
    { &hf_j2735_assistType,
      { "assistType", "j2735.assistType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PersonalAssistive", HFILL }},
    { &hf_j2735_sizing,
      { "sizing", "j2735.sizing",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UserSizeAndBehaviour", HFILL }},
    { &hf_j2735_attachment,
      { "attachment", "j2735.attachment",
        FT_UINT32, BASE_DEC, VALS(j2735_Attachment_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_attachmentRadius,
      { "attachmentRadius", "j2735.attachmentRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_animalType,
      { "animalType", "j2735.animalType",
        FT_UINT32, BASE_DEC, VALS(j2735_AnimalType_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_human,
      { "human", "j2735.human",
        FT_UINT32, BASE_DEC, VALS(j2735_HumanPropelledType_vals), 0,
        "HumanPropelledType", HFILL }},
    { &hf_j2735_animal,
      { "animal", "j2735.animal",
        FT_UINT32, BASE_DEC, VALS(j2735_AnimalPropelledType_vals), 0,
        "AnimalPropelledType", HFILL }},
    { &hf_j2735_motor,
      { "motor", "j2735.motor",
        FT_UINT32, BASE_DEC, VALS(j2735_MotorizedPropelledType_vals), 0,
        "MotorizedPropelledType", HFILL }},
    { &hf_j2735_sample,
      { "sample", "j2735.sample_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_directions,
      { "directions", "j2735.directions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HeadingSlice", HFILL }},
    { &hf_j2735_term,
      { "term", "j2735.term",
        FT_UINT32, BASE_DEC, VALS(j2735_T_term_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_termtime,
      { "termtime", "j2735.termtime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_termDistance,
      { "termDistance", "j2735.termDistance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_snapshot,
      { "snapshot", "j2735.snapshot",
        FT_UINT32, BASE_DEC, VALS(j2735_T_snapshot_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_snapshotTime,
      { "snapshotTime", "j2735.snapshotTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_snapshotDistance,
      { "snapshotDistance", "j2735.snapshotDistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_txInterval,
      { "txInterval", "j2735.txInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecondOfTime", HFILL }},
    { &hf_j2735_dataElements,
      { "dataElements", "j2735.dataElements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VehicleStatusRequestList", HFILL }},
    { &hf_j2735_sampleStart,
      { "sampleStart", "j2735.sampleStart",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_j2735_sampleEnd,
      { "sampleEnd", "j2735.sampleEnd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_j2735_distance1,
      { "distance1", "j2735.distance1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GrossDistance", HFILL }},
    { &hf_j2735_speed1,
      { "speed1", "j2735.speed1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GrossSpeed", HFILL }},
    { &hf_j2735_distance2,
      { "distance2", "j2735.distance2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GrossDistance", HFILL }},
    { &hf_j2735_speed2,
      { "speed2", "j2735.speed2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GrossSpeed", HFILL }},
    { &hf_j2735_time1,
      { "time1", "j2735.time1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecondOfTime", HFILL }},
    { &hf_j2735_time2,
      { "time2", "j2735.time2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecondOfTime", HFILL }},
    { &hf_j2735_dataType,
      { "dataType", "j2735.dataType",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleStatusDeviceTypeTag_vals), 0,
        "VehicleStatusDeviceTypeTag", HFILL }},
    { &hf_j2735_subType,
      { "subType", "j2735.subType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15", HFILL }},
    { &hf_j2735_sendOnLessThenValue,
      { "sendOnLessThenValue", "j2735.sendOnLessThenValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32767_32767", HFILL }},
    { &hf_j2735_sendOnMoreThenValue,
      { "sendOnMoreThenValue", "j2735.sendOnMoreThenValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32767_32767", HFILL }},
    { &hf_j2735_sendAll,
      { "sendAll", "j2735.sendAll",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_j2735_VehicleStatusRequestList_item,
      { "VehicleStatusRequest", "j2735.VehicleStatusRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_segNum,
      { "segNum", "j2735.segNum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProbeSegmentNumber", HFILL }},
    { &hf_j2735_probeID,
      { "probeID", "j2735.probeID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VehicleIdent", HFILL }},
    { &hf_j2735_startVector,
      { "startVector", "j2735.startVector_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FullPositionVector", HFILL }},
    { &hf_j2735_vehicleType_01,
      { "vehicleType", "j2735.vehicleType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VehicleClassification", HFILL }},
    { &hf_j2735_snapshots,
      { "snapshots", "j2735.snapshots",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_32_OF_Snapshot", HFILL }},
    { &hf_j2735_snapshots_item,
      { "Snapshot", "j2735.Snapshot_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_yawRate,
      { "yawRate", "j2735.yawRate",
        FT_UINT32, BASE_DEC, VALS(j2735_YawRateConfidence_vals), 0,
        "YawRateConfidence", HFILL }},
    { &hf_j2735_acceleration,
      { "acceleration", "j2735.acceleration",
        FT_UINT32, BASE_DEC, VALS(j2735_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_j2735_steeringWheelAngle,
      { "steeringWheelAngle", "j2735.steeringWheelAngle",
        FT_UINT32, BASE_DEC, VALS(j2735_SteeringWheelAngleConfidence_vals), 0,
        "SteeringWheelAngleConfidence", HFILL }},
    { &hf_j2735_accelConfidence,
      { "accelConfidence", "j2735.accelConfidence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccelSteerYawRateConfidence", HFILL }},
    { &hf_j2735_steerConfidence,
      { "steerConfidence", "j2735.steerConfidence",
        FT_UINT32, BASE_DEC, VALS(j2735_SteeringWheelAngleConfidence_vals), 0,
        "SteeringWheelAngleConfidence", HFILL }},
    { &hf_j2735_headingConfidence,
      { "headingConfidence", "j2735.headingConfidence",
        FT_UINT32, BASE_DEC, VALS(j2735_HeadingConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_throttleConfidence,
      { "throttleConfidence", "j2735.throttleConfidence",
        FT_UINT32, BASE_DEC, VALS(j2735_ThrottleConfidence_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_tires,
      { "tires", "j2735.tires",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TireDataList", HFILL }},
    { &hf_j2735_axles,
      { "axles", "j2735.axles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AxleWeightList", HFILL }},
    { &hf_j2735_cargoWeight,
      { "cargoWeight", "j2735.cargoWeight",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_steeringAxleTemperature,
      { "steeringAxleTemperature", "j2735.steeringAxleTemperature",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_driveAxleLocation,
      { "driveAxleLocation", "j2735.driveAxleLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_driveAxleLiftAirPressure,
      { "driveAxleLiftAirPressure", "j2735.driveAxleLiftAirPressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_driveAxleTemperature,
      { "driveAxleTemperature", "j2735.driveAxleTemperature",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_driveAxleLubePressure,
      { "driveAxleLubePressure", "j2735.driveAxleLubePressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_steeringAxleLubePressure,
      { "steeringAxleLubePressure", "j2735.steeringAxleLubePressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_TireDataList_item,
      { "TireData", "j2735.TireData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_location,
      { "location", "j2735.location",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TireLocation", HFILL }},
    { &hf_j2735_pressure,
      { "pressure", "j2735.pressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TirePressure", HFILL }},
    { &hf_j2735_temp,
      { "temp", "j2735.temp",
        FT_INT32, BASE_DEC, NULL, 0,
        "TireTemp", HFILL }},
    { &hf_j2735_wheelSensorStatus,
      { "wheelSensorStatus", "j2735.wheelSensorStatus",
        FT_UINT32, BASE_DEC, VALS(j2735_WheelSensorStatus_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_wheelEndElectFault,
      { "wheelEndElectFault", "j2735.wheelEndElectFault",
        FT_UINT32, BASE_DEC, VALS(j2735_WheelEndElectFault_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_leakageRate,
      { "leakageRate", "j2735.leakageRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TireLeakageRate", HFILL }},
    { &hf_j2735_detection,
      { "detection", "j2735.detection",
        FT_UINT32, BASE_DEC, VALS(j2735_TirePressureThresholdDetection_vals), 0,
        "TirePressureThresholdDetection", HFILL }},
    { &hf_j2735_AxleWeightList_item,
      { "AxleWeightSet", "j2735.AxleWeightSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_location_01,
      { "location", "j2735.location",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AxleLocation", HFILL }},
    { &hf_j2735_weight,
      { "weight", "j2735.weight",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AxleWeight", HFILL }},
    { &hf_j2735_thePosition,
      { "thePosition", "j2735.thePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FullPositionVector", HFILL }},
    { &hf_j2735_safetyExt,
      { "safetyExt", "j2735.safetyExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VehicleSafetyExtensions", HFILL }},
    { &hf_j2735_dataSet,
      { "dataSet", "j2735.dataSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "VehicleStatus", HFILL }},
    { &hf_j2735_vin,
      { "vin", "j2735.vin",
        FT_BYTES, BASE_NONE, NULL, 0,
        "VINstring", HFILL }},
    { &hf_j2735_ownerCode,
      { "ownerCode", "j2735.ownerCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_32", HFILL }},
    { &hf_j2735_id_06,
      { "id", "j2735.id",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleID_vals), 0,
        "VehicleID", HFILL }},
    { &hf_j2735_vehicleType_02,
      { "vehicleType", "j2735.vehicleType",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleType_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_vehicleClass,
      { "vehicleClass", "j2735.vehicleClass",
        FT_UINT32, BASE_DEC, VALS(j2735_T_vehicleClass_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_vGroup,
      { "vGroup", "j2735.vGroup",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleGroupAffected_vals), 0,
        "VehicleGroupAffected", HFILL }},
    { &hf_j2735_rGroup,
      { "rGroup", "j2735.rGroup",
        FT_UINT32, BASE_DEC, VALS(j2735_ResponderGroupAffected_vals), 0,
        "ResponderGroupAffected", HFILL }},
    { &hf_j2735_rEquip,
      { "rEquip", "j2735.rEquip",
        FT_UINT32, BASE_DEC, VALS(j2735_IncidentResponseEquipment_vals), 0,
        "IncidentResponseEquipment", HFILL }},
    { &hf_j2735_lightBar,
      { "lightBar", "j2735.lightBar",
        FT_UINT32, BASE_DEC, VALS(j2735_LightbarInUse_vals), 0,
        "LightbarInUse", HFILL }},
    { &hf_j2735_wipers,
      { "wipers", "j2735.wipers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WiperSet", HFILL }},
    { &hf_j2735_brakeStatus,
      { "brakeStatus", "j2735.brakeStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "BrakeSystemStatus", HFILL }},
    { &hf_j2735_brakePressure,
      { "brakePressure", "j2735.brakePressure",
        FT_UINT32, BASE_DEC, VALS(j2735_BrakeAppliedPressure_vals), 0,
        "BrakeAppliedPressure", HFILL }},
    { &hf_j2735_sunData,
      { "sunData", "j2735.sunData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SunSensor", HFILL }},
    { &hf_j2735_rainData,
      { "rainData", "j2735.rainData",
        FT_UINT32, BASE_DEC, VALS(j2735_RainSensor_vals), 0,
        "RainSensor", HFILL }},
    { &hf_j2735_airPres,
      { "airPres", "j2735.airPres",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AmbientAirPressure", HFILL }},
    { &hf_j2735_steering,
      { "steering", "j2735.steering_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_confidence_03,
      { "confidence", "j2735.confidence",
        FT_UINT32, BASE_DEC, VALS(j2735_SteeringWheelAngleConfidence_vals), 0,
        "SteeringWheelAngleConfidence", HFILL }},
    { &hf_j2735_rate,
      { "rate", "j2735.rate",
        FT_INT32, BASE_DEC, NULL, 0,
        "SteeringWheelAngleRateOfChange", HFILL }},
    { &hf_j2735_wheels,
      { "wheels", "j2735.wheels",
        FT_INT32, BASE_DEC, NULL, 0,
        "DrivingWheelAngle", HFILL }},
    { &hf_j2735_accelSets,
      { "accelSets", "j2735.accelSets_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_accel4way,
      { "accel4way", "j2735.accel4way_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccelerationSet4Way", HFILL }},
    { &hf_j2735_vertAccelThres,
      { "vertAccelThres", "j2735.vertAccelThres",
        FT_BYTES, BASE_NONE, NULL, 0,
        "VerticalAccelerationThreshold", HFILL }},
    { &hf_j2735_yawRateCon,
      { "yawRateCon", "j2735.yawRateCon",
        FT_UINT32, BASE_DEC, VALS(j2735_YawRateConfidence_vals), 0,
        "YawRateConfidence", HFILL }},
    { &hf_j2735_hozAccelCon,
      { "hozAccelCon", "j2735.hozAccelCon",
        FT_UINT32, BASE_DEC, VALS(j2735_AccelerationConfidence_vals), 0,
        "AccelerationConfidence", HFILL }},
    { &hf_j2735_confidenceSet,
      { "confidenceSet", "j2735.confidenceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_object,
      { "object", "j2735.object_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_obDirect_01,
      { "obDirect", "j2735.obDirect",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_j2735_fullPos,
      { "fullPos", "j2735.fullPos_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FullPositionVector", HFILL }},
    { &hf_j2735_throttlePos,
      { "throttlePos", "j2735.throttlePos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ThrottlePosition", HFILL }},
    { &hf_j2735_speedHeadC,
      { "speedHeadC", "j2735.speedHeadC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpeedandHeadingandThrottleConfidence", HFILL }},
    { &hf_j2735_speedC,
      { "speedC", "j2735.speedC",
        FT_UINT32, BASE_DEC, VALS(j2735_SpeedConfidence_vals), 0,
        "SpeedConfidence", HFILL }},
    { &hf_j2735_vehicleData_01,
      { "vehicleData", "j2735.vehicleData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_type_01,
      { "type", "j2735.type",
        FT_UINT32, BASE_DEC, VALS(j2735_VehicleType_vals), 0,
        "VehicleType", HFILL }},
    { &hf_j2735_vehicleIdent,
      { "vehicleIdent", "j2735.vehicleIdent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_j1939data,
      { "j1939data", "j2735.j1939data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_weatherReport_01,
      { "weatherReport", "j2735.weatherReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_gnssStatus,
      { "gnssStatus", "j2735.gnssStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_position_01,
      { "position", "j2735.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FullPositionVector", HFILL }},
    { &hf_j2735_furtherInfoID,
      { "furtherInfoID", "j2735.furtherInfoID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_rev_01,
      { "rev", "j2735.rev",
        FT_UINT32, BASE_DEC, VALS(j2735_RTCM_Revision_vals), 0,
        "RTCM_Revision", HFILL }},
    { &hf_j2735_anchorPoint,
      { "anchorPoint", "j2735.anchorPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FullPositionVector", HFILL }},
    { &hf_j2735_sequenceNumber,
      { "sequenceNumber", "j2735.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCount", HFILL }},
    { &hf_j2735_requests_01,
      { "requests", "j2735.requests",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalRequestList", HFILL }},
    { &hf_j2735_requestor,
      { "requestor", "j2735.requestor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorDescription", HFILL }},
    { &hf_j2735_type_02,
      { "type", "j2735.type_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorType", HFILL }},
    { &hf_j2735_position_02,
      { "position", "j2735.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorPositionVector", HFILL }},
    { &hf_j2735_routeName,
      { "routeName", "j2735.routeName",
        FT_STRING, BASE_NONE, NULL, 0,
        "DescriptiveName", HFILL }},
    { &hf_j2735_transitStatus,
      { "transitStatus", "j2735.transitStatus",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransitVehicleStatus", HFILL }},
    { &hf_j2735_transitOccupancy,
      { "transitOccupancy", "j2735.transitOccupancy",
        FT_UINT32, BASE_DEC, VALS(j2735_TransitVehicleOccupancy_vals), 0,
        "TransitVehicleOccupancy", HFILL }},
    { &hf_j2735_transitSchedule,
      { "transitSchedule", "j2735.transitSchedule",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeltaTime", HFILL }},
    { &hf_j2735_heading_04,
      { "heading", "j2735.heading",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_j2735_SignalRequestList_item,
      { "SignalRequestPackage", "j2735.SignalRequestPackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_request_01,
      { "request", "j2735.request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalRequest", HFILL }},
    { &hf_j2735_minute_02,
      { "minute", "j2735.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_j2735_duration,
      { "duration", "j2735.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_j2735_requestID,
      { "requestID", "j2735.requestID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_requestType,
      { "requestType", "j2735.requestType",
        FT_UINT32, BASE_DEC, VALS(j2735_PriorityRequestType_vals), 0,
        "PriorityRequestType", HFILL }},
    { &hf_j2735_inBoundLane,
      { "inBoundLane", "j2735.inBoundLane",
        FT_UINT32, BASE_DEC, VALS(j2735_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_j2735_outBoundLane,
      { "outBoundLane", "j2735.outBoundLane",
        FT_UINT32, BASE_DEC, VALS(j2735_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_j2735_status_02,
      { "status", "j2735.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalStatusList", HFILL }},
    { &hf_j2735_request_02,
      { "request", "j2735.request",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestID", HFILL }},
    { &hf_j2735_typeData,
      { "typeData", "j2735.typeData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestorType", HFILL }},
    { &hf_j2735_SignalStatusList_item,
      { "SignalStatus", "j2735.SignalStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_SignalStatusPackageList_item,
      { "SignalStatusPackage", "j2735.SignalStatusPackage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_requester,
      { "requester", "j2735.requester_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignalRequesterInfo", HFILL }},
    { &hf_j2735_inboundOn,
      { "inboundOn", "j2735.inboundOn",
        FT_UINT32, BASE_DEC, VALS(j2735_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_j2735_outboundOn,
      { "outboundOn", "j2735.outboundOn",
        FT_UINT32, BASE_DEC, VALS(j2735_IntersectionAccessPoint_vals), 0,
        "IntersectionAccessPoint", HFILL }},
    { &hf_j2735_status_03,
      { "status", "j2735.status",
        FT_UINT32, BASE_DEC, VALS(j2735_PrioritizationResponseStatus_vals), 0,
        "PrioritizationResponseStatus", HFILL }},
    { &hf_j2735_sigStatus,
      { "sigStatus", "j2735.sigStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignalStatusPackageList", HFILL }},
    { &hf_j2735_intersections_01,
      { "intersections", "j2735.intersections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IntersectionStateList", HFILL }},
    { &hf_j2735_type_03,
      { "type", "j2735.type",
        FT_UINT32, BASE_DEC, VALS(j2735_AdvisorySpeedType_vals), 0,
        "AdvisorySpeedType", HFILL }},
    { &hf_j2735_speed_04,
      { "speed", "j2735.speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SpeedAdvice", HFILL }},
    { &hf_j2735_confidence_04,
      { "confidence", "j2735.confidence",
        FT_UINT32, BASE_DEC, VALS(j2735_SpeedConfidence_vals), 0,
        "SpeedConfidence", HFILL }},
    { &hf_j2735_distance,
      { "distance", "j2735.distance",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoneLength", HFILL }},
    { &hf_j2735_class,
      { "class", "j2735.class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RestrictionClassID", HFILL }},
    { &hf_j2735_AdvisorySpeedList_item,
      { "AdvisorySpeed", "j2735.AdvisorySpeed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_queueLength,
      { "queueLength", "j2735.queueLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoneLength", HFILL }},
    { &hf_j2735_availableStorageLength,
      { "availableStorageLength", "j2735.availableStorageLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ZoneLength", HFILL }},
    { &hf_j2735_waitOnStop,
      { "waitOnStop", "j2735.waitOnStop",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "WaitOnStopline", HFILL }},
    { &hf_j2735_pedBicycleDetect,
      { "pedBicycleDetect", "j2735.pedBicycleDetect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PedestrianBicycleDetect", HFILL }},
    { &hf_j2735_EnabledLaneList_item,
      { "LaneID", "j2735.LaneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_status_04,
      { "status", "j2735.status",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IntersectionStatusObject", HFILL }},
    { &hf_j2735_moy,
      { "moy", "j2735.moy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_j2735_timeStamp_01,
      { "timeStamp", "j2735.timeStamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DSecond", HFILL }},
    { &hf_j2735_enabledLanes,
      { "enabledLanes", "j2735.enabledLanes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EnabledLaneList", HFILL }},
    { &hf_j2735_states,
      { "states", "j2735.states",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MovementList", HFILL }},
    { &hf_j2735_maneuverAssistList,
      { "maneuverAssistList", "j2735.maneuverAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStateList_item,
      { "IntersectionState", "j2735.IntersectionState_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_ManeuverAssistList_item,
      { "ConnectionManeuverAssist", "j2735.ConnectionManeuverAssist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_MovementEventList_item,
      { "MovementEvent", "j2735.MovementEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_eventState,
      { "eventState", "j2735.eventState",
        FT_UINT32, BASE_DEC, VALS(j2735_MovementPhaseState_vals), 0,
        "MovementPhaseState", HFILL }},
    { &hf_j2735_timing,
      { "timing", "j2735.timing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeChangeDetails", HFILL }},
    { &hf_j2735_speeds,
      { "speeds", "j2735.speeds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdvisorySpeedList", HFILL }},
    { &hf_j2735_MovementList_item,
      { "MovementState", "j2735.MovementState_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_movementName,
      { "movementName", "j2735.movementName",
        FT_STRING, BASE_NONE, NULL, 0,
        "DescriptiveName", HFILL }},
    { &hf_j2735_state_time_speed,
      { "state-time-speed", "j2735.state_time_speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MovementEventList", HFILL }},
    { &hf_j2735_startTime_01,
      { "startTime", "j2735.startTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_j2735_minEndTime_01,
      { "minEndTime", "j2735.minEndTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_j2735_maxEndTime_01,
      { "maxEndTime", "j2735.maxEndTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_j2735_likelyTime_01,
      { "likelyTime", "j2735.likelyTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_j2735_nextTime_01,
      { "nextTime", "j2735.nextTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeMark", HFILL }},
    { &hf_j2735_header,
      { "header", "j2735.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_packetID,
      { "packetID", "j2735.packetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueMSGID", HFILL }},
    { &hf_j2735_urlB,
      { "urlB", "j2735.urlB",
        FT_STRING, BASE_NONE, NULL, 0,
        "URL_Base", HFILL }},
    { &hf_j2735_dataFrames,
      { "dataFrames", "j2735.dataFrames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TravelerDataFrameList", HFILL }},
    { &hf_j2735_center,
      { "center", "j2735.center_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position3D", HFILL }},
    { &hf_j2735_radius,
      { "radius", "j2735.radius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Radius_B12", HFILL }},
    { &hf_j2735_units_01,
      { "units", "j2735.units",
        FT_UINT32, BASE_DEC, VALS(j2735_DistanceUnits_vals), 0,
        "DistanceUnits", HFILL }},
    { &hf_j2735_anchor,
      { "anchor", "j2735.anchor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position3D", HFILL }},
    { &hf_j2735_directionality,
      { "directionality", "j2735.directionality",
        FT_UINT32, BASE_DEC, VALS(j2735_DirectionOfUse_vals), 0,
        "DirectionOfUse", HFILL }},
    { &hf_j2735_closedPath,
      { "closedPath", "j2735.closedPath",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_j2735_direction,
      { "direction", "j2735.direction",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HeadingSlice", HFILL }},
    { &hf_j2735_description_03,
      { "description", "j2735.description",
        FT_UINT32, BASE_DEC, VALS(j2735_T_description_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_path_01,
      { "path", "j2735.path_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OffsetSystem", HFILL }},
    { &hf_j2735_geometry,
      { "geometry", "j2735.geometry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeometricProjection", HFILL }},
    { &hf_j2735_oldRegion,
      { "oldRegion", "j2735.oldRegion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ValidRegion", HFILL }},
    { &hf_j2735_circle,
      { "circle", "j2735.circle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_ExitService_item,
      { "ExitService item", "j2735.ExitService_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_item_01,
      { "item", "j2735.item",
        FT_UINT32, BASE_DEC, VALS(j2735_T_item_01_vals), 0,
        "T_item_01", HFILL }},
    { &hf_j2735_text_01,
      { "text", "j2735.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "ITIStextPhrase", HFILL }},
    { &hf_j2735_GenericSignage_item,
      { "GenericSignage item", "j2735.GenericSignage_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_item_02,
      { "item", "j2735.item",
        FT_UINT32, BASE_DEC, VALS(j2735_T_item_02_vals), 0,
        "T_item_02", HFILL }},
    { &hf_j2735_SpeedLimit_item,
      { "SpeedLimit item", "j2735.SpeedLimit_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_item_03,
      { "item", "j2735.item",
        FT_UINT32, BASE_DEC, VALS(j2735_T_item_03_vals), 0,
        "T_item_03", HFILL }},
    { &hf_j2735_WorkZone_item,
      { "WorkZone item", "j2735.WorkZone_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_item_04,
      { "item", "j2735.item",
        FT_UINT32, BASE_DEC, VALS(j2735_T_item_04_vals), 0,
        "T_item_04", HFILL }},
    { &hf_j2735_lon_03,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B12", HFILL }},
    { &hf_j2735_lat_04,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B12", HFILL }},
    { &hf_j2735_lon_04,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B14", HFILL }},
    { &hf_j2735_lat_05,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B14", HFILL }},
    { &hf_j2735_lon_05,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B16", HFILL }},
    { &hf_j2735_lat_06,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B16", HFILL }},
    { &hf_j2735_lon_06,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B18", HFILL }},
    { &hf_j2735_lat_07,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B18", HFILL }},
    { &hf_j2735_lon_07,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B22", HFILL }},
    { &hf_j2735_lat_08,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B22", HFILL }},
    { &hf_j2735_lon_08,
      { "lon", "j2735.lon",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B24", HFILL }},
    { &hf_j2735_lat_09,
      { "lat", "j2735.lat",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B24", HFILL }},
    { &hf_j2735_NodeAttributeLLList_item,
      { "NodeAttributeLL", "j2735.NodeAttributeLL",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeAttributeLL_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_localNode_01,
      { "localNode", "j2735.localNode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NodeAttributeLLList", HFILL }},
    { &hf_j2735_disabled_01,
      { "disabled", "j2735.disabled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SegmentAttributeLLList", HFILL }},
    { &hf_j2735_enabled_01,
      { "enabled", "j2735.enabled",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SegmentAttributeLLList", HFILL }},
    { &hf_j2735_nodes_01,
      { "nodes", "j2735.nodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NodeSetLL", HFILL }},
    { &hf_j2735_delta_01,
      { "delta", "j2735.delta",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeOffsetPointLL_vals), 0,
        "NodeOffsetPointLL", HFILL }},
    { &hf_j2735_attributes_01,
      { "attributes", "j2735.attributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NodeAttributeSetLL", HFILL }},
    { &hf_j2735_node_LL1,
      { "node-LL1", "j2735.node_LL1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LL_24B", HFILL }},
    { &hf_j2735_node_LL2,
      { "node-LL2", "j2735.node_LL2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LL_28B", HFILL }},
    { &hf_j2735_node_LL3,
      { "node-LL3", "j2735.node_LL3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LL_32B", HFILL }},
    { &hf_j2735_node_LL4,
      { "node-LL4", "j2735.node_LL4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LL_36B", HFILL }},
    { &hf_j2735_node_LL5,
      { "node-LL5", "j2735.node_LL5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LL_44B", HFILL }},
    { &hf_j2735_node_LL6,
      { "node-LL6", "j2735.node_LL6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Node_LL_48B", HFILL }},
    { &hf_j2735_NodeSetLL_item,
      { "NodeLL", "j2735.NodeLL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_scale,
      { "scale", "j2735.scale",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Zoom", HFILL }},
    { &hf_j2735_offset_01,
      { "offset", "j2735.offset",
        FT_UINT32, BASE_DEC, VALS(j2735_T_offset_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_xy,
      { "xy", "j2735.xy",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeListXY_vals), 0,
        "NodeListXY", HFILL }},
    { &hf_j2735_ll,
      { "ll", "j2735.ll",
        FT_UINT32, BASE_DEC, VALS(j2735_NodeListLL_vals), 0,
        "NodeListLL", HFILL }},
    { &hf_j2735_RegionList_item,
      { "RegionOffsets", "j2735.RegionOffsets_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_xOffset,
      { "xOffset", "j2735.xOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B16", HFILL }},
    { &hf_j2735_yOffset,
      { "yOffset", "j2735.yOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B16", HFILL }},
    { &hf_j2735_zOffset,
      { "zOffset", "j2735.zOffset",
        FT_INT32, BASE_DEC, NULL, 0,
        "OffsetLL_B16", HFILL }},
    { &hf_j2735_nodeList_01,
      { "nodeList", "j2735.nodeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegionList", HFILL }},
    { &hf_j2735_viewAngle,
      { "viewAngle", "j2735.viewAngle",
        FT_BYTES, BASE_NONE, NULL, 0,
        "HeadingSlice", HFILL }},
    { &hf_j2735_mutcdCode,
      { "mutcdCode", "j2735.mutcdCode",
        FT_UINT32, BASE_DEC, VALS(j2735_MUTCDCode_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_crc,
      { "crc", "j2735.crc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MsgCRC", HFILL }},
    { &hf_j2735_SegmentAttributeLLList_item,
      { "SegmentAttributeLL", "j2735.SegmentAttributeLL",
        FT_UINT32, BASE_DEC, VALS(j2735_SegmentAttributeLL_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_TravelerDataFrameList_item,
      { "TravelerDataFrame", "j2735.TravelerDataFrame_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_frameType,
      { "frameType", "j2735.frameType",
        FT_UINT32, BASE_DEC, VALS(j2735_TravelerInfoType_vals), 0,
        "TravelerInfoType", HFILL }},
    { &hf_j2735_msgId,
      { "msgId", "j2735.msgId",
        FT_UINT32, BASE_DEC, VALS(j2735_T_msgId_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_roadSignID,
      { "roadSignID", "j2735.roadSignID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_startYear,
      { "startYear", "j2735.startYear",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DYear", HFILL }},
    { &hf_j2735_startTime_02,
      { "startTime", "j2735.startTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinuteOfTheYear", HFILL }},
    { &hf_j2735_durationTime,
      { "durationTime", "j2735.durationTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MinutesDuration", HFILL }},
    { &hf_j2735_priority_01,
      { "priority", "j2735.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignPrority", HFILL }},
    { &hf_j2735_notUsed1,
      { "notUsed1", "j2735.notUsed1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SSPindex", HFILL }},
    { &hf_j2735_regions,
      { "regions", "j2735.regions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_16_OF_GeographicalPath", HFILL }},
    { &hf_j2735_regions_item,
      { "GeographicalPath", "j2735.GeographicalPath_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_notUsed2,
      { "notUsed2", "j2735.notUsed2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SSPindex", HFILL }},
    { &hf_j2735_notUsed3,
      { "notUsed3", "j2735.notUsed3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SSPindex", HFILL }},
    { &hf_j2735_content,
      { "content", "j2735.content",
        FT_UINT32, BASE_DEC, VALS(j2735_T_content_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_advisory,
      { "advisory", "j2735.advisory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ITIScodesAndText", HFILL }},
    { &hf_j2735_workZone,
      { "workZone", "j2735.workZone",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_genericSign,
      { "genericSign", "j2735.genericSign",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenericSignage", HFILL }},
    { &hf_j2735_speedLimit,
      { "speedLimit", "j2735.speedLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_exitService,
      { "exitService", "j2735.exitService",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_url,
      { "url", "j2735.url",
        FT_STRING, BASE_NONE, NULL, 0,
        "URL_Short", HFILL }},
    { &hf_j2735_area,
      { "area", "j2735.area",
        FT_UINT32, BASE_DEC, VALS(j2735_T_area_vals), 0,
        NULL, HFILL }},
    { &hf_j2735_shapePointSet,
      { "shapePointSet", "j2735.shapePointSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_regionPointSet,
      { "regionPointSet", "j2735.regionPointSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_j2735_BrakeAppliedStatus_unavailable,
      { "unavailable", "j2735.BrakeAppliedStatus.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_BrakeAppliedStatus_leftFront,
      { "leftFront", "j2735.BrakeAppliedStatus.leftFront",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_BrakeAppliedStatus_leftRear,
      { "leftRear", "j2735.BrakeAppliedStatus.leftRear",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_BrakeAppliedStatus_rightFront,
      { "rightFront", "j2735.BrakeAppliedStatus.rightFront",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_BrakeAppliedStatus_rightRear,
      { "rightRear", "j2735.BrakeAppliedStatus.rightRear",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_lowBeamHeadlightsOn,
      { "lowBeamHeadlightsOn", "j2735.ExteriorLights.lowBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_highBeamHeadlightsOn,
      { "highBeamHeadlightsOn", "j2735.ExteriorLights.highBeamHeadlightsOn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_leftTurnSignalOn,
      { "leftTurnSignalOn", "j2735.ExteriorLights.leftTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_rightTurnSignalOn,
      { "rightTurnSignalOn", "j2735.ExteriorLights.rightTurnSignalOn",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_hazardSignalOn,
      { "hazardSignalOn", "j2735.ExteriorLights.hazardSignalOn",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_automaticLightControlOn,
      { "automaticLightControlOn", "j2735.ExteriorLights.automaticLightControlOn",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_daytimeRunningLightsOn,
      { "daytimeRunningLightsOn", "j2735.ExteriorLights.daytimeRunningLightsOn",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_fogLightOn,
      { "fogLightOn", "j2735.ExteriorLights.fogLightOn",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_ExteriorLights_parkingLightsOn,
      { "parkingLightsOn", "j2735.ExteriorLights.parkingLightsOn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_unavailable,
      { "unavailable", "j2735.GNSSstatus.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_isHealthy,
      { "isHealthy", "j2735.GNSSstatus.isHealthy",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_isMonitored,
      { "isMonitored", "j2735.GNSSstatus.isMonitored",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_baseStationType,
      { "baseStationType", "j2735.GNSSstatus.baseStationType",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_aPDOPofUnder5,
      { "aPDOPofUnder5", "j2735.GNSSstatus.aPDOPofUnder5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_inViewOfUnder5,
      { "inViewOfUnder5", "j2735.GNSSstatus.inViewOfUnder5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_localCorrectionsPresent,
      { "localCorrectionsPresent", "j2735.GNSSstatus.localCorrectionsPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_GNSSstatus_networkCorrectionsPresent,
      { "networkCorrectionsPresent", "j2735.GNSSstatus.networkCorrectionsPresent",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from000_0to022_5degrees,
      { "from000-0to022-5degrees", "j2735.HeadingSlice.from000.0to022.5degrees",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from022_5to045_0degrees,
      { "from022-5to045-0degrees", "j2735.HeadingSlice.from022.5to045.0degrees",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from045_0to067_5degrees,
      { "from045-0to067-5degrees", "j2735.HeadingSlice.from045.0to067.5degrees",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from067_5to090_0degrees,
      { "from067-5to090-0degrees", "j2735.HeadingSlice.from067.5to090.0degrees",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from090_0to112_5degrees,
      { "from090-0to112-5degrees", "j2735.HeadingSlice.from090.0to112.5degrees",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from112_5to135_0degrees,
      { "from112-5to135-0degrees", "j2735.HeadingSlice.from112.5to135.0degrees",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from135_0to157_5degrees,
      { "from135-0to157-5degrees", "j2735.HeadingSlice.from135.0to157.5degrees",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from157_5to180_0degrees,
      { "from157-5to180-0degrees", "j2735.HeadingSlice.from157.5to180.0degrees",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from180_0to202_5degrees,
      { "from180-0to202-5degrees", "j2735.HeadingSlice.from180.0to202.5degrees",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from202_5to225_0degrees,
      { "from202-5to225-0degrees", "j2735.HeadingSlice.from202.5to225.0degrees",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from225_0to247_5degrees,
      { "from225-0to247-5degrees", "j2735.HeadingSlice.from225.0to247.5degrees",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from247_5to270_0degrees,
      { "from247-5to270-0degrees", "j2735.HeadingSlice.from247.5to270.0degrees",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from270_0to292_5degrees,
      { "from270-0to292-5degrees", "j2735.HeadingSlice.from270.0to292.5degrees",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from292_5to315_0degrees,
      { "from292-5to315-0degrees", "j2735.HeadingSlice.from292.5to315.0degrees",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from315_0to337_5degrees,
      { "from315-0to337-5degrees", "j2735.HeadingSlice.from315.0to337.5degrees",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_HeadingSlice_from337_5to360_0degrees,
      { "from337-5to360-0degrees", "j2735.HeadingSlice.from337.5to360.0degrees",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_PrivilegedEventFlags_peUnavailable,
      { "peUnavailable", "j2735.PrivilegedEventFlags.peUnavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_PrivilegedEventFlags_peEmergencyResponse,
      { "peEmergencyResponse", "j2735.PrivilegedEventFlags.peEmergencyResponse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_PrivilegedEventFlags_peEmergencyLightsActive,
      { "peEmergencyLightsActive", "j2735.PrivilegedEventFlags.peEmergencyLightsActive",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_PrivilegedEventFlags_peEmergencySoundActive,
      { "peEmergencySoundActive", "j2735.PrivilegedEventFlags.peEmergencySoundActive",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_PrivilegedEventFlags_peNonEmergencyLightsActive,
      { "peNonEmergencyLightsActive", "j2735.PrivilegedEventFlags.peNonEmergencyLightsActive",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_PrivilegedEventFlags_peNonEmergencySoundActive,
      { "peNonEmergencySoundActive", "j2735.PrivilegedEventFlags.peNonEmergencySoundActive",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_TransitStatus_none,
      { "none", "j2735.TransitStatus.none",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_TransitStatus_anADAuse,
      { "anADAuse", "j2735.TransitStatus.anADAuse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_TransitStatus_aBikeLoad,
      { "aBikeLoad", "j2735.TransitStatus.aBikeLoad",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_TransitStatus_doorOpen,
      { "doorOpen", "j2735.TransitStatus.doorOpen",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_TransitStatus_occM,
      { "occM", "j2735.TransitStatus.occM",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_TransitStatus_occL,
      { "occL", "j2735.TransitStatus.occL",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventHazardLights,
      { "eventHazardLights", "j2735.VehicleEventFlags.eventHazardLights",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventStopLineViolation,
      { "eventStopLineViolation", "j2735.VehicleEventFlags.eventStopLineViolation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventABSactivated,
      { "eventABSactivated", "j2735.VehicleEventFlags.eventABSactivated",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventTractionControlLoss,
      { "eventTractionControlLoss", "j2735.VehicleEventFlags.eventTractionControlLoss",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventStabilityControlactivated,
      { "eventStabilityControlactivated", "j2735.VehicleEventFlags.eventStabilityControlactivated",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventHazardousMaterials,
      { "eventHazardousMaterials", "j2735.VehicleEventFlags.eventHazardousMaterials",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventReserved1,
      { "eventReserved1", "j2735.VehicleEventFlags.eventReserved1",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventHardBraking,
      { "eventHardBraking", "j2735.VehicleEventFlags.eventHardBraking",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventLightsChanged,
      { "eventLightsChanged", "j2735.VehicleEventFlags.eventLightsChanged",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventWipersChanged,
      { "eventWipersChanged", "j2735.VehicleEventFlags.eventWipersChanged",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventFlatTire,
      { "eventFlatTire", "j2735.VehicleEventFlags.eventFlatTire",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventDisabledVehicle,
      { "eventDisabledVehicle", "j2735.VehicleEventFlags.eventDisabledVehicle",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_VehicleEventFlags_eventAirBagDeployment,
      { "eventAirBagDeployment", "j2735.VehicleEventFlags.eventAirBagDeployment",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_VerticalAccelerationThreshold_notEquipped,
      { "notEquipped", "j2735.VerticalAccelerationThreshold.notEquipped",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_VerticalAccelerationThreshold_leftFront,
      { "leftFront", "j2735.VerticalAccelerationThreshold.leftFront",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_VerticalAccelerationThreshold_leftRear,
      { "leftRear", "j2735.VerticalAccelerationThreshold.leftRear",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_VerticalAccelerationThreshold_rightFront,
      { "rightFront", "j2735.VerticalAccelerationThreshold.rightFront",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_VerticalAccelerationThreshold_rightRear,
      { "rightRear", "j2735.VerticalAccelerationThreshold.rightRear",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverStraightAllowed,
      { "maneuverStraightAllowed", "j2735.AllowedManeuvers.maneuverStraightAllowed",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverLeftAllowed,
      { "maneuverLeftAllowed", "j2735.AllowedManeuvers.maneuverLeftAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverRightAllowed,
      { "maneuverRightAllowed", "j2735.AllowedManeuvers.maneuverRightAllowed",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverUTurnAllowed,
      { "maneuverUTurnAllowed", "j2735.AllowedManeuvers.maneuverUTurnAllowed",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverLeftTurnOnRedAllowed,
      { "maneuverLeftTurnOnRedAllowed", "j2735.AllowedManeuvers.maneuverLeftTurnOnRedAllowed",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverRightTurnOnRedAllowed,
      { "maneuverRightTurnOnRedAllowed", "j2735.AllowedManeuvers.maneuverRightTurnOnRedAllowed",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverLaneChangeAllowed,
      { "maneuverLaneChangeAllowed", "j2735.AllowedManeuvers.maneuverLaneChangeAllowed",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_maneuverNoStoppingAllowed,
      { "maneuverNoStoppingAllowed", "j2735.AllowedManeuvers.maneuverNoStoppingAllowed",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_yieldAllwaysRequired,
      { "yieldAllwaysRequired", "j2735.AllowedManeuvers.yieldAllwaysRequired",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_goWithHalt,
      { "goWithHalt", "j2735.AllowedManeuvers.goWithHalt",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_caution,
      { "caution", "j2735.AllowedManeuvers.caution",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_AllowedManeuvers_reserved1,
      { "reserved1", "j2735.AllowedManeuvers.reserved1",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_median_RevocableLane,
      { "median-RevocableLane", "j2735.LaneAttributes.Barrier.median.RevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_median,
      { "median", "j2735.LaneAttributes.Barrier.median",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_whiteLineHashing,
      { "whiteLineHashing", "j2735.LaneAttributes.Barrier.whiteLineHashing",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_stripedLines,
      { "stripedLines", "j2735.LaneAttributes.Barrier.stripedLines",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_doubleStripedLines,
      { "doubleStripedLines", "j2735.LaneAttributes.Barrier.doubleStripedLines",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_trafficCones,
      { "trafficCones", "j2735.LaneAttributes.Barrier.trafficCones",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_constructionBarrier,
      { "constructionBarrier", "j2735.LaneAttributes.Barrier.constructionBarrier",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_trafficChannels,
      { "trafficChannels", "j2735.LaneAttributes.Barrier.trafficChannels",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_lowCurbs,
      { "lowCurbs", "j2735.LaneAttributes.Barrier.lowCurbs",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Barrier_highCurbs,
      { "highCurbs", "j2735.LaneAttributes.Barrier.highCurbs",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_bikeRevocableLane,
      { "bikeRevocableLane", "j2735.LaneAttributes.Bike.bikeRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_pedestrianUseAllowed,
      { "pedestrianUseAllowed", "j2735.LaneAttributes.Bike.pedestrianUseAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_isBikeFlyOverLane,
      { "isBikeFlyOverLane", "j2735.LaneAttributes.Bike.isBikeFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_fixedCycleTime,
      { "fixedCycleTime", "j2735.LaneAttributes.Bike.fixedCycleTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_biDirectionalCycleTimes,
      { "biDirectionalCycleTimes", "j2735.LaneAttributes.Bike.biDirectionalCycleTimes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_isolatedByBarrier,
      { "isolatedByBarrier", "j2735.LaneAttributes.Bike.isolatedByBarrier",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Bike_unsignalizedSegmentsPresent,
      { "unsignalizedSegmentsPresent", "j2735.LaneAttributes.Bike.unsignalizedSegmentsPresent",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_crosswalkRevocableLane,
      { "crosswalkRevocableLane", "j2735.LaneAttributes.Crosswalk.crosswalkRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_bicyleUseAllowed,
      { "bicyleUseAllowed", "j2735.LaneAttributes.Crosswalk.bicyleUseAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_isXwalkFlyOverLane,
      { "isXwalkFlyOverLane", "j2735.LaneAttributes.Crosswalk.isXwalkFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_fixedCycleTime,
      { "fixedCycleTime", "j2735.LaneAttributes.Crosswalk.fixedCycleTime",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_biDirectionalCycleTimes,
      { "biDirectionalCycleTimes", "j2735.LaneAttributes.Crosswalk.biDirectionalCycleTimes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_hasPushToWalkButton,
      { "hasPushToWalkButton", "j2735.LaneAttributes.Crosswalk.hasPushToWalkButton",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_audioSupport,
      { "audioSupport", "j2735.LaneAttributes.Crosswalk.audioSupport",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_rfSignalRequestPresent,
      { "rfSignalRequestPresent", "j2735.LaneAttributes.Crosswalk.rfSignalRequestPresent",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Crosswalk_unsignalizedSegmentsPresent,
      { "unsignalizedSegmentsPresent", "j2735.LaneAttributes.Crosswalk.unsignalizedSegmentsPresent",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_parkingRevocableLane,
      { "parkingRevocableLane", "j2735.LaneAttributes.Parking.parkingRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_parallelParkingInUse,
      { "parallelParkingInUse", "j2735.LaneAttributes.Parking.parallelParkingInUse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_headInParkingInUse,
      { "headInParkingInUse", "j2735.LaneAttributes.Parking.headInParkingInUse",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_doNotParkZone,
      { "doNotParkZone", "j2735.LaneAttributes.Parking.doNotParkZone",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_parkingForBusUse,
      { "parkingForBusUse", "j2735.LaneAttributes.Parking.parkingForBusUse",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_parkingForTaxiUse,
      { "parkingForTaxiUse", "j2735.LaneAttributes.Parking.parkingForTaxiUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Parking_noPublicParkingUse,
      { "noPublicParkingUse", "j2735.LaneAttributes.Parking.noPublicParkingUse",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Sidewalk_sidewalk_RevocableLane,
      { "sidewalk-RevocableLane", "j2735.LaneAttributes.Sidewalk.sidewalk.RevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Sidewalk_bicyleUseAllowed,
      { "bicyleUseAllowed", "j2735.LaneAttributes.Sidewalk.bicyleUseAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Sidewalk_isSidewalkFlyOverLane,
      { "isSidewalkFlyOverLane", "j2735.LaneAttributes.Sidewalk.isSidewalkFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Sidewalk_walkBikes,
      { "walkBikes", "j2735.LaneAttributes.Sidewalk.walkBikes",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesRevocableLane,
      { "stripeToConnectingLanesRevocableLane", "j2735.LaneAttributes.Striping.stripeToConnectingLanesRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Striping_stripeDrawOnLeft,
      { "stripeDrawOnLeft", "j2735.LaneAttributes.Striping.stripeDrawOnLeft",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Striping_stripeDrawOnRight,
      { "stripeDrawOnRight", "j2735.LaneAttributes.Striping.stripeDrawOnRight",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesLeft,
      { "stripeToConnectingLanesLeft", "j2735.LaneAttributes.Striping.stripeToConnectingLanesLeft",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesRight,
      { "stripeToConnectingLanesRight", "j2735.LaneAttributes.Striping.stripeToConnectingLanesRight",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Striping_stripeToConnectingLanesAhead,
      { "stripeToConnectingLanesAhead", "j2735.LaneAttributes.Striping.stripeToConnectingLanesAhead",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_TrackedVehicle_spec_RevocableLane,
      { "spec-RevocableLane", "j2735.LaneAttributes.TrackedVehicle.spec.RevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_TrackedVehicle_spec_commuterRailRoadTrack,
      { "spec-commuterRailRoadTrack", "j2735.LaneAttributes.TrackedVehicle.spec.commuterRailRoadTrack",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_TrackedVehicle_spec_lightRailRoadTrack,
      { "spec-lightRailRoadTrack", "j2735.LaneAttributes.TrackedVehicle.spec.lightRailRoadTrack",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_TrackedVehicle_spec_heavyRailRoadTrack,
      { "spec-heavyRailRoadTrack", "j2735.LaneAttributes.TrackedVehicle.spec.heavyRailRoadTrack",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_TrackedVehicle_spec_otherRailType,
      { "spec-otherRailType", "j2735.LaneAttributes.TrackedVehicle.spec.otherRailType",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_isVehicleRevocableLane,
      { "isVehicleRevocableLane", "j2735.LaneAttributes.Vehicle.isVehicleRevocableLane",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_isVehicleFlyOverLane,
      { "isVehicleFlyOverLane", "j2735.LaneAttributes.Vehicle.isVehicleFlyOverLane",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_hovLaneUseOnly,
      { "hovLaneUseOnly", "j2735.LaneAttributes.Vehicle.hovLaneUseOnly",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_restrictedToBusUse,
      { "restrictedToBusUse", "j2735.LaneAttributes.Vehicle.restrictedToBusUse",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_restrictedToTaxiUse,
      { "restrictedToTaxiUse", "j2735.LaneAttributes.Vehicle.restrictedToTaxiUse",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_restrictedFromPublicUse,
      { "restrictedFromPublicUse", "j2735.LaneAttributes.Vehicle.restrictedFromPublicUse",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_hasIRbeaconCoverage,
      { "hasIRbeaconCoverage", "j2735.LaneAttributes.Vehicle.hasIRbeaconCoverage",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_LaneAttributes_Vehicle_permissionOnRequest,
      { "permissionOnRequest", "j2735.LaneAttributes.Vehicle.permissionOnRequest",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_LaneDirection_ingressPath,
      { "ingressPath", "j2735.LaneDirection.ingressPath",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneDirection_egressPath,
      { "egressPath", "j2735.LaneDirection.egressPath",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_overlappingLaneDescriptionProvided,
      { "overlappingLaneDescriptionProvided", "j2735.LaneSharing.overlappingLaneDescriptionProvided",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_multipleLanesTreatedAsOneLane,
      { "multipleLanesTreatedAsOneLane", "j2735.LaneSharing.multipleLanesTreatedAsOneLane",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_otherNonMotorizedTrafficTypes,
      { "otherNonMotorizedTrafficTypes", "j2735.LaneSharing.otherNonMotorizedTrafficTypes",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_individualMotorizedVehicleTraffic,
      { "individualMotorizedVehicleTraffic", "j2735.LaneSharing.individualMotorizedVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_busVehicleTraffic,
      { "busVehicleTraffic", "j2735.LaneSharing.busVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_taxiVehicleTraffic,
      { "taxiVehicleTraffic", "j2735.LaneSharing.taxiVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_pedestriansTraffic,
      { "pedestriansTraffic", "j2735.LaneSharing.pedestriansTraffic",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_cyclistVehicleTraffic,
      { "cyclistVehicleTraffic", "j2735.LaneSharing.cyclistVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_trackedVehicleTraffic,
      { "trackedVehicleTraffic", "j2735.LaneSharing.trackedVehicleTraffic",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_LaneSharing_reserved,
      { "reserved", "j2735.LaneSharing.reserved",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_PersonalAssistive_unavailable,
      { "unavailable", "j2735.PersonalAssistive.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_PersonalAssistive_otherType,
      { "otherType", "j2735.PersonalAssistive.otherType",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_PersonalAssistive_vision,
      { "vision", "j2735.PersonalAssistive.vision",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_PersonalAssistive_hearing,
      { "hearing", "j2735.PersonalAssistive.hearing",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_PersonalAssistive_movement,
      { "movement", "j2735.PersonalAssistive.movement",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_PersonalAssistive_cognition,
      { "cognition", "j2735.PersonalAssistive.cognition",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_unavailable,
      { "unavailable", "j2735.PersonalDeviceUsageState.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_other,
      { "other", "j2735.PersonalDeviceUsageState.other",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_idle,
      { "idle", "j2735.PersonalDeviceUsageState.idle",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_listeningToAudio,
      { "listeningToAudio", "j2735.PersonalDeviceUsageState.listeningToAudio",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_typing,
      { "typing", "j2735.PersonalDeviceUsageState.typing",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_calling,
      { "calling", "j2735.PersonalDeviceUsageState.calling",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_playingGames,
      { "playingGames", "j2735.PersonalDeviceUsageState.playingGames",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_reading,
      { "reading", "j2735.PersonalDeviceUsageState.reading",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_PersonalDeviceUsageState_viewing,
      { "viewing", "j2735.PersonalDeviceUsageState.viewing",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyAndRoadWorkerActivity_unavailable,
      { "unavailable", "j2735.PublicSafetyAndRoadWorkerActivity.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyAndRoadWorkerActivity_workingOnRoad,
      { "workingOnRoad", "j2735.PublicSafetyAndRoadWorkerActivity.workingOnRoad",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyAndRoadWorkerActivity_settingUpClosures,
      { "settingUpClosures", "j2735.PublicSafetyAndRoadWorkerActivity.settingUpClosures",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyAndRoadWorkerActivity_respondingToEvents,
      { "respondingToEvents", "j2735.PublicSafetyAndRoadWorkerActivity.respondingToEvents",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyAndRoadWorkerActivity_directingTraffic,
      { "directingTraffic", "j2735.PublicSafetyAndRoadWorkerActivity.directingTraffic",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyAndRoadWorkerActivity_otherActivities,
      { "otherActivities", "j2735.PublicSafetyAndRoadWorkerActivity.otherActivities",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_unavailable,
      { "unavailable", "j2735.PublicSafetyDirectingTrafficSubType.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_policeAndTrafficOfficers,
      { "policeAndTrafficOfficers", "j2735.PublicSafetyDirectingTrafficSubType.policeAndTrafficOfficers",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_trafficControlPersons,
      { "trafficControlPersons", "j2735.PublicSafetyDirectingTrafficSubType.trafficControlPersons",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_railroadCrossingGuards,
      { "railroadCrossingGuards", "j2735.PublicSafetyDirectingTrafficSubType.railroadCrossingGuards",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_civilDefenseNationalGuardMilitaryPolice,
      { "civilDefenseNationalGuardMilitaryPolice", "j2735.PublicSafetyDirectingTrafficSubType.civilDefenseNationalGuardMilitaryPolice",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_emergencyOrganizationPersonnel,
      { "emergencyOrganizationPersonnel", "j2735.PublicSafetyDirectingTrafficSubType.emergencyOrganizationPersonnel",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_PublicSafetyDirectingTrafficSubType_highwayServiceVehiclePersonnel,
      { "highwayServiceVehiclePersonnel", "j2735.PublicSafetyDirectingTrafficSubType.highwayServiceVehiclePersonnel",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_UserSizeAndBehaviour_unavailable,
      { "unavailable", "j2735.UserSizeAndBehaviour.unavailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_UserSizeAndBehaviour_smallStature,
      { "smallStature", "j2735.UserSizeAndBehaviour.smallStature",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_UserSizeAndBehaviour_largeStature,
      { "largeStature", "j2735.UserSizeAndBehaviour.largeStature",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_UserSizeAndBehaviour_erraticMoving,
      { "erraticMoving", "j2735.UserSizeAndBehaviour.erraticMoving",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_UserSizeAndBehaviour_slowMoving,
      { "slowMoving", "j2735.UserSizeAndBehaviour.slowMoving",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_TransitVehicleStatus_loading,
      { "loading", "j2735.TransitVehicleStatus.loading",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_TransitVehicleStatus_anADAuse,
      { "anADAuse", "j2735.TransitVehicleStatus.anADAuse",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_TransitVehicleStatus_aBikeLoad,
      { "aBikeLoad", "j2735.TransitVehicleStatus.aBikeLoad",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_TransitVehicleStatus_doorOpen,
      { "doorOpen", "j2735.TransitVehicleStatus.doorOpen",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_TransitVehicleStatus_charging,
      { "charging", "j2735.TransitVehicleStatus.charging",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_TransitVehicleStatus_atStopLine,
      { "atStopLine", "j2735.TransitVehicleStatus.atStopLine",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_manualControlIsEnabled,
      { "manualControlIsEnabled", "j2735.IntersectionStatusObject.manualControlIsEnabled",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_stopTimeIsActivated,
      { "stopTimeIsActivated", "j2735.IntersectionStatusObject.stopTimeIsActivated",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_failureFlash,
      { "failureFlash", "j2735.IntersectionStatusObject.failureFlash",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_preemptIsActive,
      { "preemptIsActive", "j2735.IntersectionStatusObject.preemptIsActive",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_signalPriorityIsActive,
      { "signalPriorityIsActive", "j2735.IntersectionStatusObject.signalPriorityIsActive",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_fixedTimeOperation,
      { "fixedTimeOperation", "j2735.IntersectionStatusObject.fixedTimeOperation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_trafficDependentOperation,
      { "trafficDependentOperation", "j2735.IntersectionStatusObject.trafficDependentOperation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_standbyOperation,
      { "standbyOperation", "j2735.IntersectionStatusObject.standbyOperation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_failureMode,
      { "failureMode", "j2735.IntersectionStatusObject.failureMode",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_off,
      { "off", "j2735.IntersectionStatusObject.off",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_recentMAPmessageUpdate,
      { "recentMAPmessageUpdate", "j2735.IntersectionStatusObject.recentMAPmessageUpdate",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_recentChangeInMAPassignedLanesIDsUsed,
      { "recentChangeInMAPassignedLanesIDsUsed", "j2735.IntersectionStatusObject.recentChangeInMAPassignedLanesIDsUsed",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_noValidMAPisAvailableAtThisTime,
      { "noValidMAPisAvailableAtThisTime", "j2735.IntersectionStatusObject.noValidMAPisAvailableAtThisTime",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_j2735_IntersectionStatusObject_noValidSPATisAvailableAtThisTime,
      { "noValidSPATisAvailableAtThisTime", "j2735.IntersectionStatusObject.noValidSPATisAvailableAtThisTime",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static gint *ett[] = {
      &ett_j2735,
    &ett_j2735_LatitudeDMS2,
    &ett_j2735_LongitudeDMS2,
    &ett_j2735_Node_LLdms_48b,
    &ett_j2735_Node_LLdms_80b,
    &ett_j2735_LaneDataAttribute_addGrpB,
    &ett_j2735_MovementEvent_addGrpB,
    &ett_j2735_NodeOffsetPointXY_addGrpB,
    &ett_j2735_Position3D_addGrpB,
    &ett_j2735_TimeMark_addGrpB,
    &ett_j2735_Altitude,
    &ett_j2735_PrioritizationResponse,
    &ett_j2735_PrioritizationResponseList,
    &ett_j2735_ConnectionManeuverAssist_addGrpC,
    &ett_j2735_IntersectionState_addGrpC,
    &ett_j2735_MapData_addGrpC,
    &ett_j2735_Position3D_addGrpC,
    &ett_j2735_RestrictionUserType_addGrpC,
    &ett_j2735_SignalHeadLocation,
    &ett_j2735_SignalHeadLocationList,
    &ett_j2735_VehicleToLanePosition,
    &ett_j2735_VehicleToLanePositionList,
    &ett_j2735_BasicSafetyMessage,
    &ett_j2735_SEQUENCE_SIZE_1_8_OF_PartIIcontent,
    &ett_j2735_SEQUENCE_SIZE_1_4_OF_RegionalExtension,
    &ett_j2735_PartIIcontent,
    &ett_j2735_DisabledVehicle,
    &ett_j2735_EventDescription,
    &ett_j2735_SEQUENCE_SIZE_1_8_OF_ITIScodes,
    &ett_j2735_ObstacleDetection,
    &ett_j2735_PivotPointDescription,
    &ett_j2735_RTCMPackage,
    &ett_j2735_SpecialVehicleExtensions,
    &ett_j2735_SpeedProfileMeasurementList,
    &ett_j2735_SpeedProfile,
    &ett_j2735_SupplementalVehicleExtensions,
    &ett_j2735_TrailerData,
    &ett_j2735_TrailerHistoryPointList,
    &ett_j2735_TrailerHistoryPoint,
    &ett_j2735_TrailerUnitDescriptionList,
    &ett_j2735_TrailerUnitDescription,
    &ett_j2735_VehicleData,
    &ett_j2735_WeatherProbe,
    &ett_j2735_WeatherReport,
    &ett_j2735_RegionalExtension,
    &ett_j2735_AccelerationSet4Way,
    &ett_j2735_AntennaOffsetSet,
    &ett_j2735_BrakeSystemStatus,
    &ett_j2735_BSMcoreData,
    &ett_j2735_BumperHeights,
    &ett_j2735_ComputedLane,
    &ett_j2735_T_offsetXaxis,
    &ett_j2735_T_offsetYaxis,
    &ett_j2735_DDate,
    &ett_j2735_DDateTime,
    &ett_j2735_DFullTime,
    &ett_j2735_DMonthDay,
    &ett_j2735_DTime,
    &ett_j2735_DYearMonth,
    &ett_j2735_EmergencyDetails,
    &ett_j2735_FullPositionVector,
    &ett_j2735_Header,
    &ett_j2735_IntersectionAccessPoint,
    &ett_j2735_IntersectionReferenceID,
    &ett_j2735_LaneDataAttribute,
    &ett_j2735_LaneDataAttributeList,
    &ett_j2735_Node_LLmD_64b,
    &ett_j2735_Node_XY_20b,
    &ett_j2735_Node_XY_22b,
    &ett_j2735_Node_XY_24b,
    &ett_j2735_Node_XY_26b,
    &ett_j2735_Node_XY_28b,
    &ett_j2735_Node_XY_32b,
    &ett_j2735_NodeAttributeSetXY,
    &ett_j2735_NodeAttributeXYList,
    &ett_j2735_NodeListXY,
    &ett_j2735_NodeOffsetPointXY,
    &ett_j2735_NodeSetXY,
    &ett_j2735_NodeXY,
    &ett_j2735_PathHistory,
    &ett_j2735_PathHistoryPointList,
    &ett_j2735_PathHistoryPoint,
    &ett_j2735_PathPrediction,
    &ett_j2735_Position3D,
    &ett_j2735_PositionalAccuracy,
    &ett_j2735_PositionConfidenceSet,
    &ett_j2735_PrivilegedEvents,
    &ett_j2735_RegulatorySpeedLimit,
    &ett_j2735_RequestorType,
    &ett_j2735_RoadSegmentReferenceID,
    &ett_j2735_RTCMheader,
    &ett_j2735_RTCMmessageList,
    &ett_j2735_SegmentAttributeXYList,
    &ett_j2735_SpeedandHeadingandThrottleConfidence,
    &ett_j2735_SpeedLimitList,
    &ett_j2735_TransmissionAndSpeed,
    &ett_j2735_VehicleClassification,
    &ett_j2735_VehicleID,
    &ett_j2735_VehicleSafetyExtensions,
    &ett_j2735_VehicleSize,
    &ett_j2735_VerticalOffset,
    &ett_j2735_WiperSet,
    &ett_j2735_BrakeAppliedStatus,
    &ett_j2735_ExteriorLights,
    &ett_j2735_GNSSstatus,
    &ett_j2735_HeadingSlice,
    &ett_j2735_PrivilegedEventFlags,
    &ett_j2735_TransitStatus,
    &ett_j2735_VehicleEventFlags,
    &ett_j2735_VerticalAccelerationThreshold,
    &ett_j2735_CommonSafetyRequest,
    &ett_j2735_RequestedItemList,
    &ett_j2735_EmergencyVehicleAlert,
    &ett_j2735_IntersectionCollision,
    &ett_j2735_ApproachOrLane,
    &ett_j2735_ITIScodesAndText,
    &ett_j2735_ITIScodesAndText_item,
    &ett_j2735_T_item,
    &ett_j2735_MapData,
    &ett_j2735_ConnectingLane,
    &ett_j2735_Connection,
    &ett_j2735_ConnectsToList,
    &ett_j2735_DataParameters,
    &ett_j2735_GenericLane,
    &ett_j2735_IntersectionGeometry,
    &ett_j2735_IntersectionGeometryList,
    &ett_j2735_LaneAttributes,
    &ett_j2735_LaneList,
    &ett_j2735_LaneTypeAttributes,
    &ett_j2735_OverlayLaneList,
    &ett_j2735_PreemptPriorityList,
    &ett_j2735_SignalControlZone,
    &ett_j2735_RestrictionClassAssignment,
    &ett_j2735_RestrictionClassList,
    &ett_j2735_RestrictionUserTypeList,
    &ett_j2735_RestrictionUserType,
    &ett_j2735_RoadLaneSetList,
    &ett_j2735_RoadSegmentList,
    &ett_j2735_RoadSegment,
    &ett_j2735_AllowedManeuvers,
    &ett_j2735_LaneAttributes_Barrier,
    &ett_j2735_LaneAttributes_Bike,
    &ett_j2735_LaneAttributes_Crosswalk,
    &ett_j2735_LaneAttributes_Parking,
    &ett_j2735_LaneAttributes_Sidewalk,
    &ett_j2735_LaneAttributes_Striping,
    &ett_j2735_LaneAttributes_TrackedVehicle,
    &ett_j2735_LaneAttributes_Vehicle,
    &ett_j2735_LaneDirection,
    &ett_j2735_LaneSharing,
    &ett_j2735_MessageFrame,
    &ett_j2735_NMEAcorrections,
    &ett_j2735_PersonalSafetyMessage,
    &ett_j2735_PropelledInformation,
    &ett_j2735_PersonalAssistive,
    &ett_j2735_PersonalDeviceUsageState,
    &ett_j2735_PublicSafetyAndRoadWorkerActivity,
    &ett_j2735_PublicSafetyDirectingTrafficSubType,
    &ett_j2735_UserSizeAndBehaviour,
    &ett_j2735_ProbeDataManagement,
    &ett_j2735_T_term,
    &ett_j2735_T_snapshot,
    &ett_j2735_Sample,
    &ett_j2735_SnapshotDistance,
    &ett_j2735_SnapshotTime,
    &ett_j2735_VehicleStatusRequest,
    &ett_j2735_VehicleStatusRequestList,
    &ett_j2735_ProbeVehicleData,
    &ett_j2735_SEQUENCE_SIZE_1_32_OF_Snapshot,
    &ett_j2735_AccelSteerYawRateConfidence,
    &ett_j2735_ConfidenceSet,
    &ett_j2735_J1939data,
    &ett_j2735_TireDataList,
    &ett_j2735_TireData,
    &ett_j2735_AxleWeightList,
    &ett_j2735_AxleWeightSet,
    &ett_j2735_Snapshot,
    &ett_j2735_VehicleIdent,
    &ett_j2735_T_vehicleClass,
    &ett_j2735_VehicleStatus,
    &ett_j2735_T_steering,
    &ett_j2735_T_accelSets,
    &ett_j2735_T_object,
    &ett_j2735_T_vehicleData,
    &ett_j2735_T_weatherReport,
    &ett_j2735_RoadSideAlert,
    &ett_j2735_RTCMcorrections,
    &ett_j2735_SignalRequestMessage,
    &ett_j2735_RequestorDescription,
    &ett_j2735_RequestorPositionVector,
    &ett_j2735_SignalRequestList,
    &ett_j2735_SignalRequestPackage,
    &ett_j2735_SignalRequest,
    &ett_j2735_TransitVehicleStatus,
    &ett_j2735_SignalStatusMessage,
    &ett_j2735_SignalRequesterInfo,
    &ett_j2735_SignalStatusList,
    &ett_j2735_SignalStatusPackageList,
    &ett_j2735_SignalStatusPackage,
    &ett_j2735_SignalStatus,
    &ett_j2735_SPAT,
    &ett_j2735_AdvisorySpeed,
    &ett_j2735_AdvisorySpeedList,
    &ett_j2735_ConnectionManeuverAssist,
    &ett_j2735_EnabledLaneList,
    &ett_j2735_IntersectionState,
    &ett_j2735_IntersectionStateList,
    &ett_j2735_ManeuverAssistList,
    &ett_j2735_MovementEventList,
    &ett_j2735_MovementEvent,
    &ett_j2735_MovementList,
    &ett_j2735_MovementState,
    &ett_j2735_TimeChangeDetails,
    &ett_j2735_IntersectionStatusObject,
    &ett_j2735_TestMessage00,
    &ett_j2735_TestMessage01,
    &ett_j2735_TestMessage02,
    &ett_j2735_TestMessage03,
    &ett_j2735_TestMessage04,
    &ett_j2735_TestMessage05,
    &ett_j2735_TestMessage06,
    &ett_j2735_TestMessage07,
    &ett_j2735_TestMessage08,
    &ett_j2735_TestMessage09,
    &ett_j2735_TestMessage10,
    &ett_j2735_TestMessage11,
    &ett_j2735_TestMessage12,
    &ett_j2735_TestMessage13,
    &ett_j2735_TestMessage14,
    &ett_j2735_TestMessage15,
    &ett_j2735_TravelerInformation,
    &ett_j2735_Circle,
    &ett_j2735_GeographicalPath,
    &ett_j2735_T_description,
    &ett_j2735_GeometricProjection,
    &ett_j2735_ExitService,
    &ett_j2735_ExitService_item,
    &ett_j2735_T_item_01,
    &ett_j2735_GenericSignage,
    &ett_j2735_GenericSignage_item,
    &ett_j2735_T_item_02,
    &ett_j2735_SpeedLimit,
    &ett_j2735_SpeedLimit_item,
    &ett_j2735_T_item_03,
    &ett_j2735_WorkZone,
    &ett_j2735_WorkZone_item,
    &ett_j2735_T_item_04,
    &ett_j2735_Node_LL_24B,
    &ett_j2735_Node_LL_28B,
    &ett_j2735_Node_LL_32B,
    &ett_j2735_Node_LL_36B,
    &ett_j2735_Node_LL_44B,
    &ett_j2735_Node_LL_48B,
    &ett_j2735_NodeAttributeLLList,
    &ett_j2735_NodeAttributeSetLL,
    &ett_j2735_NodeListLL,
    &ett_j2735_NodeLL,
    &ett_j2735_NodeOffsetPointLL,
    &ett_j2735_NodeSetLL,
    &ett_j2735_OffsetSystem,
    &ett_j2735_T_offset,
    &ett_j2735_RegionList,
    &ett_j2735_RegionOffsets,
    &ett_j2735_RegionPointSet,
    &ett_j2735_RoadSignID,
    &ett_j2735_SegmentAttributeLLList,
    &ett_j2735_ShapePointSet,
    &ett_j2735_TravelerDataFrameList,
    &ett_j2735_TravelerDataFrame,
    &ett_j2735_T_msgId,
    &ett_j2735_SEQUENCE_SIZE_1_16_OF_GeographicalPath,
    &ett_j2735_T_content,
    &ett_j2735_ValidRegion,
    &ett_j2735_T_area,
  };

  /* Register protocol */
  proto_j2735 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_j2735, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  j2735_handle = register_dissector(PFNAME, dissect_j2735, proto_j2735);

  dsrcmsgid_dissector_table       = register_dissector_table("j2735.msg", "J2735 DSRC Message dissector table ", proto_j2735, FT_UINT32, BASE_DEC);
  j2735_partii_id_dissector_table = register_dissector_table("j2735.partii-id", "J2735 PARTII-EXT-ID table ", proto_j2735, FT_UINT32, BASE_DEC);

//  dissector_add_for_decode_as(PFNAME, j2735_handle);
}


/*--- proto_reg_handoff_j2735 -------------------------------------------*/
void proto_reg_handoff_j2735(void) {

  dissector_add_uint("j2735.msg", mapData, create_dissector_handle(dissect_MapData_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", signalPhaseAndTimingMessage, create_dissector_handle(dissect_SPAT_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", basicSafetyMessage, create_dissector_handle(dissect_BasicSafetyMessage_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", commonSafetyRequest, create_dissector_handle(dissect_CommonSafetyRequest_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", emergencyVehicleAlert, create_dissector_handle(dissect_EmergencyVehicleAlert_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", intersectionCollision, create_dissector_handle(dissect_IntersectionCollision_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", nmeaCorrections, create_dissector_handle(dissect_NMEAcorrections_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", probeDataManagement, create_dissector_handle(dissect_ProbeDataManagement_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", probeVehicleData, create_dissector_handle(dissect_ProbeVehicleData_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", roadSideAlert, create_dissector_handle(dissect_RoadSideAlert_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", rtcmCorrections, create_dissector_handle(dissect_RTCMcorrections_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", signalRequestMessage, create_dissector_handle(dissect_SignalRequestMessage_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", signalStatusMessage, create_dissector_handle(dissect_SignalStatusMessage_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", travelerInformation, create_dissector_handle(dissect_TravelerInformation_PDU, proto_j2735));
  dissector_add_uint("j2735.msg", personalSafetyMessage, create_dissector_handle(dissect_PersonalSafetyMessage_PDU, proto_j2735));
  dissector_add_uint("j2735.partii-id", vehicleSafetyExt, create_dissector_handle(dissect_VehicleSafetyExtensions_PDU, proto_j2735));
  dissector_add_uint("j2735.partii-id", specialVehicleExt, create_dissector_handle(dissect_SpecialVehicleExtensions_PDU, proto_j2735));
  dissector_add_uint("j2735.partii-id", supplementalVehicleExt, create_dissector_handle(dissect_SupplementalVehicleExtensions_PDU, proto_j2735));


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

  // J3268
  dissector_add_uint("ieee1609dot2.psid", 2113685, j2735_handle); // SSM
  dissector_add_uint("ieee1609dot2.psid", 2113686, j2735_handle); // SRM
  dissector_add_uint("ieee1609dot2.psid", 2113687, j2735_handle); // RSM

  // UDP
}

