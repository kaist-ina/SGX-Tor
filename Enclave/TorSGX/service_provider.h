/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/


#ifndef _SERVICE_PROVIDER_H
#define _SERVICE_PROVIDER_H

#include "remote_attestation_result.h"
#include "ias_ra.h"
#include "network_ra.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum {
    SP_OK,
    SP_UNSUPPORTED_EXTENDED_EPID_GROUP,
    SP_INTEGRITY_FAILED,
    SP_QUOTE_VERIFICATION_FAILED,
    SP_IAS_FAILED,
    SP_INTERNAL_ERROR,
    SP_PROTOCOL_ERROR,
    SP_QUOTE_VERSION_ERROR,
} sp_ra_msg_status_t;

#pragma pack(push,1)

#define SAMPLE_SP_TAG_SIZE       16
#define SAMPLE_SP_IV_SIZE        12

typedef struct sample_ec_pub_t
{
    uint8_t gx[SAMPLE_ECP_KEY_SIZE];
    uint8_t gy[SAMPLE_ECP_KEY_SIZE];
} sample_ec_pub_t;

//fixed length to align with internal structure
typedef struct sample_ps_sec_prop_desc_t
{
    uint8_t  sample_ps_sec_prop_desc[256];
} sample_ps_sec_prop_desc_t;

#pragma pack(pop)

typedef uint32_t                sample_ra_context_t;

typedef uint8_t                 sample_key_128bit_t[16];

typedef sample_key_128bit_t     sample_ra_key_128_t;

typedef struct sample_ra_msg0_t
{
    uint32_t                    extended_epid_group_id;
} sample_ra_msg0_t;


typedef struct sample_ra_msg1_t
{
    sample_ec_pub_t             g_a;        // the Endian-ness of Ga is
                                            // Little-Endian
    sample_epid_group_id_t      gid;        // the Endian-ness of GID is
                                            // Little-Endian
} sample_ra_msg1_t;

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
const uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;

typedef struct sample_ra_msg2_t
{
    sample_ec_pub_t             g_b;        // the Endian-ness of Gb is
                                            // Little-Endian
    sample_spid_t               spid;       // In little endian
    uint16_t                    quote_type; /* unlinkable Quote(0) or linkable Quote(0) in little endian*/
    uint16_t                    kdf_id;     /* key derivation function id in little endian. 
                                             0x0001 for AES-CMAC Entropy Extraction and Key Derivation */
    sample_ec_sign256_t         sign_gb_ga; // In little endian
    sample_mac_t                mac;        // mac_smk(g_b||spid||quote_type||
                                            //         sign_gb_ga)
    uint32_t                    sig_rl_size;
#ifdef _MSC_VER
#pragma warning(push)
// Disable warning that array payload has size 0
#ifdef __INTEL_COMPILER
#pragma warning ( disable:94 )
#else
#pragma warning ( disable: 4200 )
#endif
#endif
    uint8_t                     sig_rl[];
#ifdef _MSC_VER
#pragma warning(pop)
#endif
} sample_ra_msg2_t;

typedef struct sample_ra_msg3_t
{
    sample_mac_t                mac;        // mac_smk(g_a||ps_sec_prop||quote)
    sample_ec_pub_t             g_a;        // the Endian-ness of Ga is
                                            // Little-Endian
    sample_ps_sec_prop_desc_t   ps_sec_prop;
#ifdef _MSC_VER
#pragma warning(push)
    // Disable warning that array payload has size 0
#ifdef __INTEL_COMPILER
#pragma warning ( disable:94 )
#else
#pragma warning ( disable: 4200 )
#endif
#endif
    uint8_t                     quote[];
#ifdef _MSC_VER
#pragma warning(pop)
#endif
} sample_ra_msg3_t;

int sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
    uint32_t msg0_size);

int sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
						uint32_t msg1_size,
						ra_samp_response_header_t **pp_msg2);

int sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
                        uint32_t msg3_size,
                        ra_samp_response_header_t **pp_att_result_msg);

int sp_ra_free_msg2(
    sample_ra_msg2_t *p_msg2);



typedef int (*sample_enroll)(int sp_credentials, sample_spid_t* spid,
    int* authentication_token);

typedef int(*sample_get_sigrl)(const sample_epid_group_id_t gid, uint32_t* p_sig_rl_size,
    uint8_t** p_sig_rl);

typedef int(*sample_verify_attestation_evidence)(sample_quote_t* p_isv_quote,
    uint8_t* pse_manifest,
    ias_att_report_t* attestation_verification_report);


typedef struct sample_extended_epid_group
{
    uint32_t extended_epid_group_id;
    sample_enroll enroll;
    sample_get_sigrl get_sigrl;
    sample_verify_attestation_evidence verify_attestation_evidence;
} sample_extended_epid_group;

// This is a context data structure used on SP side
typedef struct _sp_db_item_t
{
    sample_ec_pub_t             g_a;
    sample_ec_pub_t             g_b;
    sample_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
    sample_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
    sample_ec_key_128bit_t      sk_key;// Shared secret key for encryption
    sample_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
    sample_ec_priv_t            b;
    sample_ps_sec_prop_desc_t   ps_sec_prop;
}sp_db_item_t;
static sp_db_item_t g_sp_db;

#ifdef  __cplusplus
}
#endif

#endif
