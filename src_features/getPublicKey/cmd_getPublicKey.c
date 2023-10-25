#include "shared_context.h"
#include "apdu_constants.h"
#include "utils.h"
#include "feature_getPublicKey.h"
#include "ethUtils.h"
#include "common_ui.h"
#include "os_io_seproxyhal.h"

void handleGetPublicKey(uint8_t p1,
                        uint8_t p2,
                        const uint8_t *dataBuffer,
                        uint8_t dataLength,
                        unsigned int *flags,
                        unsigned int *tx) {
    uint8_t privateKeyData[INT256_LENGTH];
    bip32_path_t bip32;
    cx_ecfp_private_key_t privateKey;

    if (!G_called_from_swap) {
        reset_app_context();
    }

    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        PRINTF("Error: Unexpected P1 (%u)!\n", p1);
        THROW(APDU_RESPONSE_INVALID_P1_P2);
    }
    if ((p2 != P2_CHAINCODE) && (p2 != P2_NO_CHAINCODE)) {
        PRINTF("Error: Unexpected P2 (%u)!\n", p2);
        THROW(APDU_RESPONSE_INVALID_P1_P2);
    }

    dataBuffer = parseBip32(dataBuffer, &dataLength, &bip32);

    if (dataBuffer == NULL) {
        THROW(APDU_RESPONSE_INVALID_DATA);
    }

    tmpCtx.publicKeyContext.getChaincode = (p2 == P2_CHAINCODE);
    io_seproxyhal_io_heartbeat();
    os_perso_derive_node_bip32(
        CX_CURVE_256K1,
        bip32.path,
        bip32.length,
        privateKeyData,
        (tmpCtx.publicKeyContext.getChaincode ? tmpCtx.publicKeyContext.chainCode : NULL));
    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    io_seproxyhal_io_heartbeat();
    cx_ecfp_generate_pair(CX_CURVE_256K1, &tmpCtx.publicKeyContext.publicKey, &privateKey, 1);

    //Begin Hash to Curve stuffs

    //todo: replace with actual test values
    uint8_t HTCx[32] = {0x01, 0x02};
    uint8_t HTCy[32] = {0x01, 0x02};
    //HTC Point coords
    cx_bn_t Px, Py;
    //z (should always be 1?)
    // cx_bn_t z; 

    //init bn z
    // cx_bn_alloc_init(&z, 32, (uint8_t*){1}, 1);
    //
    cx_bn_alloc_init(&Px, 32, HTCx, 32);
    cx_bn_alloc_init(&Py, 32, HTCy, 32);

    cx_curve_t curve256k1  = CX_CURVE_256K1;

    cx_ecpoint_t P; 
    cx_ecpoint_alloc(&P, curve256k1);
    cx_ecpoint_init(&P, &Px, sizeof(Px), &Py, sizeof(Py));

    //create the nullifier
    cx_ecpoint_rnd_scalarmul_bn(&P, privateKeyData);

    //printf P which should have a nullifier now
    uint8_t PxExport[sizeof(P)];

    cx_bn_export(&P, &PxExport, sizeof(P));

    PRINTF("Error: Leftover unwanted data (%u bytes long)!\n", &P);






    //todo: clear after we use to generate the PLUME nulllifier.
    
    // explicit_bzero(&privateKey, sizeof(privateKey));
    // explicit_bzero(privateKeyData, sizeof(privateKeyData));
    io_seproxyhal_io_heartbeat();
    getEthAddressStringFromKey(&tmpCtx.publicKeyContext.publicKey,
                               tmpCtx.publicKeyContext.address,
                               &global_sha3,
                               chainConfig->chainId);

    uint64_t chain_id = chainConfig->chainId;
    if (dataLength >= sizeof(chain_id)) {
        chain_id = u64_from_BE(dataBuffer, sizeof(chain_id));
        dataLength -= sizeof(chain_id);
        dataBuffer += sizeof(chain_id);
    }

    (void) dataBuffer;  // to prevent dead increment warning
    if (dataLength > 0) {
        PRINTF("Error: Leftover unwanted data (%u bytes long)!\n", dataLength);
        THROW(APDU_RESPONSE_INVALID_DATA);
    }

#ifndef NO_CONSENT
    if (p1 == P1_NON_CONFIRM)
#endif  // NO_CONSENT
    {




        *tx = set_result_get_publicKey();
        THROW(APDU_RESPONSE_OK);
    }
#ifndef NO_CONSENT
    else {
        // tmpCtx.publicKeyContext.address[0] = sizeof(PxExport);
        // tmpCtx.publicKeyContext.address[1] = (char)PxExport[1];
        // tmpCtx.publicKeyContext.address[2] = (char)PxExport[2];
        // tmpCtx.publicKeyContext.address[3] = (char)PxExport[3];



        snprintf(strings.common.fullAddress,
                 sizeof(strings.common.fullAddress),
                 "0x%.*s",
                 40,
                 tmpCtx.publicKeyContext.address);
        G_io_apdu_buffer[0] = PxExport[0];
        G_io_apdu_buffer[1] = PxExport[1];
        G_io_apdu_buffer[2] = PxExport[2];
        G_io_apdu_buffer[3] = PxExport[3];
        // don't unnecessarily pass the current app's chain ID
        ui_display_public_key(chainConfig->chainId == chain_id ? NULL : &chain_id);

        *flags |= IO_ASYNCH_REPLY;

        
    }
#endif  // NO_CONSENT
}
