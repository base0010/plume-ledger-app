#include "shared_context.h"
#include "apdu_constants.h"
#include "utils.h"
#include "feature_getPublicKey.h"
#include "ethUtils.h"
#include "common_ui.h"
#include "os_io_seproxyhal.h"
#include "ox_bn.h"
#include "ec_swu.h"

void handleGetPublicKey(uint8_t p1,
                        uint8_t p2,
                        const uint8_t *dataBuffer,
                        uint8_t dataLength,
                        unsigned int *flags,
                        unsigned int *tx) {

    PRINTF("\n In handler");

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
    io_seproxyhal_io_heartbeat();

    PRINTF("\nInternal Private Key %.*H\n", 32, privateKeyData);


    uint8_t testPrivateKey[INT256_LENGTH] = {
        0x51, 0x9b, 0x42, 0x3d, 0x71, 0x5f, 0x8b, 0x58,
        0x1f, 0x4f, 0xa8, 0xee, 0x59, 0xf4, 0x77, 0x1a,
        0x5b, 0x44, 0xc8, 0x13, 0x0b, 0x4e, 0x3e, 0xac,
        0xca, 0x54, 0xa5, 0x6d, 0xda, 0x72, 0xb4, 0x64
    };

    PRINTF("\n Test Private Key %.*H\n", 32, testPrivateKey);


    //Begin Hash to Curve stuffs
    //Point on curve should be 64b (x,y) + format byte
    uint8_t HTPInput[65]= {
        0x04, //format byte

        //Px
        0xc1, 0xca, 0xe2, 0x90, 0xe2, 0x91, 0xae, 0xe6,
        0x17, 0xeb, 0xae, 0xf1, 0xbe, 0x6d, 0x73, 0x86,
        0x14, 0x79, 0xc4, 0x8b, 0x84, 0x1e, 0xab, 0xa9,
        0xb7, 0xb5, 0x85, 0x2d, 0xdf, 0xeb, 0x13, 0x46,

        //Py
        0x64, 0xfa, 0x67, 0x8e, 0x07, 0xae, 0x11, 0x61,
        0x26, 0xf0, 0x8b, 0x02, 0x2a, 0x94, 0xaf, 0x6d,
        0xe1, 0x59, 0x85, 0xc9, 0x96, 0xc3, 0xa9, 0x1b,
        0x64, 0xc4, 0x06, 0xa9, 0x60, 0xe5, 0x10, 0x67

    };

    uint8_t TestHTPInput[65]= {
        0x04, //format byte

        //Px
        0xbc, 0xac, 0x2d, 0x0e, 0x12, 0x67, 0x9f, 0x23,
        0xc2, 0x18, 0x88, 0x93, 0x95, 0xab, 0xcd, 0xc0,
        0x1f, 0x2a, 0xff, 0xbc, 0x49, 0xc5, 0x4d, 0x11,
        0x36, 0xa2, 0x19, 0x0d, 0xb0, 0x80, 0x0b, 0x65,

        //Py
        0x3b, 0xcf, 0xb3, 0x39, 0xc9, 0x74, 0xc0, 0xe7,
        0x57, 0xd3, 0x48, 0x08, 0x1f, 0x90, 0xa1, 0x23,
        0xb0, 0xa9, 0x1a, 0x53, 0xe3, 0x2b, 0x37, 0x52,
        0x14, 0x5d, 0x87, 0xf0, 0xcd, 0x70, 0x96, 0x6e
    };

    uint8_t testDigest[INT256_LENGTH] = {
        0x00, 0x9b, 0x42, 0x3d, 0x71, 0x9f, 0x8b, 0x58,
        0x1f, 0x4f, 0xa8, 0xae, 0x59, 0xfd, 0x77, 0x1a,
        0x5b, 0x14, 0xc8, 0xff, 0x0b, 0x4e, 0x3e, 0xac,
        0xca, 0x54, 0x35, 0x6d, 0xda, 0x72, 0xb4, 0x64
    };


    PRINTF("\nHTP Test%.*H\n", 65, TestHTPInput);

    cx_curve_t curve256k1  = CX_CURVE_256K1;


    io_seproxyhal_io_heartbeat();
    // cx_ecfp_scalar_mult_no_throw(curve256k1, HTPInput, privateKeyData, 32);
    cx_err_t err = cx_ecfp_scalar_mult_no_throw(curve256k1, TestHTPInput, testPrivateKey, 32);
    if(err != CX_OK){
        PRINTF("ERROR");
    }

    //HTC Point coords
    cx_bn_t Px, Py;

    io_seproxyhal_io_heartbeat();
    PRINTF("\nNuliffier (HTP salrmul with PrivateKey) %.*H\n", 65, TestHTPInput);



    //z (should always be 1?)
    cx_bn_t x, y; 

    //init bn z
    cx_bn_alloc_init(&x, 32, (uint8_t*){1}, 32);
    cx_bn_alloc_init(&y, 32, (uint8_t*){1}, 32);



    cy_swu_hashpoint(curve256k1, x, y, testDigest);

    //
    // cx_err_t xErr = cx_bn_alloc_init(&Px, 32, HTCx, 2);

    // if(xErr != CX_OK){
    //     PRINTF("\n Error in x BN allocation");
    // }


    // cx_err_t yErr = cx_bn_alloc_init(&Py, 32, HTCy, 32);

    // if(yErr != CX_OK){
    //     PRINTF("\n ERROR in y BN allocation");
    // }

    // PRINTF("ALLOCATED BN");

 



    // cx_ecpoint_t P; 
    // cx_ecpoint_alloc(&P, curve256k1);
    // cx_ecpoint_init(&P, &Px, sizeof(Px), &Py, sizeof(Py));

    //create the nullifier
    // cx_ecpoint_rnd_scalarmult(&P, privateKeyData);
 
    
    //printf P which should have a nullifier now
    // uint8_t PxExport[sizeof(P)];

    // cx_bn_export(&P, &PxExport, sizeof(P));

    // for(int i = 0; i < (sizeof(PxExport)/sizeof(uint8_t)); i++){
    //     PRINTF("%lu\n", Px);
    // }
    





    //todo: clear after we use to generate the PLUME nulllifier.
    
    // explicit_bzero(&privateKey, sizeof(privateKey));
    // explicit_bzero(privateKeyData, sizeof(privateKeyData));
    
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

        snprintf(strings.common.nullifier,
                 sizeof(strings.common.nullifier),
                 "%.*H",
                 65,
                 TestHTPInput);

        for(int i = 0; i < 65; i++){
             G_io_apdu_buffer[i] = TestHTPInput[i];
        }
       
        // don't unnecessarily pass the current app's chain ID
        ui_display_public_key(chainConfig->chainId == chain_id ? NULL : &chain_id);

        *flags |= IO_ASYNCH_REPLY;

        
    }
#endif  // NO_CONSENT
}
