#ifndef _ERRORS_H_
#define _ERRORS_H_

/// Status word for success.
#define SW_OK 0x9000
/// Status word for incorrect P1 or P2.
#define SW_WRONG_P1P2 0x6A86
/// Status word for either wrong Lc or lenght of APDU command less than 5.
#define SW_WRONG_DATA_LENGTH 0x6A87
/// Status word for unknown command with this INS.
#define SW_INS_NOT_SUPPORTED 0x6D00
/// Status word for instruction class is different than CLA.
#define SW_CLA_NOT_SUPPORTED 0x6E00
/// Status word for wrong reponse length (buffer too small or too big).
#define SW_WRONG_RESPONSE_LENGTH 0xB000

#endif  // _ERRORS_H_