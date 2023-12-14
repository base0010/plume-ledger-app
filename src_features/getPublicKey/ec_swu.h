#include "cx.h"
#include "ox_bn.h"
#include "ox_ec.h"

/* Evaluation of X over elliptic curve of weierstrass form X^3+aX=b*/
cx_err_t cy_curve_eval_ysquare(cx_bn_t o_bn_y2, cx_bn_t i_bn_a, cx_bn_t i_bn_b,
                               cx_bn_t i_bn_x, cx_bn_t i_bn_p, size_t i_tu8_p);

/* hashing of a Point over a Weierstrass curve from a digest using
 * SWU/Brier-Coron and all technique (alternative to Pedersen Hash)
 * https://eprint.iacr.org/2009/340.pdf*/
cx_err_t cy_swu_hashpoint(cx_curve_t curve, cx_bn_t o_bn_x, cx_bn_t o_bn_y,
                          uint8_t *i_digest);


