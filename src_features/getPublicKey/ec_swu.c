/**********************************************************************************/
/* Copyright (C) 2022 - Renaud Dubois
 */
/* This file is part of cy_lib project
 */
/* License: This software is licensed under a dual BSD and GPL v2 license.
 */
/* See LICENSE file at the root folder of the project.
 */
/* FILE: cy_ec.h
 */
/* 																			      */
/* 																			      */
/* DESCRIPTION: */
/* hashing of a Point over a Weierstrass curve from a digest using
 * SWU/Brier-Coron and all technique (alternative to Pedersen Hash)
 * https://eprint.iacr.org/2009/340.pdf*/
/**********************************************************************************/

#include "ec_swu.h"




/* todo: translate to CY generic cryptography*/
/* Evaluation of X over elliptic curve of weierstrass form X^3+aX=b*/
cx_err_t cy_curve_eval_ysquare(cx_bn_t o_bn_y2, cx_bn_t i_bn_a, cx_bn_t i_bn_b,
                               cx_bn_t i_bn_x, cx_bn_t i_bn_p, size_t i_tu8_p)
{
  /* I.Declarations*/
  cx_err_t error = CX_INTERNAL_ERROR;
  cx_bn_t bn_temp, bn_temp2;

  /* II. Allocations*/
  CX_CHECK(cx_bn_alloc(&bn_temp, i_tu8_p));
  CX_CHECK(cx_bn_alloc(&bn_temp2, i_tu8_p));

  /*III.Computations*/
  CX_CHECK(cx_bn_mod_mul(bn_temp, i_bn_x, i_bn_x, i_bn_p));     /*X^2*/
  CX_CHECK(cx_bn_mod_mul(bn_temp2, bn_temp, i_bn_x, i_bn_p));   /*X^3*/
  CX_CHECK(cx_bn_mod_mul(bn_temp, i_bn_a, i_bn_x, i_bn_p));     /*a.X*/
  CX_CHECK(cx_bn_mod_add(bn_temp2, bn_temp, bn_temp2, i_bn_p)); /*X^3+a.X*/
  CX_CHECK(
      cx_bn_mod_add(o_bn_y2, i_bn_b, bn_temp2, i_bn_p)); /*Y^2=X^3+a.X+b*/

  /*IV Free*/
  CX_CHECK(cx_bn_destroy(&bn_temp));
  CX_CHECK(cx_bn_destroy(&bn_temp2));

/*V. Return*/
end:
  return error;
}
/* SWU simplified algorithm extracted from https://eprint.iacr.org/2009/340.pdf
 * (notations are conserved)*/
/*assumption:
 * Use of ec-sdk2 (a and b coeff in curve header)
 * curve is known
 * prime field characteristic p = 3 [4] (true for secp and brainpool384)
 * i_digest has same length as prime field
 */
cx_err_t cy_swu_hashpoint(cx_curve_t curve, cx_bn_t o_bn_x, cx_bn_t o_bn_y,
                          uint8_t *i_digest)
{
  cx_err_t error = CX_INTERNAL_ERROR;

  /* I.Declarations*/

  cx_bn_t bn_p; /* curve prime field characteristic*/

  uint32_t is_square_h2 = false;
  uint32_t is_square_h3 = false;

  // const cx_curve_weierstrass_t *l_curve =
  //     (const cx_curve_weierstrass_t *)cx_ecfp_get_domain(curve);

  // if (l_curve == NULL)
  //   return CX_INVALID_PARAMETER_VALUE; /* curve not known*/

  // size_t tu8_p = l_curve->length; /* prime field byte length*/
  size_t tu8_p = 32;
  /*printf("\n Curve id:%d", curve);
  printf("\n Curve order:");
  for(i=0;i<tu8_p;i++) printf(" %02x", (l_curve->n)[i]);
  printf("\n Curve field:");
                  for(i=0;i<tu8_p;i++) printf(" %02x", (l_curve->p)[i]);*/

  /* local variables*/
  cx_bn_t bn_t;
  cx_bn_t bn_alpha;
  cx_bn_t bn_temp, bn_temp2;
  cx_bn_t bn_a;
  cx_bn_t bn_b;
  cx_bn_t bn_r;

  uint32_t sign = 1;
  // printf("\n **********************************/ SWU");
  // printf("\n start ! p size=%d, bn_ctx=%x", tu8_p, cx_get_bn_ctx());

  /* II. Allocations*/
  CX_CHECK(cx_bn_alloc(&bn_alpha, tu8_p));
  CX_CHECK(cx_bn_alloc(&bn_temp, tu8_p));
  CX_CHECK(cx_bn_alloc(&bn_temp2, tu8_p));
  CX_CHECK(cx_bn_alloc(&bn_r, tu8_p));



  //allocate for p a and b curve parameters
  CX_CHECK(cx_bn_alloc(&bn_p, tu8_p));
  CX_CHECK(cx_bn_alloc(&bn_a, tu8_p));
  CX_CHECK(cx_bn_alloc(&bn_b, tu8_p));

  cx_ecdomain_parameter_bn(curve, CX_CURVE_PARAM_Field, bn_p);
  cx_ecdomain_parameter_bn(curve, CX_CURVE_PARAM_A, bn_a);
  cx_ecdomain_parameter_bn(curve, CX_CURVE_PARAM_B, bn_b);


  CX_CHECK(cx_bn_alloc_init(
      &bn_t, tu8_p, i_digest,
      tu8_p)); /* allocating and initializing big number t*/
  // CX_CHECK(cx_bn_alloc_init(
  //     &bn_p, tu8_p, l_curve->p,
  //     tu8_p)); /* allocating and initializing big number p*/
  // CX_CHECK(cx_bn_alloc_init(
  //     &bn_a, tu8_p, l_curve->a,
  //     tu8_p)); /* allocating and initializing big number a*/
  // CX_CHECK(cx_bn_alloc_init(
  //     &bn_b, tu8_p, l_curve->b,
  //     tu8_p)); /* allocating and initializing big number b*/
  // // printf("\n allocation success");

  /* III. Computations*/
  /*1. alpha<-t^2 mod q*/
  CX_CHECK(cx_bn_mod_mul(bn_temp, bn_t, bn_t, bn_p)); /* t^2*/
  CX_CHECK(cx_bn_sub(bn_alpha, bn_p, bn_temp));       /* -t^2*/

  /*2. X2 <- -b/a(1+ 1/(alpha^2+alpha))*/
  CX_CHECK(cx_bn_mod_mul(bn_temp, bn_alpha, bn_alpha, bn_p)); /* alpha^2*/
  CX_CHECK(
      cx_bn_mod_add(bn_t, bn_alpha, bn_temp, bn_p)); /* alpha^2+alpha */
  CX_CHECK(
      cx_bn_mod_invert_nprime(bn_temp, bn_t, bn_p)); /*1/(alpha^2+alpha)*/
  CX_CHECK(cx_bn_set_u32(bn_t, 1));                  /* One (Metallica)*/
  CX_CHECK(
      cx_bn_mod_add(bn_t, bn_t, bn_temp, bn_p)); /*(1+ 1/(alpha^2+alpha))*/
  CX_CHECK(cx_bn_sub(bn_temp, bn_p, bn_b));      /* -b */
  CX_CHECK(cx_bn_mod_invert_nprime(bn_temp2, bn_a, bn_p));   /*1/(a) mod q*/
  CX_CHECK(cx_bn_mod_mul(bn_temp, bn_temp, bn_temp2, bn_p)); /* -b/a
                                                                  */
  CX_CHECK(cx_bn_mod_mul(bn_t, bn_temp, bn_t, bn_p));        /* X2	*/

  /*4.1 h2^2<-X2^3+aX2+b*/
  CX_CHECK(cy_curve_eval_ysquare(bn_r, bn_a, bn_b, bn_t, bn_p, tu8_p));

  /* note : i didn't find a jacobi symbol computation, using errcode as square
   * element testing, not very clean use here*/
  if (cx_bn_mod_sqrt(bn_temp, bn_r, bn_p, sign) == CX_OK) /* h2^(q+1)/4*/
  {
    // printf("\n ******h2 is solution");
    is_square_h2 = true;
    error = CX_OK;
    cx_bn_copy(o_bn_x, bn_t);
    cx_bn_copy(o_bn_y, bn_temp);
  }

  /*3. X3<- alpha.X2*/
  CX_CHECK(cx_bn_mod_mul(bn_temp, bn_t, bn_alpha, bn_p)); /* X3	*/
  /*4.2 h3<-X3^3+aX3+b*/
  CX_CHECK(cy_curve_eval_ysquare(bn_r, bn_a, bn_b, bn_temp, bn_p, tu8_p));

  /* note : there is no jacobi symbol computation, using errcode as square
   * element testing, not very clean use here*/
  if (cx_bn_mod_sqrt(bn_temp2, bn_r, bn_p, sign) == CX_OK) /* h2^(q+1)/4*/
  {
    // printf("\n *****h3 is solution");
    is_square_h3 = true;
    error = CX_OK;
    CX_CHECK(cx_bn_copy(o_bn_x, bn_temp));
    CX_CHECK(cx_bn_copy(o_bn_y, bn_temp2));
  }

#define _DEBUGGING
#ifdef _DEBUGGING
  cx_ecpoint_t P;
  bool is_on_curve;
  /*Something went wrong : h2 or h3 should be square root*/
  if ((is_square_h2 == false) && (is_square_h3 == false)) {
    // printf("\n No square FAIL");
    return CX_INTERNAL_ERROR;
  }
  CX_CHECK(cx_ecpoint_alloc(&P, curve));

  CX_CHECK(cx_ecpoint_init_bn(&P, o_bn_x, o_bn_y)); /* P=(x,y) */
  CX_CHECK(cx_ecpoint_is_on_curve(&P, &is_on_curve));
  if (is_on_curve == false) {
    // printf("\n SWU error: point generated not on curve");
  }
  // printf("\n On curve ?:%d", is_on_curve);
  CX_CHECK(cx_ecpoint_destroy(&P));


#endif
  /*Constant time return*/
  /* IV. Free*/
  CX_CHECK(cx_bn_destroy(&bn_alpha));
  CX_CHECK(cx_bn_destroy(&bn_temp));
  CX_CHECK(cx_bn_destroy(&bn_temp2));
  CX_CHECK(cx_bn_destroy(&bn_r));
  CX_CHECK(cx_bn_destroy(&bn_t));
  CX_CHECK(cx_bn_destroy(&bn_p));
  CX_CHECK(cx_bn_destroy(&bn_a));
  CX_CHECK(cx_bn_destroy(&bn_b));
  /* V. Return errcode*/
end:
  return error;
}
