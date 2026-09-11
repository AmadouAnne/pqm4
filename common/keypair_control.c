// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
//
// Measurement sanity check for dudect.c's DWT-based timing harness: times
// crypto_kem_keypair, which is known to have data-dependent timing
// (rejection sampling in uniform polynomial generation loops a variable
// number of times depending on random byte values -- unlike crypto_kem_dec
// on this implementation, see kyber-sca/docs/methodology.md Section 5).
// If this harness shows zero variance too, that would mean the DWT
// measurement itself is broken, not that decapsulation is constant-time --
// this file is the control experiment ruling that out. Kept as a permanent,
// re-runnable artifact, not a throwaway: a result this clean (dudect.c
// found *zero* measurable cycle variance on crypto_kem_dec) needs this
// control on the record, not just asserted in prose.
#include "api.h"
#include "hal.h"

#include <stdint.h>

#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

#define MUPQ_CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_crypto_kem_keypair    NAMESPACE(crypto_kem_keypair)

#ifndef KEYPAIR_CONTROL_NUM_TRACES
#define KEYPAIR_CONTROL_NUM_TRACES 5000L
#endif

#define DEMCR              (*(volatile uint32_t *)0xE000EDFCu)
#define DWT_CTRL           (*(volatile uint32_t *)0xE0001000u)
#define DWT_CYCCNT         (*(volatile uint32_t *)0xE0001004u)
#define DEMCR_TRCENA       (1u << 24)
#define DWT_CTRL_CYCCNTENA (1u << 0)

static void dwt_init(void) {
  DEMCR |= DEMCR_TRCENA;
  DWT_CYCCNT = 0;
  DWT_CTRL |= DWT_CTRL_CYCCNTENA;
}

static void send_cycles(uint32_t cycles) {
  char buf[12];
  int pos = 0;
  char tmp[10];
  int tlen = 0;
  uint32_t v = cycles;

  if (v == 0) {
    tmp[tlen++] = '0';
  } else {
    while (v > 0) {
      tmp[tlen++] = (char)('0' + (v % 10));
      v /= 10;
    }
  }
  while (tlen > 0) {
    buf[pos++] = tmp[--tlen];
  }
  buf[pos] = '\0';

  hal_send_str(buf);
}

int main(void) {
  unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];
  long i;

  hal_setup(CLOCK_BENCHMARK);
  hal_send_str("==========================");

  dwt_init();

  hal_send_str("BEGIN keypair_control");

  for (i = 0; i < KEYPAIR_CONTROL_NUM_TRACES; i++) {
    uint32_t t0, t1;

    __asm__ volatile("cpsid i" ::: "memory");
    t0 = DWT_CYCCNT;
    MUPQ_crypto_kem_keypair(pk, sk);
    t1 = DWT_CYCCNT;
    __asm__ volatile("cpsie i" ::: "memory");

    send_cycles(t1 - t0);
  }

  hal_send_str("END keypair_control");
  hal_send_str("#");

  return 0;
}
