// SPDX-License-Identifier: Apache-2.0 or CC0-1.0
//
// Timing side-channel data-collection harness for crypto_kem_dec, following
// the dudect methodology (fixed-vs-random classes, Welch's t-test computed
// host-side -- see kyber-sca/timing/welch_ttest.py and
// kyber-sca/docs/methodology.md Section 5). Mirrors mupq/crypto_kem/speed.c's
// structure and macro-based namespacing, but times with the Cortex-M4's own
// DWT->CYCCNT free-running cycle counter instead of hal_get_time()'s
// SysTick-based one, and disables interrupts around each timed call so the
// periodic SysTick ISR (started by hal_setup()) cannot inject jitter into a
// measurement -- both deliberate choices for a timing side-channel campaign,
// see kyber-sca/firmware/dudect/README.md.
#include "api.h"
#include "hal.h"
#include "randombytes.h"

#include <stdint.h>
#include <string.h>

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc     NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec     NAMESPACE(crypto_kem_dec)

#ifndef DUDECT_NUM_TRACES
#define DUDECT_NUM_TRACES 100000L
#endif

/* Cortex-M4 DWT cycle counter, memory-mapped, no CMSIS header dependency. */
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

/* xorshift32, seeded once from the board's randombytes() (real hardware RNG
   on chips that have one; this project's documented fixed-seed fallback on
   the F411RE -- see kyber-sca/README.md). Used only to (a) pick which class
   a trial belongs to and (b) draw "random"-class ciphertext bytes. Neither
   use is security-sensitive: dudect's class assignment does not need
   cryptographic randomness, only a sequence uncorrelated with the timing
   under test, so the fixed-seed fallback does not compromise this campaign
   the same way it would for on-device long-term-key generation. */
static uint32_t xrand_state;
static uint32_t xrand(void) {
  uint32_t x = xrand_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  xrand_state = x;
  return x;
}

/* One line per trial: "<class>,<cycles>\n" -- class is 0 (fixed) or 1
   (random), cycles is the raw DWT_CYCCNT delta. Deliberately a single
   hal_send_str() call per trial (hal_send_str always appends its own '\n'),
   unlike sendfn.h's send_unsigned(ll) which needs two calls per value --
   halves UART traffic for a campaign that already needs tens of thousands
   of lines. */
static void send_trial(int cls, uint32_t cycles) {
  char buf[24];
  int pos = 0;
  char tmp[10];
  int tlen = 0;
  uint32_t v = cycles;

  buf[pos++] = (char)('0' + cls);
  buf[pos++] = ',';

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
  unsigned char ss[MUPQ_CRYPTO_BYTES];
  unsigned char ct_fixed[MUPQ_CRYPTO_CIPHERTEXTBYTES];
  unsigned char ct[MUPQ_CRYPTO_CIPHERTEXTBYTES];
  unsigned char seedbuf[4];
  long i;

  hal_setup(CLOCK_BENCHMARK);
  hal_send_str("==========================");

  dwt_init();

  /* Fixed keypair for the whole campaign. Threat model (docs/methodology.md
     Section 2): attacker knows pk, chooses ciphertexts, does not know sk --
     sk is fixed here by design, not a limitation. */
  MUPQ_crypto_kem_keypair(pk, sk);

  /* Fixed-class ciphertext: one VALID ciphertext, encapsulated once and
     reused for every "fixed" trial -- decapsulation always takes the accept
     (FO re-encryption match) path for this class. */
  MUPQ_crypto_kem_enc(ct_fixed, ss, pk);

  randombytes(seedbuf, sizeof(seedbuf));
  xrand_state = ((uint32_t)seedbuf[0] << 24) | ((uint32_t)seedbuf[1] << 16) |
                ((uint32_t)seedbuf[2] << 8) | (uint32_t)seedbuf[3];
  if (xrand_state == 0) {
    xrand_state = 0xdeadbeefu; /* xorshift32 has a fixed point at 0 */
  }

  hal_send_str("BEGIN dudect_kem_dec");

  for (i = 0; i < DUDECT_NUM_TRACES; i++) {
    int cls = (int)(xrand() & 1u);
    uint32_t t0, t1;

    if (cls == 0) {
      memcpy(ct, ct_fixed, sizeof(ct));
    } else {
      /* Random-class ciphertext: fresh random bytes each trial -- almost
         certainly INVALID, exercising the FO-transform implicit-rejection
         path (docs/methodology.md Sections 2-3: the highest-value target
         per the published literature). */
      size_t j = 0;
      while (j < sizeof(ct)) {
        uint32_t r = xrand();
        size_t chunk = (sizeof(ct) - j < 4) ? (sizeof(ct) - j) : 4;
        memcpy(ct + j, &r, chunk);
        j += chunk;
      }
    }

    __asm__ volatile("cpsid i" ::: "memory");
    t0 = DWT_CYCCNT;
    MUPQ_crypto_kem_dec(ss, ct, sk);
    t1 = DWT_CYCCNT;
    __asm__ volatile("cpsie i" ::: "memory");

    send_trial(cls, t1 - t0);
  }

  hal_send_str("END dudect_kem_dec");
  hal_send_str("#");

  return 0;
}
