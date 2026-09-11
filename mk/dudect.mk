# SPDX-License-Identifier: Apache-2.0 or CC0-1.0
#
# Builds the timing side-channel harness (common/dudect.c) against
# ml-kem-512/m4fspeed -- the hand-optimized Cortex-M4 implementation a real
# embedded deployment would actually ship (see kyber-sca/docs/methodology.md
# Section 1). Deliberately its own small rule instead of a new file under
# mupq/crypto_kem/, which would require forking mupq itself the same way
# this project already forked pqm4 -- not worth it for one harness file.
#
# Scheme identifier below matches mupq/mk/schemes.mk's implname derivation
# for crypto_kem/ml-kem-512/m4fspeed (verified against the .elf this repo's
# existing testvectors build already produces:
# elf/crypto_kem_ml-kem-512_m4fspeed_testvectors.elf). The generic
# `elf/$(2)_%.elf: CPPFLAGS+=-I$(1)` / `MUPQ_NAMESPACE=...` pattern-specific
# variables schemes.mk defines for this scheme apply automatically to any
# target matching elf/crypto_kem_ml-kem-512_m4fspeed_%.elf, dudect included,
# regardless of which rule (pattern or explicit, below) supplies the recipe.

DUDECT_SCHEME_DIR  := crypto_kem/ml-kem-512/m4fspeed
DUDECT_SCHEME_NAME := crypto_kem_ml-kem-512_m4fspeed

elf/$(DUDECT_SCHEME_NAME)_dudect.elf: LDLIBS+=-l$(DUDECT_SCHEME_NAME)
elf/$(DUDECT_SCHEME_NAME)_dudect.elf: common/dudect.c obj/lib$(DUDECT_SCHEME_NAME).a $(LINKDEPS) $(CONFIG)
	$(compiletest)

tests: elf/$(DUDECT_SCHEME_NAME)_dudect.elf
tests-bin: bin/$(DUDECT_SCHEME_NAME)_dudect.bin
tests-hex: bin/$(DUDECT_SCHEME_NAME)_dudect.hex

# Measurement sanity check (see common/keypair_control.c) -- built against
# the same scheme, same DWT harness code style.
elf/$(DUDECT_SCHEME_NAME)_keypair_control.elf: LDLIBS+=-l$(DUDECT_SCHEME_NAME)
elf/$(DUDECT_SCHEME_NAME)_keypair_control.elf: common/keypair_control.c obj/lib$(DUDECT_SCHEME_NAME).a $(LINKDEPS) $(CONFIG)
	$(compiletest)

tests: elf/$(DUDECT_SCHEME_NAME)_keypair_control.elf
tests-bin: bin/$(DUDECT_SCHEME_NAME)_keypair_control.bin
tests-hex: bin/$(DUDECT_SCHEME_NAME)_keypair_control.hex
