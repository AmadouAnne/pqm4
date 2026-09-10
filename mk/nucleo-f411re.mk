# SPDX-License-Identifier: Apache-2.0 or CC0-1.0
# Nucleo-F411RE (STM32F411RET6, Cortex-M4F) -- same board as P1
# (freertos-stm32) in this repo. Added locally: pqm4 upstream does not ship
# this board, only the close STM32F4 relatives stm32f4discovery (F407VG) and
# the CW308T targets (F303/F415).
DEVICE=stm32f411re
OPENCM3_TARGET=lib/stm32/f4

# Same exclusion list as stm32f4discovery.mk (largest-footprint schemes that
# need the discovery board's dedicated fullram linker script). The F411RE
# has less flash/RAM than the F407VG (512K/128K vs 1M/192K) so this list may
# need to grow once non-Kyber schemes are actually exercised here -- for
# ml-kem-512/768/1024 (the schemes this project targets) it is not an issue.
EXCLUDED_SCHEMES = \
	mupq/pqclean/crypto_kem/mceliece% \
	mupq/crypto_sign/tuov% \
	mupq/crypto_sign/ov-Ip% \
	mupq/crypto_sign/snova-43-25-16-2-esk% \
	mupq/crypto_sign/snova-61-33-16-2-esk% \
	mupq/crypto_sign/snova-60-10-16-4-esk% \
	mupq/crypto_sign/snova-66-15-16-3-esk% \
	mupq/crypto_sign/snova-49-11-16-3-esk% \
	mupq/crypto_sign/snova-37-8-16-4-esk% \
	mupq/crypto_sign/meds55604% \
	mupq/crypto_sign/meds167717% \
	mupq/crypto_sign/meds134180% \
	crypto_sign/ov-Ip%

include mk/opencm3.mk
