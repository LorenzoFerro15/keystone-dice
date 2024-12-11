//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef __SBI_H_
#define __SBI_H_

#include <stdint.h>
#include <stddef.h>

#include "sm_call.h"

void
sbi_putchar(char c);
void
sbi_set_timer(uint64_t stime_value);
uintptr_t
sbi_stop_enclave(uint64_t request);
void
sbi_exit_enclave(uint64_t retval);
uintptr_t
sbi_random();
uintptr_t
sbi_query_multimem(size_t *size);
uintptr_t
sbi_query_multimem_addr(uintptr_t *addr);
uintptr_t
sbi_attest_enclave(void* report, void* buf, uintptr_t len);
uintptr_t
sbi_get_sealing_key(uintptr_t key_struct, uintptr_t key_ident, uintptr_t len);
uintptr_t
sbi_create_keypair(uintptr_t pk, uintptr_t index, uintptr_t issued_crt, uintptr_t issued_crt_len);
uintptr_t
sbi_get_cert_chain(uintptr_t certs, uintptr_t sizes);
uintptr_t
sbi_crypto_interface(uintptr_t flag, uintptr_t data, uintptr_t data_len, uintptr_t out_buf, uintptr_t out_buf_len, uintptr_t pk);

// SPIRS
uintptr_t
sbi_write_buffer(uintptr_t base_addr, uintptr_t user_buffer, size_t buffer_size);

uintptr_t
sbi_read_register(uintptr_t base_addr, uintptr_t user_buffer, uint64_t *value);


#endif
