//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "syscall.h"

/* this implementes basic system calls for the enclave */

int
ocall(
    unsigned long call_id, void* data, size_t data_len, void* return_buffer,
    size_t return_len) {
  return SYSCALL_5(RUNTIME_SYSCALL_OCALL,
      call_id, data, data_len, return_buffer, return_len);
}

int
copy_from_shared(void* dst, uintptr_t offset, size_t data_len) {
  return SYSCALL_3(RUNTIME_SYSCALL_SHAREDCOPY, dst, offset, data_len);
}

int
attest_enclave(void* report, void* data, size_t size) {
  return SYSCALL_3(RUNTIME_SYSCALL_ATTEST_ENCLAVE, report, data, size);
}

/* returns sealing key */
int
get_sealing_key(
    struct sealing_key* sealing_key_struct, size_t sealing_key_struct_size,
    void* key_ident, size_t key_ident_size) {
  return SYSCALL_4(RUNTIME_SYSCALL_GET_SEALING_KEY,
      sealing_key_struct, sealing_key_struct_size,
      key_ident, key_ident_size);
}

int
create_keypair(void* pk, unsigned long index, void* issued_crt, void* issued_crt_len){
  return SYSCALL_4(RUNTIME_SYSCALL_CREATE_KEYPAIR, pk, index, issued_crt, issued_crt_len);
}

int
get_cert_chain(void* cert_1, void* cert_2, void* cert_3, void* size_1, void* size_2, void* size_3){
  return SYSCALL_6(RUNTIME_SYSCALL_GET_CHAIN, cert_1, cert_2, cert_3, size_1, size_2, size_3);
}

int
crypto_interface(unsigned long flag, void* data, size_t data_len, void* out_buf, size_t* out_buf_len, void* pk){
  return SYSCALL_6(RUNTIME_SYSCALL_CRYPTO_INTERFACE, flag, data, data_len, out_buf, out_buf_len, pk);
}

int 
rt_print_string(void* string, size_t length){
  return SYSCALL_2(RUNTIME_SYSCALL_PRINT_STRING, string, length);
}
int spirs_hw_write_buffer(uintptr_t base_addr, void* user_buffer, size_t buffer_size)
{
  return SYSCALL_3(RUNTIME_SYSCALL_WRITE_BUFFER, base_addr, (uintptr_t)user_buffer, buffer_size);
}

int spirs_hw_read_register(uintptr_t base_addr, uintptr_t offset, uint64_t *reg_out)
{
  return SYSCALL_3(RUNTIME_SYSCALL_READ_REGISTER, base_addr, offset, reg_out);
}
