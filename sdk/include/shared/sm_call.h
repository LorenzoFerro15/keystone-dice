#ifndef __SM_CALL_H__
#define __SM_CALL_H__

// BKE (Berkeley Keystone Enclave)
#define SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE 0x08424b45

#define SBI_SET_TIMER 0
#define SBI_CONSOLE_PUTCHAR 1
#define SBI_CONSOLE_GETCHAR 2

/* 0-1999 are not used (deprecated) */
#define FID_RANGE_DEPRECATED      1999
/* 2000-2999 are called by host */
#define SBI_SM_CREATE_ENCLAVE    2001
#define SBI_SM_DESTROY_ENCLAVE   2002
#define SBI_SM_RUN_ENCLAVE       2003
#define SBI_SM_RESUME_ENCLAVE    2005
#define SBI_SM_PRINT_MESSAGE     2010
#define SBI_GET_MEASURES         2011
#define SBI_GIVE_INFO_TPM        2012
#define FID_RANGE_HOST           2999

/* 3000-3999 are called by enclave */
#define SBI_SM_RANDOM            3001
#define SBI_SM_ATTEST_ENCLAVE    3002
#define SBI_SM_GET_SEALING_KEY   3003
#define SBI_SM_STOP_ENCLAVE      3004
#define SBI_SM_EXIT_ENCLAVE      3006
#define SBI_CREATE_KEYPAIR       3007
#define SBI_GET_CHAIN            3008
#define SBI_CRYPTO_INTERFACE     3009
/* SPIRS */
#define SBI_SM_READ_REGISTER     3010
#define SBI_SM_WRITE_REGISTER    3011
#define SBI_SM_WRITE_BUFFER      3012
#define SBI_SM_READ_BUFFER       3013
#define FID_RANGE_ENCLAVE        3999

/* 4000-4999 are experimental */
#define SBI_SM_CALL_PLUGIN        4000
#define FID_RANGE_CUSTOM          4999

/* Plugin IDs and Call IDs */
#define SM_MULTIMEM_PLUGIN_ID   0x01
#define SM_MULTIMEM_CALL_GET_SIZE 0x01
#define SM_MULTIMEM_CALL_GET_ADDR 0x02

/* Enclave stop reasons requested */
#define STOP_TIMER_INTERRUPT  0
#define STOP_EDGE_CALL_HOST   1
#define STOP_EXIT_ENCLAVE     2

/* Structs for interfacing into the SM */
struct runtime_params_t {
  uintptr_t dram_base;
  uintptr_t dram_size;
  uintptr_t runtime_base;
  uintptr_t user_base;
  uintptr_t free_base;
  uintptr_t untrusted_base;
  uintptr_t untrusted_size;
  uintptr_t free_requested; // for attestation
};

struct keystone_sbi_pregion_t {
  uintptr_t paddr;
  size_t size;
};

struct keystone_sbi_create_t {
  struct keystone_sbi_pregion_t epm_region;
  struct keystone_sbi_pregion_t utm_region;

  uintptr_t runtime_paddr;
  uintptr_t user_paddr;
  uintptr_t free_paddr;
  uintptr_t free_requested;
};

#endif  // __SM_CALL_H__
