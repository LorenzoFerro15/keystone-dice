//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "platform-hook.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_timer.h>
#include <sbi/sbi_string.h>

#include "sha3/sha3.h"
#include "sm.h"
#include "ed25519/ed25519.h"

struct enclave enclaves[ENCL_MAX];

// Enclave IDs are unsigned ints, so we do not need to check if eid is
// greater than or equal to 0
#define ENCLAVE_EXISTS(eid) (eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];
extern byte sm_hash[MDSIZE];
extern byte sm_signature[SIGNATURE_SIZE];
extern byte sm_public_key[PUBLIC_KEY_SIZE];
extern byte sm_private_key[PRIVATE_KEY_SIZE];
extern byte sm_cert[CERT_SIZE];
extern byte dev_cert[CERT_SIZE];
extern byte man_cert[CERT_SIZE];
extern int sm_cert_len;
extern int dev_cert_len;
extern int man_cert_len;

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);

  if(load_parameters) {
    // passing parameters for a first run
    regs->mepc = (uintptr_t) enclaves[eid].params.dram_base - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].params.dram_base;
    // $a2: DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].params.free_base;
    // $a6: (PA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_base;
    // $a7: utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;

    // enclave will only have physical addresses in the first run
    csr_write(satp, 0);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(void){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create_t* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create_t));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create_t* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;
  
  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create_t create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;
  byte CDI[64];
  sha3_ctx_t hash_ctx_to_use;
  // Variable  used to specify the serial of the cert
  unsigned char serial[] = {0x0};

  unsigned char *cert_real;
  int dif  = 0;

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set params */
  struct runtime_params_t params;
  params.dram_base = base;
  params.dram_size = size;
  params.runtime_base = create_args.runtime_paddr;
  params.user_base = create_args.user_paddr;
  params.free_base = create_args.free_paddr;
  params.untrusted_base = utbase;
  params.untrusted_size = utsize;
  params.free_requested = create_args.free_requested;

  sbi_printf("creating the enclave...\n");

  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
    sbi_printf("in enclave creation before spin lock\n");

  spin_lock(&encl_lock); // FIXME This should error for second enter.

    sbi_printf("in enclave creation after spin lock\n");
 
  ret = validate_and_hash_enclave(&enclaves[eid]);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;

  sha3_init(&hash_ctx_to_use, 64);
  sha3_update(&hash_ctx_to_use, CDI, 64);
  sha3_update(&hash_ctx_to_use, enclaves[eid].hash, 64);
  sha3_final(enclaves[eid].CDI, &hash_ctx_to_use);

  ed25519_create_keypair(enclaves[eid].local_att_pub, enclaves[eid].local_att_priv, enclaves[eid].CDI);

  sbi_printf("[SM] public_key: 0x");
  for(int i = 0; i< 32; i++) {
    sbi_printf("%02x", enclaves[eid].local_att_pub[i]);
  }
  sbi_printf("\n");

  mbedtls_x509write_crt_init(&enclaves[eid].crt_local_att);

  ret = mbedtls_x509write_crt_set_issuer_name_mod(&enclaves[eid].crt_local_att, "CN=Security Monitor");
  if (ret != 0)
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }
  
  // Setting the name of the subject of the cert
  ret = mbedtls_x509write_crt_set_subject_name_mod(&enclaves[eid].crt_local_att, "CN=Enclave LAK" );
  if (ret != 0)
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }

  // pk context used to embed the keys of the security monitor
  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  // pk context used to embed the keys of the embedded CA
  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);

  
  // The keys of the embedded CA are used to sign the different certs associated to the local attestation keys of the different enclaves  
  ret = mbedtls_pk_parse_public_key(&issu_key, sm_private_key, 64, 1);
  if (ret != 0)
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }
  ret = mbedtls_pk_parse_public_key(&issu_key, sm_public_key, 32, 0);
  if (ret != 0)
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }

  // Parsing the public key of the enclave that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key, enclaves[eid].local_att_pub, 32, 0);
  if (ret != 0)
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }

  serial[0] = eid;
  
  // The public key of the enclave is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&enclaves[eid].crt_local_att, &subj_key);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&enclaves[eid].crt_local_att, &issu_key);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&enclaves[eid].crt_local_att, serial, 1);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&enclaves[eid].crt_local_att, KEYSTONE_SHA3);
  
  mbedtls_x509write_crt_set_key_usage(&enclaves[eid].crt_local_att, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&enclaves[eid].crt_local_att, "20230101000000", "20260101000000");
  if (ret != 0)
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }
  //const char oid_ext[] = {0xff, 0x20, 0xff};
  //const char oid_ext2[] = {0x55, 0x1d, 0x13};
  //unsigned char max_path[] = {0x0A};
  dice_tcbInfo tcbInfo;
  init_dice_tcbInfo(&tcbInfo);

  measure m;
  const unsigned char OID_algo[] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0A};
  m.oid_len = 9;
  //unsigned char app[64];
  sbi_memcpy(m.OID_algho, OID_algo, m.oid_len);
  sbi_memcpy(m.digest, enclaves[eid].hash, 64);

  set_dice_tcbInfo_measure(&tcbInfo, m);

  int dim= 324;
  unsigned char buf[324];

  if(mbedtls_x509write_crt_set_dice_tcbInfo(&enclaves[eid].crt_local_att, tcbInfo, dim, buf, sizeof(buf))!=0)
    sbi_printf("\nError setting DICETCB extension!\n");

  unsigned char cert_der[1024];
  int effe_len_cert_der = 0;
  size_t len_cert_der_tot = 1024;

  ret = mbedtls_x509write_crt_der(&enclaves[eid].crt_local_att, cert_der, len_cert_der_tot, NULL, NULL);
  
  if (ret > 0)
  {
    effe_len_cert_der = ret;
    ret = 0;
  }
  else
  {
    ret = SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
    goto unlock;
  }
  cert_real = cert_der;
  dif  = 0;
  dif= 1024-effe_len_cert_der;
  cert_real += dif;

  // The der format of the cert and its length are stored in the specific variables of the enclave structure
  enclaves[eid].crt_local_att_der_length = effe_len_cert_der;
  sbi_memcpy(enclaves[eid].crt_local_att_der, cert_real, effe_len_cert_der);

  sbi_printf("[SM] certificato AK: 0x");
  for(int i = 0; i< effe_len_cert_der; i++) {
    sbi_printf("%02x", enclaves[eid].crt_local_att_der[i]);
  }
  sbi_printf("\n");

  // The number of the keypair associated to the created enclave that are not the local attestation keys is set to 0
  enclaves[eid].n_keypair = 0;

  sbi_printf("enclave created before spin unlocked\n");

  spin_unlock(&encl_lock);

  sbi_printf("enclave created and spin unlocked\n");

  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

unsigned long create_keypair(enclave_id eid, unsigned char* pk, int seed_enc, unsigned char* issued_crt, int *issued_crt_len){

  unsigned char seed[PRIVATE_KEY_SIZE];
  unsigned char pk_app[PUBLIC_KEY_SIZE];
  unsigned char sk_app[PRIVATE_KEY_SIZE];
  int ret = 0;

  unsigned char app[65];

  // The new keypair is obtained adding at the end of the CDI of the enclave an index, provided by the enclave itself
  sbi_memcpy(app, enclaves[eid].CDI, 64);
  app[64] = seed_enc + '0';
  

  sha3_ctx_t ctx_hash;

  // The hash function is used to provide the seed for the keys generation
  sha3_init(&ctx_hash, 64);
  sha3_update(&ctx_hash, app, 65);
  sha3_final(seed, &ctx_hash);
  ed25519_create_keypair(pk_app, sk_app, seed);
  
  // The new keypair is stored in the relatives arrays
  for(int i = 0; i < PUBLIC_KEY_SIZE; i ++)
    enclaves[eid].pk_array[enclaves[eid].n_keypair][i] = pk_app[i];
  for(int i = 0; i < PRIVATE_KEY_SIZE; i ++)
    enclaves[eid].sk_array[enclaves[eid].n_keypair][i] = sk_app[i];
  
  // The first keypair that is asked to be created is the Local Device Keys, that is inserted in the relative variables
  if(enclaves[eid].n_keypair == 0){
    sbi_memcpy(enclaves[eid].sk_ldev, sk_app, PRIVATE_KEY_SIZE );
    sbi_memcpy(enclaves[eid].pk_ldev, pk_app, PUBLIC_KEY_SIZE);
  }

  sbi_printf("[SM] PK: 0x");
  for(int i = 0; i< PUBLIC_KEY_SIZE; i++) {
    sbi_printf("%02x", pk_app[i]);
  }
  sbi_printf("\n");

  enclaves[eid].n_keypair +=1;
  
  ret = copy_from_sm((uintptr_t)pk, pk_app, PUBLIC_KEY_SIZE);
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  // The location in memoty of the private key of the keypair created is clean
  sbi_memset(sk_app, 0, 64);

  if(enclaves[eid].n_keypair != 1)
    return 0;

  // Associated to the keys of the enclaves, a new 509 cert is created 
  mbedtls_x509write_crt_init(&enclaves[eid].crt_ldev);

  // Setting the name of the issuer of the cert
  ret = mbedtls_x509write_crt_set_issuer_name_mod(&enclaves[eid].crt_ldev, "CN=Security Monitor");
  if (ret != 0)
  {
    return ret;
  }
  
  // Setting the name of the subject of the cert
  ret = mbedtls_x509write_crt_set_subject_name_mod(&enclaves[eid].crt_ldev, "CN=Enclave LDevID");
  if (ret != 0)
  {
    return ret;
  }

  // pk context used to embed the keys of the subject
  mbedtls_pk_context subj_key;
  mbedtls_pk_init(&subj_key);

  // pk context used to embed the keys of the embedded CA
  mbedtls_pk_context issu_key;
  mbedtls_pk_init(&issu_key);

  
  // The keys of the embedded CA are used to sign the different certs associated to the keys of the different enclaves  
  ret = mbedtls_pk_parse_public_key(&issu_key, sm_private_key, 64, 1);
  if (ret != 0)
  {
    return ret;
  }
  ret = mbedtls_pk_parse_public_key(&issu_key, sm_public_key, 32, 0);
  if (ret != 0)
  {
    return ret;
  }

  // Parsing the public key of the enclave that will be inserted in its certificate 
  ret = mbedtls_pk_parse_public_key(&subj_key, pk_app, 32, 0);
  if (ret != 0)
  {
    return ret;
  }

  // Variable  used to specify the serial of the cert
  unsigned char serial[] = {0x0};
  serial[0] = 10*eid+1;
  
  // The public key of the enclave is inserted in the structure
  mbedtls_x509write_crt_set_subject_key(&enclaves[eid].crt_ldev, &subj_key);

  // The private key of the embedded CA is used later to sign the cert
  mbedtls_x509write_crt_set_issuer_key(&enclaves[eid].crt_ldev, &issu_key);
  
  // The serial of the cert is setted
  mbedtls_x509write_crt_set_serial_raw(&enclaves[eid].crt_ldev, serial, 1);
  
  // The algoithm used to do the hash for the signature is specified
  mbedtls_x509write_crt_set_md_alg(&enclaves[eid].crt_ldev, KEYSTONE_SHA3);

  mbedtls_x509write_crt_set_key_usage(&enclaves[eid].crt_ldev, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
  
  // The validity of the crt is specified
  ret = mbedtls_x509write_crt_set_validity(&enclaves[eid].crt_ldev, "20230101000000", "20250101000000");
  if (ret != 0)
  {
    return ret;
  }
  
  dice_tcbInfo tcbInfo;
  measure m;
  const unsigned char OID_algo[] = {0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0A};
  m.oid_len = 9;
  int dim= 324;
  unsigned char buf[324];

  init_dice_tcbInfo(&tcbInfo);
  sbi_memcpy(m.OID_algho, OID_algo, m.oid_len);
  sbi_memcpy(m.digest, enclaves[eid].hash, 64);
  set_dice_tcbInfo_measure(&tcbInfo, m);

  if(mbedtls_x509write_crt_set_dice_tcbInfo(&enclaves[eid].crt_ldev, tcbInfo, dim, buf, sizeof(buf))!=0)
    sbi_printf("\nError setting DICETCB extension!\n");

  unsigned char cert_der[1024];
  int effe_len_cert_der = 0;
  size_t len_cert_der_tot = 1024;
  ret = mbedtls_x509write_crt_der(&enclaves[eid].crt_ldev, cert_der, len_cert_der_tot, NULL, NULL);

  if (ret != 0)
  {
    effe_len_cert_der = ret;
    ret = 0;
  } else {
    return -1;
  }
  unsigned char *cert_real = cert_der;
  int dif  = 0;
  dif= 1024-effe_len_cert_der;
  cert_real += dif;

  sbi_printf("[SM] crt: 0x");
  for(int i = 0; i< effe_len_cert_der; i++) {
    sbi_printf("%02x", cert_real[i]);
  }
  sbi_printf("\n[SM] crt_len: %d\n", effe_len_cert_der);

  // The der format of the cert and its length are stored in the specific variables received from the caller
  enclaves[eid].crt_ldev_der_length = effe_len_cert_der;
  sbi_memcpy(enclaves[eid].crt_ldev_der, cert_real, effe_len_cert_der);

  ret = copy_from_sm((uintptr_t)issued_crt_len, &effe_len_cert_der, sizeof(int));
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = copy_from_sm((uintptr_t)issued_crt, cert_real, effe_len_cert_der);
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  sbi_printf("[SM] ret_crt: 0x");
  for(int i = 0; i< issued_crt_len[0]; i++) {
    sbi_printf("%02x", issued_crt[i]);
  }
  sbi_printf("\n[SM] ret_crt_len: %d\n", issued_crt_len[0]);

  return 0;
}

unsigned long get_cert_chain(enclave_id eid, unsigned char** certs, int* sizes) {
  unsigned char *ret_certs[3];
  int ret_certs_len[3] = {enclaves[eid].crt_local_att_der_length, sm_cert_len, dev_cert_len};
  int ret = 0;

  ret = copy_from_sm((uintptr_t)sizes, ret_certs_len, sizeof(ret_certs_len));
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  ret = copy_to_sm(&ret_certs, (uintptr_t)certs, 3*sizeof(unsigned char *));
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /*
  sbi_printf("[SM] LAK: 0x");
  for(int i = 0; i< enclaves[eid].crt_local_att_der_length; i++) {
    sbi_printf("%02x", enclaves[eid].crt_local_att_der[i]);
  }
  sbi_printf("\n[SM] LAK_len: %d\n", enclaves[eid].crt_local_att_der_length);
  */

  // Providing the X.509 certificate in DER format of the enclave's LAK and its length
  ret = copy_from_sm((uintptr_t)ret_certs[0], enclaves[eid].crt_local_att_der, enclaves[eid].crt_local_att_der_length);
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /*
  sbi_printf("[SM] SM: 0x");
  for(int i = 0; i< length_cert; i++) {
    sbi_printf("%02x", cert_sm[i]);
  }
  sbi_printf("\n[SM] SM_len: %d\n", length_cert);
  */

  // Providing the X.509 certificate in DER format of the SM's ECA and its length
  ret = copy_from_sm((uintptr_t)ret_certs[1], sm_cert, sm_cert_len);
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /*
  sbi_printf("[SM] RoT: 0x");
  for(int i = 0; i< length_cert_root; i++) {
    sbi_printf("%02x", cert_root[i]);
  }
  sbi_printf("\n[SM] RoT_len: %d\n", length_cert_root);
  */

  // Providing the X.509 certificate in DER format of the Device Root Key and its length
  ret = copy_from_sm((uintptr_t)ret_certs[2], dev_cert, dev_cert_len);
  // sbi_printf("ret:%d\n", ret);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  return 0;
}

unsigned long do_crypto_op(enclave_id eid, int flag, unsigned char* data, int data_len, unsigned char* out_data, int* len_out_data, unsigned char* pk){

  sha3_ctx_t ctx_hash;
  unsigned char fin_hash[64];
  unsigned char sign[64];
  int ret, pos = -1;
  unsigned char data_cp[2048];
  unsigned char pk_cp[32];
  int sign_len = 64;

  if(data_len > 2048)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = copy_to_sm(data_cp, (uintptr_t)data, data_len);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  ret = copy_to_sm(pk_cp, (uintptr_t)pk, 32);
  if(ret)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  
  switch (flag){
    // Sign of TCI|pk_lDev with the private key of the attestation keypair of the enclave.
    // The sign is placed in out_data. The attestation pk can be obtained calling the get_chain_cert method
    case 1:
      sha3_init(&ctx_hash, 64);
      sha3_update(&ctx_hash, data_cp, data_len);
      sha3_update(&ctx_hash, enclaves[eid].hash, 64);
      sha3_update(&ctx_hash, enclaves[eid].pk_ldev, 32);
      sha3_final(fin_hash, &ctx_hash);

      //ed25519_sign(sign, fin_hash, 64, enclaves[eid].local_att_pub, enclaves[eid].local_att_priv);
      ed25519_sign(sign, fin_hash, 64, enclaves[eid].local_att_pub, enclaves[eid].local_att_priv);
      ret = copy_from_sm((uintptr_t)out_data, sign, 64);
      if(ret)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      ret = copy_from_sm((uintptr_t)len_out_data, &sign_len, sizeof(int));
      if(ret)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      return 0;
    break;
    case 2:
      // Sign of generic data with a specific private key.
      // In this case the enclave provides directly the hash of the data that have to be signed

      // Finding the private key associated to the public key passed
      for(int i = 0;  i < enclaves[eid].n_keypair; i ++)
        if(sbi_memcmp(enclaves[eid].pk_array[i], pk_cp, 32) == 0){
          pos = i;
          break;
        }
      if (pos == -1)
        return -1;

      ed25519_sign(sign, data_cp, data_len, enclaves[eid].pk_array[pos], enclaves[eid].sk_array[pos]);

      ret = copy_from_sm((uintptr_t)out_data, sign, 64);
      if(ret)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      ret = copy_from_sm((uintptr_t)len_out_data, &sign_len, sizeof(int));
      if(ret)
        return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
      return 0;
    break;
    
    default:
      return -1;
    break;
  }
  return 0;

}

unsigned long print_message(){
  sbi_printf("Hello world!\n");
  return 0;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  enclaves[eid].encl_satp = 0;
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = (struct runtime_params_t) {0};
  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}
