#ifndef __X509CUSTOM_H__
#define __X509CUSTOM_H__

#include <stddef.h>
#include "oid.h"

//#include <stdlib.h>
//#include <stdio.h>
//#include <stdint.h>

#define MBEDTLS_PRIVATE(member) member
#define MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN 20
#define MBEDTLS_X509_CRT_VERSION_1              0
#define MBEDTLS_X509_CRT_VERSION_2              1
#define MBEDTLS_X509_CRT_VERSION_3              2
#define MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN 20
#define MBEDTLS_X509_RFC5280_UTC_TIME_LEN   15
#define MBEDTLS_X509_MAX_DN_NAME_SIZE         256 
//#define mbedtls_free       free
//#define mbedtls_calloc     calloc
#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00
#define MBEDTLS_RSA_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT  -0x3D00
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG      -0x3C80
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA      -0x3E80
#define MBEDTLS_ERR_PK_ALLOC_FAILED        -0x3F80

#define MBEDTLS_ASN1_BOOLEAN                 0x01
#define MBEDTLS_ASN1_INTEGER                 0x02
#define MBEDTLS_ASN1_BIT_STRING              0x03
#define MBEDTLS_ASN1_OCTET_STRING            0x04
#define MBEDTLS_ASN1_NULL                    0x05
#define MBEDTLS_ASN1_OID                     0x06
#define MBEDTLS_ASN1_ENUMERATED              0x0A
#define MBEDTLS_ASN1_UTF8_STRING             0x0C
#define MBEDTLS_ASN1_SEQUENCE                0x10
#define MBEDTLS_ASN1_SET                     0x11
#define MBEDTLS_ASN1_PRINTABLE_STRING        0x13
#define MBEDTLS_ASN1_T61_STRING              0x14
#define MBEDTLS_ASN1_IA5_STRING              0x16
#define MBEDTLS_ASN1_UTC_TIME                0x17
#define MBEDTLS_ASN1_GENERALIZED_TIME        0x18
#define MBEDTLS_ASN1_UNIVERSAL_STRING        0x1C
#define MBEDTLS_ASN1_BMP_STRING              0x1E
#define MBEDTLS_ASN1_PRIMITIVE               0x00
#define MBEDTLS_ASN1_CONSTRUCTED             0x20
#define MBEDTLS_ASN1_CONTEXT_SPECIFIC        0x80
#define MBEDTLS_ERR_ASN1_BUF_TOO_SMALL                    -0x006C
#define MBEDTLS_ERR_PK_TYPE_MISMATCH       -0x3F00
#define MBEDTLS_ERR_ASN1_OUT_OF_DATA                      -0x0060
#define MBEDTLS_ERR_ASN1_UNEXPECTED_TAG                   -0x0062
#define MBEDTLS_ERR_ASN1_LENGTH_MISMATCH                  -0x0066
#define MBEDTLS_ERR_PK_INVALID_PUBKEY      -0x3B00
#define MBEDTLS_ERR_ASN1_INVALID_DATA                     -0x0068




typedef unsigned char __uint8_t;
typedef __uint8_t uint8_t;

#define MBEDTLS_BYTE_0(x) ((uint8_t) ((x)         & 0xff))
#define MBEDTLS_BYTE_1(x) ((uint8_t) (((x) >>  8) & 0xff))
#define MBEDTLS_BYTE_2(x) ((uint8_t) (((x) >> 16) & 0xff))
#define MBEDTLS_BYTE_3(x) ((uint8_t) (((x) >> 24) & 0xff))
#define MBEDTLS_BYTE_4(x) ((uint8_t) (((x) >> 32) & 0xff))
#define MBEDTLS_BYTE_5(x) ((uint8_t) (((x) >> 40) & 0xff))
#define MBEDTLS_BYTE_6(x) ((uint8_t) (((x) >> 48) & 0xff))
#define MBEDTLS_BYTE_7(x) ((uint8_t) (((x) >> 56) & 0xff))

#define MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER MBEDTLS_OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
#define MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER   MBEDTLS_OID_X509_EXT_SUBJECT_KEY_IDENTIFIER
#define MBEDTLS_X509_EXT_KEY_USAGE                MBEDTLS_OID_X509_EXT_KEY_USAGE
#define MBEDTLS_X509_EXT_CERTIFICATE_POLICIES     MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES
#define MBEDTLS_X509_EXT_POLICY_MAPPINGS          MBEDTLS_OID_X509_EXT_POLICY_MAPPINGS
#define MBEDTLS_X509_EXT_SUBJECT_ALT_NAME         MBEDTLS_OID_X509_EXT_SUBJECT_ALT_NAME         /* Supported (DNS) */
#define MBEDTLS_X509_EXT_ISSUER_ALT_NAME          MBEDTLS_OID_X509_EXT_ISSUER_ALT_NAME
#define MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS  MBEDTLS_OID_X509_EXT_SUBJECT_DIRECTORY_ATTRS
#define MBEDTLS_X509_EXT_BASIC_CONSTRAINTS        MBEDTLS_OID_X509_EXT_BASIC_CONSTRAINTS        /* Supported */
#define MBEDTLS_X509_EXT_NAME_CONSTRAINTS         MBEDTLS_OID_X509_EXT_NAME_CONSTRAINTS
#define MBEDTLS_X509_EXT_POLICY_CONSTRAINTS       MBEDTLS_OID_X509_EXT_POLICY_CONSTRAINTS
#define MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE       MBEDTLS_OID_X509_EXT_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS  MBEDTLS_OID_X509_EXT_CRL_DISTRIBUTION_POINTS
#define MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY       MBEDTLS_OID_X509_EXT_INIHIBIT_ANYPOLICY
#define MBEDTLS_X509_EXT_FRESHEST_CRL             MBEDTLS_OID_X509_EXT_FRESHEST_CRL
#define MBEDTLS_X509_EXT_NS_CERT_TYPE             MBEDTLS_OID_X509_EXT_NS_CERT_TYPE
#ifndef INT_MAX
#define INT_MAX         2147483647  
#endif

/**
 * \name X509 Error codes
 * \{
 */
/** Unavailable feature, e.g. RSA hashing/encryption combination. */
#define MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE              -0x2080
/** Requested OID is unknown. */
#define MBEDTLS_ERR_X509_UNKNOWN_OID                      -0x2100
/** The CRT/CRL/CSR format is invalid, e.g. different type expected. */
#define MBEDTLS_ERR_X509_INVALID_FORMAT                   -0x2180
/** The CRT/CRL/CSR version element is invalid. */
#define MBEDTLS_ERR_X509_INVALID_VERSION                  -0x2200
/** The serial tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_SERIAL                   -0x2280
/** The algorithm tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_ALG                      -0x2300
/** The name tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_NAME                     -0x2380
/** The date tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_DATE                     -0x2400
/** The signature tag or value invalid. */
#define MBEDTLS_ERR_X509_INVALID_SIGNATURE                -0x2480
/** The extension tag or value is invalid. */
#define MBEDTLS_ERR_X509_INVALID_EXTENSIONS               -0x2500
/** CRT/CRL/CSR has an unsupported version number. */
#define MBEDTLS_ERR_X509_UNKNOWN_VERSION                  -0x2580
/** Signature algorithm (oid) is unsupported. */
#define MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG                  -0x2600
/** Signature algorithms do not match. (see \c ::mbedtls_x509_crt sig_oid) */
#define MBEDTLS_ERR_X509_SIG_MISMATCH                     -0x2680
/** Certificate verification failed, e.g. CRL, CA or signature check failed. */
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED               -0x2700
/** Format not recognized as DER or PEM. */
#define MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT              -0x2780
/** Input invalid. */
#define MBEDTLS_ERR_X509_BAD_INPUT_DATA                   -0x2800
/** Allocation of memory failed. */
#define MBEDTLS_ERR_X509_ALLOC_FAILED                     -0x2880
/** Read/write of file failed. */
#define MBEDTLS_ERR_X509_FILE_IO_ERROR                    -0x2900
/** Destination buffer is too small. */
#define MBEDTLS_ERR_X509_BUFFER_TOO_SMALL                 -0x2980
/** A fatal error occurred, eg the chain is too long or the vrfy callback failed. */
#define MBEDTLS_ERR_X509_FATAL_ERROR                      -0x3000
/** \} name X509 Error codes */
#define MBEDTLS_ERR_ASN1_INVALID_LENGTH                   -0x0064

#define ADD_STRLEN(s)     s, sizeof(s) - 1
#define MBEDTLS_OID_SIZE(x) (sizeof(x) - 1)
#define ADD_LEN(s)      s, MBEDTLS_OID_SIZE(s)
#define MBEDTLS_ERR_PK_INVALID_ALG         -0x3A80

#define MBEDTLS_ASN1_CHK_ADD(g, f)                      \
    do                                                  \
    {                                                   \
        if ((ret = (f)) < 0)                         \
        return ret;                              \
        else                                            \
        (g) += ret;                                 \
    } while (0);

static inline int mbedtls_error_add(int high, int low,
                                    const char *file, int line)
{
  /*
#if defined(MBEDTLS_TEST_HOOKS)
    if (*mbedtls_test_hook_error_add != NULL) {
        (*mbedtls_test_hook_error_add)(high, low, file, line);
    }
#endif*/
    (void) file;
    (void) line;

    return high + low;
}


#define MBEDTLS_ERROR_ADD(high, low) \
    mbedtls_error_add(high, low, __FILE__, __LINE__)

#define CHECK(code) if ((ret = (code)) != 0) { return ret; }

#define CHECK_RANGE(min, max, val)                      \
    do                                                  \
    {                                                   \
        if ((val) < (min) || (val) > (max))    \
        {                                               \
            return ret;                              \
        }                                               \
    } while (0)

#define OID_DESCRIPTOR(s, name, description)  { ADD_LEN(s), name, description }

#define MBEDTLS_ERROR_ADD(high, low) \
    mbedtls_error_add(high, low, __FILE__, __LINE__)

typedef enum {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE,
    MBEDTLS_PK_ED25519
} mbedtls_pk_type_t;


typedef enum {
    MBEDTLS_MD_NONE=0,    /**< None. */
    MBEDTLS_MD_MD5,       /**< The MD5 message digest. */
    MBEDTLS_MD_SHA1,      /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224,    /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256,    /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384,    /**< The SHA-384 message digest. */

    MBEDTLS_MD_SHA512,    /**< The SHA3-512 message digest. */

    MBEDTLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */

    //the algorithm used in the original Keystone project 
    KEYSTONE_SHA3,

} mbedtls_md_type_t;

typedef enum {
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI,
    MBEDTLS_PK_DEBUG_ECP,
} mbedtls_pk_debug_type;

typedef struct mbedtls_pk_debug_item {
    mbedtls_pk_debug_type MBEDTLS_PRIVATE(type);
    const char *MBEDTLS_PRIVATE(name);
    void *MBEDTLS_PRIVATE(value);
} mbedtls_pk_debug_item;

typedef struct mbedtls_ed25519_context {
    int MBEDTLS_PRIVATE(ver);                    /*!<  Reserved for internal purposes.
                                                  *    Do not set this field in application
                                                  *    code. Its meaning might change without
                                                  *    notice. */
    size_t len;                 /*!<  The size of \p N in Bytes. */
    unsigned char pub_key[32];
    unsigned char priv_key[64];

}
mbedtls_ed25519_context;


struct mbedtls_pk_info_t {
    /** Public key type */
    mbedtls_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)(const void *);

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)(mbedtls_pk_type_t type);

    /** Verify signature */
    int (*verify_func)(void *ctx, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);

    /** Make signature */
    int (*sign_func)(void *ctx, mbedtls_md_type_t md_alg,
                     const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng);
    
     /** Decrypt message */
    int (*decrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    /** Encrypt message */
    int (*encrypt_func)(void *ctx, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    /** Check public-private key pair */
    int (*check_pair_func)(const void *pub, const void *prv,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng);

    /** Allocate a new context */
    /*void *  mbedtls_ed25519_context (*ctx_alloc_func)(void); //(void) */

    /** Free the given context */
    void (*ctx_free_func)(void *ctx);

    void (*debug_func)(const void *ctx, mbedtls_pk_debug_item *items);

};

typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;




typedef struct mbedtls_pk_context {
    const mbedtls_pk_info_t *pk_info;    /**< Public key information         */
    /*void **/mbedtls_ed25519_context pk_ctx;                        /**< Underlying public key context  */
} mbedtls_pk_context;

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef struct mbedtls_asn1_buf {
    int tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
    unsigned char p_arr[512];
}
mbedtls_asn1_buf;
typedef struct mbedtls_asn1_buf_no_arr {
    int tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
}
mbedtls_asn1_buf_no_arr;

typedef struct mbedtls_asn1_named_data {
    mbedtls_asn1_buf oid;                   /**< The object identifier. */
    mbedtls_asn1_buf val;                   /**< The named value. */

    /** The next entry in the sequence.
     *
     * The details of memory management for named data sequences are not
     * documented and may change in future versions. Set this field to \p NULL
     * when initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct mbedtls_asn1_named_data *next;

    /** Merge next item into the current one?
     *
     * This field exists for the sake of Mbed TLS's X.509 certificate parsing
     * code and may change in future versions of the library.
     */
    unsigned char MBEDTLS_PRIVATE(next_merged);
}
mbedtls_asn1_named_data;

typedef struct mbedtls_asn1_named_data_noarr {
    mbedtls_asn1_buf_no_arr oid;                   /**< The object identifier. */
    mbedtls_asn1_buf_no_arr val;                   /**< The named value. */

    /** The next entry in the sequence.
     *
     * The details of memory management for named data sequences are not
     * documented and may change in future versions. Set this field to \p NULL
     * when initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct mbedtls_asn1_named_data *next;

    /** Merge next item into the current one?
     *
     * This field exists for the sake of Mbed TLS's X.509 certificate parsing
     * code and may change in future versions of the library.
     */
    unsigned char MBEDTLS_PRIVATE(next_merged);
}
mbedtls_asn1_named_data_noarr;

typedef struct mbedtls_x509write_cert {
    int MBEDTLS_PRIVATE(version);
    unsigned char MBEDTLS_PRIVATE(serial)[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
    size_t MBEDTLS_PRIVATE(serial_len);
    mbedtls_pk_context *MBEDTLS_PRIVATE(subject_key);
    mbedtls_pk_context *MBEDTLS_PRIVATE(issuer_key);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(subject);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(issuer);
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_alg);
    char MBEDTLS_PRIVATE(not_before)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char MBEDTLS_PRIVATE(not_after)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(extensions);

    //Changes
    mbedtls_asn1_named_data issuer_arr[10];
    mbedtls_asn1_named_data subject_arr[10];
    int ne_issue_arr;
    int ne_subje_arr;
    mbedtls_asn1_named_data extens_arr[5];
    int ne_ext_arr;

}
mbedtls_x509write_cert;


/* Structure linking OIDs for X.509 DN AttributeTypes to their
 * string representations and default string encodings used by Mbed TLS. */
typedef struct {
    const char *name; /* String representation of AttributeType, e.g.
                       * "CN" or "emailAddress". */
    size_t name_len; /* Length of 'name', without trailing 0 byte. */
    const char *oid; /* String representation of OID of AttributeType,
                      * as per RFC 5280, Appendix A.1. */
    int default_tag; /* The default character encoding used for the
                      * given attribute type, e.g.
                      * MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
} x509_attr_descriptor_t;



typedef struct mbedtls_asn1_sequence {
    mbedtls_asn1_buf buf;                   /**< Buffer containing the given ASN.1 item. */

    /** The next entry in the sequence.
     *
     * The details of memory management for sequences are not documented and
     * may change in future versions. Set this field to \p NULL when
     * initializing a structure, and do not modify it except via Mbed TLS
     * library functions.
     */
    struct mbedtls_asn1_sequence *next;
}
mbedtls_asn1_sequence;

typedef mbedtls_asn1_buf_no_arr mbedtls_x509_buf_crt;
typedef mbedtls_asn1_buf mbedtls_x509_buf;
typedef mbedtls_asn1_named_data mbedtls_x509_name;
typedef mbedtls_asn1_named_data_noarr mbedtls_x509_name_noarr;
typedef mbedtls_asn1_sequence mbedtls_x509_sequence;

typedef struct mbedtls_x509_time {
    int year, mon, day;         /**< Date. */
    int hour, min, sec;         /**< Time. */
}
mbedtls_x509_time;

typedef struct measure{
    unsigned char OID_algho[10];
    int oid_len;
    unsigned char digest[64];
}measure;

typedef struct dice_tcbInfo{

  unsigned char vendor[32];
  int l_ven;
  unsigned char model[32];
  int l_mod;
  unsigned char version[32];
  int l_ver;
  int svn;
  int layer;
  int index;
  unsigned char flags[4];
  unsigned char vendorInfo[16];
  int l_vi;
  unsigned char type[16];
  int l_ty;
  unsigned char flagMask[4];
  measure fwids[2];

}dice_tcbInfo;

/**
 * Container for an X.509 certificate. The certificate may be chained.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct mbedtls_x509_crt {
    int MBEDTLS_PRIVATE(own_buffer);                     /**< Indicates if \c raw is owned
                                                          *   by the structure or not.        */
    mbedtls_x509_buf_crt raw;               /**< The raw certificate data (DER). */
    mbedtls_x509_buf_crt tbs;               /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;                /**< The X.509 version. (1=v1, 2=v2, 3=v3) */
    mbedtls_x509_buf_crt serial;            /**< Unique id for certificate issued by a specific CA. */
    mbedtls_x509_buf_crt sig_oid;           /**< Signature algorithm, e.g. sha1RSA */

    mbedtls_x509_buf_crt issuer_raw;        /**< The raw issuer data (DER). Used for quick comparison. */
    mbedtls_x509_buf_crt subject_raw;       /**< The raw subject data (DER). Used for quick comparison. */

    //mbedtls_x509_name issuer;           /**< The parsed issuer data (named information object). */
    //mbedtls_x509_name subject;          /**< The parsed subject data (named information object). */
    //mbedtls_asn1_named_data issuer_name[10];
    //mbedtls_asn1_named_data subject_name[10];
    mbedtls_asn1_named_data_noarr issuer_arr[10];
    mbedtls_asn1_named_data_noarr subject_arr[10];
    int ne_issue_arr;
    int ne_subje_arr;

    dice_tcbInfo dice_tcb_info;


    mbedtls_x509_time valid_from;       /**< Start time of certificate validity. */
    mbedtls_x509_time valid_to;         /**< End time of certificate validity. */

    mbedtls_x509_buf_crt pk_raw;
    mbedtls_pk_context pk;              /**< Container for the public key context. */

    mbedtls_x509_buf_crt issuer_id;         /**< Optional X.509 v2/v3 issuer unique identifier. */
    mbedtls_x509_buf_crt subject_id;        /**< Optional X.509 v2/v3 subject unique identifier. */
    mbedtls_x509_buf_crt v3_ext;            /**< Optional X.509 v3 extensions.  */
    //mbedtls_x509_buf hash;
    //mbedtls_x509_sequence subject_alt_names;    /**< Optional list of raw entries of Subject Alternative Names extension (currently only dNSName, uniformResourceIdentifier and OtherName are listed). */

    //mbedtls_x509_sequence certificate_policies; /**< Optional list of certificate policies (Only anyPolicy is printed and enforced, however the rest of the policies are still listed). */

    int MBEDTLS_PRIVATE(ext_types);              /**< Bit string containing detected and parsed extensions */
    int MBEDTLS_PRIVATE(ca_istrue);              /**< Optional Basic Constraint extension value: 1 if this certificate belongs to a CA, 0 otherwise. */
    int MBEDTLS_PRIVATE(max_pathlen);            /**< Optional Basic Constraint extension value: The maximum path length to the root certificate. Path length is 1 higher than RFC 5280 'meaning', so 1+ */

    unsigned int MBEDTLS_PRIVATE(key_usage);     /**< Optional key usage extension value: See the values in x509.h */

    mbedtls_x509_sequence ext_key_usage; /**< Optional list of extended key usage OIDs. */

    unsigned char MBEDTLS_PRIVATE(ns_cert_type); /**< Optional Netscape certificate type extension value: See the values in x509.h */

    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);               /**< Signature: hash of the tbs part signed with the private key. */
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next certificate in the linked list that constitutes the CA chain.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct mbedtls_x509_crt *next;
}
mbedtls_x509_crt;
typedef void mbedtls_ed25519_restart_ctx;
typedef int (*mbedtls_x509_crt_ext_cb_t)(void *p_ctx,
                                         mbedtls_x509_crt const *crt,
                                         mbedtls_x509_buf const *oid,
                                         int critical,
                                         const unsigned char *p,
                                         const unsigned char *end);


#define MBEDTLS_OID_PKCS1_MD5           MBEDTLS_OID_PKCS1 "\x04" /**< md5WithRSAEncryption ::= { pkcs-1 4 } */
#define MBEDTLS_MD_CAN_MD5
#define MBEDTLS_ERR_OID_NOT_FOUND                         -0x002E

#define FN_OID_GET_OID_BY_ATTR2(FN_NAME, TYPE_T, LIST, ATTR1_TYPE, ATTR1,   \
                                ATTR2_TYPE, ATTR2)                          \
    int FN_NAME(ATTR1_TYPE ATTR1, ATTR2_TYPE ATTR2, const char **oid,         \
                size_t *olen)                                                 \
    {                                                                           \
        const TYPE_T *cur = (LIST);                                             \
        while (cur->descriptor.asn1 != NULL) {                                 \
            if (cur->ATTR1 == (ATTR1) && cur->ATTR2 == (ATTR2)) {              \
                *oid = cur->descriptor.asn1;                                    \
                *olen = cur->descriptor.asn1_len;                               \
                return 0;                                                    \
            }                                                                   \
            cur++;                                                              \
        }                                                                       \
        return MBEDTLS_ERR_OID_NOT_FOUND;                                   \
    }

int mbedtls_oid_get_oid_by_sig_alg(mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                                   const char **oid, size_t *olen);

/**
 * \brief Base OID descriptor structure
 */
typedef struct mbedtls_oid_descriptor_t {
    const char *asn1;               /*!< OID ASN.1 representation       */
    size_t asn1_len;                /*!< length of asn1                 */
    const char *name;               /*!< official name (e.g. from RFC)  */
    const char *description;        /*!< human friendly description     */
#
} mbedtls_oid_descriptor_t;

typedef struct {
    mbedtls_oid_descriptor_t    descriptor;
    mbedtls_md_type_t           md_alg;
    mbedtls_pk_type_t           pk_alg;
} oid_sig_alg_t;


typedef struct mbedtls_asn1_bitstring {
    size_t len;                 /**< ASN1 length, in octets. */
    unsigned char unused_bits;  /**< Number of unused bits at the end of the string */
    unsigned char *p;           /**< Raw ASN1 data for the bit string */
}
mbedtls_asn1_bitstring;
typedef mbedtls_asn1_bitstring mbedtls_x509_bitstring;

static const x509_attr_descriptor_t x509_attrs[] =
{
    { ADD_STRLEN("CN"),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("commonName"),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("C"),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("countryName"),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("O"),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationName"),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("L"),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("locality"),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("R"),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("OU"),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationalUnitName"),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("ST"),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("stateOrProvinceName"),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("emailAddress"),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("serialNumber"),
      MBEDTLS_OID_AT_SERIAL_NUMBER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalAddress"),
      MBEDTLS_OID_AT_POSTAL_ADDRESS, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalCode"),
      MBEDTLS_OID_AT_POSTAL_CODE, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("dnQualifier"),
      MBEDTLS_OID_AT_DN_QUALIFIER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("title"),
      MBEDTLS_OID_AT_TITLE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("surName"),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("SN"),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("givenName"),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("GN"),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("initials"),
      MBEDTLS_OID_AT_INITIALS, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("pseudonym"),
      MBEDTLS_OID_AT_PSEUDONYM, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("generationQualifier"),
      MBEDTLS_OID_AT_GENERATION_QUALIFIER, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("domainComponent"),
      MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("DC"),
      MBEDTLS_OID_DOMAIN_COMPONENT,   MBEDTLS_ASN1_IA5_STRING },
    { NULL, 0, NULL, MBEDTLS_ASN1_NULL }
};

/*
 * X.509 v3 Key Usage Extension flags
 * Reminder: update mbedtls_x509_info_key_usage() when adding new flags.
 */
#define MBEDTLS_X509_KU_DIGITAL_SIGNATURE            (0x80)  /* bit 0 */
#define MBEDTLS_X509_KU_NON_REPUDIATION              (0x40)  /* bit 1 */
#define MBEDTLS_X509_KU_KEY_ENCIPHERMENT             (0x20)  /* bit 2 */
#define MBEDTLS_X509_KU_DATA_ENCIPHERMENT            (0x10)  /* bit 3 */
#define MBEDTLS_X509_KU_KEY_AGREEMENT                (0x08)  /* bit 4 */
#define MBEDTLS_X509_KU_KEY_CERT_SIGN                (0x04)  /* bit 5 */
#define MBEDTLS_X509_KU_CRL_SIGN                     (0x02)  /* bit 6 */
#define MBEDTLS_X509_KU_ENCIPHER_ONLY                (0x01)  /* bit 7 */
#define MBEDTLS_X509_KU_DECIPHER_ONLY              (0x8000)  /* bit 8 */


                                                        
#define MBEDTLS_PUT_UINT16_LE(n, data, offset, flag)                                   \
    {                                           \
      if(flag)                               \
         n = ((uint16_t)(((n) & 0xFF) << 8) | ((uint16_t)(((n) >> 8) & 0xFF))); \
      memcpy((data) + (offset), &n, sizeof(n));  \
    }

void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx);
//int mbedtls_x509write_crt_set_subject_name(mbedtls_x509write_cert *ctx, const char *subject_name);
//int mbedtls_x509write_crt_set_issuer_name(mbedtls_x509write_cert *ctx, const char *issuer_name);
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,  const unsigned char *key, size_t keylen, int type_k);
void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);
int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx, const char *not_before, const char *not_after);  
void mbedtls_pk_init(mbedtls_pk_context *ctx);     
size_t ed25519_get_bitlen(const void *ctx);
int ed25519_can_do(mbedtls_pk_type_t type);
void/* mbedtls_ed25519_context*/ ed25519_alloc_wrap(void);
void ed25519_free_wrap(void *ctx);
int mbedtls_ed25519_check_pub_priv(unsigned char* priv, unsigned char* pub, unsigned char* seed);
int ed25519_check_pair_wrap(const void *pub, const void *prv, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_encrypt_wrap(void *ctx,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_decrypt_wrap(void *ctx, const unsigned char *input, size_t ilen,unsigned char *output, size_t *olen, size_t osize, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name);
//void mbedtls_asn1_free_named_data_list(mbedtls_asn1_named_data **head);
const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len);
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data( mbedtls_asn1_named_data **head,const char *oid, size_t oid_len,const unsigned char *val,size_t val_len);
mbedtls_asn1_named_data *asn1_find_named_data(mbedtls_asn1_named_data *list,const char *oid, size_t len);
void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);
const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type);
int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info);
mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx);
int pk_set_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int ed25519_sign_wrap(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len,unsigned char *sig,
                        size_t sig_size, size_t *sig_len, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int ed25519_verify_wrap(void *ctx, mbedtls_md_type_t md_alg, const unsigned char *hash, size_t hash_len, 
                          const unsigned char *sig, size_t sig_len);
void mbedtls_ed25519_free(mbedtls_ed25519_context *ctx);
void mbedtls_ed25519_init(mbedtls_ed25519_context *ctx);
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx,
                              unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);//, unsigned char* test, int *l_topass);
int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *key, unsigned char *buf, size_t size);
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start, const mbedtls_pk_context *key);     
int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, mbedtls_ed25519_context ed25519);                       
int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start, size_t len);
int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start, unsigned char tag);
int mbedtls_asn1_write_algorithm_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len);
int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start);
int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len);
int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size);                          
int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);
int x509_write_name(unsigned char **p,
                           unsigned char *start,
                           mbedtls_asn1_named_data *cur_name);
int mbedtls_asn1_write_tagged_string(unsigned char **p, const unsigned char *start, int tag,
                                     const char *text, size_t text_len);
int x509_write_time(unsigned char **p, unsigned char *start,
                           const char *t, size_t size);
int asn1_write_tagged_int(unsigned char **p, const unsigned char *start, int val, int tag);
int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val);
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size);    
int pk_set_ed25519privkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len);        
void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx, mbedtls_md_type_t md_alg); 
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,  unsigned char *buf, size_t buflen);                                                       
int mbedtls_x509_crt_parse_der_internal(mbedtls_x509_crt *chain,  unsigned char *buf, size_t buflen, int make_copy,
                                               mbedtls_x509_crt_ext_cb_t cb, void *p_ctx);
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt);
int x509_crt_parse_der_core(mbedtls_x509_crt *crt, unsigned char *buf,size_t buflen, int make_copy, mbedtls_x509_crt_ext_cb_t cb, void *p_ctx);
int mbedtls_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag);
int mbedtls_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len);
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt);
void mbedtls_pk_free(mbedtls_pk_context *ctx);
void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name);
void mbedtls_asn1_sequence_free(mbedtls_asn1_sequence *seq);
int x509_get_version(unsigned char **p, const unsigned char *end, int *ver);
int mbedtls_x509_get_serial(unsigned char **p, const unsigned char *end, mbedtls_x509_buf_crt *serial);
int mbedtls_x509_get_alg(unsigned char **p, const unsigned char *end, mbedtls_x509_buf_crt *alg, mbedtls_x509_buf *params);
int mbedtls_asn1_get_alg(unsigned char **p, const unsigned char *end,mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params);
//int mbedtls_x509_get_sig_alg(const mbedtls_x509_buf_crt *sig_oid, const mbedtls_x509_buf_crt *sig_params,mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg, void **sig_opts);
int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end, mbedtls_x509_name *cur);
int x509_get_attr_type_value(unsigned char **p, const unsigned char *end, mbedtls_x509_name *cur);
void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name);
int x509_get_dates(unsigned char **p, const unsigned char *end,mbedtls_x509_time *from, mbedtls_x509_time *to);
int mbedtls_x509_get_time(unsigned char **p, const unsigned char *end,mbedtls_x509_time *tm);
int x509_parse_time(unsigned char **p, size_t len, size_t yearlen, mbedtls_x509_time *tm);
int x509_parse_int(unsigned char **p, size_t n, int *res);
int x509_date_is_valid(const mbedtls_x509_time *t);
int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end, mbedtls_pk_context *pk);
int mbedtls_x509_get_sig(unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig);
int mbedtls_asn1_get_bitstring_null(unsigned char **p, const unsigned char *end, size_t *len);
int mbedtls_asn1_get_int(unsigned char **p,const unsigned char *end, int *val);
int asn1_get_tagged_int(unsigned char **p,const unsigned char *end,int tag, int *val);
int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,  mbedtls_asn1_named_data *first);
int x509_write_extension(unsigned char **p, unsigned char *start, mbedtls_asn1_named_data *ext);
int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start, int boolean);
int mbedtls_x509_set_extension(mbedtls_asn1_named_data *head, const char *oid, size_t oid_len,
                               int critical, /*const*/ unsigned char *val, size_t val_len, int *ne);
int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx,  const char *oid, size_t oid_len, int critical, /*const*/ unsigned char *val, size_t val_len);
int pk_get_pk_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params);
                         
/* unsigned int my_strlen(const char *s);

int my_strncmp( const char * s1, const char * s2, size_t n );
char* my_strncpy(char* destination, const char* source, size_t num);
void * my_memmove(void* dest, const void* src, unsigned int n);
int my_memcmp (const void *str1, const void *str2, size_t count);
void* my_memset(void* dest, int byte, size_t len);
void* my_memcpy(void* dest, const void* src, size_t len); */
int mbedtls_x509write_crt_set_issuer_name_mod(mbedtls_x509write_cert *ctx, const char *issuer_name);
int mbedtls_x509_string_to_names_mod(mbedtls_asn1_named_data *head, const char *name, int *ne);
int mbedtls_asn1_store_named_data_mod( mbedtls_asn1_named_data *head,const char *oid, size_t oid_len,const unsigned char *val,size_t val_len, int *ne);
int asn1_find_named_data_mod(mbedtls_asn1_named_data *list,const char *oid, size_t len, size_t ne);
int mbedtls_x509write_crt_set_subject_name_mod(mbedtls_x509write_cert *ctx, const char *subject_name);
int x509_write_name_mod(unsigned char **p, unsigned char *start,mbedtls_asn1_named_data cur_name);
int mbedtls_x509_write_names_mod(unsigned char **p, unsigned char *start,mbedtls_asn1_named_data *arr, int ne);
int x509_get_attr_type_value_mod(unsigned char **p,const unsigned char *end, mbedtls_asn1_named_data_noarr *cur);
int mbedtls_x509_get_name_mod(unsigned char **p, const unsigned char *end, mbedtls_asn1_named_data_noarr *cur, int *ne);
void mbedtls_asn1_free_named_data_list_mod(int *ne);
int mbedtls_asn1_get_alg_mod(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf_no_arr *alg, mbedtls_asn1_buf *params);  
int mbedtls_x509_get_alg_mod(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *alg, mbedtls_x509_buf *params);
int mbedtls_x509_get_sig_alg_mod(const mbedtls_x509_buf_crt *sig_oid, const mbedtls_x509_buf *sig_params,
                             mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                             void **sig_opts);

int mbedtls_asn1_get_bool(unsigned char **p,
                          const unsigned char *end,
                          int *val);
int x509_write_extension_mod(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_named_data ext);
int mbedtls_x509_write_extensions_mod(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *arr_exte, int ne);
int x509_get_crt_ext(unsigned char **p,
                            const unsigned char *end,
                            mbedtls_x509_crt *crt,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx);
int x509_get_basic_constraints(unsigned char **p,
                                      const unsigned char *end,
                                      int *ca_istrue,
                                      int *max_pathlen);
int mbedtls_x509write_crt_set_basic_constraints(mbedtls_x509write_cert *ctx,
                                                int is_ca, int max_pathlen);
void set_dice_tcbInfo(dice_tcbInfo* tcbInfo);
void init_dice_tcbInfo(dice_tcbInfo* tcbInfo);

int mbedtls_x509write_crt_set_dice_tcbInfo(mbedtls_x509write_cert *ctx,
                                                dice_tcbInfo info_struct, int dim, unsigned char buf[], size_t buf_size);

/*int mbedtls_x509write_crt_set_dice_tcbInfo(mbedtls_x509write_cert *ctx,
                                                dice_tcbInfo info_struct);*/

int x509_get_dice_tcbInfo(unsigned char **p,
                                      const unsigned char *end,
                                      dice_tcbInfo* info_struct);  
int setting_tcbInfo(dice_tcbInfo* dice_tcbInfo, unsigned char vendor[], int l_ven, unsigned char model[], int l_m, unsigned char version[], int l_ver,
                            int svn, int layer, int index, unsigned char flags[], int l_f, unsigned char vendor_info[], int l_vf, unsigned char type[], int l_t,
                            measure measures[], int l_mea);   

void set_dice_tcbInfo_vendor(dice_tcbInfo* tcbInfo, unsigned char vendor[], int lv);
void set_dice_tcbInfo_version(dice_tcbInfo* tcbInfo, unsigned char version[], int lv);
void set_dice_tcbInfo_model(dice_tcbInfo* tcbInfo, unsigned char model[], int l);
void set_dice_tcbInfo_vi(dice_tcbInfo* tcbInfo, unsigned char vi[], int l);
void set_dice_tcbInfo_type(dice_tcbInfo* tcbInfo, unsigned char type[], int l);
void set_dice_tcbInfo_measure(dice_tcbInfo* tcbInfo, measure m);
/*
int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf *ext, int tag);
*/
int mbedtls_x509_get_ext(unsigned char **p, const unsigned char *end,
                         mbedtls_x509_buf_crt *ext, int tag);
int x509_get_uid(unsigned char **p,
                        const unsigned char *end,
                        mbedtls_x509_buf_crt *uid, int n);
        /*
int x509_get_uid(unsigned char **p, const unsigned char *end,mbedtls_x509_buf *uid, int n);

        */       

int mbedtls_asn1_write_bitstring(unsigned char **p, const unsigned char *start,
                                 const unsigned char *buf, size_t bits);
int mbedtls_asn1_get_bitstring(unsigned char **p, const unsigned char *end,
                               mbedtls_asn1_bitstring *bs);    
int pk_get_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int mbedtls_asn1_write_ed25519_identifier(unsigned char **p, const unsigned char *start,
                                            const char *oid, size_t oid_len);
int mbedtls_asn1_get_alg_ed25519(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf *alg);

int mbedtls_x509write_crt_set_key_usage(mbedtls_x509write_cert *ctx,
                                        unsigned int key_usage);
int mbedtls_x509_get_key_usage(unsigned char **p,
                               const unsigned char *end,
                               unsigned int *key_usage);       

int mbedtls_asn1_write_named_bitstring(unsigned char **p,
                                       const unsigned char *start,
                                       const unsigned char *buf,
                                       size_t bits);

#endif
  
