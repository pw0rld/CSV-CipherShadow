#ifndef __CSV_STATUS_H__
#define __CSV_STATUS_H__

#include <stdint.h>
#include <linux/ioctl.h>

#define HRK_FILENAME "./hrk.cert"
#define HSK_FILENAME "./hsk.cert"
#define CEK_FILENAME "./cek.cert"
#define HSK_CEK_FILENAME "hsk_cek.cert"

#define HRK_CERT_SITE "https://cert.hygon.cn/hrk"
#define KDS_CERT_SITE "https://cert.hygon.cn/hsk_cek?snumber="


#define ATTESTATION_REPORT_FILE "./report.cert"

#define HASH_LEN                      32
#define CERT_ECC_MAX_SIG_SIZE        72
#define GUEST_ATTESTATION_NONCE_SIZE 16
#define GUEST_ATTESTATION_DATA_SIZE  64
#define VM_ID_SIZE                   16
#define VM_VERSION_SIZE              16
#define SN_LEN                       64
#define USER_DATA_SIZE               64
#define HASH_BLOCK_LEN               32

#ifdef LOG_ON
    #define logcat printf
#else
    #define logcat(format, ...)
#endif

typedef enum _key_usage {
    KEY_USAGE_TYPE_HRK     = 0,
    KEY_USAGE_TYPE_HSK     = 0x13,
    KEY_USAGE_TYPE_INVALID = 0x1000,
    KEY_USAGE_TYPE_MIN     = 0x1001,
    KEY_USAGE_TYPE_OCA     = 0x1001,
    KEY_USAGE_TYPE_PEK     = 0x1002,
    KEY_USAGE_TYPE_PDH     = 0x1003,
    KEY_USAGE_TYPE_CEK     = 0x1004,
    KEY_USAGE_TYPE_MAX     = 0x1004,
} key_usage_t;

typedef struct _hash_block_u {
    unsigned char block[HASH_LEN];
} hash_block_u;

/**
 * struct csv_issue_cmd - CSV ioctl parameters
 *
 * @cmd: CSV commands to execute
 * @opaque: pointer to the command structure
 * @error: CSV FW return code on failure
 */
struct csv_issue_cmd {
    uint32_t cmd;					/* In */
    uint64_t data;					/* In */
    uint32_t error;					/* Out */
}  __attribute__((packed));

#define CSV_IOC_TYPE		'S'
#define CSV_ISSUE_CMD	_IOWR(CSV_IOC_TYPE, 0x0, struct csv_issue_cmd)

enum {
    CSV_USER_CMD_FACTORY_RESET = 0,
    CSV_USER_CMD_PDH_CERT_EXPORT = 5,
    CSV_USER_CMD_GET_ID = 7,
    CSV_USER_CMD_GET_ID2 = 8,
    CSV_USER_CMD_ATTESTATION = 38,
    CSV_USER_CMD_MAX,
};

/* verify */
#define  CERT_ECC_MAX_KEY_SIZE          72
#define  CERT_ECC_MAX_SIG_SIZE          72
#define  CERT_ECC_KEY_RESERVED_SIZE     880
#define  CERT_SM2_KEY_RESERVED_SIZE     624
#define  CERT_SM2_ROOT_KEY_RESERVED_SIZE     620
#define  CERT_ECC_SIG_RESERVED_SIZE     368

typedef enum _curve_id {
    CURVE_ID_TYPE_INVALID = 0,
    CURVE_ID_TYPE_MIN     = 0X1,
    CURVE_ID_TYPE_P256    = 0x1,
    CURVE_ID_TYPE_P384    = 0x2,
    CURVE_ID_TYPE_SM2_256 = 0x3,
    CURVE_ID_TYPE_MAX     = 0X3
} curve_id_t;

#define CSV_CERT_RSVD3_SIZE      624
#define CSV_CERT_RSVD4_SIZE      368
#define CSV_CERT_RSVD5_SIZE      368
#define HYGON_USER_ID_SIZE       256
#define SIZE_INT32               4
#define SIZE_24                  24
#define SIZE_108                 108
#define SIZE_112                 112
#define ECC_POINT_SIZE           72
#define CHIP_KEY_ID_LEN          16
#define SM2_UID_SIZE_U           256
#define ECC_LEN                  32  // p-256
#define ECC_KEY_BITS             256

#define ATTESTATION_REPORT_SIGNED_SIZE 180
#define KVM_HC_VM_ATTESTATION	       100	/* Specific to Hygon platform */

typedef struct _userid_u {
    unsigned short   len;
    unsigned char    uid[SM2_UID_SIZE_U - sizeof(unsigned short)];
} __attribute__ ((packed)) userid_u;


/**
 * hash block data structure
 * used to store the hash result value
 */
typedef struct _hash_block {
    uint8_t block[HASH_BLOCK_LEN];
} __attribute__ ((packed)) hash_block_t;

typedef struct _chip_key_id {
    uint8_t id[CHIP_KEY_ID_LEN];
} __attribute__ ((packed)) chip_key_id_t;

typedef struct _ecc_pubkey {
    uint32_t curve_id;
    uint32_t Qx[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t Qy[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t user_id[HYGON_USER_ID_SIZE / SIZE_INT32];
} __attribute__ ((packed)) ecc_pubkey_t;

typedef struct _ecc_signature {
    uint32_t sig_r[ECC_POINT_SIZE / SIZE_INT32];
    uint32_t sig_s[ECC_POINT_SIZE / SIZE_INT32];
} __attribute__ ((packed)) ecc_signature_t;


struct _hygon_root_cert {
    uint32_t      version;
    chip_key_id_t key_id;
    chip_key_id_t certifying_id;
    uint32_t      key_usage;
    uint32_t      reserved1[SIZE_24 / SIZE_INT32];
    union {
        uint32_t     pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + HYGON_USER_ID_SIZE) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved2[SIZE_108 / SIZE_INT32];
    union {
        uint32_t        signature[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig;
    };
    uint32_t reserved3[SIZE_112 / SIZE_INT32];
} __attribute__((packed));


struct _hygon_csv_cert {
    uint32_t version;
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  reserved1;
    uint8_t  reserved2;
    uint32_t pubkey_usage;
    uint32_t pubkey_algo;
    union {
        uint32_t     pubkey[(SIZE_INT32 + ECC_POINT_SIZE * 2 + HYGON_USER_ID_SIZE) / SIZE_INT32];
        ecc_pubkey_t ecc_pubkey;
    };
    uint32_t reserved3[CSV_CERT_RSVD3_SIZE / SIZE_INT32];
    uint32_t sig1_usage;
    uint32_t sig1_algo;
    union {
        uint32_t        sig1[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
    uint32_t reserved4[CSV_CERT_RSVD4_SIZE / SIZE_INT32];
    uint32_t sig2_usage;
    uint32_t sig2_algo;
    union {
        uint32_t        sig2[ECC_POINT_SIZE * 2 / SIZE_INT32];
        ecc_signature_t ecc_sig2;
    };
    uint32_t reserved5[CSV_CERT_RSVD5_SIZE / SIZE_INT32];
} __attribute__((packed));

typedef struct _hygon_root_cert CHIP_ROOT_CERT_t;
typedef struct _hygon_csv_cert  CSV_CERT_t;

typedef struct _csv_cert_chain {
    CSV_CERT_t pek_cert;
    CSV_CERT_t oca_cert;
    CSV_CERT_t cek_cert;
} CSV_CERT_CHAIN_t;


struct csv_attestation_report {
    hash_block_t user_pubkey_digest;
    uint8_t     vm_id[VM_ID_SIZE];
    uint8_t     vm_version[VM_VERSION_SIZE];
    uint8_t     user_data[USER_DATA_SIZE];
    uint8_t      mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_t measure;
    uint32_t policy;
    uint32_t sig_usage;
    uint32_t sig_algo;
    uint32_t anonce;
    union {
        uint32_t sig1[ECC_POINT_SIZE*2/SIZE_INT32];
        ecc_signature_t ecc_sig1;
    };
    CSV_CERT_t pek_cert;
    uint8_t sn[SN_LEN];
    uint8_t reserved2[32];
    hash_block_u      mac;
};

/**
 * struct csv_user_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_length: length of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_length: length of PDH certificate chain
 */
struct csv_user_data_pdh_cert_export {
    uint64_t pdh_cert_address;				/* In */
    uint32_t pdh_cert_length;				/* In/Out */
    uint64_t cert_chain_address;			/* In */
    uint32_t cert_chain_length;			    /* In/Out */
}  __attribute__((packed));


struct ecc_point_q {
    curve_id_t     curve_id;
    unsigned char    Qx[ECC_LEN];
    unsigned char    Qy[ECC_LEN];
};

struct ecdsa_sign {
    unsigned char    r[ECC_LEN];
    unsigned char    s[ECC_LEN];
};

/**
 * virtual machine status command buffer.
 *
 * @vm_type                - virtual machine type: 0=nocsv; 1=csv
 * @verify_chain           - verify certificate chain: 0=no; 1=yes
 * @reserved               - reserved. Set to zero.
 */
typedef struct vm_status_t {
    uint32_t vm_type: 1,
        verify_chain: 1,
        reserved: 30;
} vm_status;

/**
 * @brief  get random in csv virtual machine
 *
 * @param  [in]  len: the length of random data stored
 * @param  [out] buf: information of random number with a length of len
 *
 * @returns success: 0, failure: -1 and so on
*/
int TCM_GetRandom(uint8_t *buf, uint32_t len);

/**
 * @brief  get virtual machine status
 *
 * @param  [out] status: information of virtual machine status
 *
 * @returns success: 0, failure: -1 and so on
*/
int csv_get_status(uint32_t *status);

/*make the files in the csv_sdk dir reuse the functions in csv_status.c*/
extern uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE];
extern uint8_t r_mnonce[GUEST_ATTESTATION_NONCE_SIZE];

struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};
struct csv_guest_mem{
    unsigned long va;
    int size;
};

int vmmcall_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);
int verify_session_mac(struct csv_attestation_report *report);
void csv_data_dump(const char* name, uint8_t *data, uint32_t len);
int get_attestation_report_ioctl(struct csv_attestation_report *report);
void gen_random_bytes(void *buf, uint32_t len);
int get_attestation_report(struct csv_attestation_report *report);

#endif /* __CSV_STATUS_H__ */
