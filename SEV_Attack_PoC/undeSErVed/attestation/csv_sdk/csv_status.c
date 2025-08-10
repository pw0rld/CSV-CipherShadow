#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <immintrin.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/sm3.h"
#include "csv_status.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGEMAP_LEN 8

static uint8_t g_user_data[USER_DATA_SIZE];
static uint8_t g_measure[HASH_BLOCK_LEN];
static uint8_t g_chip_id[SN_LEN];

uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE] = {0};
uint8_t r_mnonce[GUEST_ATTESTATION_NONCE_SIZE] = {0};

static CSV_CERT_t g_pek_cert;


/* get hygon attestation report in user mode */
void gen_random_bytes(void *buf, uint32_t len)
{
    uint32_t i;
    uint8_t *buf_byte = (uint8_t *)buf;

    for (i = 0; i < len; i++) {
        buf_byte[i] = rand() & 0xFF;
    }
}

void csv_data_dump(const char* name, uint8_t *data, uint32_t len)
{
    logcat("%s:\n", name);
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        logcat("%02hhx", c);
    }
    logcat("\n");
}

uint64_t va_to_pa(uint64_t va)
{
    FILE *pagemap;
    uint64_t offset, pfn;

    pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) {
        logcat("open pagemap fail\n");
        return 0;
    }

    offset = va / PAGE_SIZE * PAGEMAP_LEN;
    if(fseek(pagemap, offset, SEEK_SET) != 0) {
        logcat("seek pagemap fail\n");
        fclose(pagemap);
        return 0;
    }

    if (fread(&pfn, 1, PAGEMAP_LEN - 1, pagemap) != PAGEMAP_LEN - 1) {
        logcat("read pagemap fail\n");
        fclose(pagemap);
        return 0;
    }

    pfn &= 0x7FFFFFFFFFFFFF;

    return pfn << PAGE_SHIFT;
}

long hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
    long ret = 0;

    asm volatile("vmmcall"
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(len)
             : "memory");
    return ret;
}

int get_attestation_report(struct csv_attestation_report *report)
{
    struct csv_attestation_user_data *user_data;
    uint64_t user_data_pa;
    long ret;

    if (!report) {
        logcat("NULL pointer for report\n");
        return -1;
    }

    // prepare user data
    user_data = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (user_data == MAP_FAILED) {
        logcat("mmap failed\n");
        return -1;
    }
    logcat("mmap %p\n", user_data);

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    logcat("mnonce: %s\n", user_data->mnonce);
    memcpy(g_mnonce, user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    // compute hash and save to the private page
    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    logcat("data: %s\n", user_data->data);

    // call host to get attestation report
    user_data_pa = va_to_pa((uint64_t)user_data);
    logcat("user_data_pa: %lx\n", user_data_pa);

    ret = hypercall(KVM_HC_VM_ATTESTATION, user_data_pa, PAGE_SIZE);
    if (ret) {
        logcat("hypercall fail: %ld\n", ret);
        munmap(user_data, PAGE_SIZE);
        return -1;
    }
    memcpy(report, user_data, sizeof(*report));
    munmap(user_data, PAGE_SIZE);

    return 0;
}

int verify_session_mac(struct csv_attestation_report *report)
{
    hash_block_u hmac = {0};

    sm3_hmac((const unsigned char*)(&report->pek_cert),
             sizeof(report->pek_cert) + SN_LEN + sizeof(report->reserved2),
             g_mnonce, GUEST_ATTESTATION_NONCE_SIZE,(unsigned char*)(hmac.block));

    if(memcmp(hmac.block, report->mac.block, sizeof(report->mac.block)) == 0){
        logcat("mac verify success\n");
        return 0;
    }else{
        logcat("mac verify failed\n");
        return -1;
    }
}

int vmmcall_get_attestation_report(unsigned char* report_buf, unsigned int buf_len)
{
    int ret;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report)){
        logcat("The allocated length is too short to meet the generated report!\n");
        logcat("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (report_buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    logcat("get attestation report & save to %s\n", ATTESTATION_REPORT_FILE);

    ret = get_attestation_report(&report);
    if (ret) {
        logcat("get attestation report fail\n");
        return -1;
    }

    ret = verify_session_mac(&report);
    if (ret) {
        logcat("PEK cert and ChipId have been tampered with\n");
        return ret;
    } else {
        logcat("check PEK cert and ChipId successfully\n");
    }

    memset(report.reserved2, 0, sizeof(report.reserved2));

    memcpy(report_buf, &report, sizeof(report));

    return 0;
}


/* verify hygon attestation report */
void csv_report_dump(struct csv_attestation_report *report)
{
    csv_data_dump("userdata", g_user_data, sizeof(report->user_data));
    csv_data_dump("mnonce", g_mnonce, sizeof(report->mnonce));
    csv_data_dump("measure", g_measure, sizeof(report->measure.block));
    csv_data_dump("sn", g_chip_id, sizeof(report->sn));
}

void invert_endian(unsigned char* buf, int len)
{
    int i;

    for(i = 0; i < len/2; i++)
    {
        unsigned int tmp = buf[i];
        buf[i] = buf[len - i -1];
        buf[len - i -1] =  tmp;
    }
}

int gmssl_sm2_verify(struct ecc_point_q  Q,unsigned char *userid,
                      unsigned int userid_len, const unsigned char *msg, unsigned int msg_len, struct ecdsa_sign *sig_in){
    int        ret;
    EC_KEY    *eckey;
    unsigned char dgst[ECC_LEN];
    long unsigned int dgstlen;

    if (!msg || !userid|| !sig_in) {
        logcat("gmssl_sm2 dsa256_verify invalid input parameter\n");
        return -1;
    }

    invert_endian(sig_in->r, ECC_LEN);
    invert_endian(sig_in->s, ECC_LEN);

    BIGNUM *bn_qx = BN_bin2bn(Q.Qx, 32, NULL);
    BIGNUM *bn_qy = BN_bin2bn(Q.Qy, 32, NULL);

    eckey = EC_KEY_new();
    EC_GROUP *group256 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_group(eckey, group256);
    EC_POINT *ecpt_pubkey = EC_POINT_new(group256);
    EC_POINT_set_affine_coordinates_GFp(group256, ecpt_pubkey, bn_qx, bn_qy, NULL);
    EC_KEY_set_public_key(eckey, ecpt_pubkey);

    if (eckey == NULL) {
        /* error */
        logcat("EC_KEY_new_by_curve_name");
        EC_POINT_free(ecpt_pubkey);
        return -1;
    }

    dgstlen = sizeof(dgst);
    SM2_compute_message_digest(EVP_sm3(), EVP_sm3(), msg, msg_len, (const char *)userid,
                                userid_len,dgst, &dgstlen, eckey);

    /* verify */
    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *sig_r=BN_new();
    BIGNUM *sig_s=BN_new();
    BN_bin2bn(sig_in->r, 32, sig_r);
    BN_bin2bn(sig_in->s, 32, sig_s);
    ECDSA_SIG_set0(s, sig_r, sig_s);
    logcat("Signature:\n\tr=%s\n\ts=%s\n", BN_bn2hex(sig_r), BN_bn2hex(sig_s));

    ret = SM2_do_verify(dgst, dgstlen, s, eckey);

    EC_POINT_free(ecpt_pubkey);
    ECDSA_SIG_free(s);
    EC_GROUP_free(group256);
    EC_KEY_free(eckey);

    if (1 != ret) {
        logcat("SM2_do_verify fail!, ret=%d\n", ret);
        return -1;
    }else
    logcat("SM2_do_verify success!\n");

    return 0;
}

int csv_cert_verify(const char *data, uint32_t datalen, ecc_signature_t *signature, ecc_pubkey_t *pubkey)
{
    struct ecc_point_q Q;

    Q.curve_id = pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    struct ecdsa_sign sig_in;
    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, ((userid_u*)pubkey->user_id)->uid, ((userid_u*)pubkey->user_id)->len, (const unsigned char *)data, datalen, &sig_in);
}

int csv_attestation_report_verify(struct csv_attestation_report *report)
{
    CSV_CERT_t *pek_cert;
    int ret = 0 ;

    csv_report_dump(report);

    logcat("verify: do verify\n");
    pek_cert = &g_pek_cert;
    ret = csv_cert_verify((const char *)report, ATTESTATION_REPORT_SIGNED_SIZE, &report->ecc_sig1, &pek_cert->ecc_pubkey);
    logcat("verify %s\n", ret ? "fail" : "success");

    return ret;
}

int verify_hrk_cert_signature(CHIP_ROOT_CERT_t *hrk){
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;

    uint32_t      need_copy_len   = 0;
    uint8_t       hrk_userid[256] = {0};
    userid_u* sm2_userid      = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = &hrk->ecc_pubkey;
    ecc_signature_t *signature = &hrk->ecc_sig;

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx,pubkey->Qx,ECC_LEN);
    memcpy(Q.Qy,pubkey->Qy,ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len               = ((userid_u*)pubkey->user_id)->len;
    need_copy_len                 = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, (const uint8_t *)hrk,64 + 512 , &sig_in);
}

int verify_hsk_cert_signature(CHIP_ROOT_CERT_t *hrk,CHIP_ROOT_CERT_t *hsk){
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;

    uint32_t need_copy_len = 0;
    uint8_t  hrk_userid[256] = {0};
    userid_u* sm2_userid      = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = (ecc_pubkey_t*)hrk->pubkey;
    ecc_signature_t *signature = &hsk->ecc_sig;

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx,pubkey->Qx,ECC_LEN);
    memcpy(Q.Qy,pubkey->Qy,ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len               = ((userid_u*)pubkey->user_id)->len;
    need_copy_len                 = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, (const uint8_t *)hsk,64 + 512 , &sig_in);
}

int verify_cek_signature(CHIP_ROOT_CERT_t *hsk, CSV_CERT_t *cek){
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;

    uint32_t need_copy_len = 0;
    uint8_t  hrk_userid[256] = {0};
    userid_u* sm2_userid      = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = (ecc_pubkey_t*)hsk->pubkey;
    ecc_signature_t *signature;

    if(KEY_USAGE_TYPE_INVALID == cek->sig1_usage){
        signature = &cek->ecc_sig2;
    }else{
        signature = &cek->ecc_sig1;
    }

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx,pubkey->Qx,ECC_LEN);
    memcpy(Q.Qy,pubkey->Qy,ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len               = ((userid_u*)pubkey->user_id)->len;
    need_copy_len                 = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, (const uint8_t *)cek,16 + 1028, &sig_in);
}

int verify_pek_cert_with_cek_signature(CSV_CERT_t *cek,CSV_CERT_t *pek){
    struct ecc_point_q Q;
    struct ecdsa_sign sig_in;

    uint32_t need_copy_len = 0;
    uint8_t  hrk_userid[256] = {0};
    userid_u* sm2_userid      = (userid_u*)hrk_userid;

    ecc_pubkey_t *pubkey = &cek->ecc_pubkey;
    ecc_signature_t *signature = &pek->ecc_sig1;

    Q.curve_id = (curve_id_t)pubkey->curve_id;
    memcpy(Q.Qx,pubkey->Qx,ECC_LEN);
    memcpy(Q.Qy,pubkey->Qy,ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    sm2_userid->len               = ((userid_u*)pubkey->user_id)->len;
    need_copy_len                 = sm2_userid->len;
    if (sm2_userid->len > (256 - sizeof(uint16_t))) {
        need_copy_len = 256 - sizeof(uint16_t);
    }
    memcpy(sm2_userid->uid, (uint8_t*)(((userid_u*)pubkey->user_id)->uid), need_copy_len);

    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, sm2_userid->uid, sm2_userid->len, (const uint8_t *)pek,16 + 1028 , &sig_in);
}

int load_data_from_file(const char *path, void *buff,size_t len)
{
    if (!path || !*path) {
        logcat("no file\n");
        return -ENOENT;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        logcat("open file %s fail %s\n", path, strerror(errno));
        return fd;
    }

    int rlen = 0, n;

    while (rlen < len) {
        n = read(fd, buff + rlen,len);
        if (n == -1) {
            logcat("read file error\n");
            close(fd);
            return n;
        }
        if (!n) {
            break;
        }
        rlen += n;
    }

    close(fd);

    return 0;
}

int get_hrk_cert(char *cert_file)
{
    int  cmd_ret   = -1;
    char command_buff[256];

    sprintf(command_buff,"wget -O %s "HRK_CERT_SITE,cert_file);
    cmd_ret = system(command_buff);

    return (int)cmd_ret;
}

int load_hrk_file(char *filename,void *buff,size_t len){
    int ret;

    ret = get_hrk_cert(filename);
    if(ret == -1){
        logcat("Error:Download hrk failed\n");
        return ret;
    }
    logcat("Get hrk file successful\n\n");
    ret = load_data_from_file(filename,buff,len);
    return ret;
}

int get_hsk_cek_cert(char *cert_file,char *chip_id)
{
    int  cmd_ret   = -1;
    char command_buff[256];

    sprintf(command_buff,"wget -O %s "KDS_CERT_SITE"%s",cert_file,chip_id);
    cmd_ret = system(command_buff);

    return (int)cmd_ret;
}

int load_hsk_cek_file(char *chip_id,void *hsk,size_t hsk_len,void *cek,size_t cek_len){
    int ret;
    struct {
        CHIP_ROOT_CERT_t hsk;
        CSV_CERT_t cek;
    } __attribute__((aligned(1)))  HCK_file;

    ret = get_hsk_cek_cert(HSK_CEK_FILENAME,chip_id);
    if(ret == -1){
        logcat("Error:Download hsk-cek failed\n");
        return ret;
    }
    logcat("Get hsk-cek file successful\n\n");

    ret = load_data_from_file(HSK_CEK_FILENAME,&HCK_file,sizeof(HCK_file));
    if(ret){
        logcat("Error: load HSK CEK file failed\n");
        return ret;
    }

    memcpy(hsk,&HCK_file.hsk,hsk_len);
    memcpy(cek,&HCK_file.cek,cek_len);
    return 0;
}

int validate_cert_chain(struct csv_attestation_report *report){
    CSV_CERT_t cek;
    CHIP_ROOT_CERT_t hsk;
    CHIP_ROOT_CERT_t hrk;
    int success = 0;
    int ret;

    do {
        ret = load_hrk_file(HRK_FILENAME,&hrk,sizeof(CHIP_ROOT_CERT_t));
        if(ret){
            logcat("hrk.cert doesn't exist or size isn't correct\n");
            break;
        }
        if(hrk.key_usage != KEY_USAGE_TYPE_HRK) {
            logcat("hrk.cert key_usage field isn't correct, please use command parse_cert to check hrk.cert\n");
            break;
        }

        ret = load_hsk_cek_file((char *)g_chip_id, &hsk,sizeof(CHIP_ROOT_CERT_t),&cek,sizeof(CSV_CERT_t));
        if(ret){
            logcat("Error:load hsk-cek cert failed\n");
            break;
        }
        if (hsk.key_usage != KEY_USAGE_TYPE_HSK)  // Variable size
        {
            logcat("hsk.cert key_usage field isn't correct, please use command parse_cert to check hsk.cert\n");
            break;
        }

        if (cek.pubkey_usage != KEY_USAGE_TYPE_CEK) {
            logcat("cek.cert pub_key_usage field doesn't correct, please use command parse_cert to check cek.cert\n");
            break;
        }

        if (cek.sig1_usage != KEY_USAGE_TYPE_HSK) {
            logcat("cek.cert sig_1_usage field isn't correct, please use command parse_cert to check cek.cert\n");
            break;
        }

        if (cek.sig2_usage != KEY_USAGE_TYPE_INVALID) {
            logcat("cek.cert sig_2_usage field isn't correct, please use command parse_cert to check cek.cert\n");
            break;
        }

        success = 1;
    }while(0);

    if(!success){
        logcat("Error:load error cert file\n");
        return -1;
    }

    success = 0;
    do {
        ret = verify_hrk_cert_signature(&hrk);
        if(ret){
            logcat("hrk pubkey verify hrk cert failed\n");
            break;
        }
        logcat("hrk pubkey verify hrk cert successful\n");

        ret = verify_hsk_cert_signature(&hrk, &hsk);
        if(ret){
            logcat("hrk pubkey verify hsk cert failed\n");
            break;
        }
        logcat("hrk pubkey verify hsk cert successful\n");
        ret = verify_cek_signature(&hsk, &cek);
        if(ret){
            logcat("hsk pubkey verify cek cert failed\n");
            break;
        }
        logcat("hsk pubkey verify cek cert successful\n");

        ret = verify_pek_cert_with_cek_signature(&cek, &g_pek_cert);
        if(ret){
            logcat("cek pubkey and verify pek cert failed\n");
            break;
        }
        logcat("cek pubkey verify pek cert successful\n");

        success = 1;
    }while(0);

    if(success){
        logcat("validata cert chain successful\n\n");
        return 0;
    }

    return -1;
}

int verify_attestation_report(unsigned char* report_buf, unsigned int buf_len, int verify_chain)
{
    struct csv_attestation_report report;
    int ret = 0;
    int i   = 0;
    int j   = 0;

    if (buf_len < sizeof(report)){
        logcat("The allocated length is too short to meet the generated report!\n");
        logcat("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (report_buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    logcat("verify attestation report\n");

    memcpy(&report, report_buf, sizeof(report));

    // retrieve mnonce, PEK cert and ChipId by report->anonce
    j = sizeof(report.user_data) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)g_user_data)[i] = ((uint32_t *)report.user_data)[i] ^ report.anonce;

    j = sizeof(report.mnonce) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
         ((uint32_t *)g_mnonce)[i] = ((uint32_t *)report.mnonce)[i] ^ report.anonce;

    j = sizeof(report.measure) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)g_measure)[i] = ((uint32_t *)report.measure.block)[i] ^ report.anonce;

    j = ((uint8_t *)report.sn - (uint8_t *)&report.pek_cert) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)&g_pek_cert)[i] = ((uint32_t *)&report.pek_cert)[i] ^ report.anonce;

    j = ((uint8_t *)&report.reserved2 - (uint8_t *)report.sn) / sizeof(uint32_t);
    for (i = 0; i < j; i++)
        ((uint32_t *)g_chip_id)[i] = ((uint32_t *)report.sn)[i] ^ report.anonce;

    if(verify_chain){
        logcat("\nValidate cert chain:\n");
        ret = validate_cert_chain(&report);
        if(ret){
            logcat("validata cert chain failed\n\n");
            return -1;
        }
    }

    logcat("verify report\n");
    ret = csv_attestation_report_verify(&report);

    return ret;
}


/* get random number with len bytes */
int generate_rand64_num(unsigned long long *buf)
{
    return _rdrand64_step(buf);
}

int TCM_GetRandom(uint8_t *buf, uint32_t len)
{
    uint32_t ret, temp_len, i;

    if (len < 1){
        logcat("The allocated length should be more than 0!\n");
        return -1;
    }

    if (buf == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    temp_len = ((len+7)/8)*8;
    unsigned long long *temp_buf = (unsigned long long*)malloc(temp_len);

    for (i=0; i<(len+7)/8; i++){
        ret = generate_rand64_num(temp_buf);
        if (!ret) {
            logcat("get random failed\n");
            free(temp_buf);
            return -1;
        }
        temp_buf++;
    }
    temp_buf -= (len+7)/8;
    memcpy(buf, temp_buf, len);
    free(temp_buf);

    return 0;
}


/* get the current virtual machine status */
int csv_get_status(uint32_t *status)
{
    int ret;
    if (status == NULL) {
        logcat("allocate memory failed\n");
        return -1;
    }

    uint32_t len = sizeof(struct csv_attestation_report);
    uint8_t* report_buf = (uint8_t*)malloc(len);

    vm_status* data_buf = (vm_status*)malloc(sizeof(vm_status));

    ret = vmmcall_get_attestation_report(report_buf, len);
    if (ret) {
        logcat("get report fail\n");
        goto finish;
    }
    logcat("get report success\n");

    ret = verify_attestation_report(report_buf, len, 0);
    if (ret) {
        logcat("verify report fail\n");
        goto finish;
    }
    data_buf->vm_type = 1;
    logcat("verify report success\n");

    ret = verify_attestation_report(report_buf, len, 1);
    if (ret) {
        logcat("verify chain fail\n");
        goto finish;
    }
    data_buf->verify_chain = 1;
    logcat("verify chain success\n");

finish:
    logcat("vm_type: %d\n", data_buf->vm_type);
    logcat("verify_chain: %d\n", data_buf->verify_chain);

    free(report_buf);
    memcpy(status, data_buf, sizeof(vm_status));
    free(data_buf);
    return ret;
}

