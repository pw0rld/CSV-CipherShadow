#ifndef __CSVSDK_H__
#define __CSVSDK_H__

/**
 * @brief  get attestation report in user mode
 *
 * @param  [in]  buf_len: the length of report data stored
 * @param  [out] report_buf: information of output report with a length of buf_len
 *
 * @returns success: 0, failure: -1 and so on
*/
int vmmcall_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);



/**
 * @brief  get attestation report in kernel mode
 *
 * @param  [in]  buf_len: the length of report data stored
 * @param  [out] report_buf: information of output report with a length of buf_len
 *
 * @returns success: 0, failure: -1 and so on
*/
int ioctl_get_attestation_report(unsigned char* report_buf, unsigned int buf_len);


/**
 * @brief  verify attestation report and certificate chain
 *
 * @param  [in]  buf_len: the length of report data stored
 * @param  [in]  verify_chain:
 * - verify_chain=1 indicates verifying the certificate chain
 * - verify_chain=0 indicates not verifying the certificate chain
 * @param  [in] report_buf: information of input report with a length of buf_len
 *
 * @returns success: 0, failure: -1 and so on
*/
int verify_attestation_report(unsigned char* report_buf, unsigned int buf_len, int verify_chain);


/**
 * @brief  get sealing key in user mode
 *
 * @param  [in]  buf_len: the length of sealing key data stored
 * @param  [out] key_buf: information of output sealing with a length of buf_len
 *
 * @returns success: 0, failure: -1 and so on
*/
int vmmcall_get_sealing_key(unsigned char* key_buf, unsigned int buf_len);



/**
 * @brief  get sealing key in kernel mode
 *
 * @param  [in]  buf_len: the length of sealing key data stored
 * @param  [out] key_buf: information of output sealing with a length of buf_len
 *
 * @returns success: 0, failure: -1 and so on
*/
int ioctl_get_sealing_key(unsigned char* key_buf, unsigned int buf_len);

#endif /* __CSVSDK_H__ */
