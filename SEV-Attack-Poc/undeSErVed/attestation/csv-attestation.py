#!/usr/bin/env python3

# Copyright (c) 2023 Alibaba Cloud
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from pysmx.SM3 import digest
from pysmx.SM2 import Verify
import ctypes, os, struct ,fcntl
import requests, copy, argparse, json
from requests.packages import urllib3

'''
#define HASH_LEN                     32
#define CERT_ECC_MAX_SIG_SIZE        72
#define GUEST_ATTESTATION_NONCE_SIZE 16
#define GUEST_ATTESTATION_DATA_SIZE  64
#define VM_ID_SIZE                   16
#define VM_VERSION_SIZE              16
#define SN_LEN                       64
#define USER_DATA_SIZE               64
#define HASH_BLOCK_LEN               32

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
'''

class GmHelper():
    __SM2_A = 'fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc'
    __SM2_B = '28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93'
    __SM2_G_X = '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7'
    __SM2_G_Y = 'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'
    __EC_KEY = __SM2_A + __SM2_B + __SM2_G_X + __SM2_G_Y

    def __init__(self):
        return

    def hmac_sm3(self, key, input_data):
        real_key = bytes(key) + bytearray(64 - len(key))
        ipad_xor = bytearray(64)
        opad_xor = bytearray(64)

        for i in range(0, 64):
            ipad_xor[i] = real_key[i] ^ 0x36
            opad_xor[i] = real_key[i] ^ 0x5c

        first_hash = digest(ipad_xor + input_data)
        second_hash = digest(opad_xor + first_hash)

        return second_hash

    def verify_sm2_sigature_with_id(self, id, id_len, qx, qy, msg, r, s):
        pubkey_hex = qx[::-1].hex() + qy[::-1].hex()
        sign_hex = r[::-1].hex() + s[::-1].hex()

        # id_md(id, ec_key)
        id_msg = int(((id_len * 8) >> 8) % 256).to_bytes(1, 'little') + \
                int(((id_len * 8)) % 256).to_bytes(1, 'little') + \
                id + bytearray.fromhex(self.__EC_KEY) + bytearray.fromhex(pubkey_hex)

        za = digest(id_msg)

        # msg_md(za || msg)
        msg_all = za + msg
        msg_all_digest = digest(msg_all)

        return Verify(sign_hex, msg_all_digest.hex(), pubkey_hex, Hexstr=1, len_para=64)

class AttestationReportProducor():
    __IOC_NRBITS = 8
    __IOC_TYPEBITS = 8
    __IOC_SIZEBITS = 14
    __IOC_DIRBITS = 2

    __IOC_NRMASK = (1 << __IOC_NRBITS) - 1
    __IOC_TYPEMASK = (1 << __IOC_TYPEBITS) - 1
    __IOC_SIZEMASK = (1 << __IOC_SIZEBITS) - 1
    __IOC_DIRMASK = (1 << __IOC_DIRBITS) - 1

    __IOC_NRSHIFT = 0
    __IOC_TYPESHIFT = __IOC_NRSHIFT + __IOC_NRBITS
    __IOC_SIZESHIFT = __IOC_TYPESHIFT + __IOC_TYPEBITS
    __IOC_DIRSHIFT = __IOC_SIZESHIFT + __IOC_SIZEBITS

    __IOC_NONE = 0
    __IOC_WRITE = 1
    __IOC_READ = 2

    GUEST_ATTESTATION_DATA_SIZE = 64
    GUEST_ATTESTATION_NONCE_SIZE = 16
    GUEST_ATTESTATION_SM3_SIZE = 32
    GUEST_ATTESTATION_REPORT_SIZE = 2548

    report = ''
    userdata = ''
    def __init__(self, userdata):
        if not userdata is None:
            self.userdata = userdata
        self.report = self.__get_report_from_csv_guest()
        return

    def __IOC(self, dir, type, nr, size):
        assert dir <= self.__IOC_DIRMASK, dir
        assert type <= self.__IOC_TYPEMASK, type
        assert nr <= self.__IOC_NRMASK, nr
        assert size <= self.__IOC_SIZEMASK, size
        return (dir << self.__IOC_DIRSHIFT) | (type << self.__IOC_TYPESHIFT) | (nr << self.__IOC_NRSHIFT) | (size << self.__IOC_SIZESHIFT)

    def __get_report_from_csv_guest(self):
        fd = os.open('/dev/csv-guest', os.O_RDWR)
        # both of the input and output data are all stored here
        buf = ctypes.create_string_buffer(4096)

        # generate random user_data and mnonce
        if len(self.userdata):
            data = bytearray(self.GUEST_ATTESTATION_DATA_SIZE)
            userdata_bytes = self.userdata.encode("utf-8")
            if len(self.userdata) > self.GUEST_ATTESTATION_DATA_SIZE:
                data[:] = userdata_bytes[0:self.GUEST_ATTESTATION_DATA_SIZE]
            else:
                data[self.GUEST_ATTESTATION_DATA_SIZE - len(userdata_bytes):] = userdata_bytes[0:self.GUEST_ATTESTATION_DATA_SIZE]
        else:
            data = os.urandom(self.GUEST_ATTESTATION_DATA_SIZE)
        data += os.urandom(self.GUEST_ATTESTATION_NONCE_SIZE)

        buf.value = bytes(data) + digest(data)
        input_va = ctypes.addressof(buf)
        param_va = bytearray(struct.pack('@QI', input_va, 4096))

        csv_issue_cmd = self.__IOC(self.__IOC_READ|self.__IOC_WRITE, 68, 1, 16)
        fcntl.ioctl(fd, csv_issue_cmd, param_va, True)

        os.close(fd)

        # output_buf[0:GUEST_ATTESTATION_REPORT_SIZE] is attestation report!
        return buf[0:self.GUEST_ATTESTATION_REPORT_SIZE]

    def persistent_report(self, path):
        if os.path.isdir(path):
            path = path + 'report'

        with open(path, 'wb+') as f:
            f.write(self.report)
        return path

class AttestationReportVerifier():
    raw_report = ''
    real_report = ''
    anonce = ''
    gm_helper = ''
    chip_id = ''
    pek = ''
    __policy = ["NODEBUG", "NOKS", "ES", "NOSEND", "DOMAIN", "CSV", "REUSE"]

    def __init__(self, path):
        if os.path.isdir(path):
            path = path + 'report'

        with open(path, 'rb') as f:
            self.raw_report = bytearray(f.read())

        self.real_report = copy.copy(self.raw_report)
        self.anonce = self.raw_report[0xbc:0xc0]

        # restore user_data, mnonce and measure
        self.real_report[0x00:0xb8] = self.__clear_nonce(self.anonce, self.raw_report[0x00:0xb8])
        # restore pek_cert and sn
        self.real_report[0x150:0x9b4] = self.__clear_nonce(self.anonce, self.raw_report[0x150:0x9b4])

        # extract chip_ip and pek
        self.chip_id = self.real_report[0x974:0x9b4].decode('utf-8')
        self.chip_id = self.real_report[0x974:0x974 + self.chip_id.find('\0')].decode('utf-8')
        self.pek = self.real_report[0x150:0x974]

        # init gm helper
        self.gm_helper = GmHelper()
        return

    def __clear_nonce(self, nonce, data):
        nonce = nonce * int(len(data)/len(nonce))
        return bytes(a ^ b for (a, b) in zip(nonce, data) )

    def __verify_hygon_cert_info(self, hygon_cert, curve_id, key_usage, key_id):
        hygon_key_usage = hygon_cert[0x24:0x28]
        hygon_key_usage = int.from_bytes(hygon_key_usage, 'little')
        if hygon_key_usage != key_usage:
            print("ERROR: the KEY_USAGE is %d (should be %d)" % (hygon_key_usage, key_usage))
            return False

        hygon_curve_id = hygon_cert[0x40:0x44]
        hygon_curve_id = int.from_bytes(hygon_curve_id, 'little')
        if hygon_curve_id != curve_id:
            print("ERROR: the CURVE_ID is %d (should be %d)" % (hygon_curve_id, curve_id))
            return False

        hygon_certifying_id = hygon_cert[0x14:0x24]
        if hygon_certifying_id != key_id:
            print("ERROR: the key_id doesn't equal cerifying_id")
            return False

        return True

    def __verify_csv_cert_info(self, csv_cert, sig_usage, sig_algo, key_usage, key_id):
        csv_key_usage = csv_cert[0x08:0x0C]
        csv_key_usage = int.from_bytes(csv_key_usage, 'little')
        if csv_key_usage != key_usage:
            print("ERROR: the KEY_USAGE is %d (should be %d)" % (csv_key_usage, key_usage))
            return False

        csv_sig_usage = csv_cert[0x414:0x418]
        csv_sig_usage = int.from_bytes(csv_sig_usage, 'little')
        if csv_sig_usage != sig_usage:
            print("ERROR: the SIG_USAGE is %d (should be %d)" % (csv_sig_usage, sig_usage))
            return False

        csv_sig_algo = csv_cert[0x418:0x41C]
        csv_sig_algo = int.from_bytes(csv_sig_algo, 'little')
        if csv_sig_algo != sig_algo:
            print("ERROR: the SIG_USAGE is %d (should be %d)" % (csv_sig_algo, sig_algo))
            return False

        csv_certifying_id = csv_cert[0x1a4:0x1b4]
        if csv_certifying_id != key_id:
            print("ERROR: the key_id doesn't equal cerifying_id")
            return False

        return True

    ##
    # verify cert chain: HRK->HSK->CEK->PEK
    ##
    def __veriy_cert_chain(self):
        # disable warning as we will verify the cert's fingerprint
        urllib3.disable_warnings()

        # get and verify Hygon Root Key (HRK)
        res = requests.get('https://cert.hygon.cn/hrk', verify=False)
        if res.status_code != 200:
            print("ERROR: Failed to download HRK")
            return False

        hrk = res.content

        # check root cert fingerprint
        if 'f5a46663059fdb4cdd06d097ed21782142923bb3430b3b938f23d54292094e3a' != digest(hrk).hex():
            print("Error: Failed to verify Hygon Rook Key certificate")

        # check hrk cert info
        if False == self.__verify_hygon_cert_info(hrk, 0x03, 0, hrk[0x04:0x14]):
            print("ERROR: failed to verify HRK info")
            return False

        # verify hrk cert signature (self-signed)
        hrk_id_len = int.from_bytes(hrk[0xd4:0xd6], 'little')
        if False == self.gm_helper.verify_sm2_sigature_with_id(hrk[0xd6:0xd6+hrk_id_len], hrk_id_len,
                                        hrk[0x44:0x64],
                                        hrk[0x8c:0xac], hrk[:0x240],
                                        hrk[0x240:0x260], hrk[0x288:0x2a8]):
            print("ERROR: Failed to verify self-signed HRK")
            return False

        # retrive hsk and cek
        res = requests.get('https://cert.hygon.cn/hsk_cek?snumber=%s' % self.chip_id, verify=False)
        if res.status_code != 200:
            print("ERROR: Failed to download HSK_CEK")
            return False

        hsk_cek = res.content
        hsk = hsk_cek[:0x340]
        cek = hsk_cek[0x340:0x2916]

        # verify hsk cert info
        if False == self.__verify_hygon_cert_info(hsk, 0x03, 0x13, hrk[0x04:0x14]):
            print("ERROR: failed to verify HSK info")
            return False

        # verify hsk cert signature (hrk-signed)
        hsk_id_len = int.from_bytes(hsk[0xd4:0xd6], 'little')
        if False == self.gm_helper.verify_sm2_sigature_with_id(hrk[0xd6:0xd6+hrk_id_len], hrk_id_len,
                                        hrk[0x44:0x64],
                                        hrk[0x8c:0xac], hsk[:0x240],
                                        hsk[0x240:0x260], hsk[0x288:0x2a8]):
            print("ERROR: Failed to verify HRK-signed HSK")
            return False

        # verify cek cert info
        if False == self.__verify_csv_cert_info(cek, 0x13, 0x04, 0x1004, hsk[0x04:0x14]):
            print("ERROR: Failed to verify CEK info")
            return False

        # verify cek cert signature (hsk-signed)
        cek_id_len = int.from_bytes(cek[0xa4:0xa6], 'little')
        if False == self.gm_helper.verify_sm2_sigature_with_id(hsk[0xd6:0xd6+hsk_id_len], hsk_id_len,
                                        hsk[0x44:0x64],
                                        hsk[0x8c:0xac], cek[:0x414],
                                        cek[0x41c:0x43c], cek[0x464:0x484]):
            print("ERROR: Failed to verify HSK-signed CEK")
            return False

        # verify pek cert info
        if False == self.__verify_csv_cert_info(self.pek, 0x1004, 0x04, 0x1002, self.pek[0x1a4:0x1b4]):
            print("ERROR: failed to verify PEK info")
            return False

        # verify pek cert signature (cek-signed)
        pek_id_len = int.from_bytes(self.pek[0xa4:0xa6], 'little')
        if False == self.gm_helper.verify_sm2_sigature_with_id(cek[0xa6:0xa6+cek_id_len], cek_id_len,
                                        cek[0x14:0x34],
                                        cek[0x5c:0x7c], self.pek[:0x414],
                                        self.pek[0x41c:0x43c], self.pek[0x464:0x484]):
            print("ERROR: Failed to verify CEK-signed PEK")
            return False

        return True

    def verify_signature(self):
        # verify sm3
        mnonce = self.real_report[0x80:0x90]
        verified_data = self.raw_report[0x150:0x9d4]

        mac = self.gm_helper.hmac_sm3(mnonce, verified_data)
        if mac != self.raw_report[0x9d4:0x9f4]:
            print("Error: failed to verify report's HMAC")
            return False

        # verify hygon cert chain
        if False == self.__veriy_cert_chain():
            print("Error: failed to verify vert chain")
            return False

        # verify attestation report with cek
        pek_user_id_len = int.from_bytes(self.pek[0xa4:0xa6], 'little')
        pek_user_id = self.pek[0xa6:0xa6 + pek_user_id_len]

        if False == self.gm_helper.verify_sm2_sigature_with_id(pek_user_id, pek_user_id_len,
                                            bytearray(self.pek[0x14:0x34]),
                                            bytearray(self.pek[0x5c:0x7c]), self.raw_report[0:0xb4],
                                            bytearray(self.real_report[0xc0:0xe0]),
                                            bytearray(self.real_report[0xc0+0x48:0xc0+0x68])):
            print('ERROR: Failed to verify attestation report signature')
            return False

        return True

    def parse_attestation_report(self):
        parsed_report = {}

        parsed_report['PUBKEY_DIGEST'] = self.real_report[0:0x20].hex()
        parsed_report['ID'] = self.real_report[0x20:0x30].hex()
        parsed_report['Version'] = self.real_report[0x30:0x40].hex()
        parsed_report['Userdata'] = self.real_report[0x40:0x80].hex()
        parsed_report['MNONCE'] = self.real_report[0x80:0x90].hex()
        parsed_report['DIGEST_HEX'] = self.real_report[0x90:0xb0].hex()
        parsed_report['CHIP_ID'] = self.chip_id

        policy = []
        raw_policy = int.from_bytes(self.real_report[0xb0:0xb4], 'little')
        for i in range(0, len(self.__policy)):
            if raw_policy & 2**i:
                policy.append(self.__policy[i])

        policy.append('HSK_VERSION-0x%x' % ((raw_policy >> 8) & 0xf))
        policy.append('CEK_VERSION-0x%x' % ((raw_policy >> 12) & 0xf))
        policy.append('API_MAJOR-0x%x' % ((raw_policy >> 16) & 0xff))
        policy.append('API_MINOR-0x%x' % ((raw_policy >> 32) & 0xff))

        policy_str = ''
        for data in policy:
            policy_str += data + ' || '
        parsed_report['POLICY'] = policy_str + 'API_MINOR-0x%x' % ((raw_policy >> 32) & 0xff)

        print("****Verified Attestation Report****")
        print(json.dumps(parsed_report, indent=4))
        return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Utility for Hygon China Secure Virtualization (CSV) remote attestation, " \
                                    "compatible with Hygon CSV Spec v1.6. This is solely for testing purposes and should " \
                                    "not be used for production. For more information please visit https://openanolis.cn/sig/Hygon-Arch",
                                    add_help=True)
    parser.add_argument("action", choices=['generate', 'verify'], help="generate or verify an attestation report for this VM")
    parser.add_argument("-r", "--report", help="the path to attestation report")
    parser.add_argument("-u", "--userdata", help="the userdata used to generate attestation report")

    args = parser.parse_args()
    if args.action == "generate" and args.report:
        producer = AttestationReportProducor(args.userdata)
        path = producer.persistent_report(args.report)
        print("Attestation report is written to %s successfully!" % path)
    elif args.action == 'verify' and args.report:
        verifier = AttestationReportVerifier(args.report)
        if verifier.verify_signature():
            verifier.parse_attestation_report()
    else:
        parser.error("Invalid command")
