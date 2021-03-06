#include "test/test-rsa.h"

static rsa_test_params_t rsa_test_params1;
static rsa_test_params_t rsa_test_params2;

static unsigned char rsa_pkcs1v15_in_decrypted_buffer1[RSA_PKCS1V15_DECRYPTED_DATA_LENGTH];
static unsigned char rsa_pkcs1v15_in_decrypted_buffer2[RSA_PKCS1V15_DECRYPTED_DATA_LENGTH];
static unsigned char rsa_pkcs1v15_in_encrypted_buffer1[RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH];
static unsigned char rsa_pkcs1v15_in_encrypted_buffer2[RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH];
static unsigned char rsa_oaep_in_decrypted_buffer1[RSA_OAEP_DECRYPTED_DATA_LENGTH];
static unsigned char rsa_oaep_in_decrypted_buffer2[RSA_OAEP_DECRYPTED_DATA_LENGTH];
static unsigned char rsa_oaep_in_encrypted_buffer1[RSA_OAEP_ENCRYPTED_DATA_LENGTH];
static unsigned char rsa_oaep_in_encrypted_buffer2[RSA_OAEP_ENCRYPTED_DATA_LENGTH];

rsa_test_params_t * rsa_tests = &rsa_test_params1;

unsigned char rsa_out_buffer[RSA_LENGTH];

unsigned char rsa_private_key[RSA_PRIVATE_KEY_LENGTH] = {
	0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02,
	0x82, 0x01, 0x01, 0x00, 0xc8, 0x40, 0x6f, 0xc7,
	0xd0, 0xc9, 0xfb, 0xd2, 0x5c, 0xf3, 0xc5, 0xbc,
	0x77, 0x0e, 0x68, 0x5a, 0x87, 0x4a, 0xb9, 0x57,
	0x08, 0xd4, 0x6b, 0x3e, 0x9a, 0x89, 0x8a, 0x9f,
	0xdd, 0xad, 0x16, 0xa8, 0xa3, 0x82, 0x42, 0x22,
	0x5b, 0x69, 0x77, 0x28, 0xba, 0x15, 0x2b, 0xb3,
	0xf3, 0x24, 0xea, 0xe4, 0x86, 0x34, 0x73, 0xc1,
	0xe5, 0x2b, 0x0b, 0xdb, 0xcd, 0x54, 0x35, 0x55,
	0xda, 0xf1, 0xfd, 0x61, 0x3f, 0x1e, 0xe7, 0x1e,
	0xf1, 0xc0, 0x38, 0xcb, 0xfc, 0x0d, 0x9d, 0x65,
	0xba, 0x50, 0x1f, 0xb7, 0x8d, 0xb3, 0x59, 0x8c,
	0x48, 0xf2, 0x34, 0xf1, 0x46, 0x86, 0xab, 0xf2,
	0xc0, 0xdd, 0x1c, 0x6d, 0xbe, 0xf9, 0x8f, 0x79,
	0xa8, 0x6f, 0x02, 0x25, 0x07, 0xba, 0xc0, 0x91,
	0x27, 0x46, 0xfb, 0xc8, 0xe8, 0x78, 0xc0, 0xb4,
	0x91, 0xb6, 0xd6, 0x5d, 0xbe, 0x74, 0x00, 0x60,
	0x73, 0xe9, 0x0e, 0x10, 0x60, 0x48, 0x82, 0xbf,
	0x50, 0x58, 0xc4, 0x6f, 0xf0, 0x4e, 0xcf, 0x92,
	0x43, 0x36, 0x75, 0xe5, 0x79, 0xb9, 0x78, 0x81,
	0xbc, 0xb6, 0xf5, 0x74, 0xfe, 0x0f, 0x3f, 0xd4,
	0x88, 0xfb, 0xe6, 0x4f, 0xd8, 0x8a, 0x60, 0xc9,
	0x25, 0xed, 0xa1, 0xef, 0x4a, 0x57, 0x81, 0xb1,
	0xce, 0xaf, 0x3d, 0xcf, 0x2a, 0x44, 0x51, 0x76,
	0x16, 0x54, 0x3d, 0x4b, 0x77, 0x09, 0x39, 0x6c,
	0x85, 0xc5, 0x0c, 0x59, 0x49, 0x12, 0xba, 0x3f,
	0x98, 0x1f, 0x29, 0x16, 0xc6, 0xed, 0x08, 0x09,
	0xa9, 0xdc, 0xe4, 0x92, 0x70, 0x71, 0x57, 0x1c,
	0xcb, 0xf2, 0xfa, 0x03, 0x84, 0xf0, 0xd8, 0x27,
	0xbc, 0xa5, 0x0a, 0x95, 0x21, 0xbc, 0x87, 0x61,
	0x9a, 0xfd, 0x78, 0xab, 0xe3, 0x2f, 0xef, 0x16,
	0x86, 0x5b, 0xe7, 0x8e, 0x48, 0xef, 0x3c, 0xa1,
	0x6e, 0xd6, 0xe7, 0xda, 0x4c, 0x69, 0x5c, 0x4f,
	0x7a, 0x20, 0x58, 0x1d, 0x02, 0x03, 0x01, 0x00,
	0x01, 0x02, 0x82, 0x01, 0x00, 0x78, 0xd8, 0xda,
	0x1c, 0x5d, 0xd5, 0xe7, 0x10, 0x96, 0x63, 0xce,
	0x8a, 0xe3, 0xd6, 0x60, 0x07, 0x71, 0xea, 0x18,
	0x5b, 0x7b, 0xca, 0xa5, 0x45, 0xcc, 0x81, 0x00,
	0x95, 0x65, 0x73, 0xd5, 0x5e, 0xc3, 0xfe, 0x11,
	0xe7, 0x25, 0xff, 0x49, 0x97, 0xdc, 0x64, 0x76,
	0x51, 0x4c, 0x84, 0x94, 0xf4, 0x80, 0x41, 0x1b,
	0x32, 0x82, 0x18, 0x2e, 0x39, 0xe1, 0x79, 0xd6,
	0x0e, 0x0f, 0xe9, 0x45, 0x9d, 0xf0, 0x37, 0xb8,
	0x06, 0xa6, 0xa1, 0xf8, 0x24, 0xb1, 0xe1, 0x8d,
	0x81, 0x1c, 0xa4, 0xc9, 0xdf, 0x3d, 0xb6, 0x64,
	0x6e, 0x12, 0x7f, 0x88, 0x8f, 0xaa, 0x9e, 0x0f,
	0x1a, 0x9a, 0x65, 0x55, 0x88, 0xad, 0x5d, 0x71,
	0xc6, 0x5b, 0x6d, 0x52, 0x80, 0x02, 0x60, 0x23,
	0x61, 0xf5, 0xb0, 0x12, 0xb6, 0xb6, 0x04, 0x59,
	0x57, 0x1f, 0x30, 0x95, 0xc1, 0x50, 0xf4, 0x34,
	0x5e, 0x00, 0xd5, 0x3e, 0x54, 0x76, 0x5e, 0xd4,
	0x26, 0xf8, 0xa7, 0x93, 0xf8, 0xe9, 0x67, 0xcc,
	0xf9, 0x04, 0x8e, 0xcb, 0x3f, 0x5e, 0xde, 0x89,
	0xc5, 0x9b, 0x80, 0x88, 0xfc, 0xef, 0xc1, 0x30,
	0xc4, 0x69, 0xb4, 0xde, 0xfc, 0x2c, 0x29, 0x18,
	0x89, 0x8e, 0xca, 0x93, 0xfd, 0x4a, 0x2c, 0x2e,
	0x75, 0x7f, 0x61, 0xd6, 0xcb, 0xd0, 0x8a, 0xfe,
	0x79, 0xf6, 0x47, 0x47, 0x9a, 0x6d, 0xb7, 0x27,
	0xf0, 0x75, 0x9e, 0x26, 0xd3, 0xd0, 0x3e, 0x54,
	0x3c, 0x19, 0x94, 0xa7, 0x9a, 0x79, 0xb8, 0x8e,
	0x6f, 0xa6, 0x2a, 0xba, 0x84, 0x89, 0x04, 0xc3,
	0x92, 0x16, 0xd1, 0x21, 0x5b, 0x0b, 0x59, 0x00,
	0xe7, 0x98, 0x63, 0x21, 0x85, 0x36, 0x88, 0x9b,
	0x7d, 0x8f, 0x9b, 0x41, 0x20, 0x52, 0x79, 0x2d,
	0x33, 0xb6, 0x85, 0xd1, 0xf4, 0x2e, 0x86, 0x88,
	0x60, 0xa7, 0xda, 0xa1, 0x2b, 0x2f, 0x82, 0xe1,
	0x3e, 0xba, 0x49, 0x31, 0xc9, 0x02, 0x81, 0x81,
	0x00, 0xe3, 0x51, 0xb6, 0x11, 0xb7, 0x61, 0x34,
	0x60, 0x73, 0xe1, 0xa0, 0x92, 0x25, 0x96, 0x36,
	0x79, 0x89, 0xbc, 0x22, 0x28, 0xcb, 0xcd, 0x2f,
	0x51, 0x15, 0xa4, 0x44, 0xb8, 0x2f, 0xf4, 0xea,
	0x07, 0x5f, 0xf0, 0x54, 0x7e, 0x72, 0x5f, 0xe9,
	0xe1, 0xec, 0xa2, 0xc9, 0x34, 0x12, 0x30, 0xa7,
	0xe1, 0xd0, 0x63, 0xbe, 0x64, 0xcc, 0x97, 0x98,
	0xdc, 0xff, 0xbe, 0xd7, 0x24, 0xab, 0x7c, 0x27,
	0x3d, 0x4f, 0x76, 0x46, 0x10, 0xb2, 0x29, 0xc5,
	0x6e, 0xbe, 0x27, 0x40, 0xf0, 0xfe, 0x33, 0xbe,
	0x84, 0x98, 0xe0, 0x5a, 0x6c, 0x17, 0xbf, 0xa1,
	0x1d, 0x07, 0x52, 0xb0, 0x28, 0x3c, 0xa6, 0x51,
	0x39, 0xc3, 0xb7, 0xb5, 0x6b, 0xcf, 0x8a, 0xa1,
	0x99, 0x94, 0x4d, 0xe1, 0x76, 0x17, 0x09, 0x18,
	0xe8, 0x5e, 0x5f, 0xfa, 0x76, 0x18, 0x70, 0x77,
	0x6c, 0x04, 0x9c, 0x80, 0x48, 0x37, 0x7c, 0xfa,
	0x17, 0x02, 0x81, 0x81, 0x00, 0xe1, 0x84, 0x75,
	0xd3, 0xbe, 0x3b, 0xe6, 0x11, 0x71, 0xe2, 0x56,
	0xd4, 0x31, 0xb8, 0x04, 0x66, 0xc2, 0x29, 0xa2,
	0x14, 0x16, 0x81, 0xa2, 0xd7, 0x47, 0x20, 0x9a,
	0xd6, 0x2a, 0x98, 0x8e, 0x01, 0x61, 0x12, 0x41,
	0xb6, 0xd7, 0x34, 0x7a, 0xc8, 0x07, 0x34, 0xe4,
	0x2f, 0x4c, 0xb9, 0xe3, 0x72, 0xa8, 0x16, 0xed,
	0x36, 0xfb, 0x18, 0xd7, 0x87, 0xa2, 0xff, 0x6a,
	0xfe, 0xde, 0x37, 0x5d, 0x1a, 0x45, 0xb1, 0x16,
	0x0a, 0x2c, 0x35, 0xab, 0x6e, 0xc1, 0x12, 0xac,
	0x7d, 0xe3, 0x7a, 0xd9, 0xc1, 0xda, 0xaa, 0x36,
	0xdc, 0xc8, 0x03, 0x30, 0x39, 0x59, 0xe6, 0x85,
	0x4e, 0x6b, 0xd2, 0x2d, 0xbf, 0xb8, 0xb4, 0x45,
	0xb1, 0x6b, 0xf4, 0xcf, 0x41, 0x4d, 0xab, 0x5c,
	0x29, 0x81, 0x4b, 0x87, 0x57, 0xf1, 0x0a, 0x6e,
	0x2d, 0x40, 0x80, 0x31, 0xc3, 0x1b, 0xdc, 0xc0,
	0x78, 0x3a, 0x1b, 0x83, 0xeb, 0x02, 0x81, 0x80,
	0x78, 0x37, 0x87, 0x65, 0x39, 0x28, 0xf4, 0x0d,
	0x2a, 0x5b, 0xa1, 0x92, 0x88, 0xc4, 0x37, 0x0c,
	0xf1, 0x95, 0x88, 0x2f, 0x31, 0x10, 0xd3, 0x3c,
	0x3b, 0x88, 0xc3, 0x3a, 0xf1, 0x49, 0xc1, 0xd6,
	0xa2, 0x9b, 0x33, 0xe4, 0x27, 0x52, 0xa8, 0x1a,
	0xee, 0x0d, 0x6d, 0x00, 0xd7, 0xb9, 0xd9, 0x9f,
	0x27, 0x99, 0x08, 0x60, 0xc0, 0x7e, 0x4f, 0xbe,
	0x58, 0x96, 0x31, 0xab, 0x57, 0xf1, 0x71, 0xc3,
	0x0f, 0xda, 0x09, 0xd5, 0xdc, 0x93, 0x10, 0xb1,
	0xaf, 0x68, 0x8d, 0x04, 0xa6, 0x3a, 0xf1, 0x3f,
	0xa8, 0xa5, 0xc5, 0xcc, 0x32, 0x87, 0x0a, 0x8a,
	0x92, 0x8b, 0xdd, 0x53, 0x7a, 0x37, 0xae, 0xef,
	0x30, 0x9d, 0x60, 0x19, 0xa3, 0x09, 0xba, 0xca,
	0xc0, 0xce, 0xab, 0x34, 0xcb, 0x9b, 0xe9, 0x0b,
	0x42, 0x95, 0xd9, 0x9c, 0x48, 0xf2, 0x79, 0x85,
	0xab, 0xae, 0xa4, 0x7d, 0x0c, 0xb3, 0x50, 0x83,
	0x02, 0x81, 0x80, 0x35, 0xc9, 0x91, 0x0c, 0xca,
	0xaf, 0xa0, 0xa5, 0x02, 0x83, 0x98, 0x70, 0x0d,
	0xd7, 0xb4, 0xfd, 0x09, 0x4c, 0x42, 0xc3, 0x05,
	0xc7, 0x2f, 0x9e, 0xa6, 0xf1, 0x48, 0xdc, 0xd1,
	0xd6, 0x06, 0xf0, 0x9f, 0x45, 0x6a, 0x75, 0x00,
	0x89, 0x1c, 0xcb, 0xbe, 0xa4, 0x47, 0xd4, 0x5c,
	0x39, 0x6d, 0xdd, 0x37, 0xe8, 0x17, 0xf5, 0xe8,
	0x17, 0xb9, 0xb8, 0x39, 0x11, 0x30, 0x64, 0xcf,
	0x7d, 0x66, 0xf0, 0x50, 0x34, 0xf7, 0x6b, 0xbf,
	0xb5, 0xa1, 0x48, 0xce, 0x35, 0xf4, 0xfc, 0x25,
	0x98, 0x74, 0x7d, 0x7e, 0xf8, 0xe0, 0x12, 0xf2,
	0x85, 0x88, 0x27, 0xf5, 0xa0, 0x3c, 0xa5, 0x42,
	0xa4, 0x23, 0x93, 0x39, 0xab, 0x8d, 0x7f, 0xce,
	0x9e, 0xda, 0x1b, 0xda, 0x39, 0x87, 0xc6, 0xc2,
	0x76, 0xd0, 0x36, 0x12, 0x60, 0x89, 0x7c, 0xb3,
	0x88, 0x9f, 0xd5, 0xc8, 0x3c, 0x73, 0x8f, 0x79,
	0x54, 0x7c, 0xb7, 0x02, 0x81, 0x80, 0x20, 0x31,
	0x41, 0x4c, 0xa4, 0xc9, 0x99, 0xd1, 0x0c, 0x83,
	0x2b, 0x94, 0x30, 0x1c, 0x25, 0x92, 0x84, 0x2c,
	0x16, 0x0e, 0xcf, 0x2b, 0x3b, 0x7b, 0x92, 0x2b,
	0x5d, 0xae, 0x46, 0x82, 0xf1, 0x7f, 0xc1, 0x42,
	0x1b, 0x96, 0x12, 0x01, 0x1d, 0x62, 0x29, 0xe5,
	0x8d, 0x4c, 0xa8, 0xf4, 0x47, 0x02, 0x9a, 0x92,
	0x65, 0x27, 0xbd, 0x49, 0x12, 0xd2, 0xc6, 0xcc,
	0xc7, 0x2b, 0x18, 0x02, 0x90, 0x4a, 0xd6, 0x65,
	0x6f, 0x2a, 0x3c, 0x40, 0x68, 0xf5, 0x36, 0x70,
	0xd4, 0x52, 0x82, 0xae, 0xa8, 0xa2, 0x38, 0xc0,
	0x00, 0x13, 0x5f, 0x15, 0x45, 0x1a, 0x95, 0x17,
	0xc1, 0x62, 0x9e, 0xc8, 0xe3, 0xe2, 0xc4, 0xf7,
	0xbf, 0xaa, 0xef, 0xfb, 0x15, 0xde, 0xa8, 0xa9,
	0x64, 0x3e, 0x0e, 0x5a, 0xa0, 0x12, 0x7d, 0x0d,
	0x5b, 0xb1, 0xef, 0xf3, 0xaf, 0xed, 0x8f, 0x5b,
	0xd8, 0xb3, 0xbc, 0xa1, 0x35, 0xd1
};

unsigned char rsa_public_key[RSA_PUBLIC_KEY_LENGTH] = {
	0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
	0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xc8, 0x40, 0x6f, 0xc7, 0xd0, 0xc9, 0xfb,
	0xd2, 0x5c, 0xf3, 0xc5, 0xbc, 0x77, 0x0e, 0x68,
	0x5a, 0x87, 0x4a, 0xb9, 0x57, 0x08, 0xd4, 0x6b,
	0x3e, 0x9a, 0x89, 0x8a, 0x9f, 0xdd, 0xad, 0x16,
	0xa8, 0xa3, 0x82, 0x42, 0x22, 0x5b, 0x69, 0x77,
	0x28, 0xba, 0x15, 0x2b, 0xb3, 0xf3, 0x24, 0xea,
	0xe4, 0x86, 0x34, 0x73, 0xc1, 0xe5, 0x2b, 0x0b,
	0xdb, 0xcd, 0x54, 0x35, 0x55, 0xda, 0xf1, 0xfd,
	0x61, 0x3f, 0x1e, 0xe7, 0x1e, 0xf1, 0xc0, 0x38,
	0xcb, 0xfc, 0x0d, 0x9d, 0x65, 0xba, 0x50, 0x1f,
	0xb7, 0x8d, 0xb3, 0x59, 0x8c, 0x48, 0xf2, 0x34,
	0xf1, 0x46, 0x86, 0xab, 0xf2, 0xc0, 0xdd, 0x1c,
	0x6d, 0xbe, 0xf9, 0x8f, 0x79, 0xa8, 0x6f, 0x02,
	0x25, 0x07, 0xba, 0xc0, 0x91, 0x27, 0x46, 0xfb,
	0xc8, 0xe8, 0x78, 0xc0, 0xb4, 0x91, 0xb6, 0xd6,
	0x5d, 0xbe, 0x74, 0x00, 0x60, 0x73, 0xe9, 0x0e,
	0x10, 0x60, 0x48, 0x82, 0xbf, 0x50, 0x58, 0xc4,
	0x6f, 0xf0, 0x4e, 0xcf, 0x92, 0x43, 0x36, 0x75,
	0xe5, 0x79, 0xb9, 0x78, 0x81, 0xbc, 0xb6, 0xf5,
	0x74, 0xfe, 0x0f, 0x3f, 0xd4, 0x88, 0xfb, 0xe6,
	0x4f, 0xd8, 0x8a, 0x60, 0xc9, 0x25, 0xed, 0xa1,
	0xef, 0x4a, 0x57, 0x81, 0xb1, 0xce, 0xaf, 0x3d,
	0xcf, 0x2a, 0x44, 0x51, 0x76, 0x16, 0x54, 0x3d,
	0x4b, 0x77, 0x09, 0x39, 0x6c, 0x85, 0xc5, 0x0c,
	0x59, 0x49, 0x12, 0xba, 0x3f, 0x98, 0x1f, 0x29,
	0x16, 0xc6, 0xed, 0x08, 0x09, 0xa9, 0xdc, 0xe4,
	0x92, 0x70, 0x71, 0x57, 0x1c, 0xcb, 0xf2, 0xfa,
	0x03, 0x84, 0xf0, 0xd8, 0x27, 0xbc, 0xa5, 0x0a,
	0x95, 0x21, 0xbc, 0x87, 0x61, 0x9a, 0xfd, 0x78,
	0xab, 0xe3, 0x2f, 0xef, 0x16, 0x86, 0x5b, 0xe7,
	0x8e, 0x48, 0xef, 0x3c, 0xa1, 0x6e, 0xd6, 0xe7,
	0xda, 0x4c, 0x69, 0x5c, 0x4f, 0x7a, 0x20, 0x58,
	0x1d, 0x02, 0x03, 0x01, 0x00, 0x01
};

static rsa_test_params_t rsa_test_params1 = {
	&rsa_test_params2,
	rsa_pkcs1v15_in_decrypted_buffer1,
	rsa_pkcs1v15_in_encrypted_buffer1,
	rsa_oaep_in_decrypted_buffer1,
	rsa_oaep_in_encrypted_buffer1
};

static rsa_test_params_t rsa_test_params2 = {
	&rsa_test_params1,
	rsa_pkcs1v15_in_decrypted_buffer2,
	rsa_pkcs1v15_in_encrypted_buffer2,
	rsa_oaep_in_decrypted_buffer2,
	rsa_oaep_in_encrypted_buffer2
};

static unsigned char rsa_pkcs1v15_in_decrypted_buffer1[RSA_PKCS1V15_DECRYPTED_DATA_LENGTH] = {
	0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae,
	0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb, 0xe9, 0xeb,
	0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99,
	0x24, 0x5e, 0x0d, 0x1c, 0x06, 0xb7, 0x47, 0xde,
	0xb3, 0x12, 0x4d, 0xc8, 0x43, 0xbb, 0x8b, 0xa6,
	0x1f, 0x03, 0x5a, 0x7d, 0x09, 0x38, 0x25, 0x1f,
	0x5d, 0xd4, 0xcb, 0xfc, 0x96, 0xf5, 0x45, 0x3b,
	0x13, 0x0d, 0x89, 0x0a, 0x1c, 0xdb, 0xae, 0x32,
	0x20, 0x9a, 0x50, 0xee, 0x40, 0x78, 0x36, 0xfd,
	0x12, 0x49, 0x32, 0xf6, 0x9e, 0x7d, 0x49, 0xdc,
	0xad, 0x4f, 0x14, 0xf2, 0x44, 0x40, 0x66, 0xd0,
	0x6b, 0xc4, 0x30, 0xb7, 0x32, 0x3b, 0xa1, 0x22,
	0xf6, 0x22, 0x91, 0x9d, 0xe1, 0x8b, 0x1f, 0xda,
	0xb0, 0xca, 0x99, 0x02, 0xb9, 0x72, 0x9d, 0x49,
	0x2c, 0x80, 0x7e, 0xc5, 0x99, 0xd5, 0xe9, 0x80,
	0xb2, 0xea, 0xc9, 0xcc, 0x53, 0xbf, 0x67, 0xd6,
	0xbf, 0x14, 0xd6, 0x7e, 0x2d, 0xdc, 0x8e, 0x66,
	0x83, 0xef, 0x57, 0x49, 0x61, 0xff, 0x69, 0x8f,
	0x61, 0xcd, 0xd1, 0x1e, 0x9d, 0x9c, 0x16, 0x72,
	0x72, 0xe6, 0x1d, 0xf0, 0x84, 0x4f, 0x4a, 0x77,
	0x02, 0xd7, 0xe8, 0x39, 0x2c, 0x53, 0xcb, 0xc9,
	0x12, 0x1e, 0x33, 0x74, 0x9e, 0x0c, 0xf4, 0xd5,
	0xd4, 0x9f, 0xd4, 0xa4, 0x59, 0x7e, 0x35, 0xcf,
	0x32, 0x22, 0xf4, 0xcc, 0xcf, 0xd3, 0x90, 0x2d,
	0x48, 0xd3, 0x8f, 0x75, 0xe6, 0xd9, 0x1d, 0x2a,
	0xe5, 0xc0, 0xf7, 0x2b, 0x78, 0x81, 0x87, 0x44,
	0x0e, 0x5f, 0x50, 0x00, 0xd4, 0x61, 0x8d, 0xbe,
	0x7b, 0x05, 0x15, 0x07, 0x3b, 0x33, 0x82, 0x1f,
	0x18, 0x70, 0x92, 0xda, 0x64, 0x54, 0xce, 0xb1,
	0x85, 0x3e, 0x69, 0x15, 0xf8, 0x46, 0x6a, 0x04,
	0x96, 0x73, 0x0e, 0xd9, 0x16
};

static unsigned char rsa_pkcs1v15_in_decrypted_buffer2[RSA_PKCS1V15_DECRYPTED_DATA_LENGTH] = {
	0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae,
	0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb, 0xe9, 0xeb,
	0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99,
	0x24, 0x5e, 0x0d, 0x1c, 0x06, 0xb7, 0x47, 0xde,
	0xb3, 0x12, 0x4d, 0xc8, 0x43, 0xbb, 0x8b, 0xa6,
	0x1f, 0x03, 0x5a, 0x7d, 0x09, 0x38, 0x25, 0x1f,
	0x5d, 0xd4, 0xcb, 0xfc, 0x96, 0xf5, 0x45, 0x3b,
	0x13, 0x0d, 0x89, 0x0a, 0x1c, 0xdb, 0xae, 0x32,
	0x20, 0x9a, 0x50, 0xee, 0x40, 0x78, 0x36, 0xfd,
	0x12, 0x49, 0x32, 0xf6, 0x9e, 0x7d, 0x49, 0xdc,
	0xad, 0x4f, 0x14, 0xf2, 0x44, 0x40, 0x66, 0xd0,
	0x6b, 0xc4, 0x30, 0xb7, 0x32, 0x3b, 0xa1, 0x22,
	0xf6, 0x22, 0x91, 0x9d, 0xe1, 0x8b, 0x1f, 0xda,
	0xb0, 0xca, 0x99, 0x02, 0xb9, 0x72, 0x9d, 0x49,
	0x2c, 0x80, 0x7e, 0xc5, 0x99, 0xd5, 0xe9, 0x80,
	0xb2, 0xea, 0xc9, 0xcc, 0x53, 0xbf, 0x67, 0xd6,
	0xbf, 0x14, 0xd6, 0x7e, 0x2d, 0xdc, 0x8e, 0x66,
	0x83, 0xef, 0x57, 0x49, 0x61, 0xff, 0x69, 0x8f,
	0x61, 0xcd, 0xd1, 0x1e, 0x9d, 0x9c, 0x16, 0x72,
	0x72, 0xe6, 0x1d, 0xf0, 0x84, 0x4f, 0x4a, 0x77,
	0x02, 0xd7, 0xe8, 0x39, 0x2c, 0x53, 0xcb, 0xc9,
	0x12, 0x1e, 0x33, 0x74, 0x9e, 0x0c, 0xf4, 0xd5,
	0xd4, 0x9f, 0xd4, 0xa4, 0x59, 0x7e, 0x35, 0xcf,
	0x32, 0x22, 0xf4, 0xcc, 0xcf, 0xd3, 0x90, 0x2d,
	0x48, 0xd3, 0x8f, 0x75, 0xe6, 0xd9, 0x1d, 0x2a,
	0xe5, 0xc0, 0xf7, 0x2b, 0x78, 0x81, 0x87, 0x44,
	0x0e, 0x5f, 0x50, 0x00, 0xd4, 0x61, 0x8d, 0xbe,
	0x7b, 0x05, 0x15, 0x07, 0x3b, 0x33, 0x82, 0x1f,
	0x18, 0x70, 0x92, 0xda, 0x64, 0x54, 0xce, 0xb1,
	0x85, 0x3e, 0x69, 0x15, 0xf8, 0x46, 0x6a, 0x04,
	0x96, 0x73, 0x0e, 0xd9, 0x16
};

static unsigned char rsa_pkcs1v15_in_encrypted_buffer1[RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH] = {
	0x38, 0x3e, 0xe8, 0xab, 0xa1, 0x15, 0x0a, 0xea,
	0x44, 0x5b, 0xd5, 0x5f, 0xfc, 0x38, 0xb4, 0x8f,
	0x71, 0x58, 0x62, 0x04, 0x06, 0x7e, 0xad, 0xe1,
	0x5d, 0xbd, 0x1d, 0x4d, 0x8f, 0xf3, 0x47, 0x24,
	0x5b, 0xf6, 0xe2, 0xc8, 0xfe, 0x65, 0xaf, 0x86,
	0x2d, 0x07, 0xe6, 0xee, 0x1d, 0x11, 0xc7, 0xd0,
	0xa3, 0x7f, 0x76, 0x59, 0xec, 0xdd, 0x22, 0x33,
	0xfd, 0x54, 0x03, 0x24, 0xe6, 0xd2, 0xd3, 0x2c,
	0x42, 0xbd, 0xec, 0xa6, 0x38, 0x5a, 0x7d, 0xdc,
	0xfd, 0xf6, 0x91, 0x83, 0xe3, 0xc4, 0x2b, 0x33,
	0xd7, 0x7a, 0x20, 0xb3, 0x0a, 0x81, 0x7a, 0x3a,
	0x57, 0xd4, 0x01, 0xc3, 0xb2, 0x21, 0xe2, 0xa8,
	0x4b, 0x04, 0x83, 0xf2, 0xe3, 0xb3, 0x4b, 0x99,
	0x3e, 0x56, 0xce, 0x29, 0xf4, 0xbd, 0xef, 0xf5,
	0x7d, 0x00, 0xa5, 0xf8, 0x31, 0x03, 0xca, 0xd9,
	0x61, 0xa3, 0x36, 0x95, 0xfe, 0xa0, 0xd9, 0xb7,
	0x62, 0x36, 0x24, 0x1f, 0xd3, 0x25, 0x79, 0xe7,
	0x0e, 0x48, 0x0f, 0x2d, 0xf7, 0xc4, 0x67, 0xc8,
	0x11, 0x3c, 0xb9, 0xc6, 0x00, 0x27, 0x00, 0x3f,
	0x45, 0xee, 0x1a, 0x6a, 0x69, 0x77, 0xee, 0x87,
	0xd4, 0x7f, 0xa1, 0x2e, 0x37, 0x8b, 0x61, 0xe0,
	0x31, 0xb1, 0x7b, 0x1d, 0x2f, 0x0d, 0x94, 0x00,
	0xba, 0xa6, 0x42, 0xcf, 0x16, 0x5f, 0x2c, 0x04,
	0x0c, 0xc3, 0xdb, 0x08, 0x08, 0xfb, 0x28, 0xe7,
	0x18, 0xbd, 0xbc, 0x8c, 0xd0, 0x5f, 0xfb, 0xfe,
	0x8d, 0xc6, 0x62, 0x3d, 0xf2, 0x88, 0x6a, 0x7b,
	0xa4, 0xdd, 0x94, 0x7c, 0x2c, 0x63, 0x81, 0xe3,
	0xbf, 0xe0, 0xe3, 0x9f, 0x72, 0x7e, 0x7f, 0xff,
	0x3e, 0x85, 0xb6, 0x4c, 0xe2, 0xbf, 0x3f, 0xc6,
	0x93, 0x3d, 0xa3, 0xdc, 0x14, 0x7c, 0xc0, 0x99,
	0x3f, 0xf1, 0x39, 0xae, 0xb2, 0xf8, 0x3c, 0x84,
	0xc3, 0xd2, 0x25, 0xed, 0xe5, 0x0b, 0x78, 0xc0
};

static unsigned char rsa_pkcs1v15_in_encrypted_buffer2[RSA_PKCS1V15_ENCRYPTED_DATA_LENGTH] = {
	0x34, 0x09, 0xe9, 0x32, 0x5f, 0x77, 0x87, 0x5b,
	0x9b, 0xf1, 0x84, 0xee, 0xc0, 0x67, 0x55, 0xd3,
	0x2d, 0xc4, 0x01, 0xef, 0xe6, 0x05, 0x54, 0x69,
	0xb5, 0x25, 0xa7, 0x03, 0x34, 0x94, 0x03, 0x79,
	0x01, 0x77, 0x5f, 0x8e, 0xd5, 0xaf, 0x6e, 0x11,
	0x3e, 0x23, 0x35, 0xfc, 0x10, 0xb4, 0xdc, 0xa5,
	0x32, 0xd8, 0x8a, 0x4b, 0x03, 0xd0, 0xa1, 0xaf,
	0x61, 0x8f, 0xcc, 0xb2, 0x08, 0x70, 0x98, 0x05,
	0x3c, 0xb9, 0x6b, 0xd8, 0xf1, 0xbf, 0x34, 0x71,
	0xbd, 0xb2, 0x05, 0xf8, 0x70, 0x58, 0xbb, 0x4d,
	0xf7, 0x93, 0x33, 0xdd, 0x14, 0x2c, 0xcf, 0x59,
	0x2d, 0xa2, 0x1e, 0x74, 0xbc, 0xff, 0xc5, 0x89,
	0xd4, 0xd0, 0xb9, 0xa4, 0xc7, 0xf1, 0x94, 0x2b,
	0xc1, 0xa6, 0xdd, 0xbb, 0xe7, 0x64, 0xee, 0x19,
	0xa2, 0x37, 0x31, 0x39, 0xa2, 0x67, 0x6b, 0x54,
	0x9e, 0x03, 0x67, 0xce, 0x6e, 0xde, 0x71, 0x01,
	0x79, 0x08, 0x0e, 0x17, 0x17, 0x97, 0xb6, 0xe8,
	0x82, 0x38, 0xd4, 0x56, 0x88, 0x12, 0x78, 0xc1,
	0xa9, 0x92, 0xcb, 0x53, 0x79, 0x66, 0xdb, 0xe5,
	0xcb, 0xd4, 0xa3, 0xb9, 0xbe, 0xf1, 0xb6, 0x3c,
	0xcb, 0x05, 0xb1, 0x7e, 0xf5, 0xcb, 0xc3, 0x9d,
	0x0a, 0xe8, 0x79, 0xa0, 0xc3, 0x8c, 0x82, 0x10,
	0x67, 0xe9, 0x50, 0x00, 0x38, 0x40, 0x6e, 0x7e,
	0xcf, 0x57, 0x15, 0x77, 0xaf, 0xf9, 0xac, 0x9d,
	0xc4, 0x23, 0x1c, 0x40, 0x15, 0x29, 0x90, 0xb2,
	0xd8, 0xd2, 0x40, 0xb4, 0xa8, 0x27, 0x14, 0x02,
	0xed, 0xad, 0xea, 0x54, 0x88, 0xc0, 0x97, 0xa2,
	0xa1, 0x85, 0xe7, 0x61, 0xda, 0x36, 0x4f, 0x59,
	0x2d, 0x28, 0xd3, 0xba, 0x61, 0xa8, 0x16, 0xfb,
	0xfa, 0x8b, 0x1f, 0xbb, 0xa5, 0x36, 0xd8, 0x88,
	0xa6, 0x7b, 0x34, 0x84, 0x17, 0x01, 0x32, 0xb6,
	0x01, 0x94, 0x90, 0xea, 0x96, 0x37, 0x93, 0xe3
};

static unsigned char rsa_oaep_in_decrypted_buffer1[RSA_OAEP_DECRYPTED_DATA_LENGTH] = {
	0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae,
	0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb, 0xe9, 0xeb,
	0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99,
	0x24, 0x5e, 0x0d, 0x1c, 0x06, 0xb7, 0x47, 0xde,
	0xb3, 0x12, 0x4d, 0xc8, 0x43, 0xbb, 0x8b, 0xa6,
	0x1f, 0x03, 0x5a, 0x7d, 0x09, 0x38, 0x25, 0x1f,
	0x5d, 0xd4, 0xcb, 0xfc, 0x96, 0xf5, 0x45, 0x3b,
	0x13, 0x0d, 0x89, 0x0a, 0x1c, 0xdb, 0xae, 0x32,
	0x20, 0x9a, 0x50, 0xee, 0x40, 0x78, 0x36, 0xfd,
	0x12, 0x49, 0x32, 0xf6, 0x9e, 0x7d, 0x49, 0xdc,
	0xad, 0x4f, 0x14, 0xf2, 0x44, 0x40, 0x66, 0xd0,
	0x6b, 0xc4, 0x30, 0xb7, 0x32, 0x3b, 0xa1, 0x22,
	0xf6, 0x22, 0x91, 0x9d, 0xe1, 0x8b, 0x1f, 0xda,
	0xb0, 0xca, 0x99, 0x02, 0xb9, 0x72, 0x9d, 0x49,
	0x2c, 0x80, 0x7e, 0xc5, 0x99, 0xd5, 0xe9, 0x80,
	0xb2, 0xea, 0xc9, 0xcc, 0x53, 0xbf, 0x67, 0xd6,
	0xbf, 0x14, 0xd6, 0x7e, 0x2d, 0xdc, 0x8e, 0x66,
	0x83, 0xef, 0x57, 0x49, 0x61, 0xff, 0x69, 0x8f,
	0x61, 0xcd, 0xd1, 0x1e, 0x9d, 0x9c, 0x16, 0x72,
	0x72, 0xe6, 0x1d, 0xf0, 0x84, 0x4f, 0x4a, 0x77,
	0x02, 0xd7, 0xe8, 0x39, 0x2c, 0x53, 0xcb, 0xc9,
	0x12, 0x1e, 0x33, 0x74, 0x9e, 0x0c, 0xf4, 0xd5,
	0xd4, 0x9f, 0xd4, 0xa4, 0x59, 0x7e, 0x35, 0xcf,
	0x32, 0x22, 0xf4, 0xcc, 0xcf, 0xd3, 0x90, 0x2d,
	0x48, 0xd3, 0x8f, 0x75, 0xe6, 0xd9, 0x1d, 0x2a,
	0xe5, 0xc0, 0xf7, 0x2b, 0x78, 0x81, 0x87, 0x44,
	0x0e, 0x5f, 0x50, 0x00, 0xd4, 0x61
};

static unsigned char rsa_oaep_in_decrypted_buffer2[RSA_OAEP_DECRYPTED_DATA_LENGTH] = {
	0x29, 0x23, 0xbe, 0x84, 0xe1, 0x6c, 0xd6, 0xae,
	0x52, 0x90, 0x49, 0xf1, 0xf1, 0xbb, 0xe9, 0xeb,
	0xb3, 0xa6, 0xdb, 0x3c, 0x87, 0x0c, 0x3e, 0x99,
	0x24, 0x5e, 0x0d, 0x1c, 0x06, 0xb7, 0x47, 0xde,
	0xb3, 0x12, 0x4d, 0xc8, 0x43, 0xbb, 0x8b, 0xa6,
	0x1f, 0x03, 0x5a, 0x7d, 0x09, 0x38, 0x25, 0x1f,
	0x5d, 0xd4, 0xcb, 0xfc, 0x96, 0xf5, 0x45, 0x3b,
	0x13, 0x0d, 0x89, 0x0a, 0x1c, 0xdb, 0xae, 0x32,
	0x20, 0x9a, 0x50, 0xee, 0x40, 0x78, 0x36, 0xfd,
	0x12, 0x49, 0x32, 0xf6, 0x9e, 0x7d, 0x49, 0xdc,
	0xad, 0x4f, 0x14, 0xf2, 0x44, 0x40, 0x66, 0xd0,
	0x6b, 0xc4, 0x30, 0xb7, 0x32, 0x3b, 0xa1, 0x22,
	0xf6, 0x22, 0x91, 0x9d, 0xe1, 0x8b, 0x1f, 0xda,
	0xb0, 0xca, 0x99, 0x02, 0xb9, 0x72, 0x9d, 0x49,
	0x2c, 0x80, 0x7e, 0xc5, 0x99, 0xd5, 0xe9, 0x80,
	0xb2, 0xea, 0xc9, 0xcc, 0x53, 0xbf, 0x67, 0xd6,
	0xbf, 0x14, 0xd6, 0x7e, 0x2d, 0xdc, 0x8e, 0x66,
	0x83, 0xef, 0x57, 0x49, 0x61, 0xff, 0x69, 0x8f,
	0x61, 0xcd, 0xd1, 0x1e, 0x9d, 0x9c, 0x16, 0x72,
	0x72, 0xe6, 0x1d, 0xf0, 0x84, 0x4f, 0x4a, 0x77,
	0x02, 0xd7, 0xe8, 0x39, 0x2c, 0x53, 0xcb, 0xc9,
	0x12, 0x1e, 0x33, 0x74, 0x9e, 0x0c, 0xf4, 0xd5,
	0xd4, 0x9f, 0xd4, 0xa4, 0x59, 0x7e, 0x35, 0xcf,
	0x32, 0x22, 0xf4, 0xcc, 0xcf, 0xd3, 0x90, 0x2d,
	0x48, 0xd3, 0x8f, 0x75, 0xe6, 0xd9, 0x1d, 0x2a,
	0xe5, 0xc0, 0xf7, 0x2b, 0x78, 0x81, 0x87, 0x44,
	0x0e, 0x5f, 0x50, 0x00, 0xd4, 0x61
};

static unsigned char rsa_oaep_in_encrypted_buffer1[RSA_OAEP_ENCRYPTED_DATA_LENGTH] = {
	0x1a, 0xf2, 0x45, 0x92, 0x3b, 0xe0, 0x13, 0x87,
	0xd8, 0x57, 0x94, 0x8e, 0x6d, 0x12, 0xc8, 0x50,
	0xa2, 0xa0, 0x04, 0xd4, 0xf6, 0x48, 0x53, 0x73,
	0x9d, 0x6a, 0x22, 0x03, 0x68, 0x55, 0x76, 0x52,
	0xec, 0x07, 0x27, 0xa6, 0xf1, 0xf8, 0x9a, 0x33,
	0xec, 0xd3, 0x63, 0x6f, 0x09, 0xab, 0x10, 0x3f,
	0xd7, 0x4a, 0x16, 0x38, 0xe9, 0xf4, 0x66, 0x30,
	0x32, 0x4f, 0xfc, 0xa6, 0x70, 0xaa, 0x16, 0x52,
	0xdc, 0xb8, 0x9b, 0x3a, 0x19, 0x18, 0x46, 0x1b,
	0x4e, 0xf3, 0x7e, 0xb2, 0xf1, 0x30, 0xe1, 0x18,
	0xf4, 0x53, 0xed, 0x2b, 0x7d, 0x70, 0xed, 0xd7,
	0x6c, 0xb2, 0x88, 0x35, 0xc8, 0x43, 0x38, 0xcf,
	0x5e, 0xee, 0x56, 0x59, 0xb3, 0x9e, 0x5f, 0xd3,
	0x44, 0x68, 0x6a, 0x86, 0x45, 0x0b, 0xa2, 0xa1,
	0x39, 0x29, 0x30, 0xf0, 0xfb, 0xe8, 0x33, 0xd8,
	0xa9, 0xe1, 0x51, 0x0d, 0x86, 0x5c, 0x98, 0x7d,
	0x5d, 0x27, 0x69, 0x88, 0xfd, 0xa8, 0x2a, 0x1d,
	0x1b, 0x44, 0xe3, 0xbd, 0x12, 0x0a, 0xad, 0xe5,
	0xc4, 0x54, 0xcc, 0xd6, 0x92, 0xbb, 0x88, 0xb6,
	0xd4, 0x9f, 0xbe, 0x82, 0xc7, 0xab, 0xf0, 0xd6,
	0xfa, 0x0c, 0xab, 0xdb, 0xee, 0x35, 0xe1, 0xb6,
	0xb1, 0xee, 0x91, 0xd5, 0xda, 0x76, 0x75, 0x8e,
	0x2a, 0xd6, 0x26, 0x1c, 0x5f, 0xf8, 0xc5, 0x7f,
	0xc8, 0x9c, 0x79, 0xba, 0x19, 0xcc, 0x1c, 0xaa,
	0xa2, 0x1e, 0x3e, 0x56, 0xa3, 0x88, 0x2c, 0x37,
	0x47, 0xa0, 0x3f, 0x08, 0xea, 0x94, 0x91, 0x3e,
	0x62, 0x71, 0x45, 0x7b, 0xd2, 0xaa, 0xbb, 0xab,
	0x63, 0xe7, 0xbf, 0x48, 0x7b, 0xe1, 0x7e, 0xc7,
	0x81, 0x79, 0xe7, 0xee, 0x75, 0x69, 0x81, 0x50,
	0x8d, 0x6f, 0xe7, 0xf0, 0xd6, 0x11, 0xfd, 0x3a,
	0x0e, 0xf5, 0xe2, 0x42, 0xbf, 0xdb, 0xf9, 0x16,
	0xc7, 0xb4, 0xf5, 0xca, 0xe9, 0x0a, 0x17, 0xb1
};

static unsigned char rsa_oaep_in_encrypted_buffer2[RSA_OAEP_ENCRYPTED_DATA_LENGTH] = {
	0x4d, 0x51, 0x65, 0x2b, 0x4e, 0x5b, 0x65, 0x77,
	0x96, 0x0d, 0x0d, 0xd0, 0x98, 0xb4, 0x8c, 0x30,
	0xfb, 0x3a, 0x65, 0xf6, 0x23, 0x3a, 0xb0, 0xba,
	0x53, 0xcc, 0x42, 0xd8, 0xa3, 0x11, 0x7f, 0xe0,
	0x97, 0x0c, 0x98, 0x16, 0xff, 0xca, 0xa9, 0x06,
	0xb8, 0x47, 0x50, 0x66, 0x91, 0x33, 0x93, 0x7f,
	0x05, 0x00, 0xf0, 0x12, 0x54, 0xcf, 0xd4, 0x1d,
	0x35, 0x33, 0x7a, 0x59, 0x82, 0xd9, 0xfb, 0x6d,
	0x98, 0x85, 0xd6, 0xb7, 0x1c, 0x4d, 0xca, 0x0f,
	0x33, 0xf9, 0xda, 0xf8, 0xde, 0x65, 0x07, 0x67,
	0x38, 0x68, 0x5e, 0x6f, 0x6c, 0xb4, 0x56, 0xb8,
	0xdf, 0x7d, 0xda, 0xc0, 0xff, 0xdd, 0xd4, 0x90,
	0xd1, 0xec, 0x1b, 0x37, 0x26, 0x97, 0x6d, 0x63,
	0xf3, 0xfe, 0x05, 0x96, 0x4c, 0x1a, 0x14, 0x6e,
	0x0a, 0x2d, 0xdd, 0x54, 0x27, 0xdd, 0x6d, 0x1f,
	0x5e, 0x8e, 0xd1, 0x49, 0xd4, 0x35, 0xcb, 0x1c,
	0xdd, 0x0e, 0x9e, 0xba, 0x0a, 0xa6, 0x1e, 0xb5,
	0x8d, 0xc7, 0x9f, 0x30, 0xcb, 0xf4, 0x55, 0x25,
	0xa6, 0x8e, 0x8e, 0xce, 0xed, 0xf2, 0x75, 0x5b,
	0xb7, 0x8e, 0xb8, 0xf3, 0x7c, 0xb0, 0xaf, 0x41,
	0x69, 0xfb, 0x49, 0x11, 0xf3, 0x0c, 0x32, 0xf9,
	0x79, 0xbc, 0x9d, 0x10, 0x0e, 0xf8, 0x06, 0xe4,
	0x34, 0x45, 0xd3, 0x77, 0x68, 0x81, 0x4d, 0x28,
	0x5a, 0x2b, 0x37, 0x98, 0xdc, 0x88, 0x15, 0x7d,
	0x9e, 0xfc, 0x34, 0x7f, 0x66, 0xd5, 0x6b, 0xc8,
	0x34, 0x6e, 0xba, 0xd6, 0x6a, 0xf8, 0x55, 0xcd,
	0xc7, 0xe2, 0xc4, 0xd5, 0xca, 0x4d, 0xff, 0xc6,
	0x01, 0xd3, 0xbb, 0xe9, 0x3b, 0x17, 0x79, 0x2d,
	0x77, 0x68, 0x5b, 0x60, 0x7c, 0x62, 0x1e, 0xef,
	0x99, 0x30, 0x49, 0x6e, 0x25, 0x33, 0xab, 0x96,
	0x59, 0x07, 0x14, 0xf6, 0x56, 0x0e, 0xb0, 0xf1,
	0x69, 0xd1, 0x6c, 0xa8, 0x93, 0x97, 0xb7, 0x45
};
