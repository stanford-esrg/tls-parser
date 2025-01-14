mod tls_rsa {
    use tls_parser::*;

    #[rustfmt::skip]
    static SERVER_RSA_PARAMS: &[u8] = &[
        0x00, 0x40, 0xa8, 0xc5, 0xcb, 0x9a, 0xaa, 0x6c,
        0xe5, 0xe9, 0x04, 0x7e, 0xe6, 0x01, 0x84, 0xa4,
        0x81, 0x7c, 0xed, 0x86, 0xda, 0x37, 0x9f, 0x6d,
        0xbf, 0x00, 0xf6, 0x44, 0xe5, 0xc2, 0xd4, 0x10,
        0x5d, 0x90, 0xf3, 0x7d, 0x3f, 0x17, 0x81, 0xb0,
        0xc5, 0x2f, 0xa6, 0x0c, 0xf9, 0x76, 0x7d, 0xc4,
        0x32, 0xc5, 0x66, 0x29, 0xd4, 0x5f, 0x62, 0x44,
        0xc6, 0xf8, 0x33, 0x96, 0x27, 0x9d, 0x44, 0xc9,
        0x37, 0x89, 0x00, 0x03, 0x01, 0x00, 0x01, 0x02,
        0x01, 0x00, 0x80, 0x60, 0x89, 0x48, 0x3a, 0xea,
        0xcf, 0xee, 0x59, 0xd1, 0x9a, 0x1d, 0x01, 0x85,
        0x8b, 0x17, 0x32, 0x19, 0x3d, 0xcd, 0x66, 0xfe,
        0x63, 0xb7, 0xb6, 0x73, 0xce, 0x17, 0x29, 0x6e,
        0x19, 0x5b, 0x6e, 0x07, 0x8f, 0x2c, 0x69, 0x9d,
        0xde, 0x20, 0x29, 0x1a, 0xcb, 0xb8, 0x58, 0xcb,
        0xe7, 0x0e, 0xf7, 0xc7, 0xbc, 0x7b, 0x98, 0xc5,
        0x3b, 0x03, 0xae, 0x32, 0xfe, 0xe9, 0xb3, 0x04,
        0x61, 0x0f, 0x76, 0x78, 0xec, 0x04, 0xe3, 0x03,
        0x15, 0xf3, 0xd1, 0xa8, 0xca, 0x45, 0xbf, 0x64,
        0xa4, 0xdc, 0xd3, 0x3e, 0xfd, 0xa6, 0x77, 0x03,
        0x87, 0xcf, 0x8a, 0xe8, 0x13, 0xc2, 0xcc, 0x6b,
        0xe5, 0xa0, 0x52, 0x88, 0xf5, 0xd3, 0x55, 0xe0,
        0x7f, 0xf7, 0x62, 0x9a, 0x86, 0x2b, 0xad, 0x2a,
        0x1e, 0xf0, 0x4a, 0x7b, 0x85, 0x9a, 0x09, 0xf9,
        0x30, 0x35, 0x54, 0x4c, 0x8a, 0x41, 0x14, 0x1a,
        0xc9, 0x51, 0x23
    ];

    #[test]
    fn test_tls_server_rsa_params() {
        let bytes = SERVER_RSA_PARAMS;
        let modulus = &bytes[2..66];
        let exponent = &bytes[68..71];
        let expected1 = ServerRSAParams { modulus, exponent };
        let expected2 = &bytes[71..];
        let res = parse_server_rsa_params(bytes);
        assert_eq!(res, Ok((expected2, expected1)));
    }

    #[rustfmt::skip]
    static CLIENT_RSA_PARAMS: &[u8] = &[
        0x00, 0x80, 0xa8, 0xd7, 0x1c, 0xa4, 0x28, 0x82,
        0xbe, 0x84, 0xa3, 0x8c, 0xaf, 0xb2, 0x73, 0x0a,
        0xf3, 0x0b, 0x11, 0x08, 0xb4, 0x59, 0x5d, 0x19,
        0x0c, 0xf6, 0xb2, 0xbe, 0x10, 0x8c, 0x27, 0x34,
        0x16, 0x5c, 0x73, 0xf1, 0xf2, 0x2b, 0x0f, 0xf4,
        0x3a, 0x5d, 0x6e, 0x05, 0x45, 0xb3, 0xd5, 0xe6,
        0xd7, 0x2c, 0x51, 0xae, 0x99, 0xa9, 0xf9, 0x76,
        0x26, 0x20, 0x20, 0x8a, 0xcb, 0x98, 0xd9, 0x66,
        0x38, 0xdb, 0x02, 0x41, 0x95, 0x30, 0x41, 0xe2,
        0x6a, 0xd2, 0x8f, 0x1d, 0x99, 0xef, 0xf9, 0xdb,
        0xe7, 0xad, 0x5a, 0xa5, 0x57, 0x43, 0x01, 0x49,
        0xc6, 0x9b, 0x43, 0xf7, 0xec, 0xa5, 0xd0, 0x16,
        0x21, 0x1b, 0x9c, 0xc4, 0x9e, 0xab, 0xc3, 0xd2,
        0x49, 0xdd, 0x7b, 0x0f, 0x64, 0x53, 0x66, 0x7d,
        0x84, 0x97, 0xb2, 0x73, 0xe9, 0x43, 0xb4, 0x71,
        0x23, 0x5f, 0xca, 0xc4, 0xdc, 0xd2, 0x8c, 0xdf,
        0x7e, 0x87
    ];

    #[test]
    fn test_tls_client_rsa_params() {
        let empty = &b""[..];
        let bytes = CLIENT_RSA_PARAMS;
        let encrypted_pms = &bytes[2..];
        let expected1 = EncryptedPreMasterSecret {
            data: encrypted_pms,
        };
        let res = parse_client_rsa_params(bytes);
        assert_eq!(res, Ok((empty, expected1)));
    }
}
