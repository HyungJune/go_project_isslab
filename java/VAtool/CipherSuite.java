package VAtool;

import java.util.HashMap;

public class CipherSuite {

	HashMap<String, String> rc4Map;
	HashMap<String, String> slothMap;
	
	public CipherSuite() {
		rc4Map = new HashMap<String, String>();
		initRc4();
		
		
		
	}

	private void initSloth(){
		
	}
	
	private void initRc4(){
		rc4Map.put("018", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5");
		rc4Map.put("020", "TLS_KRB5_WITH_RC4_128_SHA");
		rc4Map.put("024", "TLS_KRB5_WITH_RC4_128_MD5");
		rc4Map.put("02b", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
		rc4Map.put("028", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA");
		rc4Map.put("08a", "TLS_PSK_WITH_RC4_128_SHA");
		rc4Map.put("08e", "TLS_DHE_PSK_WITH_RC4_128_SHA");
		rc4Map.put("c002", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
		rc4Map.put("c007", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
		rc4Map.put("c00c", "TLS_ECDH_RSA_WITH_RC4_128_SHA");
		rc4Map.put("c011", "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
		rc4Map.put("c016", "TLS_ECDH_anon_WITH_RC4_128_SHA");
		rc4Map.put("c033", "TLS_ECDHE_PSK_WITH_RC4_128_SHA");

		rc4Map.put("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "MD5");
		rc4Map.put("TLS_KRB5_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_KRB5_WITH_RC4_128_MD5", "MD5");
		rc4Map.put("TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "MD5");
		rc4Map.put("TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "SHA1");
		rc4Map.put("TLS_PSK_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_DHE_PSK_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_ECDH_RSA_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_ECDH_anon_WITH_RC4_128_SHA", "SHA1");
		rc4Map.put("TLS_ECDHE_PSK_WITH_RC4_128_SHA", "SHA1");
	}
	
	public static final byte[] TLS_NULL_WITH_NULL_NULL = { 0x00, 0x00 };
	public static final byte[] TLS_RSA_WITH_NULL_MD5 = { 0x00, 0x01 };
	public static final byte[] TLS_RSA_WITH_NULL_SHA = { 0x00, 0x02 };
	public static final byte[] TLS_RSA_EXPORT_WITH_RC4_40_MD5 = { 0x00, 0x03 };
	public static final byte[] TLS_RSA_WITH_RC4_128_MD5 = { 0x00, 0x04 };
	public static final byte[] TLS_RSA_WITH_RC4_128_SHA = { 0x00, 0x05 };
	public static final byte[] TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = { 0x00,
			0x06 };
	public static final byte[] TLS_RSA_WITH_IDEA_CBC_SHA = { 0x00, 0x07 };
	public static final byte[] TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00, 0x08 };
	public static final byte[] TLS_RSA_WITH_DES_CBC_SHA = { 0x00, 0x09 };
	public static final byte[] TLS_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0A };
	public static final byte[] TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00,
			0x0B };
	public static final byte[] TLS_DH_DSS_WITH_DES_CBC_SHA = { 0x00, 0x0C };
	public static final byte[] TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x0D };
	public static final byte[] TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00,
			0x0E };
	public static final byte[] TLS_DH_RSA_WITH_DES_CBC_SHA = { 0x00, 0x0F };
	public static final byte[] TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x10 };
	public static final byte[] TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = { 0x00,
			0x11 };
	public static final byte[] TLS_DHE_DSS_WITH_DES_CBC_SHA = { 0x00, 0x12 };
	public static final byte[] TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x13 };
	public static final byte[] TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = { 0x00,
			0x14 };
	public static final byte[] TLS_DHE_RSA_WITH_DES_CBC_SHA = { 0x00, 0x15 };
	public static final byte[] TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x16 };
	public static final byte[] TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = { 0x00,
			0x17 };
	public static final byte[] TLS_DH_anon_WITH_RC4_128_MD5 = { 0x00, 0x18 };
	public static final byte[] TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = { 0x00,
			0x19 };
	public static final byte[] TLS_DH_anon_WITH_DES_CBC_SHA = { 0x00, 0x1A };
	public static final byte[] TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x1B };
	public static final byte[] TLS_KRB5_WITH_DES_CBC_SHA = { 0x00, 0x1E };
	public static final byte[] TLS_KRB5_WITH_3DES_EDE_CBC_SHA = { 0x00, 0x1F };
	public static final byte[] TLS_KRB5_WITH_RC4_128_SHA = { 0x00, 0x20 };
	public static final byte[] TLS_KRB5_WITH_IDEA_CBC_SHA = { 0x00, 0x21 };
	public static final byte[] TLS_KRB5_WITH_DES_CBC_MD5 = { 0x00, 0x22 };
	public static final byte[] TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = { 0x00, 0x23 };
	public static final byte[] TLS_KRB5_WITH_RC4_128_MD5 = { 0x00, 0x24 };
	public static final byte[] TLS_KRB5_WITH_IDEA_CBC_MD5 = { 0x00, 0x25 };
	public static final byte[] TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = { 0x00,
			0x26 };
	public static final byte[] TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = { 0x00,
			0x27 };
	public static final byte[] TLS_KRB5_EXPORT_WITH_RC4_40_SHA = { 0x00, 0x28 };
	public static final byte[] TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = { 0x00,
			0x29 };
	public static final byte[] TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = { 0x00,
			0x2A };
	public static final byte[] TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = { 0x00, 0x2B };
	public static final byte[] TLS_PSK_WITH_NULL_SHA = { 0x00, 0x2C };
	public static final byte[] TLS_DHE_PSK_WITH_NULL_SHA = { 0x00, 0x2D };
	public static final byte[] TLS_RSA_PSK_WITH_NULL_SHA = { 0x00, 0x2E };
	public static final byte[] TLS_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x2F };
	public static final byte[] TLS_DH_DSS_WITH_AES_128_CBC_SHA = { 0x00, 0x30 };
	public static final byte[] TLS_DH_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x31 };
	public static final byte[] TLS_DHE_DSS_WITH_AES_128_CBC_SHA = { 0x00, 0x32 };
	public static final byte[] TLS_DHE_RSA_WITH_AES_128_CBC_SHA = { 0x00, 0x33 };
	public static final byte[] TLS_DH_anon_WITH_AES_128_CBC_SHA = { 0x00, 0x34 };
	public static final byte[] TLS_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x35 };
	public static final byte[] TLS_DH_DSS_WITH_AES_256_CBC_SHA = { 0x00, 0x36 };
	public static final byte[] TLS_DH_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x37 };
	public static final byte[] TLS_DHE_DSS_WITH_AES_256_CBC_SHA = { 0x00, 0x38 };
	public static final byte[] TLS_DHE_RSA_WITH_AES_256_CBC_SHA = { 0x00, 0x39 };
	public static final byte[] TLS_DH_anon_WITH_AES_256_CBC_SHA = { 0x00, 0x3A };
	public static final byte[] TLS_RSA_WITH_NULL_SHA256 = { 0x00, 0x3B };
	public static final byte[] TLS_RSA_WITH_AES_128_CBC_SHA256 = { 0x00, 0x3C };
	public static final byte[] TLS_RSA_WITH_AES_256_CBC_SHA256 = { 0x00, 0x3D };
	public static final byte[] TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = { 0x00,
			0x3E };
	public static final byte[] TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,
			0x3F };
	public static final byte[] TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = { 0x00,
			0x40 };
	public static final byte[] TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = { 0x00, 0x41 };
	public static final byte[] TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = { 0x00,
			0x42 };
	public static final byte[] TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = { 0x00,
			0x43 };
	public static final byte[] TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = { 0x00,
			0x44 };
	public static final byte[] TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = { 0x00,
			0x45 };
	public static final byte[] TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = { 0x00,
			0x46 };
	public static final byte[] TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = { 0x00,
			0x67 };
	public static final byte[] TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = { 0x00,
			0x68 };
	public static final byte[] TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,
			0x69 };
	public static final byte[] TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = { 0x00,
			0x6A };
	public static final byte[] TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = { 0x00,
			0x6B };
	public static final byte[] TLS_DH_anon_WITH_AES_128_CBC_SHA256 = { 0x00,
			0x6C };
	public static final byte[] TLS_DH_anon_WITH_AES_256_CBC_SHA256 = { 0x00,
			0x6D };
	public static final byte[] TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = { 0x00,
			(byte) 0x84 };
	public static final byte[] TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = { 0x00,
			(byte) 0x85 };
	public static final byte[] TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = { 0x00,
			(byte) 0x86 };
	public static final byte[] TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = { 0x00,
			(byte) 0x87 };
	public static final byte[] TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = { 0x00,
			(byte) 0x88 };
	public static final byte[] TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = { 0x00,
			(byte) 0x89 };
	public static final byte[] TLS_PSK_WITH_RC4_128_SHA = { 0x00, (byte) 0x8A };
	public static final byte[] TLS_PSK_WITH_3DES_EDE_CBC_SHA = { 0x00,
			(byte) 0x8B };
	public static final byte[] TLS_PSK_WITH_AES_128_CBC_SHA = { 0x00,
			(byte) 0x8C };
	public static final byte[] TLS_PSK_WITH_AES_256_CBC_SHA = { 0x00,
			(byte) 0x8D };
	public static final byte[] TLS_DHE_PSK_WITH_RC4_128_SHA = { 0x00,
			(byte) 0x8E };
	public static final byte[] TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = { 0x00,
			(byte) 0x8F };
	public static final byte[] TLS_DHE_PSK_WITH_AES_128_CBC_SHA = { 0x00,
			(byte) 0x90 };
	public static final byte[] TLS_DHE_PSK_WITH_AES_256_CBC_SHA = { 0x00,
			(byte) 0x91 };
	public static final byte[] TLS_RSA_PSK_WITH_RC4_128_SHA = { 0x00,
			(byte) 0x92 };
	public static final byte[] TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = { 0x00,
			(byte) 0x93 };
	public static final byte[] TLS_RSA_PSK_WITH_AES_128_CBC_SHA = { 0x00,
			(byte) 0x94 };
	public static final byte[] TLS_RSA_PSK_WITH_AES_256_CBC_SHA = { 0x00,
			(byte) 0x95 };
	public static final byte[] TLS_RSA_WITH_SEED_CBC_SHA = { 0x00, (byte) 0x96 };
	public static final byte[] TLS_DH_DSS_WITH_SEED_CBC_SHA = { 0x00,
			(byte) 0x97 };
	public static final byte[] TLS_DH_RSA_WITH_SEED_CBC_SHA = { 0x00,
			(byte) 0x98 };
	public static final byte[] TLS_DHE_DSS_WITH_SEED_CBC_SHA = { 0x00,
			(byte) 0x99 };
	public static final byte[] TLS_DHE_RSA_WITH_SEED_CBC_SHA = { 0x00,
			(byte) 0x9A };
	public static final byte[] TLS_DH_anon_WITH_SEED_CBC_SHA = { 0x00,
			(byte) 0x9B };
	public static final byte[] TLS_RSA_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0x9C };
	public static final byte[] TLS_RSA_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0x9D };
	public static final byte[] TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0x9E };
	public static final byte[] TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0x9F };
	public static final byte[] TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xA0 };
	public static final byte[] TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xA1 };
	public static final byte[] TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xA2 };
	public static final byte[] TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xA3 };
	public static final byte[] TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xA4 };
	public static final byte[] TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xA5 };
	public static final byte[] TLS_DH_anon_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xA6 };
	public static final byte[] TLS_DH_anon_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xA7 };
	public static final byte[] TLS_PSK_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xA8 };
	public static final byte[] TLS_PSK_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xA9 };
	public static final byte[] TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xAA };
	public static final byte[] TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xAB };
	public static final byte[] TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = { 0x00,
			(byte) 0xAC };
	public static final byte[] TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = { 0x00,
			(byte) 0xAD };
	public static final byte[] TLS_PSK_WITH_AES_128_CBC_SHA256 = { 0x00,
			(byte) 0xAE };
	public static final byte[] TLS_PSK_WITH_AES_256_CBC_SHA384 = { 0x00,
			(byte) 0xAF };
	public static final byte[] TLS_PSK_WITH_NULL_SHA256 = { 0x00, (byte) 0xB0 };
	public static final byte[] TLS_PSK_WITH_NULL_SHA384 = { 0x00, (byte) 0xB1 };
	public static final byte[] TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = { 0x00,
			(byte) 0xB2 };
	public static final byte[] TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = { 0x00,
			(byte) 0xB3 };
	public static final byte[] TLS_DHE_PSK_WITH_NULL_SHA256 = { 0x00,
			(byte) 0xB4 };
	public static final byte[] TLS_DHE_PSK_WITH_NULL_SHA384 = { 0x00,
			(byte) 0xB5 };
	public static final byte[] TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = { 0x00,
			(byte) 0xB6 };
	public static final byte[] TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = { 0x00,
			(byte) 0xB7 };
	public static final byte[] TLS_RSA_PSK_WITH_NULL_SHA256 = { 0x00,
			(byte) 0xB8 };
	public static final byte[] TLS_RSA_PSK_WITH_NULL_SHA384 = { 0x00,
			(byte) 0xB9 };
	public static final byte[] TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = { 0x00,
			(byte) 0xBA };
	public static final byte[] TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = {
			0x00, (byte) 0xBB };
	public static final byte[] TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = {
			0x00, (byte) 0xBC };
	public static final byte[] TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = {
			0x00, (byte) 0xBD };
	public static final byte[] TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = {
			0x00, (byte) 0xBE };
	public static final byte[] TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = {
			0x00, (byte) 0xBF };
	public static final byte[] TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = { 0x00,
			(byte) 0xC0 };
	public static final byte[] TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = {
			0x00, (byte) 0xC1 };
	public static final byte[] TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = {
			0x00, (byte) 0xC2 };
	public static final byte[] TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = {
			0x00, (byte) 0xC3 };
	public static final byte[] TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = {
			0x00, (byte) 0xC4 };
	public static final byte[] TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = {
			0x00, (byte) 0xC5 };
	public static final byte[] TLS_EMPTY_RENEGOTIATION_INFO_SCSV = { 0x00,
			(byte) 0xFF };
	public static final byte[] TLS_FALLBACK_SCSV = { 0x56, 0x00 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_NULL_SHA = { (byte) 0xC0,
			0x01 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_RC4_128_SHA = { (byte) 0xC0,
			0x02 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x03 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x04 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x05 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_NULL_SHA = { (byte) 0xC0,
			0x06 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = {
			(byte) 0xC0, 0x07 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x08 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x09 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x0A };
	public static final byte[] TLS_ECDH_RSA_WITH_NULL_SHA = { (byte) 0xC0, 0x0B };
	public static final byte[] TLS_ECDH_RSA_WITH_RC4_128_SHA = { (byte) 0xC0,
			0x0C };
	public static final byte[] TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x0D };
	public static final byte[] TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x0E };
	public static final byte[] TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x0F };
	public static final byte[] TLS_ECDHE_RSA_WITH_NULL_SHA = { (byte) 0xC0,
			0x10 };
	public static final byte[] TLS_ECDHE_RSA_WITH_RC4_128_SHA = { (byte) 0xC0,
			0x11 };
	public static final byte[] TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x12 };
	public static final byte[] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x13 };
	public static final byte[] TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x14 };
	public static final byte[] TLS_ECDH_anon_WITH_NULL_SHA = { (byte) 0xC0,
			0x15 };
	public static final byte[] TLS_ECDH_anon_WITH_RC4_128_SHA = { (byte) 0xC0,
			0x16 };
	public static final byte[] TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x17 };
	public static final byte[] TLS_ECDH_anon_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x18 };
	public static final byte[] TLS_ECDH_anon_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x19 };
	public static final byte[] TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x1A };
	public static final byte[] TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x1B };
	public static final byte[] TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x1C };
	public static final byte[] TLS_SRP_SHA_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x1D };
	public static final byte[] TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x1E };
	public static final byte[] TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x1F };
	public static final byte[] TLS_SRP_SHA_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x20 };
	public static final byte[] TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x21 };
	public static final byte[] TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x22 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = {
			(byte) 0xC0, 0x23 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = {
			(byte) 0xC0, 0x24 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = {
			(byte) 0xC0, 0x25 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = {
			(byte) 0xC0, 0x26 };
	public static final byte[] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = {
			(byte) 0xC0, 0x27 };
	public static final byte[] TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = {
			(byte) 0xC0, 0x28 };
	public static final byte[] TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = {
			(byte) 0xC0, 0x29 };
	public static final byte[] TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = {
			(byte) 0xC0, 0x2A };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = {
			(byte) 0xC0, 0x2B };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = {
			(byte) 0xC0, 0x2C };
	public static final byte[] TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = {
			(byte) 0xC0, 0x2D };
	public static final byte[] TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = {
			(byte) 0xC0, 0x2E };
	public static final byte[] TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = {
			(byte) 0xC0, 0x2F };
	public static final byte[] TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = {
			(byte) 0xC0, 0x30 };
	public static final byte[] TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = {
			(byte) 0xC0, 0x31 };
	public static final byte[] TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = {
			(byte) 0xC0, 0x32 };
	public static final byte[] TLS_ECDHE_PSK_WITH_RC4_128_SHA = { (byte) 0xC0,
			0x33 };
	public static final byte[] TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = {
			(byte) 0xC0, 0x34 };
	public static final byte[] TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = {
			(byte) 0xC0, 0x35 };
	public static final byte[] TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = {
			(byte) 0xC0, 0x36 };
	public static final byte[] TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = {
			(byte) 0xC0, 0x37 };
	public static final byte[] TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = {
			(byte) 0xC0, 0x38 };
	public static final byte[] TLS_ECDHE_PSK_WITH_NULL_SHA = { (byte) 0xC0,
			0x39 };
	public static final byte[] TLS_ECDHE_PSK_WITH_NULL_SHA256 = { (byte) 0xC0,
			0x3A };
	public static final byte[] TLS_ECDHE_PSK_WITH_NULL_SHA384 = { (byte) 0xC0,
			0x3B };
	public static final byte[] TLS_RSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x3C };
	public static final byte[] TLS_RSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x3D };
	public static final byte[] TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x3E };
	public static final byte[] TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x3F };
	public static final byte[] TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x40 };
	public static final byte[] TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x41 };
	public static final byte[] TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x42 };
	public static final byte[] TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x43 };
	public static final byte[] TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x44 };
	public static final byte[] TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x45 };
	public static final byte[] TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x46 };
	public static final byte[] TLS_DH_anon_WITH_ARIA_256_CBC_SHA38 = {
			(byte) 0xC0, 0x47 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x48 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x49 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x4A };
	public static final byte[] TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x4B };
	public static final byte[] TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x4C };
	public static final byte[] TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x4D };
	public static final byte[] TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x4E };
	public static final byte[] TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x4F };
	public static final byte[] TLS_RSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x50 };
	public static final byte[] TLS_RSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x51 };
	public static final byte[] TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x52 };
	public static final byte[] TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x53 };
	public static final byte[] TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x54 };
	public static final byte[] TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x55 };
	public static final byte[] TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x56 };
	public static final byte[] TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x57 };
	public static final byte[] TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x58 };
	public static final byte[] TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x59 };
	public static final byte[] TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x5A };
	public static final byte[] TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x5B };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x5C };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x5D };
	public static final byte[] TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x5E };
	public static final byte[] TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x5F };
	public static final byte[] TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x60 };
	public static final byte[] TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x61 };
	public static final byte[] TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x62 };
	public static final byte[] TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x63 };
	public static final byte[] TLS_PSK_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x64 };
	public static final byte[] TLS_PSK_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x65 };
	public static final byte[] TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x66 };
	public static final byte[] TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x67 };
	public static final byte[] TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x68 };
	public static final byte[] TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x69 };
	public static final byte[] TLS_PSK_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x6A };
	public static final byte[] TLS_PSK_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x6B };
	public static final byte[] TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x6C };
	public static final byte[] TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x6D };
	public static final byte[] TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x6E };
	public static final byte[] TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x6F };
	public static final byte[] TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x70 };
	public static final byte[] TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x71 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x72 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x73 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x74 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x75 };
	public static final byte[] TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x76 };
	public static final byte[] TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x77 };
	public static final byte[] TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, 0x78 };
	public static final byte[] TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, 0x79 };
	public static final byte[] TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x7A };
	public static final byte[] TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x7B };
	public static final byte[] TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x7C };
	public static final byte[] TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x7D };
	public static final byte[] TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, 0x7E };
	public static final byte[] TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, 0x7F };
	public static final byte[] TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x80 };
	public static final byte[] TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x81 };
	public static final byte[] TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x82 };
	public static final byte[] TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x83 };
	public static final byte[] TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x84 };
	public static final byte[] TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x85 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x86 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x87 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x88 };
	public static final byte[] TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x89 };
	public static final byte[] TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x8A };
	public static final byte[] TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x8B };
	public static final byte[] TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x8C };
	public static final byte[] TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x8D };
	public static final byte[] TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x8E };
	public static final byte[] TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x8F };
	public static final byte[] TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x90 };
	public static final byte[] TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x91 };
	public static final byte[] TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = {
			(byte) 0xC0, (byte) 0x92 };
	public static final byte[] TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = {
			(byte) 0xC0, (byte) 0x93 };
	public static final byte[] TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, (byte) 0x94 };
	public static final byte[] TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, (byte) 0x95 };
	public static final byte[] TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, (byte) 0x96 };
	public static final byte[] TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, (byte) 0x97 };
	public static final byte[] TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, (byte) 0x98 };
	public static final byte[] TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, (byte) 0x99 };
	public static final byte[] TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = {
			(byte) 0xC0, (byte) 0x9A };
	public static final byte[] TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = {
			(byte) 0xC0, (byte) 0x9B };
	public static final byte[] TLS_RSA_WITH_AES_128_CCM = { (byte) 0xC0,
			(byte) 0x9C };
	public static final byte[] TLS_RSA_WITH_AES_256_CCM = { (byte) 0xC0,
			(byte) 0x9D };
	public static final byte[] TLS_DHE_RSA_WITH_AES_128_CCM = { (byte) 0xC0,
			(byte) 0x9E };
	public static final byte[] TLS_DHE_RSA_WITH_AES_256_CCM = { (byte) 0xC0,
			(byte) 0x9F };
	public static final byte[] TLS_RSA_WITH_AES_128_CCM_8 = { (byte) 0xC0,
			(byte) 0xA0 };
	public static final byte[] TLS_RSA_WITH_AES_256_CCM_8 = { (byte) 0xC0,
			(byte) 0xA1 };
	public static final byte[] TLS_DHE_RSA_WITH_AES_128_CCM_8 = { (byte) 0xC0,
			(byte) 0xA2 };
	public static final byte[] TLS_DHE_RSA_WITH_AES_256_CCM_8 = { (byte) 0xC0,
			(byte) 0xA3 };
	public static final byte[] TLS_PSK_WITH_AES_128_CCM = { (byte) 0xC0,
			(byte) 0xA4 };
	public static final byte[] TLS_PSK_WITH_AES_256_CCM = { (byte) 0xC0,
			(byte) 0xA5 };
	public static final byte[] TLS_DHE_PSK_WITH_AES_128_CCM = { (byte) 0xC0,
			(byte) 0xA6 };
	public static final byte[] TLS_DHE_PSK_WITH_AES_256_CCM = { (byte) 0xC0,
			(byte) 0xA7 };
	public static final byte[] TLS_PSK_WITH_AES_128_CCM_8 = { (byte) 0xC0,
			(byte) 0xA8 };
	public static final byte[] TLS_PSK_WITH_AES_256_CCM_8 = { (byte) 0xC0,
			(byte) 0xA9 };
	public static final byte[] TLS_PSK_DHE_WITH_AES_128_CCM_8 = { (byte) 0xC0,
			(byte) 0xAA };
	public static final byte[] TLS_PSK_DHE_WITH_AES_256_CCM_8 = { (byte) 0xC0,
			(byte) 0xAB };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_128_CCM = {
			(byte) 0xC0, (byte) 0xAC };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_256_CCM = {
			(byte) 0xC0, (byte) 0xAD };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = {
			(byte) 0xC0, (byte) 0xAE };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = {
			(byte) 0xC0, (byte) 0xAF };
	public static final byte[] TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xA8 };
	public static final byte[] TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xA9 };
	public static final byte[] TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xAA };
	public static final byte[] TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xAB };
	public static final byte[] TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xAC };
	public static final byte[] TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xAD };
	public static final byte[] TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = {
			(byte) 0xCC, (byte) 0xAE };

}
