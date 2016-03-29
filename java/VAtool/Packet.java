package VAtool;

import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import javax.swing.JOptionPane;

public class Packet {
	
	packetHeader pheader;
	packetPayload ppayload;

	CipherSuite ciphersuite;
	
	public Packet(packetHeader ph, packetPayload pp) {
		this.pheader = ph;
		this.ppayload = pp;
		ciphersuite = new CipherSuite();
	}
	
	
	public static class packetHeader {
		int type, ver, len;

		public packetHeader(int type, int ver, int len) {
			this.type = type;
			this.ver = ver;
			this.len = len;
		}
	};

	public static class packetPayload {
		byte[] payload;

		public packetPayload(byte[] payload) {
			this.payload = payload;
		}
	};
	
	public static packetHeader readHeader(DataInputStream din) throws IOException {
		byte[] header = new byte[5];
		
			din.readFully(header);
		
		ByteBuffer bb = ByteBuffer.wrap(header);
		
		for(int i=0;i<header.length;i++)
			System.out.println("header["+i+"]: "+Integer.toHexString(0xff & header[i]));
		
		
		return new packetHeader(bb.get(), bb.getShort(), bb.getShort());
	}

	public static packetPayload readPayload(DataInputStream din, int len) {
		byte[] payload = new byte[len];
		try {
			din.readFully(payload);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new packetPayload(payload);
	}

	public static Packet readPacket(DataInputStream din) throws IOException {
		packetHeader ph = readHeader(din);
		packetPayload pp = readPayload(din, ph.len);

		return new Packet(ph, pp);
	}

	public TLSVulnerability parseServerHello(TLSVulnerability tlsvul) {

		System.out.println("Content Type: " + ppayload.payload[0]);
		int ciphersuiteIdx = ppayload.payload[38] + 38 + 1;
		System.out.println("ciphersuiteIdx: " + ciphersuiteIdx);
		String selectedCipher = new String(
				Integer.toHexString(0xff & ppayload.payload[ciphersuiteIdx])
						+ ""
						+ Integer
								.toHexString(0xff & ppayload.payload[ciphersuiteIdx + 1]));
		System.out.println("Cipher Suite: " + selectedCipher);

		if (ciphersuite.rc4Map.containsKey(selectedCipher) && tlsvul.isRc4attack) {
			tlsvul.rc4.isVulnerable = true;
			tlsvul.rc4.description = new String("The target server selected \""
					+ ciphersuite.rc4Map.get(selectedCipher)
					+ "\" which is included in vulnerable cipher suites");
			tlsvul.rc4.level = new String("Vulnerable");

			
			tlsvul.isRc4attack = false;
		}

		if(tlsvul.isPoodleattack){
			tlsvul.poodle.isVulnerable = true;
			tlsvul.poodle.description = new String("The target server selected CBC mode cipher suite with SSLv3");
			tlsvul.poodle.level = new String("Vulnerable");
			tlsvul.isPoodleattack = false;
		}
		return tlsvul;
		/*
		 * for(int i=0;i<pkt.ppayload.payload.length;i++)
		 * System.out.print("payload["+i+"]: "+pkt.ppayload.payload[i]+"\t");
		 * 
		 * System.out.println();
		 */
	}
	
	public  static byte[] HBrequest = new byte[] { 
		0x18, 0x03, 0x03, 	// content type: 18: 24, version: 0303 TLS1.2, 
		0x00, 0x19,		 		//length: 0019: 25
		0x01, 					// Heartbeat MessageType: request
		0x00, 0x06,			 	// payload_length: 0006
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // The padding.Len MUST be  at least 16: default 16.
};
	
	public static byte[] hb_test = new byte[]{
		  0x16, 0x03, 0x02, 0x00, (byte)0xdc, 0x01, 0x00, 0x00, (byte) 0xd8, 0x03, 0x02, 0x53,  
	      0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf, 
	      (byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 0x04, 0x33, (byte) 0xd4, (byte) 0xde, 0x00, 
	      0x00, 0x66, (byte) 0xc0, 0x14, (byte) 0xc0, 0x0a, (byte) 0xc0, 0x22,  (byte) 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, (byte) 0x88, 
	      0x00, (byte) 0x87, (byte) 0xc0, 0x0f, (byte) 0xc0, 0x05, 0x00, 0x35,  0x00, (byte) 0x84, (byte) 0xc0, 0x12, (byte) 0xc0, 0x08, (byte) 0xc0, 0x1c, 
	      (byte) 0xc0, 0x1b, 0x00, 0x16, 0x00, 0x13, (byte) 0xc0, 0x0d,  (byte) 0xc0, 0x03, 0x00, 0x0a, (byte) 0xc0, 0x13, (byte) 0xc0, 0x09, 
	      (byte) 0xc0, 0x1f, (byte) 0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32,  0x00, (byte) 0x9a, 0x00, (byte) 0x99, 0x00, 0x45, 0x00, 0x44, 
	      (byte) 0xc0, 0x0e, (byte) 0xc0, 0x04, 0x00, 0x2f, 0x00, (byte) 0x96,  0x00, 0x41, (byte) 0xc0, 0x11, (byte) 0xc0, 0x07, (byte) 0xc0, 0x0c, 
	      (byte) 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15,  0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 
	      0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, (byte) 0xff,  0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04, 
	      0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x34,  0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 
	      0x00, 0x0b, 0x00, 0x0c, 0x00, 0x18, 0x00, 0x09,  0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 
	      0x00, 0x06, 0x00, 0x07, 0x00, 0x14, 0x00, 0x15,  0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 
	      0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0f,  0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00, 
	      0x00, 0x0f, 0x00, 0x01, 0x01 

	};
	
	public static byte[] rc4_test = new byte[] {
		0x16,
		0x03,
		0x03,
		0x00,
		(byte) 0x9a, // Content type = 16: 22 (handshake message); Version =
						// 03 03; Packet length = 008e:142 | 009a: 154 |
						// 004e: 78
		0x01,
		0x00,
		0x00,
		(byte) 0x96, // Message type = 01 (client hello); Length = 00008a:
						// 138 |00 00 96 : 150 | 004a: 74
		0x03,
		0x03, // Client version = 03 03 (TLS 1.2)

		0x53,
		0x43,
		0x5b,
		(byte) 0x90,
		(byte) 0x9d,
		(byte) 0x9b,
		0x72,
		0x0b,
		(byte) 0xbc,
		0x0c,
		(byte) 0xbc,
		0x2b,
		(byte) 0x92,
		(byte) 0xa8,
		0x48,
		(byte) 0x97,
		(byte) 0xcf,
		(byte) 0xbd,
		0x39,
		0x04,
		(byte) 0xcc,
		0x16,
		0x0a,
		(byte) 0x85,
		0x03,
		(byte) 0x90,
		(byte) 0x9f,
		0x77,
		0x04,
		0x33,
		(byte) 0xd4,
		(byte) 0xde,// Random 32B

		0x00, // Session id = 00
		0x00,
		0x1a, // Cipher suite length 000e:14 001a: 26

		CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5[0],
		CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5[1],
		 CipherSuite.TLS_KRB5_WITH_RC4_128_SHA[0],
		 CipherSuite.TLS_KRB5_WITH_RC4_128_SHA[1],

		CipherSuite.TLS_KRB5_WITH_RC4_128_MD5[0],
		CipherSuite.TLS_KRB5_WITH_RC4_128_MD5[1],
		CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5[0],
		CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5[1],
		CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA[0],
		CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA[1],
		CipherSuite.TLS_PSK_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_PSK_WITH_RC4_128_SHA[1],

		CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA[0],
		CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA[1],
		//CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256[0],
		//CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256[1],
		// CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256[0],
		// CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256[1],
		0x01, // Compression methods length
		0x00, // Compression method 0 : no compression = 0
		0x00,
		0x53, // Extension length = 0x53 : 83 | 0x13: 19

		0x00,
		0x0b, // ec_point_format
		0x00,
		0x04, // length
		0x03,
		0x00,
		0x01,
		0x02,

		0x00,
		0x0a, // supported_groups(renamed from "elliptic_curvers")
		0x00,
		0x34, // length: 52
		0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00,
		0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17,
		0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00,
		0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
		0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, // 52

		0x00, 0x23, // SessionTicket TLS RFC4507
		0x00, 0x00, // length 0

		0x00, 0x0f, // heartbeat RFC6520
		0x00, 0x01, // length 1
		0x01, // peer_allowed_to_send

		0x00, 0x0d, // signature_algorithms RFC5246
		0x00, 0x06, // length 6
		0x00, 0x04, // S&H length 4/2 = including 2 algorithms
		0x01, 0x00, // hash: md5, signature: anon
		0x04, 0x01, // hash: SHA256, signature: RSA

// Extension
};
	
	public static byte[] sslv3_test = new byte[] {
		0x16, 0x03, 0x00, 0x00, (byte) 0xac, 	// Content type = 16: 22 (handshake message); Version = 03 00; SSLv3
															//  Packet length = 009a: 154 
		
		0x01,	0x00, 0x00, (byte) 0xa8, // Message type = 01 (client hello); Length = 00 00 96 : 150 
		0x03, 0x00, // Client version = 03 03 (SSLv3)

		0x53,	0x43,	0x5b,	(byte) 0x90, (byte) 0x9d, (byte) 0x9b, 0x72, 0x0b, (byte) 0xbc, 0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8,
		0x48,	(byte) 0x97, (byte) 0xcf, (byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03, (byte) 0x90, (byte) 0x9f, 0x77,
		0x04, 0x33, (byte) 0xd4, (byte) 0xde,// Random 32B

		0x00, // Session id = 00
		
		0x00, 0x2c, // Cipher suite length  002c: 44 - 26 = 18

		CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA[0],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA[1],
		CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA[0],
		CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA[1],
		CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA[0],
		CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA[1],
		CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA[0],
		CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA[1],
		CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA[0],
		CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA[1],
		CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256[0],
		CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256[1],
		CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA[0],
		CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA[1],
		
		
		
		
		0x01, // Compression methods length
		0x00, // Compression method 0 : no compression = 0
		
		0x00, 0x53, // Extension length = 0x53 : 83 | 0x13: 19

		0x00, 0x0b, // ec_point_format
		0x00, 0x04, // length
		0x03,
		0x00,
		0x01,
		0x02,

		0x00, 0x0a, // supported_groups(renamed from "elliptic_curvers")
		0x00, 0x34, // length: 52
		0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00,
		0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17,
		0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00,
		0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
		0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, // 52

		0x00, 0x23, // SessionTicket TLS RFC4507
		0x00, 0x00, // length 0

		0x00, 0x0f, // heartbeat RFC6520
		0x00, 0x01, // length 1
		0x01, // peer_allowed_to_send

		0x00, 0x0d, // signature_algorithms RFC5246
		0x00, 0x06, // length 6
		0x00, 0x04, // S&H length 4/2 = including 2 algorithms
		0x01, 0x00, // hash: md5, signature: anon
		0x04, 0x01, // hash: SHA256, signature: RSA

// Extension
};
	
	public static byte[] sslv2_test = new byte[]{
		(byte) 0x80, 0x31, 0x01, 0x00, 0x02, 0x00, 0x18, 0x00, 0x00, 0x00, 0x10, 
		0x02, 0x00, (byte) 0x80,
		0x06, 0x00, 0x40,
		0x01, 0x00, (byte) 0x80,
		0x05, 0x00, (byte) 0x80,
		0x04, 0x00, (byte) 0x80,
		0x07, 0x00, (byte) 0xc0,
		0x08, 0x00, (byte) 0x80,
		0x03, 0x00, (byte) 0x80,
		0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
		
		};
}
