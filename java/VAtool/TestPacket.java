package VAtool;

import java.util.ArrayList;

import SSLPacket.CipherSuitPacket;
import SSLPacket.CipherSuite;
import SSLPacket.ExtensionFormat;
import SSLPacket.ExtensionPacket;
import SSLPacket.SSLClientHelloPacket;

public class TestPacket {
	public static byte[] makeTestPacket(){
		ArrayList<CipherSuitPacket> CipherSuitList = new ArrayList();
		
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_KRB5_WITH_RC4_128_MD5));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5 ));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_PSK_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA));
		
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_KRB5_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA));
		CipherSuitList.add(new CipherSuitPacket(CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA));
		
		ArrayList<ExtensionPacket> ExtensionList = new ArrayList();
		byte[] ec_point_format_contents = {
				0x03, 
				0x00, 
				0x01, 
				0x02,
		};
		ExtensionList.add(new ExtensionPacket(ExtensionFormat.EC_POINT_FORMATS, ec_point_format_contents));
		byte[] supported_groups_contents = {
				0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 
				0x00, 0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 
				0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07, 0x00, 0x14, 
				0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 
				0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 
				0x00, 0x11,
		};
		ExtensionList.add(new ExtensionPacket(ExtensionFormat.SUPPORTED_GROUPS,supported_groups_contents));
		
		ExtensionList.add(new ExtensionPacket(ExtensionFormat.SESSIONTICKET_TLS));
		
		byte[] heartbeat_contents = {0x01};
		ExtensionList.add(new ExtensionPacket(ExtensionFormat.HEARTBEAT,heartbeat_contents));
		
		byte[] signature_algorithms_contents = {
				0x00, 0x04,		//S&H length 4/2 = including 2 algorithms 
			    0x01, 0x00,		//hash: md5, signature: anon
			    0x04, 0x01, 	//hash: SHA256, signature: RSA
		};
		ExtensionList.add(new ExtensionPacket(ExtensionFormat.SIGNATURE_ALGORITHMS,signature_algorithms_contents));
		
		CipherSuitPacket[] cipher_suit_packet= new CipherSuitPacket[CipherSuitList.size()];
		ExtensionPacket[] extension_packet = new ExtensionPacket[ExtensionList.size()];
		
		for(int i = 0; i <CipherSuitList.size();i++){
			cipher_suit_packet[i] = CipherSuitList.get(i);
		}
		
		for(int i = 0;i < ExtensionList.size();i++){
			extension_packet[i] = ExtensionList.get(i);
		}
		
		SSLClientHelloPacket SSL_client_hello = new SSLClientHelloPacket(cipher_suit_packet, extension_packet);
		byte[] packet = SSL_client_hello.makeBytePacket();
		
		return packet;
	}
}
