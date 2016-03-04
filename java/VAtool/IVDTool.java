package VAtool;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;





public class IVDTool {
	
	private static class packet{
		packetHeader pheader;
		packetPayload ppayload;
		
		public packet(packetHeader ph, packetPayload pp){
			this.pheader = ph;
			this.ppayload = pp;
		}
	}
	
	private static class packetHeader{
		int type, ver, len;
				
		public packetHeader(int type, int ver, int len){
			this.type = type;
			this.ver = ver;
			this.len = len;
		}
	};

	private static class packetPayload{
		byte[] payload;
		
		public packetPayload(byte[] payload){
			this.payload = payload;
		}
	};
	
	private String host;
	private static int port;
	
	public IVDTool(){
		host = null;
		port = 443;
	}
	
	public void setHost(String host){this.host = host;}
	
	public static ASN1Primitive toDERObject(byte[] data) throws IOException{
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream asnInpuStream = new ASN1InputStream(inStream);
		
		return asnInpuStream.readObject();
	}
	
	public void defaultHandshake(){
		
		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		System.out.println("Connecting... " + host + " : " + port);
		try {
			final SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
		
			String[] suites = socket.getSupportedCipherSuites();
	
			socket.setEnabledCipherSuites(suites);
			socket.addHandshakeCompletedListener(new HandshakeCompletedListener(){

				public void handshakeCompleted(HandshakeCompletedEvent e) {
					// TODO Auto-generated method stub
					
					java.security.cert.Certificate lc[];
					
					System.out.println("Handshake success!");
					System.out.println("Using cipher suite: " + e.getCipherSuite());
					try {
						lc = e.getPeerCertificates();
						X509Certificate x509cert = (X509Certificate) lc[0];
						
						System.out.println(x509cert.toString());
						
						byte[] encodedExtensionValueA = x509cert.getExtensionValue("2.5.29.35");
						if (encodedExtensionValueA != null) {
						    ASN1Primitive extensionValue;
							try {
								extensionValue = JcaX509ExtensionUtils.parseExtensionValue(encodedExtensionValueA);
								String values = extensionValue.toString();
								System.out.println("https.tls.certificate.parsed.extensions.authority_key_id : " + values.substring(5,45));
							} catch (IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						}
						
						System.out.println("public key : " + x509cert.getPublicKey());
						System.out.println("443.https.tls.certificate.parsed.extensions.basic_constraints : "+ x509cert.getBasicConstraints());
						System.out.println("443.https.tls.certificate.parsed.extensions.certificate_policies : "+ x509cert.getExtensionValue("2.5.29.36"));
						System.out.println("443.https.tls.certificate.parsed.extensions.extended_key_usage : "+x509cert.getExtendedKeyUsage());
						
						byte[] encodedExtensionValueB = x509cert.getExtensionValue("2.5.29.14");
						if (encodedExtensionValueB != null) {
						    ASN1Primitive extensionValue;
							try {
								extensionValue = JcaX509ExtensionUtils
								        .parseExtensionValue(encodedExtensionValueB);
								String values = extensionValue.toString();
								System.out.println("443.https.tls.certificate.parsed.extensions.subject_key_id : " + values.substring(1,41));
							} catch (IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						}
						System.out.println("443.https.tls.certificate.parsed.extensions.key_usage.digital_signature : " + x509cert.getKeyUsage()[0]);
						System.out.println("443.https.tls.certificate.parsed.extensions.key_usage.key_encipherment : "+ x509cert.getKeyUsage()[2]);
						System.out.println("443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names : " + x509cert.getSubjectAlternativeNames());
						System.out.println("443.https.tls.certificate.parsed.issuer_dn : " + x509cert.getIssuerX500Principal().getName());
						System.out.println("443.https.tls.certificate.parsed.serial_number : " + x509cert.getSerialNumber());
						System.out.println("443.https.tls.certificate.parsed.signature.signature_algorithm.name : " + x509cert.getSigAlgName());
						System.out.println("443.https.tls.certificate.parsed.signature.signature_algorithm.oid : " + x509cert.getSigAlgOID());
						
						System.out.println("443.https.tls.certificate.parsed.subject_dn : " + x509cert.getSubjectDN().getName());
						
						System.out.println("443.https.tls.certificate.parsed.validity.end : " + x509cert.getNotBefore());
						System.out.println("443.https.tls.certificate.parsed.validity.start : " + x509cert.getNotAfter());
						System.out.println("443.https.tls.certificate.parsed.version : "+ x509cert.getVersion());
						
						System.out.println("443.https.tls.cipher_suite.name : "+ socket.getSession().getCipherSuite() );
						System.out.println("443.https.tls.version : "+ socket.getSession().getProtocol() );
						
												
					} catch (SSLPeerUnverifiedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (CertificateParsingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}});
			
			
			socket.startHandshake();
			
			System.out.println("Connected to " + socket.getRemoteSocketAddress());
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void heartbleadTest(){
		Socket s;
		InputStream in;
		DataInputStream din;
		OutputStream out;
		
		int idx = 0;
		
		try {
			s = new Socket(host, port);
			in = s.getInputStream();
			din = new DataInputStream(in);
			out = s.getOutputStream();
			
			System.out.println("--Handshake message--");
			System.out.println("Client Hello...");
			out.write(sslHello_origin);
			
			System.out.println("Waiting for Server Hello...");
			while(true){
				packet pkt = readPacket(din);
				System.out.println("Type:" + pkt.pheader.type + " Ver: " + pkt.pheader.ver + " Len: " + pkt.pheader.len);
				
				for(int i=0;i<3;i++)
					System.out.print("payload["+i+"]: " + pkt.ppayload.payload[i]+"\t");
				System.out.println();
				System.out.println();
				if(pkt.pheader.type == 22 && pkt.ppayload.payload[0] == 0xE) break;
			}
			
			while(true){
				System.out.println("headtbeat...");
				out.write(sslHB);
				packet hpkt = readPacket(din);
				System.out.println("Type:" + hpkt.pheader.type + " Ver: " + hpkt.pheader.ver + " Len: " + hpkt.pheader.len);
				
				System.out.print("Heartbeat payload: ");
				for(int i=0;i<hpkt.ppayload.payload.length;i++)
					System.out.print(hpkt.ppayload.payload[i] + " // ");
				System.out.println();
				switch(hpkt.pheader.type){
				case 24:
					System.out.println("Received heartbeat response: ");
					if(hpkt.ppayload.payload.length>3)
						System.out.println("WARNING: server returned more data than it should - server is vulnerable!");
					else
						System.out.println("Server processed malformed heartbeat, but did not return any extra data");
					return;
				case 21:
					System.out.println("Received alert: ");
					System.out.println("Server returned error, likely not vulnerable");
					return;
				default:
					System.out.println("No heartbeat response received, server likely not vulnerable");
					return;
				}
			}
			
			
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	
		
	}
	
	public packetHeader readHeader(DataInputStream din){
		byte[] header = new byte[5];
		try {
			din.readFully(header);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ByteBuffer bb = ByteBuffer.wrap(header);
		
		return new packetHeader(bb.get(), bb.getShort(), bb.getShort());
	}
	
	public packetPayload readPayload(DataInputStream din, int len) {
		byte[] payload = new byte[len];
		try {
			din.readFully(payload);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new packetPayload(payload);
	}
	
	public packet readPacket(DataInputStream din) {
		packetHeader ph = readHeader(din);
		packetPayload pp = readPayload(din, ph.len);
		
		return new packet(ph, pp);
	}
	
	private static byte sslHello_origin[] = new byte[] {
		0x16, 0x03, 0x03, 0x00, (byte) 0xe6, // Content type = 16: 22 (handshake message); Version = 03 03; Packet length = 00e6: 230
		0x01, 0x00, 0x00, (byte) 0xe2, //Message type = 01 (client hello); Length = 00 00 e2 : 226
		0x03, 0x03, //Client version = 03 03 (TLS 1.2)
		
		0x53, 0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf, 
		(byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 
		0x04, 0x33, (byte) 0xd4, (byte) 0xde,//Random 32B
		
		0x00, //Session id = 00
		0x00, 0x66, //Cipher suite length 0066: 102
		
		(byte) 0xc0, 0x14, //TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		(byte) 0xc0, 0x0a, //TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		(byte) 0xc0, 0x22, //TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA 
		(byte) 0xc0, 0x21, //TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x39, //TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		0x00, 0x38, //TLS_DHE_DSS_WITH_AES_256_CBC_SHA
		0x00, (byte) 0x88, //TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 
		0x00, (byte) 0x87, //TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
		(byte) 0xc0, 0x0f, //TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
		(byte) 0xc0, 0x05, //TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
		0x00, 0x35,  //TLS_RSA_WITH_AES_256_CBC_SHA 
		0x00, (byte) 0x84,  //TLS_RSA_WITH_CAMELLIA_256_CBC_SHA 
		(byte) 0xc0, 0x12, //TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
		(byte) 0xc0, 0x08, //TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
		(byte) 0xc0, 0x1c, 
		(byte) 0xc0, 0x1b, 
		0x00, 0x16, 
		0x00, 0x13, 
		(byte) 0xc0, 0x0d,  
		(byte) 0xc0, 0x03, 
		0x00, 0x0a, 
		(byte) 0xc0, 0x13, 
		(byte) 0xc0, 0x09, 
		(byte) 0xc0, 0x1f, 
		(byte) 0xc0, 0x1e, 
		0x00, 0x33, 
		0x00, 0x32,  
		0x00, (byte) 0x9a, 
		0x00, (byte) 0x99, 
		0x00, 0x45, 
		0x00, 0x44, 
		(byte) 0xc0, 0x0e, 
		(byte) 0xc0, 0x04, 
		0x00, 0x2f, 
		0x00, (byte) 0x96,  
		0x00, 0x41, 
		(byte) 0xc0, 0x11, 
		(byte) 0xc0, 0x07, 
		(byte) 0xc0, 0x0c, 
		(byte) 0xc0, 0x02, 
		0x00, 0x05, 
		0x00, 0x04, 
		0x00, 0x15,  
		0x00, 0x12, 
		0x00, 0x09, 
		0x00, 0x14, 
		0x00, 0x11, 
		0x00, 0x08, 
		0x00, 0x06, 
		0x00, 0x03, 
		0x00, (byte) 0xff, //102 cipher suites //51°³
		
		0x01, //Compression methods length
		0x00, //Compression method 0 : no compression = 0
		0x00, 0x53, //Extension length = 79 -> 89
		
		0x00, 0x0b, //ec_point_format
		0x00, 0x04, //length
		0x03, 
		0x00, 
		0x01, 
		0x02,
		
		0x00, 0x0a,	//supported_groups(renamed from "elliptic_curvers")
		0x00, 0x34,  //length: 52
		0x00, 0x32, 
		0x00, 0x0e, 
		0x00, 0x0d, 
		0x00, 0x19, 
		0x00, 0x0b, 
		0x00, 0x0c, 		
		0x00, 0x18, 
		0x00, 0x09,  
		0x00, 0x0a, 
		0x00, 0x16, 
		0x00, 0x17, 
		0x00, 0x08, 
		0x00, 0x06, 
		0x00, 0x07, 
		0x00, 0x14, 
		0x00, 0x15,  
		0x00, 0x04, 
		0x00, 0x05, 
		0x00, 0x12, 
		0x00, 0x13, 
		0x00, 0x01, 
		0x00, 0x02, 
		0x00, 0x03, 
		0x00, 0x0f,  
		0x00, 0x10, 
		0x00, 0x11,	//52
		
		0x00, 0x23, //SessionTicket TLS	RFC4507
		0x00, 0x00,		//length 0
		
		0x00, 0x0f, //heartbeat RFC6520
		0x00, 0x01, //length 1
		0x01, 		// peer_allowed_to_send
		
		0x00, 0x0d,		//signature_algorithms RFC5246 
		0x00, 0x06, 	//length 6
		0x00, 0x04,		//S&H length 4/2 = including 2 algorithms 
	    0x01, 0x00,		//hash: md5, signature: anon
	    0x04, 0x01, 	//hash: SHA256, signature: RSA
	   
		
		
		// Extension
	};
	
	private static byte sslHB[] = new byte[]{
		0x18, 0x03, 0x03, 0x00, 0x19, 	// content type: 18: 24, version: 0303 TLS1.2, length: 0019: 25 
 		0x01,										// Heartbeat MessageType: request 
 		0x00, 0x06,								// payload_length: 0006 
 		0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00// The padding.Len MUST be at least 16: default 16. 
	};
	
	
	
}
