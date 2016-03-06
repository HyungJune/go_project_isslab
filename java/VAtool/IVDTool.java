package VAtool;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;





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
	
	String ski;
	String uki;
	
	
	
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
								uki = extensionValue.toString();
								System.out.println("https.tls.certificate.parsed.extensions.authority_key_id : " + uki.substring(5,45));
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
								ski = extensionValue.toString();
								System.out.println("443.https.tls.certificate.parsed.extensions.subject_key_id : " + ski.substring(1,41));
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
						
						
						
						
						
						
						Document doc = new Document();  
						
						
						Element InfoSet = new Element("InfoSet");
						  
						Element Info = new Element("Info");
						
						Element info_name1 = new Element("public_key");
						Element info_name2 = new Element("authority_key_id");
						Element info_name3 = new Element("basic_constraints");
						Element info_name4 = new Element("certificate_policies");
						Element info_name5 = new Element("extended_key_usage");
						Element info_name6 = new Element("subject_key_id");
						Element info_name7 = new Element("digital_signature");
						Element info_name8 = new Element("key_encipherment");
						Element info_name9 = new Element("dns_names");
						Element info_name10 = new Element("issuer_dn");
						Element info_name11 = new Element("serial_number");
						Element info_name12 = new Element("signature_algorithm");
						Element info_name13 = new Element("signature_algorithm_oid");
						Element info_name14 = new Element("subject_dn");
						Element info_name15 = new Element("validity_end");
						Element info_name16 = new Element("validity_start");
						Element info_name17 = new Element("version");
						Element info_name18 = new Element("cipher_suite_name");
						Element info_name19 = new Element("tls_version");
						
						
						
						InfoSet.addContent(Info);
						Info.addContent(info_name1);
						Info.addContent(info_name2);
						Info.addContent(info_name3);
						Info.addContent(info_name4);
						Info.addContent(info_name5);
						Info.addContent(info_name6);
						Info.addContent(info_name7);
						Info.addContent(info_name8);
						Info.addContent(info_name9);
						Info.addContent(info_name10);
						Info.addContent(info_name11);
						Info.addContent(info_name12);
						Info.addContent(info_name13);
						Info.addContent(info_name14);
						Info.addContent(info_name15);
						Info.addContent(info_name16);
						Info.addContent(info_name17);
						Info.addContent(info_name18);
						Info.addContent(info_name19);
						
						info_name1.setText(x509cert.getPublicKey().toString());
						info_name2.setText(uki.substring(5,45));
						info_name3.setText(String.valueOf(x509cert.getBasicConstraints()));
						info_name4.setText("null");
						info_name5.setText(x509cert.getExtendedKeyUsage().toString());
						info_name6.setText(ski.substring(1,41));
						info_name7.setText(String.valueOf(x509cert.getKeyUsage()[0]));
						info_name8.setText(String.valueOf(x509cert.getKeyUsage()[2]));
						info_name9.setText(x509cert.getSubjectAlternativeNames().toString());
						info_name10.setText(x509cert.getIssuerX500Principal().getName());
						info_name11.setText(x509cert.getSerialNumber().toString());
						info_name12.setText(x509cert.getSigAlgName().toString());
						info_name13.setText(x509cert.getSigAlgOID().toString());
						info_name14.setText(x509cert.getSubjectDN().getName());
						info_name15.setText(x509cert.getNotBefore().toString());
						info_name16.setText(x509cert.getNotAfter().toString());
						info_name17.setText(String.valueOf(x509cert.getVersion()));
						info_name18.setText(socket.getSession().getCipherSuite().toString());
						info_name19.setText(socket.getSession().getProtocol().toString());
						
						doc.setRootElement(InfoSet);
						
						
						
						
						 FileOutputStream out = new FileOutputStream("d:\\Info.xml"); 
					      //xml 파일을 떨구기 위한 경로와 파일 이름 지정해 주기
					      XMLOutputter serializer = new XMLOutputter();                 
					                                                                    
					      Format f = serializer.getFormat();                            
					      f.setEncoding("UTF-8");
					      //encoding 타입을 UTF-8 로 설정
					      f.setIndent(" ");                                             
					      f.setLineSeparator("\r\n");                                   
					      f.setTextMode(Format.TextMode.TRIM);                          
					      serializer.setFormat(f);                                      
					                                                                    
					      serializer.output(doc, out);                                  
					      out.flush();                                                  
					      out.close();    
					      
					      //String 으로 xml 출력
					     // XMLOutputter outputter = new XMLOutputter(Format.getPrettyFormat().setEncoding("UTF-8")) ;
					     // System.out.println(outputter.outputString(doc));
						
						
						
						
						
						
						
												
					} catch (SSLPeerUnverifiedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (CertificateParsingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (FileNotFoundException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (IOException e1) {
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
		boolean serverHello = false;
		
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
				
				
				if(pkt.pheader.type == 22 && pkt.ppayload.payload[0] == 0x2){
					parseServerHello(pkt);
				}
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
	
	public void parseServerHello(packet pkt){
		
		System.out.println("Content Type: " +pkt.ppayload.payload[0]);
		System.out.println("Cipher Suite: " + Integer.toHexString(pkt.ppayload.payload[39])+" " + Integer.toHexString(pkt.ppayload.payload[40]));
	}
	
	private static byte sslHello_origin[] = new byte[] {
		0x16, 0x03, 0x03, 0x00, (byte) 0x9a, // Content type = 16: 22 (handshake message); Version = 03 03; Packet length = 008e:142 | 009a: 154
		0x01, 0x00, 0x00, (byte) 0x96, //Message type = 01 (client hello); Length =    00008a: 138         |00 00 96 : 150
		0x03, 0x03, //Client version = 03 03 (TLS 1.2)
		
		0x53, 0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf, 
		(byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 
		0x04, 0x33, (byte) 0xd4, (byte) 0xde,//Random 32B
		
		0x00, //Session id = 00
		0x00, 0x1a, //Cipher suite length 000d:14        001a: 26
		
		0x00, 0x18,
		0x00, 0x20,
		0x00, 0x24,
		0x00, 0x2b,
		0x00, 0x28,
		0x00, (byte) 0x8a,
		0x00, (byte) 0x8e,
		(byte) 0xc0, 0x02,
		(byte) 0xc0, 0x07,
		(byte) 0xc0, 0x0c,
		(byte) 0xc0, 0x11,
		(byte) 0xc0, 0x16,
		(byte) 0xc0, 0x33,
		
		
		
		0x01, //Compression methods length
		0x00, //Compression method 0 : no compression = 0
		0x00, 0x53, //Extension length = 53 : 83
		
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