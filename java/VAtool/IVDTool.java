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
import java.util.HashMap;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;


public class IVDTool {
	
	public static final int HANDSHAKE = 22;
	public static final int ALERT = 21;
	
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
	
	static boolean hbstart;
	String ski, uki;
	TLSVulnerability tlsvul;
	HashMap<String, String> ciphersuiteMap;
	
	Element InfoSet;	
	Element InfoCert;
	Element InfoVul;
	Element InfoTargetServer;
	
	Element info_name1;
	Element info_name2;
	Element info_name3;
	Element info_name4;
	Element info_name5;
	Element info_name6;
	Element info_name7;
	Element info_name8;
	Element info_name9;
	Element info_name10;
	Element info_name11;
	Element info_name12;
	Element info_name13;
	Element info_name14;
	Element info_name15;
	Element info_name16;
	Element info_name17;
	Element info_name18;
	Element info_name19;
	
	Element info_name20;
	Element info_name21;
	Element info_name22;
	Element info_name23;
	Element info_name24;
	Element info_name25;	
	Element info_name26;
	Element info_name27;
	Element info_name28;
	
	Element info_name29;
	public IVDTool(){
		host = null;
		port = 443;
		uki = null;
		ski = null;
		hbstart = false;
		tlsvul = new TLSVulnerability();
		ciphersuiteMap = new HashMap<String, String>();
		ciphersuiteMap.put("018", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5");
		ciphersuiteMap.put("020", "TLS_KRB5_WITH_RC4_128_SHA");
		ciphersuiteMap.put("024", "TLS_KRB5_WITH_RC4_128_MD5");
		ciphersuiteMap.put("02b", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5");
		ciphersuiteMap.put("028", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA");
		ciphersuiteMap.put("08a", "TLS_PSK_WITH_RC4_128_SHA");
		ciphersuiteMap.put("08e", "TLS_DHE_PSK_WITH_RC4_128_SHA");
		ciphersuiteMap.put("c002", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA");
		ciphersuiteMap.put("c007", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA");
		ciphersuiteMap.put("c00c", "TLS_ECDH_RSA_WITH_RC4_128_SHA");
		ciphersuiteMap.put("c011", "TLS_ECDHE_RSA_WITH_RC4_128_SHA");
		ciphersuiteMap.put("c016", "TLS_ECDH_anon_WITH_RC4_128_SHA");
		ciphersuiteMap.put("c033", "TLS_ECDHE_PSK_WITH_RC4_128_SHA");
		
		ciphersuiteMap.put("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", "MD5");
		ciphersuiteMap.put("TLS_KRB5_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_KRB5_WITH_RC4_128_MD5", "MD5");
		ciphersuiteMap.put("TLS_KRB5_EXPORT_WITH_RC4_40_MD5", "MD5");
		ciphersuiteMap.put("TLS_KRB5_EXPORT_WITH_RC4_40_SHA", "SHA1");
		ciphersuiteMap.put("TLS_PSK_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_DHE_PSK_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_ECDH_ECDSA_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_ECDH_RSA_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_ECDHE_RSA_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_ECDH_anon_WITH_RC4_128_SHA", "SHA1");
		ciphersuiteMap.put("TLS_ECDHE_PSK_WITH_RC4_128_SHA", "SHA1");
		
		 InfoSet = new Element("InfoSet");
		 
		 InfoCert = new Element("InfoCert");
		 
		  info_name1 = new Element("public_key");
		 info_name2 = new Element("authority_key_id");
		 info_name3 = new Element("basic_constraints");
		 info_name4 = new Element("certificate_policies");
		 info_name5 = new Element("extended_key_usage");
		 info_name6 = new Element("subject_key_id");
		 info_name7 = new Element("digital_signature");
		 info_name8 = new Element("key_encipherment");
		 info_name9 = new Element("dns_names");
		 info_name10 = new Element("issuer_dn");
		 info_name11 = new Element("serial_number");
		 info_name12 = new Element("signature_algorithm");
		 info_name13 = new Element("signature_algorithm_oid");
		 info_name14 = new Element("subject_dn");
		 info_name15 = new Element("validity_end");
		 info_name16 = new Element("validity_start");
		 info_name17 = new Element("version");
		 info_name18 = new Element("cipher_suite_name");
		 info_name19 = new Element("tls_version");
		
		InfoSet.addContent(InfoCert);
		
		InfoCert.addContent(info_name1);
		InfoCert.addContent(info_name2);
		InfoCert.addContent(info_name3);
		InfoCert.addContent(info_name4);
		InfoCert.addContent(info_name5);
		InfoCert.addContent(info_name6);
		InfoCert.addContent(info_name7);
		InfoCert.addContent(info_name8);
		InfoCert.addContent(info_name9);
		InfoCert.addContent(info_name10);
		InfoCert.addContent(info_name11);
		InfoCert.addContent(info_name12);
		InfoCert.addContent(info_name13);
		InfoCert.addContent(info_name14);
		InfoCert.addContent(info_name15);
		InfoCert.addContent(info_name16);
		InfoCert.addContent(info_name17);
		InfoCert.addContent(info_name18);
		InfoCert.addContent(info_name19);
		
//		InfoVul = new Element("InfoVul");		
		
		
		info_name20 = new Element("hbName");
		info_name21 = new Element("hbLevel");		
		info_name22 = new Element("hbDesc");		
		info_name23 = new Element("rc4Name");		
		info_name24 = new Element("rc4Level");		
		info_name25 = new Element("rc4Desc");
		info_name26 = new Element("slothName");
		info_name27 = new Element("slothLevel");
		info_name28 = new Element("slothDesc");
		info_name29 = new Element("targetServer");
				
		InfoCert.addContent(info_name20);
		InfoCert.addContent(info_name21);
		InfoCert.addContent(info_name22);
		InfoCert.addContent(info_name23);
		InfoCert.addContent(info_name24);
		InfoCert.addContent(info_name25);
		InfoCert.addContent(info_name26);
		InfoCert.addContent(info_name27);
		InfoCert.addContent(info_name28);
		InfoCert.addContent(info_name29);
		
/*		InfoSet.addContent(InfoVul);
		
		InfoVul.addContent(info_name20);
		InfoVul.addContent(info_name21);
		InfoVul.addContent(info_name22);
		InfoVul.addContent(info_name23);
		InfoVul.addContent(info_name24);
		InfoVul.addContent(info_name25);
		InfoVul.addContent(info_name26);
		InfoVul.addContent(info_name27);
		InfoVul.addContent(info_name28);
		
		InfoTargetServer = new Element("InfoTargetServer");
		
		info_name29 = new Element("targetServer");
		
		InfoSet.addContent(InfoTargetServer);
		
		InfoTargetServer.addContent(info_name29);*/
		
	}
	
	public void start(){
		this.defaultHandshake();
		while(true){
			if(socket.isClosed()){
    			this.heartbleadTest();
    			break;
			}
		}
		System.out.println("Real END!");
	}
			
	public void setHost(String host){this.host = host;}
	
	public static ASN1Primitive toDERObject(byte[] data) throws IOException{
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream asnInpuStream = new ASN1InputStream(inStream);
		
		return asnInpuStream.readObject();
	}

	 SSLSocket socket;
	 X509Certificate x509cert;
	 
	public void defaultHandshake(){

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		System.out.println("Connecting... " + host + " : " + port);
		try {
			socket = (SSLSocket)factory.createSocket(host, port);
		
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
						x509cert = (X509Certificate) lc[0];
						
						System.out.println(x509cert.toString());
						
						byte[] encodedExtensionValueA = x509cert.getExtensionValue("2.5.29.35");
						if (encodedExtensionValueA != null) {
						    ASN1Primitive extensionValue;
							try {
								extensionValue = JcaX509ExtensionUtils.parseExtensionValue(encodedExtensionValueA);
								uki = extensionValue.toString();
								
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
						
						System.out.println("https.tls.certificate.parsed.extensions.authority_key_id : " + uki.substring(5,45));
						
						socket.close();
												
					} catch (SSLPeerUnverifiedException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (CertificateParsingException e1) {
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

	
	public void dataParsing(){
//		Document doc = new Document();
				
		info_name1.setText(x509cert.getPublicKey().toString());
		info_name2.setText(uki.substring(5,45));
		info_name3.setText(String.valueOf(x509cert.getBasicConstraints()));
		info_name4.setText("null");
		try {
			info_name5.setText(x509cert.getExtendedKeyUsage().toString());
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		info_name6.setText(ski.substring(1,41));
		info_name7.setText(String.valueOf(x509cert.getKeyUsage()[0]));
		info_name8.setText(String.valueOf(x509cert.getKeyUsage()[2]));
		try {
			info_name9.setText(x509cert.getSubjectAlternativeNames().toString());
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
		info_name20.setText(tlsvul.heartbleed.name);
		info_name21.setText(tlsvul.heartbleed.level);
		info_name22.setText(tlsvul.heartbleed.description);
		info_name23.setText(tlsvul.rc4.name);
		info_name24.setText(tlsvul.rc4.level);
		info_name25.setText(tlsvul.rc4.description);
		info_name26.setText(tlsvul.sloth.name);
		info_name27.setText(tlsvul.sloth.level);
		info_name28.setText(tlsvul.sloth.description);
					
		info_name29.setText(host);
		/*doc.setRootElement(InfoSet);
		
		return doc;*/
	}
	
	public void saveFile(){
		Document doc = new Document();
		doc.setRootElement(InfoSet);
		FileOutputStream out;
		try {
			out = new FileOutputStream("./info.xml");
			XMLOutputter serializer = new XMLOutputter();
			
			Format f = serializer.getFormat();
			f.setEncoding("UTF-8");
			f.setIndent(" ");
			f.setLineSeparator("\r\n");                                   
		      f.setTextMode(Format.TextMode.TRIM);                          
		      serializer.setFormat(f);                                      
		                                                                    
		      serializer.output(doc, out);   
		      out.flush();                                                  
		      out.close();  
		      
		} catch (FileNotFoundException e) {
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
		boolean clientHelloDone = false;
		
		System.out.println("\t\t\t\t\t\t\t\t\t\t\t\tuki: "+uki);
		
//		byte[] test_packet = TestPacket.makeTestPacket();
		
		try {
			s = new Socket(host, port);
			in = s.getInputStream();
			din = new DataInputStream(in);
			out = s.getOutputStream();
			
			System.out.println("--Handshake message--");
			System.out.println("Client Hello...");
			out.write(sslHello_origin);
			
			System.out.println("Waiting for Server Hello...");
			boolean key = false;
			while(!key){
				packet pkt = readPacket(din);
				System.out.println("Handshake: Type:" + pkt.pheader.type + " Ver: " + pkt.pheader.ver + " Len: " + pkt.pheader.len);
				
				switch(pkt.pheader.type){
				case HANDSHAKE:
					if(pkt.ppayload.payload[0] == 0x02){
						parseServerHello(pkt);
					}
					if(pkt.ppayload.payload[0] == 0x0E){
						key = true;
						clientHelloDone = true;
					}
					break;
					
				case ALERT:
					System.out.println("Alert Message level: "+pkt.ppayload.payload[0]+" Description: "+pkt.ppayload.payload[1]);
					key = true;
					break;
						
				default:
					key = true;
						break;
				}				
			}
			
			if(clientHelloDone){
				boolean esc = false;
			while(!esc){
				System.out.println("headtbeat...");
				out.write(sslHB);
				packet hpkt = readPacket(din);
	/*			System.out.println("Heartbeat: Type:" + hpkt.pheader.type + " Ver: " + hpkt.pheader.ver + " Len: " + hpkt.pheader.len);
				
				System.out.print("Heartbeat payload: ");
				for(int i=0;i<hpkt.ppayload.payload.length;i++)
					System.out.print(hpkt.ppayload.payload[i] + " // ");
				System.out.println();*/
				switch(hpkt.pheader.type){
				case 24:
					tlsvul.heartbleed.isVulnerable = true;
					System.out.println("Received heartbeat response: ");
					if(hpkt.ppayload.payload.length>6){
						tlsvul.heartbleed.description= new String("WARNING: server returned more data than it should - server is vulnerable!");
						tlsvul.heartbleed.level = new String("Vulnerable");
					}
					else{
						tlsvul.heartbleed.description = new String("Server processed malformed heartbeat, but did not return any extra data");
						tlsvul.heartbleed.level = new String("Weak Vulnerable");
					}
					esc = true;
					break;
					
				case 21:
					tlsvul.heartbleed.isVulnerable = false;
					System.out.println("Received alert: ");
					tlsvul.heartbleed.description= new String("Server returned error, likely not vulnerable");
					tlsvul.heartbleed.level = new String("Secure");
					esc = true;
					break;
				default:
					tlsvul.heartbleed.isVulnerable = false;
					tlsvul.heartbleed.description = new String("No heartbeat response received, server likely not vulnerable");
					tlsvul.heartbleed.level = new String("Secure");
					esc = true;
					break;
				}
			}
			
			}
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	
		System.out.println("Heartbleed: "+tlsvul.heartbleed.isVulnerable+"\nDescription: "+tlsvul.heartbleed.description+" \nLevel: "+tlsvul.heartbleed.level);
		System.out.println("RC4: " + tlsvul.rc4.isVulnerable + "\nDescription: "+tlsvul.rc4.description+"\nLevel: "+tlsvul.rc4.level);
		System.out.println("SLOTH: "+tlsvul.sloth.isVulnerable +"\nDescription: "+tlsvul.sloth.description + "\nLevel: "+tlsvul.sloth.level);
		
	//	dataParsing(tlsvul);
		
		System.out.println("어서와 여기가 마지막이야.");
		dataParsing();
		saveFile();
		
		tlsvul.heartbleed.isVulnerable = false;
		tlsvul.heartbleed.description = null;
		tlsvul.heartbleed.level = null;
		tlsvul.rc4.isVulnerable = false;
		tlsvul.rc4.description = null;
		tlsvul.rc4.level = null;
		tlsvul.sloth.isVulnerable = false;
		tlsvul.sloth.description = null;
		tlsvul.sloth.level = null;
		
	
		
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
		int ciphersuiteIdx = pkt.ppayload.payload[38]+38+1;
		System.out.println("ciphersuiteIdx: "+ciphersuiteIdx);
		String selectedCipher = new String(Integer.toHexString(0xff & pkt.ppayload.payload[ciphersuiteIdx])+""+Integer.toHexString(0xff & pkt.ppayload.payload[ciphersuiteIdx+1]));
		System.out.println("Cipher Suite: " + selectedCipher);
		
		if(ciphersuiteMap.containsKey(selectedCipher)){
			tlsvul.rc4.isVulnerable = true;
			tlsvul.rc4.description = new String("The target server selected \""+ciphersuiteMap.get(selectedCipher)+"\" Which is included in vulnerable cipher suites");
			tlsvul.rc4.level = new String("Vulnerable");
			tlsvul.sloth.isVulnerable = true;
			tlsvul.sloth.description = new String("The target server selected "+ciphersuiteMap.get(ciphersuiteMap.get(selectedCipher)));
			tlsvul.sloth.level = new String("Vulnerable");
		}
		
/*		for(int i=0;i<pkt.ppayload.payload.length;i++)
			System.out.print("payload["+i+"]: "+pkt.ppayload.payload[i]+"\t");
		
		System.out.println();*/
		
	}
	
	private static byte sslHello_origin[] = new byte[] {
		0x16, 0x03, 0x03, 0x00, (byte) 0x9a, // Content type = 16: 22 (handshake message); Version = 03 03; Packet length = 008e:142 | 009a: 154 | 004e: 78
		0x01, 0x00, 0x00, (byte) 0x96, //Message type = 01 (client hello); Length =    00008a: 138         |00 00 96 : 150      | 004a: 74        
		0x03, 0x03, //Client version = 03 03 (TLS 1.2)
		
		0x53, 0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf, 
		(byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 
		0x04, 0x33, (byte) 0xd4, (byte) 0xde,//Random 32B
		
		0x00, //Session id = 00
		0x00, 0x1a, //Cipher suite length 000e:14        001a: 26
		
		CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5[0], CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5[1],
		//CipherSuite.TLS_KRB5_WITH_RC4_128_SHA[0], CipherSuite.TLS_KRB5_WITH_RC4_128_SHA[1],
		
		CipherSuite.TLS_KRB5_WITH_RC4_128_MD5[0], CipherSuite.TLS_KRB5_WITH_RC4_128_MD5[1],
		CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5[0], CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_MD5[1],
		CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA[0], CipherSuite.TLS_KRB5_EXPORT_WITH_RC4_40_SHA[1],
		CipherSuite.TLS_PSK_WITH_RC4_128_SHA[0], CipherSuite.TLS_PSK_WITH_RC4_128_SHA[1],
		
		CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA[0], CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA[0], CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA[1],
		CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA[0], CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA[1], 
		CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA[0], CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA[1], 
		CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA[0], CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA[1], 
		CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA[0], CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA[1], 
		CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA[0], CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA[1], 
		CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256[0], CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256[1],
//		CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256[0], CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256[1],
		0x01, //Compression methods length
		0x00, //Compression method 0 : no compression = 0
		0x00, 0x53, //Extension length = 0x53 : 83 |  0x13: 19 
	
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
