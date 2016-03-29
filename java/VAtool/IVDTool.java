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
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JProgressBar;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

public class IVDTool {

	public static final int HANDSHAKE = 22;
	public static final int ALERT = 21;
	
	private String host;
	private static int port;

	static boolean hbstart;
	String ski, uki;
	TLSVulnerability tlsvul;
	boolean rc4attack; 
	public String sigAlgName;

//	Info info;
	JSONInfo jsoninfo;

	public IVDTool() {
		host = null;
		port = 443;
		uki = null;
		ski = null;
		hbstart = false;
		tlsvul = new TLSVulnerability();
		rc4attack = false;
		sigAlgName = null;
		
//		info = new Info();
		jsoninfo = new JSONInfo();
	}
	
	public TLSVulnerability getTlsvul(){return tlsvul;}
	
	public void setHost(String host) {
		this.host = host;
	}

	public static ASN1Primitive toDERObject(byte[] data) throws IOException {
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream asnInpuStream = new ASN1InputStream(inStream);

		return asnInpuStream.readObject();
	}

	public SSLSocket socket;
	X509Certificate x509cert;

	public void defaultHandshake() {

		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory
				.getDefault();
		System.out.println("Connecting... " + host + " : " + port);
		
		try {
			socket = (SSLSocket) factory.createSocket(host, port);
		} catch (UnknownHostException e2) {
			// TODO Auto-generated catch block
			JOptionPane.showMessageDialog(null, "Unknown Host Exception\nPlease Re-enter host name");
			e2.printStackTrace();
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
		}
		
		try {	
		
		
			String[] suites = socket.getSupportedCipherSuites();
	//		SSLParameters sp = socket.getSSLParameters();

			socket.setEnabledCipherSuites(suites);
		
			socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {

				public void handshakeCompleted(HandshakeCompletedEvent e) {
					// TODO Auto-generated method stub

					java.security.cert.Certificate lc[];

					System.out.println("Handshake success!");
					System.out.println("Using cipher suite: "
							+ e.getCipherSuite());
					try {
						lc = e.getPeerCertificates();
						x509cert = (X509Certificate) lc[0];

						System.out.println(x509cert.toString());

						byte[] encodedExtensionValueA = x509cert
								.getExtensionValue("2.5.29.35");
						if (encodedExtensionValueA != null) {
							ASN1Primitive extensionValue;
							try {
								extensionValue = JcaX509ExtensionUtils
										.parseExtensionValue(encodedExtensionValueA);
								uki = extensionValue.toString();

							} catch (IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						}

						System.out.println("public key : "
								+ x509cert.getPublicKey());
						System.out
								.println("443.https.tls.certificate.parsed.extensions.basic_constraints : "
										+ x509cert.getBasicConstraints());
						System.out
								.println("443.https.tls.certificate.parsed.extensions.certificate_policies : "
										+ x509cert
												.getExtensionValue("2.5.29.36"));
						System.out
								.println("443.https.tls.certificate.parsed.extensions.extended_key_usage : "
										+ x509cert.getExtendedKeyUsage());

						byte[] encodedExtensionValueB = x509cert
								.getExtensionValue("2.5.29.14");
						if (encodedExtensionValueB != null) {
							ASN1Primitive extensionValue;
							try {
								extensionValue = JcaX509ExtensionUtils
										.parseExtensionValue(encodedExtensionValueB);
								ski = extensionValue.toString();
								System.out
										.println("443.https.tls.certificate.parsed.extensions.subject_key_id : "
												+ ski.substring(1, 41));
							} catch (IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						}
						System.out
								.println("443.https.tls.certificate.parsed.extensions.key_usage.digital_signature : "
										+ x509cert.getKeyUsage()[0]);
						System.out
								.println("443.https.tls.certificate.parsed.extensions.key_usage.key_encipherment : "
										+ x509cert.getKeyUsage()[2]);
						System.out
								.println("443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names : "
										+ x509cert.getSubjectAlternativeNames());
						System.out
								.println("443.https.tls.certificate.parsed.issuer_dn : "
										+ x509cert.getIssuerX500Principal()
												.getName());
						System.out
								.println("443.https.tls.certificate.parsed.serial_number : "
										+ x509cert.getSerialNumber());
						System.out
								.println("443.https.tls.certificate.parsed.signature.signature_algorithm.name : "
										+ x509cert.getSigAlgName());
						System.out
								.println("443.https.tls.certificate.parsed.signature.signature_algorithm.oid : "
										+ x509cert.getSigAlgOID());

						System.out
								.println("443.https.tls.certificate.parsed.subject_dn : "
										+ x509cert.getSubjectDN().getName());

						System.out
								.println("443.https.tls.certificate.parsed.validity.end : "
										+ x509cert.getNotBefore());
						System.out
								.println("443.https.tls.certificate.parsed.validity.start : "
										+ x509cert.getNotAfter());
						System.out
								.println("443.https.tls.certificate.parsed.version : "
										+ x509cert.getVersion());

						System.out.println("443.https.tls.cipher_suite.name : "
								+ socket.getSession().getCipherSuite());
						System.out.println("443.https.tls.version : "
								+ socket.getSession().getProtocol());

						System.out
								.println("https.tls.certificate.parsed.extensions.authority_key_id : "
										+ uki.substring(5, 45));

						sigAlgName =  x509cert.getSigAlgName().toString();
						
						if(sigAlgName.contains("SHA128") || sigAlgName.contains("MD5") || sigAlgName.contains("SHA1")){
							
							tlsvul.sloth.isVulnerable = true;
							tlsvul.sloth.description = new String("The target server supports "+sigAlgName+" signature algorithm");
							tlsvul.sloth.level = new String("Vulnerable");
						}
						
						else{
							tlsvul.sloth.isVulnerable = false;
							tlsvul.sloth.description = new String("The target server does not support MD5 and SHA1 algorithm");
							tlsvul.sloth.level = new String("Secure");
						}
						
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
				}
			});

			socket.startHandshake();

			System.out.println("Connected to "
					+ socket.getRemoteSocketAddress());

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
		
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.out.println("!------------------default error");
			tlsvul.error++;
			//e.printStackTrace();
		}
	}

	public void dataParsing() {
	//	info.setInfo(x509cert, uki, ski, tlsvul, socket, host);
		jsoninfo.setJSONInfo(x509cert, uki, ski, tlsvul, socket, host);
	}

	public void saveFile() {
		//info.saveFile();
		jsoninfo.saveFile();
	}

	public void poddleTest(){
		Socket s;
		InputStream in;
		DataInputStream din;
		OutputStream out;
		tlsvul.isPoodleattack = true;

		// byte[] test_packet = TestPacket.makeTestPacket();
	
		try {
			s = new Socket(host, port);
			
			in = s.getInputStream();
			din = new DataInputStream(in);
			out = s.getOutputStream();

			System.out.println("--Handshake message--");
			System.out.println("Client Hello...");
			out.write(Packet.sslv3_test);

			System.out.println("Waiting for Server Hello...");
			boolean key = false;
			while (!key) {
				Packet pkt = Packet.readPacket(din);
				System.out.println("Handshake: Type:" + pkt.pheader.type
						+ " Ver: " + pkt.pheader.ver + " Len: "
						+ pkt.pheader.len);

				switch (pkt.pheader.type) {
				case HANDSHAKE:
					if (pkt.ppayload.payload[0] == 0x02) {
						tlsvul = pkt.parseServerHello(tlsvul);
					}
					if (pkt.ppayload.payload[0] == 0x0E) {
						key = true;
					}
					break;

				case ALERT:
					System.out.println("Alert Message level: "
							+ pkt.ppayload.payload[0] + " Description: "
							+ pkt.ppayload.payload[1]);
					
					tlsvul.poodle.level = new String("Secure");
					tlsvul.poodle.description = new String("The target server dose not support SSLv3(with CBC mode) it is secure against POODLE attack");
					key = true;
					break;

				default:
					key = true;
					break;
				}
			}

			
			
			s.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			tlsvul.poodle.level = new String("Secure");
			tlsvul.poodle.description = new String("The target server dose not support SSLv3(with CBC mode) it is secure against POODLE attack");
			System.out.println("!------------------POODLE attack error");
			tlsvul.error++;
			//e.printStackTrace();
		}	
		
	}
	
	public void drownTest(){
		Socket socket;
		InputStream in;
		DataInputStream din;
		OutputStream out;
		byte[] headpayload = new byte[9];
		
		try {
			socket = new Socket(host, port);
			in = socket.getInputStream();
			din = new DataInputStream(in);
			out = socket.getOutputStream();
			
			System.out.println("--Handshake message--");
			System.out.println("Client Hello... ---> " +host);
			out.write(Packet.sslv2_test);
			
			System.out.println("Waiting for Server Hello...");
			boolean key = false;
			
			
			int bytelen = 0;
			din.readFully(headpayload);
			
//			System.out.println("header["+0+"]: "+Integer.toHexString(0xff & onebyte[0]));
			byte[] firstlen = new byte[1];
			firstlen[0] = (byte) (headpayload[0]&0x3f);
			bytelen = (headpayload[0]&0x80) == 0x80 ? 2 : 3;
			
			switch(bytelen){
			case 2:
							
				headpayload[0] = firstlen[0];
				
				for(int i=0;i<headpayload.length;i++)
					System.out.println("-----header["+i+"]: "+Integer.toHexString(0xff & headpayload[i]));
				ByteBuffer bb = ByteBuffer.wrap(headpayload);
				int payloadlen  = bb.getShort();
				int HandshakeMsgType = bb.get();
				int sessionIDhit = bb.get();
				int certificatetype = bb.get();
				int version = bb.getShort();
				int certificatelen = bb.getShort();
				
				this.tlsvul.drown.isVulnerable = true;
				this.tlsvul.drown.level = new String("Vulnerable");
				this.tlsvul.drown.description = new String("Server supports SSLv2. It has vulnerability on DROWN attack. ");

				
				break;
			case 3:
				//padding...
				//JOptionPane.showMessageDialog(null, "Padding");
				break;
				
			} 

		

		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
/*
			for(int i=0;i<9;i++)
				System.out.println("-----header["+i+"]: "+Integer.toHexString(0xff & headpayload[i]));
		
			System.out.println("Alert Message level: " + headpayload[5]	+ " Description: " + headpayload[6]	);*/
			this.tlsvul.drown.isVulnerable = false;
			this.tlsvul.drown.level = new String("Secure");
			this.tlsvul.drown.description = new String("Server does not support SSLv2. It is secure against DROWN attack. ");
			tlsvul.error++;
			System.out.println("!------------------Drown error");
			//e.printStackTrace();
		}

	}
	
	public void rc4Test(){
		Socket s;
		InputStream in;
		DataInputStream din;
		OutputStream out;
		tlsvul.isRc4attack = true;

		// byte[] test_packet = TestPacket.makeTestPacket();
	
		try {
			s = new Socket(host, port);
			
			in = s.getInputStream();
			din = new DataInputStream(in);
			out = s.getOutputStream();

			System.out.println("--Handshake message--");
			System.out.println("Client Hello...");
			out.write(Packet.rc4_test);

			System.out.println("Waiting for Server Hello...");
			boolean key = false;
			while (!key) {
				Packet pkt = Packet.readPacket(din);
				System.out.println("Handshake: Type:" + pkt.pheader.type
						+ " Ver: " + pkt.pheader.ver + " Len: "
						+ pkt.pheader.len);

				switch (pkt.pheader.type) {
				case HANDSHAKE:
					if (pkt.ppayload.payload[0] == 0x02) {
						tlsvul = pkt.parseServerHello(tlsvul);
					}
					if (pkt.ppayload.payload[0] == 0x0E) {
						key = true;
					}
					break;

				case ALERT:
					System.out.println("Alert Message level: "
							+ pkt.ppayload.payload[0] + " Description: "
							+ pkt.ppayload.payload[1]);
					key = true;
					tlsvul.rc4.isVulnerable = false;
					tlsvul.rc4.description = new String("The target server does not support RC4 encryption");
					tlsvul.rc4.level = new String("Secure");
			/*		tlsvul.sloth.isVulnerable = false;
					tlsvul.sloth.description = new String("The target server does not support MD5 and SHA1 algorithm");
					tlsvul.sloth.level = new String("Secure");*/
					break;

				default:
					key = true;
					break;
				}
			}

			s.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			tlsvul.error++;
			// TODO Auto-generated catch block
			System.out.println("!------------------RC4 attack error");
			//e.printStackTrace();
		}
	}
	
	public void heartbleadTest() {
		Socket s;
		InputStream in;
		DataInputStream din;
		OutputStream out;
		boolean clientHelloDone = false;
	
		try {
			s = new Socket(host, port);
			
			in = s.getInputStream();
			din = new DataInputStream(in);
			out = s.getOutputStream();

			System.out.println("--Handshake message--");
			System.out.println("Client Hello...");
			out.write(Packet.hb_test);

			System.out.println("Waiting for Server Hello...");
			boolean key = false;
			s.setSoTimeout(2000);
			while (!key) {
				Packet pkt = Packet.readPacket(din);
				System.out.println("Handshake: Type:" + pkt.pheader.type
						+ " Ver: " + pkt.pheader.ver + " Len: "
						+ pkt.pheader.len);

				switch (pkt.pheader.type) {
				case HANDSHAKE:
					if (pkt.ppayload.payload[0] == 0x02) {
						tlsvul = pkt.parseServerHello(tlsvul);
					}
					if (pkt.ppayload.payload[0] == 0x0E) {
						key = true;
						clientHelloDone = true;
					}
					break;

				case ALERT:
					System.out.println("Alert Message level: "
							+ pkt.ppayload.payload[0] + " Description: "
							+ pkt.ppayload.payload[1]);
					key = true;
					break;

				default:
					key = true;
					break;
				}
			}

			if (clientHelloDone) {
				boolean esc = false;
				while (!esc) {
					System.out.println("heartbeat...");
					out.write(Packet.HBrequest);
		
					Packet hpkt = Packet.readPacket(din);

					switch (hpkt.pheader.type) {
					case 24:
						tlsvul.heartbleed.isVulnerable = true;
						System.out.println("Received heartbeat response: ");
						if (hpkt.ppayload.payload.length > 6) {
							tlsvul.heartbleed.description = new String(
									"WARNING: server returned more data than it should - server is vulnerable!");
							tlsvul.heartbleed.level = new String("Vulnerable");
						} else {
							tlsvul.heartbleed.description = new String(
									"Server processed malformed heartbeat, but did not return any extra data");
							tlsvul.heartbleed.level = new String(
									"Weak Vulnerable");
						}
						esc = true;
						break;

					case 21:
						tlsvul.heartbleed.isVulnerable = false;
						System.out.println("Received alert: ");
						tlsvul.heartbleed.description = new String(
								"Server returned error, likely not vulnerable");
						tlsvul.heartbleed.level = new String("Secure");
						esc = true;
						break;
					default:
						tlsvul.heartbleed.isVulnerable = false;
						tlsvul.heartbleed.description = new String(
								"No heartbeat response received, server likely not vulnerable");
						tlsvul.heartbleed.level = new String("Secure");
						esc = true;
						break;
					}
				}

			}

			s.close();
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			tlsvul.error++;
			System.out.println("!------------------Heartbleed error");
			tlsvul.heartbleed.isVulnerable = false;
			tlsvul.heartbleed.description = new String(
					"No heartbeat response received, server likely not vulnerable");
			tlsvul.heartbleed.level = new String("Secure");
			//e.printStackTrace();
		}


	}
	
	public void resetTlsvul(){
		tlsvul.heartbleed.isVulnerable = false;
		tlsvul.heartbleed.description = null;
		tlsvul.heartbleed.level = null;
		tlsvul.rc4.isVulnerable = false;
		tlsvul.rc4.description = null;
		tlsvul.rc4.level = null;
		tlsvul.sloth.isVulnerable = false;
		tlsvul.sloth.description = null;
		tlsvul.sloth.level = null;
		tlsvul.drown.isVulnerable = false;
		tlsvul.drown.description = null;
		tlsvul.drown.level = null;
		tlsvul.poodle.isVulnerable = false;
		tlsvul.poodle.description = null;
		tlsvul.poodle.level = null;
		tlsvul.error = 0;
	}
	
	public void genInfo(){
		dataParsing();
		saveFile();
		
		System.out.println("Heartbleed: " + tlsvul.heartbleed.isVulnerable
				+ "\nDescription: " + tlsvul.heartbleed.description
				+ " \nLevel: " + tlsvul.heartbleed.level);
		System.out.println("RC4: " + tlsvul.rc4.isVulnerable
				+ "\nDescription: " + tlsvul.rc4.description + "\nLevel: "
				+ tlsvul.rc4.level);
		System.out.println("SLOTH: " + tlsvul.sloth.isVulnerable
				+ "\nDescription: " + tlsvul.sloth.description + "\nLevel: "
				+ tlsvul.sloth.level);
		
		System.out.println("DROWN: " + tlsvul.drown.isVulnerable
				+ "\nDescription: " + tlsvul.drown.description
				+ " \nLevel: " + tlsvul.drown.level);
		System.out.println("POODLE: " + tlsvul.poodle.isVulnerable
				+ "\nDescription: " + tlsvul.poodle.description
				+ " \nLevel: " + tlsvul.poodle.level);
		
	}
	



}
