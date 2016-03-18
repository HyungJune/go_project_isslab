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

	Info info;
	JSONInfo json_info;

	public IVDTool() {
		host = null;
		port = 443;
		uki = null;
		ski = null;
		hbstart = false;
		tlsvul = new TLSVulnerability();

		info = new Info();

	}

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
			JOptionPane.showMessageDialog(null, "Unknown Host Exception");
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
			e.printStackTrace();
		}
	}

	public void dataParsing() {
		json_info = new JSONInfo(x509cert, uki, ski, tlsvul, socket, host);
		info.setInfo(x509cert, uki, ski, tlsvul, socket, host);
	}

	public void saveFile() {
		json_info.saveFile();
		info.saveFile();

	}

	public void drownTest(){
		Socket socket;
		InputStream in;
		DataInputStream din;
		OutputStream out;

		try {
			socket = new Socket(host, port);
			in = socket.getInputStream();
			din = new DataInputStream(in);
			out = socket.getOutputStream();

			System.out.println("--Handshake message--");
			System.out.println("Client Hello... ---> " +host);
			out.write(Packet.sslv2);

			System.out.println("Waiting for Server Hello...");
			boolean key = false;

			byte[] onebyte = new byte[1];
			int bytelen = 0;
			din.readFully(onebyte);

			System.out.println("header["+0+"]: "+Integer.toHexString(0xff & onebyte[0]));
			byte[] firstlen = new byte[1];
			firstlen[0] = (byte) (onebyte[0]&0x3f);
			bytelen = (onebyte[0]&0x80) == 0x80 ? 2 : 3;
			switch(bytelen){
			case 2:
				byte[] head = new byte[8];
				din.readFully(head);
				byte[] header = new byte[9];
				header[0] = firstlen[0];
				header[1] = head[0];
				header[2] = head[1];
				header[3] = head[2];
				header[4] = head[3];
				header[5] = head[4];
				header[6] = head[5];
				header[7] = head[6];
				header[8] = head[7];
				for(int i=0;i<header.length;i++)
					System.out.println("-----header["+i+"]: "+Integer.toHexString(0xff & header[i]));
				ByteBuffer bb = ByteBuffer.wrap(header);
				int payloadlen  = bb.getShort();
				int HandshakeMsgType = bb.get();
				int sessionIDhit = bb.get();
				int certificatetype = bb.get();
				int version = bb.getShort();
				int certificatelen = bb.getShort();


				break;
			case 3:
				//padding...
				JOptionPane.showMessageDialog(null, "Padding");
				break;

			}

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
					break;

				default:
					key = true;
					break;
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

	public void heartbleadTest() {
		Socket s;
		InputStream in;
		DataInputStream din;
		OutputStream out;
		boolean clientHelloDone = false;

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
					out.write(sslHB);

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
			e.printStackTrace();
		}

		System.out.println("Heartbleed: " + tlsvul.heartbleed.isVulnerable
				+ "\nDescription: " + tlsvul.heartbleed.description
				+ " \nLevel: " + tlsvul.heartbleed.level);
		System.out.println("RC4: " + tlsvul.rc4.isVulnerable
				+ "\nDescription: " + tlsvul.rc4.description + "\nLevel: "
				+ tlsvul.rc4.level);
		System.out.println("SLOTH: " + tlsvul.sloth.isVulnerable
				+ "\nDescription: " + tlsvul.sloth.description + "\nLevel: "
				+ tlsvul.sloth.level);

		// dataParsing(tlsvul);




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

		//JOptionPane.showMessageDialog(null, "hello world c");

	}

	private static byte sslHB[] = new byte[] {
			0x18, 0x03, 0x03, 	// content type: 18: 24, version: 0303 TLS1.2,
			0x00, 0x19,		 		//length: 0019: 25
			0x01, 					// Heartbeat MessageType: request
			0x00, 0x06,			 	// payload_length: 0006
			0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // The padding.Len MUST be  at least 16: default 16.
	};

}
