package VAtool;

import java.io.IOException;
import java.net.UnknownHostException;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;


public class IVDTool {
	
	
	SSLSocket socket;
	String host;
	int port;

	
	
	
	public IVDTool(){
		host = null;
		port = 443;
	}

	
	
	
	
	
	
	
	
	
	public void setHost(String host){this.host = host;}
	public void tryHandshake(){
		SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		System.out.println("Connecting... " + host + " : " + port);
		
		try {
			socket = (SSLSocket)factory.createSocket(host, port);
			String[] suites = socket.getSupportedCipherSuites();
	//		socket.setEnabledCipherSuites();
			socket.setEnabledCipherSuites(suites);
			socket.addHandshakeCompletedListener(new HandshakeCompletedListener(){

				public void handshakeCompleted(HandshakeCompletedEvent e) {
					
					
					java.security.cert.Certificate lc[];
			
					// TODO Auto-generated method stub
					
					
					System.out.println("Handshake success!");
					
					 try {
							lc = e.getPeerCertificates();
							X509Certificate t = (X509Certificate) lc[0];
							
							System.out.println(t.toString());
							
						
							
							
						
							byte[] encodedExtensionValue = t.getExtensionValue("2.5.29.35");
							if (encodedExtensionValue != null) {
							    ASN1Primitive extensionValue;
								try {
									extensionValue = JcaX509ExtensionUtils
									        .parseExtensionValue(encodedExtensionValue);
									String values = extensionValue.toString();
									System.out.println("https.tls.certificate.parsed.extensions.authority_key_id : " + values);
								} catch (IOException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}
							}
							
							
							//System.out.println("https.tls.certificate.parsed.extensions.authority_key_id : " + t.getExtensionValue("2.5.29.35"));
							System.out.println("https.tls.certificate.parsed.extensions.basic_constraints : "+ t.getBasicConstraints());
							System.out.println("https.tls.certificate.parsed.extensions.certificate_policies : "+ t.getExtensionValue("2.5.29.36"));
							System.out.println("443.https.tls.certificate.parsed.extensions.extended_key_usage : "+ t.getExtendedKeyUsage());
							System.out.println("443.https.tls.certificate.parsed.extensions.key_usage.digital_signature : " + t.getKeyUsage()[0]);
							System.out.println("443.https.tls.certificate.parsed.extensions.key_usage.key_encipherment : "+ t.getKeyUsage()[2]);
							System.out.println("443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names : " + t.getSubjectAlternativeNames());
							System.out.println("443.https.tls.certificate.parsed.issuer_dn : " + t.getIssuerX500Principal().getName());
							System.out.println("443.https.tls.certificate.parsed.serial_number : " + t.getSerialNumber());
							System.out.println("443.https.tls.certificate.parsed.signature.signature_algorithm.name : " + t.getSigAlgName());
							System.out.println("443.https.tls.certificate.parsed.signature.signature_algorithm.oid : " + t.getSigAlgOID());
							
							
							
							
							System.out.println("443.https.tls.certificate.parsed.signature.value : " + t.getSignature());
							//System.out.println("443.https.tls.certificate.parsed.extensions.subject_key_id : " + t.get);
							System.out.println("443.https.tls.certificate.parsed.subject_dn : " + t.getSubjectDN().getName());
							
							System.out.println("443.https.tls.certificate.parsed.validity.end : " + t.getNotBefore());
							System.out.println("443.https.tls.certificate.parsed.validity.start : " + t.getNotAfter());
							System.out.println("443.https.tls.certificate.parsed.version : "+ t.getVersion());
							
							System.out.println("443.https.tls.cipher_suite.name : "+ socket.getSession().getCipherSuite() );
							System.out.println("443.https.tls.version : "+ socket.getSession().getProtocol() );
							
							
							
						    }
						    catch (SSLPeerUnverifiedException e1) {
							
						    } catch (CertificateEncodingException e1) {
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

}
