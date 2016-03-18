package VAtool;

import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;

import javax.net.ssl.SSLSocket;
import javax.security.cert.CertificateParsingException;

import org.jdom2.Element;
import org.json.simple.JSONObject;

public class JSONInfo {
	private HashMap<String, String> map = new HashMap<String, String>();
	
	public JSONInfo(X509Certificate x509cert, String uki, String ski, TLSVulnerability tlsvul, SSLSocket socket, String host){
		map.put("public_key", x509cert.getPublicKey().toString());
		map.put("authority_key_id", uki.substring(5,45));
		map.put("basic_constraints", String.valueOf(x509cert.getBasicConstraints()));
		map.put("certificate_policies", null);
		try{
			map.put("extened_key_usage", x509cert.getExtendedKeyUsage().toString());
		} catch (java.security.cert.CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		map.put("subject_key_id", ski.substring(1,41));
		map.put("digital_signature", String.valueOf(x509cert.getKeyUsage()[0]));
		map.put("key_encipherment", String.valueOf(x509cert.getKeyUsage()[2]));
		try{
			map.put("dns_names", x509cert.getSubjectAlternativeNames().toString());
		}catch(java.security.cert.CertificateParsingException e){
			e.printStackTrace();
		}
		map.put("issuer_dn", x509cert.getIssuerX500Principal().getName());
		map.put("serial_number", x509cert.getSerialNumber().toString());
		map.put("signature_algorithm", x509cert.getSigAlgName().toString());
		map.put("signature_algorithm_oid", x509cert.getSigAlgOID().toString());
		map.put("subject_dn", x509cert.getSubjectDN().getName());
		map.put("validity_end", x509cert.getNotBefore().toString());
		map.put("validity_start", x509cert.getNotAfter().toString());
		map.put("version", String.valueOf(x509cert.getVersion()));
		map.put("cipher_suite_name", socket.getSession().getCipherSuite().toString());
		map.put("tls_version", socket.getSession().getProtocol().toString());
		
		map.put("hbName", tlsvul.heartbleed.name);
		map.put("hbLevel", tlsvul.heartbleed.level);
		map.put("hbDesc", tlsvul.heartbleed.description);
		map.put("rc4Name", tlsvul.rc4.name);
		map.put("rc4Level", tlsvul.rc4.level);
		map.put("rc4Desc", tlsvul.rc4.description);
		map.put("slothName", tlsvul.sloth.name);
		map.put("slothLevel", tlsvul.sloth.level);
		map.put("slothDesc", tlsvul.sloth.description);
		map.put("targetServer", host);
	}
	
	public void saveFile(){
		JSONObject obj = new JSONObject();
		Iterator<String> keys = map.keySet().iterator();
		System.out.println("---------------------Test JSON -------------");
		while(keys.hasNext()){
			String key = keys.next();
			obj.put(key, map.get(key));
		}
		
		try{
			FileWriter file = new FileWriter("./info.json");
			file.write(obj.toJSONString());
			file.flush();
			file.close();
		}catch(IOException e){
			e.printStackTrace();
		}
		
		System.out.print(obj);
	}
}