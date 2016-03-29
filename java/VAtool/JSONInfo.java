package VAtool;

import java.util.LinkedHashMap;
import java.util.Set;

import javax.net.ssl.SSLSocket;
import javax.swing.JOptionPane;

import org.json.simple.JSONObject;

import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.X509Certificate;

public class JSONInfo {
	private LinkedHashMap<String, String> map;	
	
	public JSONInfo(){
		map = new LinkedHashMap();	
	}
	
	public void setJSONInfo(X509Certificate x509cert, String uki, String ski, TLSVulnerability tlsvul, SSLSocket socket, String host){
		map.put("public_key_parameter", x509cert.getPublicKey().toString());

		if(uki == null)
			map.put("authority_key_id", null);
		else
			map.put("authority_key_id", uki.substring(5,45));
		map.put("basic_constraints", String.valueOf(x509cert.getBasicConstraints()));
		map.put("certificate_policies", null);
		try{
			map.put("extened_key_usage", x509cert.getExtendedKeyUsage().toString());
		} catch (java.security.cert.CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (ski == null)
			map.put("subject_key_id", null);
		else
			map.put("subject_key_id", ski.substring(1, 41));
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
		map.put("drownName", tlsvul.drown.name);
		map.put("drownLevel", tlsvul.drown.level);
		map.put("drownDesc", tlsvul.drown.description);
		map.put("poodleName", tlsvul.poodle.name);
		map.put("poodleLevel", tlsvul.poodle.level);
		map.put("poodleDesc", tlsvul.poodle.description);
		
		map.put("targetServer", host);
		
		//////////////////////////////////////////////////
		String delims = "[\n]";
		String[] public_key_parse =  x509cert.getPublicKey().toString().split(delims);
		String[] public_key_info = public_key_parse[0].split("[ ]");
		String public_key = public_key_info[1] + " " + public_key_info[4] + " " + public_key_info[5];
		System.out.println(public_key);
		
		map.put("publickey", public_key);
		
		String[] issuer_parse = x509cert.getIssuerX500Principal().getName().split("[,]");
		String[] issuer = issuer_parse[0].split("[=]");
		System.out.println(issuer[1]);
		
		map.put("issuer", issuer[1]);
		
		String[] subject_parse = x509cert.getSubjectDN().getName().split("[,]");
		String[] subject = subject_parse[0].split("[=]");
		
		System.out.println(subject[1]);
		
		map.put("subject", subject[1]);

	}
	
	public void saveFile(){
		JSONObject obj = new JSONObject();
		Set<String> keys = map.keySet();
		System.out.println("---------------------Test JSON -------------");
		obj.putAll(map);
		String key = "1234567891234567";
		
		try{
			FileWriter file = new FileWriter("./info.ivd");
			file.write(Security.encrypt(obj.toJSONString(),key));
			//file.write(obj.toJSONString());
			file.flush();
			file.close();
		}catch(IOException e){
			e.printStackTrace();
		}
		
		System.out.print(obj);
	}
}
