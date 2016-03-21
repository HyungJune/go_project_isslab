package VAtool;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocket;

import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.output.Format;
import org.jdom2.output.XMLOutputter;

public class Info {

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

	public Info() {
		
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

		// InfoVul = new Element("InfoVul");

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

		// InfoVul = new Element("InfoVul");

		/*
		 * InfoSet.addContent(InfoVul);
		 * 
		 * InfoVul.addContent(info_name20); InfoVul.addContent(info_name21);
		 * InfoVul.addContent(info_name22); InfoVul.addContent(info_name23);
		 * InfoVul.addContent(info_name24); InfoVul.addContent(info_name25);
		 * InfoVul.addContent(info_name26); InfoVul.addContent(info_name27);
		 * InfoVul.addContent(info_name28);
		 * 
		 * InfoTargetServer = new Element("InfoTargetServer");
		 * 
		 * info_name29 = new Element("targetServer");
		 * 
		 * InfoSet.addContent(InfoTargetServer);
		 * 
		 * InfoTargetServer.addContent(info_name29);
		 */
	}

	public void setInfo(X509Certificate x509cert, String uki, String ski,
			TLSVulnerability tlsvul, SSLSocket socket, String host) {
		info_name1.setText(x509cert.getPublicKey().toString());
		info_name2.setText(uki.substring(5, 45));
		info_name3.setText(String.valueOf(x509cert.getBasicConstraints()));
		info_name4.setText("null");
		try {
			info_name5.setText(x509cert.getExtendedKeyUsage().toString());
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		info_name6.setText(ski.substring(1, 41));
		info_name7.setText(String.valueOf(x509cert.getKeyUsage()[0]));
		info_name8.setText(String.valueOf(x509cert.getKeyUsage()[2]));
		try {
			info_name9
					.setText(x509cert.getSubjectAlternativeNames().toString());
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
	}

	public void saveFile() {
		Document doc = new Document();
		doc.setRootElement(InfoSet);
		FileOutputStream out;
		try {
		
			out = new FileOutputStream("./info.ivd");
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

}
