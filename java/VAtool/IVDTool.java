package VAtool;

import java.io.IOException;
import java.net.UnknownHostException;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;



public class IVDTool {
	
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
			SSLSocket socket = (SSLSocket)factory.createSocket(host, port);
			String[] suites = socket.getSupportedCipherSuites();
	//		socket.setEnabledCipherSuites();
			socket.setEnabledCipherSuites(suites);
			socket.addHandshakeCompletedListener(new HandshakeCompletedListener(){

				public void handshakeCompleted(HandshakeCompletedEvent e) {
					// TODO Auto-generated method stub
					System.out.println("Handshake success!");
					System.out.println("Using cipher suite: " + e.getCipherSuite());
					try {
						for(int i=0;i<e.getLocalCertificates().length;i++)
						System.out.println("Certificates [" + i +"]: "+ e.getPeerCertificates()[i]);
					} catch (SSLPeerUnverifiedException e1) {
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
