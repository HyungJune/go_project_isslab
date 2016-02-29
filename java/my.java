import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


public class my {
	private boolean mHeartbeatResponseWasDetetected; 
	private boolean mHeartbeatRequestWasInjected; 
	private int mFirstDetectedFatalAlertDescription = -1; 
	public static abstract class TlsProtocols { 
        public static final int CHANGE_CIPHER_SPEC = 20; 
        public static final int ALERT = 21; 
        public static final int HANDSHAKE = 22; 
        public static final int APPLICATION_DATA = 23; 
        public static final int HEARTBEAT = 24; 
        private TlsProtocols() {} 
    } 
	private static class SSLPacket { 
	 	int type, ver, len; 
		byte[] pay = null; 
		
		public SSLPacket(int type, int ver, int len) { 
		 	this.type = type; 
			this.ver = ver; 
		 	this.len = len; 
		 } 
	}; 
	private static byte sslHb[] = new byte[] { 
	 		0x18, 0x03, 0x02, 0x00, 0x03, 
	 		0x01, 0x40, 0x00 
	}; 
	private static abstract class HeartbeatProtocol { 
		private HeartbeatProtocol() {} 
		
		private static final int MESSAGE_TYPE_REQUEST = 1; 
		@SuppressWarnings("unused") 
		private static final int MESSAGE_TYPE_RESPONSE = 2; 
		
		private static final int MESSAGE_HEADER_LENGTH = 3; 
		private static final int MESSAGE_PADDING_LENGTH = 16; 
	} 
	  
	public static class TlsRecord { 
        public int protocol; 
        public int versionMajor; 
        public int versionMinor; 
        public byte[] fragment; 
 
        public static TlsRecord parse(byte[] record) throws IOException { 
            TlsRecord result = new TlsRecord(); 
            if (record.length < TlsRecordReader.RECORD_HEADER_LENGTH) { 
                throw new IOException("Record too short: " + record.length); 
            } 
            result.protocol = record[0] & 0xff; 
            result.versionMajor = record[1] & 0xff; 
            result.versionMinor = record[2] & 0xff; 
            int fragmentLength = getUnsignedShortBigEndian(record, 3); 
            int actualFragmentLength = record.length - TlsRecordReader.RECORD_HEADER_LENGTH; 
            if (fragmentLength != actualFragmentLength) { 
                throw new IOException("Fragment length mismatch. Expected: " + fragmentLength 
                        + ", actual: " + actualFragmentLength); 
            } 
            result.fragment = new byte[fragmentLength]; 
            System.arraycopy( 
                    record, TlsRecordReader.RECORD_HEADER_LENGTH, 
                    result.fragment, 0, 
                    fragmentLength); 
            return result; 
        } 
 
        public static byte[] unparse(TlsRecord record) { 
            byte[] result = new byte[TlsRecordReader.RECORD_HEADER_LENGTH + record.fragment.length]; 
            result[0] = (byte) record.protocol; 
            result[1] = (byte) record.versionMajor; 
            result[2] = (byte) record.versionMinor; 
            putUnsignedShortBigEndian(result, 3, record.fragment.length); 
            System.arraycopy( 
                    record.fragment, 0, 
                    result, TlsRecordReader.RECORD_HEADER_LENGTH, 
                    record.fragment.length); 
            return result; 
        } 
    } 
	
	public static class TlsRecordReader {
		private static final int MAX_RECORD_LENGTH = 16384; 
		public static final int RECORD_HEADER_LENGTH = 5;
		
		private final InputStream in; 
		private final byte[] buffer; 
		private int firstBufferedByteOffset;
		private int bufferedByteCount; 
		    /** 
     * Reader of TLS records. 
     */ 
		public TlsRecordReader(InputStream in) { 
			this.in = in; 
			 buffer = new byte[MAX_RECORD_LENGTH]; 
		}
		/** 
		 *           * Reads the next TLS record. 
         * 
         * @return TLS record or {@code null} if EOF was encountered before any bytes of a record 
         *         could be read. 
         */ 
		public byte[] readRecord() throws IOException { 
             // Ensure that a TLS record header (or more) is in the buffer. 
             if (bufferedByteCount < RECORD_HEADER_LENGTH) { 
                 boolean eofPermittedInstead = (bufferedByteCount == 0); 
                 boolean eofEncounteredInstead = 
                         !readAtLeast(RECORD_HEADER_LENGTH, eofPermittedInstead); 
                 if (eofEncounteredInstead) { 
                     // End of stream reached exactly before a TLS record start. 
                     return null; 
                 } 
             } 
  
             // TLS record header (or more) is in the buffer. 
             // Ensure that the rest of the record is in the buffer. 
             int fragmentLength = getUnsignedShortBigEndian(buffer, firstBufferedByteOffset + 3); 
             int recordLength = RECORD_HEADER_LENGTH + fragmentLength; 
             if (recordLength > MAX_RECORD_LENGTH) { 
                 throw new IOException("TLS record too long: " + recordLength); 
             } 
             if (bufferedByteCount < recordLength) { 
                 readAtLeast(recordLength - bufferedByteCount, false); 
             } 
  
             // TLS record (or more) is in the buffer. 
             byte[] record = new byte[recordLength]; 
             System.arraycopy(buffer, firstBufferedByteOffset, record, 0, recordLength); 
             firstBufferedByteOffset += recordLength; 
             bufferedByteCount -= recordLength; 
             return record; 
         }
		 /** 
         * Reads at least the specified number of bytes from the underlying {@code InputStream} into 
         * the {@code buffer}. 
         * 
         * <p>Bytes buffered but not yet returned to the client in the {@code buffer} are relocated 
         * to the start of the buffer to make space if necessary. 
         * 
         * @param eofPermittedInstead {@code true} if it's permitted for an EOF to be encountered 
         *        without any bytes having been read. 
         * 
         * @return {@code true} if the requested number of bytes (or more) has been read, 
         *         {@code false} if {@code eofPermittedInstead} was {@code true} and EOF was 
         *         encountered when no bytes have yet been read. 
         */
		private boolean readAtLeast(int size, boolean eofPermittedInstead) throws IOException { 
             ensureRemainingBufferCapacityAtLeast(size); 
             boolean firstAttempt = true; 
             while (size > 0) { 
                 int chunkSize = in.read( 
                         buffer, 
                         firstBufferedByteOffset + bufferedByteCount, 
                         buffer.length - (firstBufferedByteOffset + bufferedByteCount)); 
                 if (chunkSize == -1) { 
                     if ((firstAttempt) && (eofPermittedInstead)) { 
                         return false; 
                     } else { 
                         throw new EOFException("Premature EOF"); 
                     } 
                 } 
                 firstAttempt = false; 
                 bufferedByteCount += chunkSize; 
                 size -= chunkSize; 
             } 
             return true; 
        } 
		/** 
         * Ensures that there is enough capacity in the buffer to store the specified number of 
         * bytes at the {@code firstBufferedByteOffset + bufferedByteCount} offset. 
         */ 
        private void ensureRemainingBufferCapacityAtLeast(int size) throws IOException { 
            int bufferCapacityRemaining = 
                    buffer.length - (firstBufferedByteOffset + bufferedByteCount); 
            if (bufferCapacityRemaining >= size) { 
                return; 
            } 
            // Insufficient capacity at the end of the buffer. 
            if (firstBufferedByteOffset > 0) { 
                // Some of the bytes at the start of the buffer have already been returned to the 
                // client of this reader. Check if moving the remaining buffered bytes to the start 
                // of the buffer will make enough space at the end of the buffer. 
                bufferCapacityRemaining += firstBufferedByteOffset; 
                if (bufferCapacityRemaining >= size) { 
                    System.arraycopy(buffer, firstBufferedByteOffset, buffer, 0, bufferedByteCount); 
                    firstBufferedByteOffset = 0; 
                    return; 
                } 
            } 
 
            throw new IOException("Insuffucient remaining capacity in the buffer. Requested: " 
                    + size + ", remaining: " + bufferCapacityRemaining); 
        } 
	}
	public static void main(String[] args){
	/*	String https_url = "https://isslab.korea.ac.kr";
		int port = 443;
		TrustManager[] trustAllCerts = new TrustManager[]{
				new X509TrustManager(){
					public java.security.cert.X509Certificate[] getAcceptedIssuers(){
						return null;
					}
					public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType){
						
					}
					public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType){
						
					}
				}
		};
		try{
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		
		URL url = new URL(https_url);
		
		SSLSocketFactory sf = sc.getSocketFactory();
		SSLSocket con = (SSLSocket) sf.createSocket("google.co.kr",  port);
		InputStream in = con.getInputStream();
		DataInputStream din = new DataInputStream(in);
		OutputStream out = con.getOutputStream();
		
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
		}catch(MalformedURLException e){
			e.printStackTrace();
		}catch(IOException e){
			e.printStackTrace();
		}catch(Exception e){
			e.printStackTrace();
		}*/
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
	
	private void forwardTlsRecords( 
             String logPrefix, 
             InputStream in, 
             OutputStream out, 
             int handshakeMessageTypeAfterWhichToInjectHeartbeatRequest) throws Exception { 
         System.out.println(logPrefix + ": record forwarding started"); 
         boolean interestingRecordsLogged = 
                 handshakeMessageTypeAfterWhichToInjectHeartbeatRequest == -1; 
         try { 
             TlsRecordReader reader = new TlsRecordReader(in); 
             byte[] recordBytes; 
             // Fragments contained in records may be encrypted after a certain point in the 
             // handshake. Once they are encrypted, this MiTM cannot inspect their plaintext which. 
             boolean fragmentEncryptionMayBeEnabled = false; 
             while ((recordBytes = reader.readRecord()) != null) { 
                 TlsRecord record = TlsRecord.parse(recordBytes); 
                 forwardTlsRecord(logPrefix, 
                         recordBytes, 
                         record, 
                         fragmentEncryptionMayBeEnabled, 
                         out, 
                         interestingRecordsLogged, 
                         handshakeMessageTypeAfterWhichToInjectHeartbeatRequest); 
                 if (record.protocol == TlsProtocols.CHANGE_CIPHER_SPEC) { 
                     fragmentEncryptionMayBeEnabled = true; 
                 } 
             } 
         } catch (Exception e) { 
        	 System.out.println(logPrefix + ": failed");
        	 e.printStackTrace();
             throw e; 
         } finally { 
        	 System.out.println(logPrefix + ": record forwarding finished"); 
         } 
     }
	private void forwardTlsRecord( 
             String logPrefix, 
             byte[] recordBytes, 
             TlsRecord record, 
             boolean fragmentEncryptionMayBeEnabled, 
             OutputStream out, 
             boolean interestingRecordsLogged, 
             int handshakeMessageTypeAfterWhichToInjectHeartbeatRequest) throws IOException { 
         // Save information about the records if its of interest to this test 
         if (interestingRecordsLogged) { 
             switch (record.protocol) { 
                 case TlsProtocols.ALERT: 
                     if (!fragmentEncryptionMayBeEnabled) { 
                         AlertMessage alert = AlertMessage.tryParse(record); 
                         if ((alert != null) && (alert.level == AlertMessage.LEVEL_FATAL)) { 
                             setFatalAlertDetected(alert.description); 
                         } 
                     } 
                     break; 
                 case TlsProtocols.HEARTBEAT: 
                     // When TLS records are encrypted, we cannot determine whether a 
                     // heartbeat is a HeartbeatResponse. In our setup, the client and the 
                     // server are not expected to sent HeartbeatRequests. Thus, we err on 
                     // the side of caution and assume that any heartbeat message sent by 
                     // client or server is a HeartbeatResponse. 
                     System.out.println(logPrefix 
                             + ": heartbeat response detected -- vulnerable to Heartbleed"); 
                     setHeartbeatResponseWasDetected(); 
                     break; 
             } 
         } 
  
         System.out.println(logPrefix + ": Forwarding TLS record. " 
                 + getRecordInfo(record, fragmentEncryptionMayBeEnabled)); 
         out.write(recordBytes); 
         out.flush(); 
  
         // Inject HeartbeatRequest, if necessary, after the specified handshake message type 
         if (handshakeMessageTypeAfterWhichToInjectHeartbeatRequest != -1) { 
             if ((!fragmentEncryptionMayBeEnabled) && (isHandshakeMessageType( 
                     record, handshakeMessageTypeAfterWhichToInjectHeartbeatRequest))) { 
                 // The Heartbeat Request message below is malformed because its declared 
                 // length of payload one byte larger than the actual payload. The peer is 
                 // supposed to reject such messages. 
                 byte[] payload = "arbitrary".getBytes("US-ASCII"); 
                 byte[] heartbeatRequestRecordBytes = createHeartbeatRequestRecord( 
                         record.versionMajor, 
                         record.versionMinor, 
                         payload.length + 1, 
                         payload); 
                 System.out.println(logPrefix + ": Injecting malformed HeartbeatRequest: " 
                         + getRecordInfo( 
                                 TlsRecord.parse(heartbeatRequestRecordBytes), false)); 
                 setHeartbeatRequestWasInjected(); 
                 out.write(heartbeatRequestRecordBytes); 
                 out.flush(); 
             } 
         } 
     } 
	
	 private static int getUnsignedShortBigEndian(byte[] buf, int offset) { 
         return ((buf[offset] & 0xff) << 8) | (buf[offset + 1] & 0xff); 
     } 
     private static void putUnsignedShortBigEndian(byte[] buf, int offset, int value) { 
         buf[offset] = (byte) ((value >>> 8) & 0xff); 
         buf[offset + 1] = (byte) (value & 0xff); 
     } 
     
     public static class AlertMessage { 
         public static final int LEVEL_FATAL = 2; 
         public static final int DESCRIPTION_UNEXPECTED_MESSAGE = 10; 
  
         public int level; 
         public int description; 
  
         /** 
          * Parses the provided TLS record as an alert message. 
          * 
          * @return alert message or {@code null} if the record does not contain an alert message. 
          */ 
         public static AlertMessage tryParse(TlsRecord record) { 
             if (record.protocol != TlsProtocols.ALERT) { 
                 return null; 
             } 
             if (record.fragment.length < 2) { 
                 return null; 
             } 
             AlertMessage result = new AlertMessage(); 
             result.level = record.fragment[0] & 0xff; 
             result.description = record.fragment[1] & 0xff; 
             return result; 
         } 
     } 
     private synchronized void setFatalAlertDetected(int description) { 
    	 if (mFirstDetectedFatalAlertDescription == -1) { 
    		 mFirstDetectedFatalAlertDescription = description; 
    	 } 
     } 
     private synchronized void setHeartbeatResponseWasDetected() { 
         mHeartbeatResponseWasDetetected = true; 
     } 
     private synchronized void setHeartbeatRequestWasInjected() { 
    	 mHeartbeatRequestWasInjected = true; 
     } 
     private static String getRecordInfo(TlsRecord record, boolean mayBeEncrypted) { 
    	 StringBuilder result = new StringBuilder(); 
    	 result.append(getProtocolName(record.protocol)) 
    	 	.append(", ") 
            .append(getFragmentInfo(record, mayBeEncrypted)); 
    	 return result.toString(); 
     } 
     
     private static String getProtocolName(int protocol) { 
    	 switch (protocol) { 
         case TlsProtocols.ALERT: 
        	 return "alert"; 
         case TlsProtocols.APPLICATION_DATA: 
             return "application data"; 
         case TlsProtocols.CHANGE_CIPHER_SPEC: 
             return "change cipher spec"; 
         case TlsProtocols.HANDSHAKE: 
             return "handshake"; 
         case TlsProtocols.HEARTBEAT: 
             return "heatbeat"; 
         default: 
             return String.valueOf(protocol); 
         } 
     }
     private static String getFragmentInfo(TlsRecord record, boolean mayBeEncrypted) { 
    	 StringBuilder result = new StringBuilder(); 
         if (mayBeEncrypted) { 
        	 result.append("encrypted?"); 
         } else { 
             switch (record.protocol) { 
             case TlsProtocols.ALERT: 
            	 result.append("level: " + ((record.fragment.length > 0) 
            			 ? String.valueOf(record.fragment[0] & 0xff) : "n/a") 
            			 + ", description: " 
            			 + ((record.fragment.length > 1) 
            					 ? String.valueOf(record.fragment[1] & 0xff) : "n/a")); 
            	 break; 
             case TlsProtocols.APPLICATION_DATA: 
            	 break;
             case TlsProtocols.CHANGE_CIPHER_SPEC: 
                 result.append("payload: " + ((record.fragment.length > 0) 
                         ? String.valueOf(record.fragment[0] & 0xff) : "n/a")); 
                 break; 
             case TlsProtocols.HANDSHAKE: 
                 result.append("type: " + ((record.fragment.length > 0) 
                         ? String.valueOf(record.fragment[0] & 0xff) : "n/a")); 
                 break; 
             case TlsProtocols.HEARTBEAT: 
                 result.append("type: " + ((record.fragment.length > 0) 
                         ? String.valueOf(record.fragment[0] & 0xff) : "n/a") 
                         + ", payload length: " 
                         + ((record.fragment.length >= 3) 
                                 ? String.valueOf( 
                                         getUnsignedShortBigEndian(record.fragment, 1)) 
                                 : "n/a")); 
                 break; 
             } 
         }
         result.append(", ").append("fragment length: " + record.fragment.length); 
         return result.toString(); 
     } 
     
     private static byte[] createHeartbeatRequestRecord( 
    		 int versionMajor, int versionMinor, 
             int declaredPayloadLength, byte[] payload) { 
 
    	 	byte[] fragment = new byte[HeartbeatProtocol.MESSAGE_HEADER_LENGTH 
    	 	                           + payload.length + HeartbeatProtocol.MESSAGE_PADDING_LENGTH]; 
    	 	fragment[0] = HeartbeatProtocol.MESSAGE_TYPE_REQUEST; 
    	 	putUnsignedShortBigEndian(fragment, 1, declaredPayloadLength); // payload_length 
    	 	TlsRecord record = new TlsRecord(); 
    	 	record.protocol = TlsProtocols.HEARTBEAT; 
    	 	record.versionMajor = versionMajor; 
    	 	record.versionMinor = versionMinor; 
    	 	record.fragment = fragment; 
    	 	return TlsRecord.unparse(record); 
     } 
     public static final boolean isHandshakeMessageType(TlsRecord record, int type) { 
    	 HandshakeMessage handshake = HandshakeMessage.tryParse(record); 
    	 if (handshake == null) { 
    		 return false; 
    	 } 
    	 return handshake.type == type; 
     } 
     public static class HandshakeMessage { 
    	 public static final int TYPE_SERVER_HELLO = 2; 
    	 public static final int TYPE_CERTIFICATE = 11; 
    	 public static final int TYPE_CLIENT_KEY_EXCHANGE = 16; 
    	 
    	 public int type; 
    	 
    	 /** 
    	  * Parses the provided TLS record as a handshake message. 
    	  * 
    	  * @return alert message or {@code null} if the record does not contain a handshake message. 
    	  */ 
    	 public static HandshakeMessage tryParse(TlsRecord record) { 
    		 if (record.protocol != TlsProtocols.HANDSHAKE) { 
    			 return null; 
    		 } 
    		 if (record.fragment.length < 1) { 
    			 return null; 
    		 } 
    		 HandshakeMessage result = new HandshakeMessage(); 
    		 result.type = record.fragment[0] & 0xff; 
    		 return result; 
    	 } 
     } 
}
