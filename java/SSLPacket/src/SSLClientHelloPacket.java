import java.nio.ByteBuffer;

public class SSLClientHelloPacket {
	private byte contentType; //done
	private byte[] tlsVersion;//done
	
	
	private byte[] packetLength;//
	
	private byte messageType;//done
	
	private byte[] payloadLength;//done
	
	private byte[] clientVersion; //done
	private byte[] random; //done
	private byte sessionId;//done
	
	private byte[] ciphersuitLength; //done
	private CipherSuitPacket[] ciphersuits; //done
	
	private byte compressionMethodLength ;//done
	private byte compressionMethod;//done
	
	private byte[] extensionLength; // done
	private ExtensionPacket[] extensions;// done
	
	private byte[] packet;
	SSLClientHelloPacket(CipherSuitPacket[] ciphersuits, ExtensionPacket[] extensions){
		this.contentType = 0x16;
		
		this.tlsVersion = new byte[2];
		this.tlsVersion[0] = 0x03;
		this.tlsVersion[1] = 0x02;
		
		
		this.messageType = 0x01;	

		this.clientVersion = new byte[2];
		this.clientVersion[0] = 0x03;
		this.clientVersion[1] = 0x02;
		
		/* Default random */
		this.random = new byte[32];
		this.random[0] = 0x53;
		this.random[1] = 0x43;
		this.random[2] = 0x5b;
		this.random[3] = (byte)0x90;
		this.random[4] = (byte)0x9d;
		this.random[5] = (byte)0x9b;
		this.random[6] = 0x72;
		this.random[7] = 0x0b;
		this.random[8] = (byte)0xbc;
		this.random[9] = 0x0c;
		this.random[10] = (byte)0xbc;
		this.random[11] = 0x2b;
		this.random[12] = (byte)0x92;
		this.random[13] = (byte)0xa8;
		this.random[14] = 0x48;
		this.random[15] = (byte)0x97;
		this.random[16] = (byte)0xcf;
		this.random[17] = (byte)0xbd;
		this.random[18] = 0x39;
		this.random[19] = 0x04;
		this.random[20] = (byte)0xcc;
		this.random[21] = 0x16;
		this.random[22] = 0x0a;
		this.random[23] = (byte)0x85;
		this.random[24] = 0x03;
		this.random[25] = (byte)0x90;
		this.random[26] = (byte)0x9f;
		this.random[27] = 0x77;
		this.random[28] = 0x04;
		this.random[29] = 0x33;
		this.random[30] = (byte)0xd4;
		this.random[31] = (byte)0xde;
		
		this.sessionId = 0x00;
		//39
		/* ciphersuit should be made */
		this.ciphersuits = ciphersuits;
		this.extensions = extensions;
		this.ciphersuitLength = ByteBuffer.allocate(2).putShort((short)(this.ciphersuits.length * 2)).array();
		System.out.println("Ciphersuit length : " + ciphersuits.length *2);
		int extensionTotalSize = 0;
		System.out.println("Extensions length : " + extensions.length);
		for(int i = 0;i<extensions.length;i++){
			extensionTotalSize += extensions[i].getTotalSize();
		}
		System.out.println("Extension ToTal Size in SSLPacket : " + extensionTotalSize);
		this.extensionLength = ByteBuffer.allocate(2).putShort((short)extensionTotalSize).array();
		
		this.compressionMethodLength = 0x01;
		this.compressionMethod = 0x00;
		//2
	
		int payloadTotalSize = this.clientVersion.length + this.random.length + this.ciphersuitLength.length
				+ 2*this.ciphersuits.length + this.extensionLength.length + extensionTotalSize + 3;
		System.out.println("PayloadTotalSize : " + payloadTotalSize);
		this.payloadLength = ByteBuffer.allocate(3).putShort((short)payloadTotalSize).array();
		
		int totalSize = payloadTotalSize + this.tlsVersion.length + 2 + this.payloadLength.length + 2;
		
		this.packetLength = ByteBuffer.allocate(2).putShort((short)totalSize).array();
		System.out.println("PacketLength = " + String.format("0x%02X", packetLength[0]) + " " 
				+ String.format("0x%02X", packetLength[1]));
		this.packet = new byte[totalSize];
	}
	
	byte[] makeBytePacket(){
		int i = 0;
		/* set contentType */
		this.packet[i++] = this.contentType;
		
		/* set TLS version */
		i = copyByteByIndex(this.packet, this.tlsVersion, i);
		
		/* set Packet length */
		i = copyByteByIndex(this.packet, this.packetLength, i);
		
		/* set Message type */
		this.packet[i++] = this.messageType;
		
		/* set Payload length */
		i = copyByteByIndex(this.packet, this.payloadLength,i);
		
		/* set Client Version */
		i = copyByteByIndex(this.packet, this.clientVersion,i);
		
		/* set Radom Byte */
		i = copyByteByIndex(this.packet, this.random, i);
		
		/* set session id */
		this.packet[i++] = this.sessionId;
		
		/* set Cipher suite length */
		i = copyByteByIndex(this.packet, this.ciphersuitLength, i);
		
		/* set Cipher suits */
		for(int j =0;j<this.ciphersuits.length;j++){
			i = copyByteByIndex(this.packet,this.ciphersuits[j].getPacket(),i);
		}
		 /* set Compression methods length */
		this.packet[i++] = this.compressionMethodLength;
		
		/* set Compression methods */
		this.packet[i++] = this.compressionMethod;
		
		/* set Extension length */
		i = copyByteByIndex(this.packet, this.extensionLength, i);
		
		/* set Extensions */
		System.out.println("Set Extension i : " + i);
		for(int j=0;j<this.extensions.length;j++){
			i = copyByteByIndex(this.packet, this.extensions[j].getPacket(),i);
		}
		 
		
		return this.packet;
	}
	
	static int copyByteByIndex(byte[] des, byte[] source, int start){
		for(int i =0;i<source.length;i++){
			des[start++] = source[i];
		}
		return start;
	}
	
	
}

class ExtensionPacket {
	private byte[] format;
	private byte[] length;
	private byte[] contents;
	private int totalSize;
	private byte[] packet;
	
	ExtensionPacket(byte[] format, byte[] contents){
		this.format = format;
		this.contents = contents;
		
		//this.length = new byte[2];
		this.length = ByteBuffer.allocate(2).putShort((short)contents.length).array();
		this.totalSize = this.format.length + this.length.length
				+ this.contents.length;
		
		this.packet = new byte[totalSize];
		System.out.println("Extension Total Size : " + totalSize);
		
		int i = 0;
		
		/* set format */
		i = SSLClientHelloPacket.copyByteByIndex(packet, format, i);
		
		/* set length */
		i = SSLClientHelloPacket.copyByteByIndex(packet, length, i);
		
		/* set contents */
		i = SSLClientHelloPacket.copyByteByIndex(packet, contents, i);
	}
	
	int getTotalSize(){
		return this.totalSize;
	}
	
	byte[] getPacket(){
		return this.packet;
	}
}

class CipherSuitPacket{
	private byte firstByte;
	private byte lastByte;
	private byte[] packet;
	CipherSuitPacket(byte[] cipherSuit){
		this.firstByte = cipherSuit[0];
		this.lastByte = cipherSuit[1];
		
		this.packet = new byte[2];
		
		this.packet[0] = this.firstByte;
		this.packet[1] = this.lastByte;
	}
	
	byte[] getPacket(){
		return this.packet;
	}
}
