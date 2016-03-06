package SSLPacket;

import java.nio.ByteBuffer;

public class ExtensionPacket {
	private byte[] format;
	private byte[] length;
	private byte[] contents;
	private int totalSize;
	private byte[] packet;
	public ExtensionPacket(byte[] format){
		this.format = format;
		this.length = new byte[2];
		this.length[0] = 0x00;
		this.length[1] = 0x00;
		contents = null;
		totalSize = 0;
		int i = 0;
		this.totalSize = this.format.length + this.length.length;
		packet = new byte[totalSize];
		
		i = SSLClientHelloPacket.copyByteByIndex(packet, format, i);
		
		/* set length */
		i = SSLClientHelloPacket.copyByteByIndex(packet, length, i);	
	}
	public ExtensionPacket(byte[] format, byte[] contents){
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
	
	public int getTotalSize(){
		return this.totalSize;
	}
	
	public byte[] getPacket(){
		return this.packet;
	}
}
