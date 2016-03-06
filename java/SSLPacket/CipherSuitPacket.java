package SSLPacket;

public class CipherSuitPacket{
	private byte firstByte;
	private byte lastByte;
	private byte[] packet;
	public CipherSuitPacket(byte[] cipherSuit){
		this.firstByte = cipherSuit[0];
		this.lastByte = cipherSuit[1];
		
		this.packet = new byte[2];
		
		this.packet[0] = this.firstByte;
		this.packet[1] = this.lastByte;
	}
	
	public byte[] getPacket(){
		return this.packet;
	}
}

