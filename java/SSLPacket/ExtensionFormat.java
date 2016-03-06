package SSLPacket;

import java.nio.ByteBuffer;

public class ExtensionFormat {
	
	public static final byte[] SERVER_NAME = ByteBuffer.allocate(2).putShort((short) 0).array();
	public static final byte[] MAX_FRAGMENT_LENGTH = ByteBuffer.allocate(2).putShort((short)1).array();
	public static final byte[] CLIENT_CERTIFICATE_RUL = ByteBuffer.allocate(2).putShort((short)2).array();
	public static final byte[] TRUSTED_CA_KEYS = ByteBuffer.allocate(2).putShort((short)3).array();
	public static final byte[] TRUNCATED_HMAC = ByteBuffer.allocate(2).putShort((short)4).array();
	public static final byte[] STATUS_REQUEST = ByteBuffer.allocate(2).putShort((short)5).array();
	public static final byte[] USER_MAPPING = ByteBuffer.allocate(2).putShort((short)6).array();
	public static final byte[] CLIENT_AUTHZ = ByteBuffer.allocate(2).putShort((short)7).array();
	public static final byte[] SERVER_AUTHZ = ByteBuffer.allocate(2).putShort((short)8).array();
	public static final byte[] CERT_TYPE = ByteBuffer.allocate(2).putShort((short)9).array();
	public static final byte[] SUPPORTED_GROUPS = ByteBuffer.allocate(2).putShort((short)10).array();
	public static final byte[] EC_POINT_FORMATS = ByteBuffer.allocate(2).putShort((short)11).array();
	public static final byte[] SRP = ByteBuffer.allocate(2).putShort((short)12).array();
	public static final byte[] SIGNATURE_ALGORITHMS = ByteBuffer.allocate(2).putShort((short)13).array();
	public static final byte[] USE_SRTP = ByteBuffer.allocate(2).putShort((short)14).array();
	public static final byte[] HEARTBEAT = ByteBuffer.allocate(2).putShort((short)15).array();
	public static final byte[] APPLICATION_LAYER_PROTOCOL_NEGOTIATION = ByteBuffer.allocate(2).putShort((short)16).array();
	public static final byte[] STATUS_REQUEST_V2 = ByteBuffer.allocate(2).putShort((short)17).array();
	public static final byte[] SIGNED_CERTIFICATE_TIMESTAMP = ByteBuffer.allocate(2).putShort((short)18).array();
	public static final byte[] CLIENT_CERTIFICATE_TYPE = ByteBuffer.allocate(2).putShort((short)19).array();
	public static final byte[] SERVER_CERTIFICATE_TYPE = ByteBuffer.allocate(2).putShort((short)20).array();
	public static final byte[] PADDING = ByteBuffer.allocate(2).putShort((short)21).array();
	public static final byte[] ENCRYPT_THEN_MAC = ByteBuffer.allocate(2).putShort((short)22).array();
	public static final byte[] EXTENDED_MASTER_SECRET = ByteBuffer.allocate(2).putShort((short)23).array();
	public static final byte[] TOKEN_BINDING = ByteBuffer.allocate(2).putShort((short)24).array();
	public static final byte[] SESSIONTICKET_TLS = ByteBuffer.allocate(2).putShort((short)35).array();
	public static final byte[] RENEGOTIATION_INFO = ByteBuffer.allocate(2).putShort((short)65281).array();
}
