import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.swing.JOptionPane;

import Frame.IVDFrame;
import VAtool.IVDTool;

public class MAIN {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyManagementException 
	 */
	public static void main(String[] args) throws KeyManagementException, NoSuchAlgorithmException, IOException {
		// TODO Auto-generated method stub
		//System.setProperty("jsse.enableSNIExtension", "false");
		//IVDFrame frame = new IVDFrame();
		String host = null;
		IVDTool ivd = new IVDTool();
		
		host = JOptionPane.showInputDialog("Enter the host name:");
		ivd.setHost(host);
		ivd.tryHandshake();
	
	}

}
