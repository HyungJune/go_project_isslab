package Frame;
import javax.swing.JFrame;

import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JMenu;
import javax.swing.JTextField;


import VAtool.IVDTool;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JButton;
import javax.swing.JFileChooser;


import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.swing.JLabel;
import javax.swing.JProgressBar;

public class IVDFrame extends JFrame{
	private final JTextField textField = new JTextField();
	private final JButton btnAnalyze = new JButton("analyze");
	IVDTool ivd = new IVDTool();
	public JProgressBar progressBar;
	JLabel lblNewLabel;
    private JFileChooser jfc = new JFileChooser();

	/*
    public boolean fileSave()
    {
        File fileName;
        JFileChooser fc = new JFileChooser();
        int yn = fc.showSaveDialog(this);
        
        if(yn != JFileChooser.APPROVE_OPTION)
        {
             fileName = null;
             return false;
        }
        
        fileName = fc.getSelectedFile();
        
        return true;
    
    }*/
	
	
	public IVDFrame(){
			

		setTitle("IVD Tool");
		
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);
		
		JMenu mnNewMenu_1 = new JMenu("Help");
		menuBar.add(mnNewMenu_1);
		
		JMenuItem mntmAboutUs = new JMenuItem("How to Use");
		mnNewMenu_1.add(mntmAboutUs);
		
		JMenuItem mntmNewMenuItem = new JMenuItem("About us");
		mnNewMenu_1.add(mntmNewMenuItem);
		getContentPane().setLayout(null);
		textField.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
			}
		});
		textField.addFocusListener(new FocusAdapter() {
			public void focusGained(FocusEvent arg0) {
			}
		});
		
		textField.setBounds(89, 44, 371, 31);
		getContentPane().add(textField);
		textField.setColumns(10);
		
		textField.addActionListener(new ActionListener() {

		 
		    public void actionPerformed(ActionEvent e) {
		    	ivd.setHost(textField.getText());
		    	go();
		    	ivd.defaultHandshake();
		    	while(true){
		    		
		    		if(ivd.socket.isBound()){
		    			try {
							ivd.heartbleadTest();
						} catch (InvalidKeyException | UnsupportedEncodingException | NoSuchAlgorithmException
								| NoSuchPaddingException | InvalidAlgorithmParameterException
								| IllegalBlockSizeException | BadPaddingException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
		    			break;
		    		}
		    	}
	//	    	ivd.start(progressBar, lblNewLabel);		
			   	JOptionPane.showMessageDialog(null, "Complete!");
		    }
		});
		
		
		
		btnAnalyze.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent arg0) {
				ivd.setHost(textField.getText());
				go();
		    	ivd.defaultHandshake();
		    	while(true){
		    		
		    		if(ivd.socket.isBound()){
		    			try {
							ivd.heartbleadTest();
						} catch (InvalidKeyException | UnsupportedEncodingException | NoSuchAlgorithmException
								| NoSuchPaddingException | InvalidAlgorithmParameterException
								| IllegalBlockSizeException | BadPaddingException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
		    			break;
		    		}
		    	}
			//	ivd.start(progressBar, lblNewLabel);
				JOptionPane.showMessageDialog(null, "Complete!");
				
			}
		});
		btnAnalyze.setBounds(472, 44, 77, 31);
		getContentPane().add(btnAnalyze);
		
		JLabel lblTargetHost = new JLabel("Target Host");
		lblTargetHost.setBounds(12, 52, 77, 15);
		getContentPane().add(lblTargetHost);
		
		progressBar = new JProgressBar();
		progressBar.setBounds(89, 127, 371, 22);
		progressBar.setMinimum(0);
		progressBar.setMaximum(100);
		progressBar.setValue(0);
		getContentPane().add(progressBar);
		
		lblNewLabel = new JLabel("");
		lblNewLabel.setBounds(468, 127, 57, 22);
		getContentPane().add(lblNewLabel);
					
		this.setSize(600,241);
		this.setVisible(true);
		
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		

	}
	public void go(){
		
		for(int i=0;i<=100;i++){
			
			
			try {
				progressBar.setValue(i);
				lblNewLabel.setText(i+"%");
				System.out.println("i: "+i);
				Thread.sleep(50);
				
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		}
	}
}
