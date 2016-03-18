package Frame;
import javax.swing.JFrame;

import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JMenu;
import javax.swing.JTextField;


import VAtool.IVDTool;


import javax.swing.JButton;
import javax.swing.JFileChooser;


import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;


import javax.swing.JLabel;
import javax.swing.JProgressBar;

public class IVDFrame extends JFrame{
	private final JTextField textField = new JTextField();
	private final JButton btnAnalyze = new JButton("collect");
	IVDTool ivd = new IVDTool();
	public JProgressBar progressBar;
	JLabel lblNewLabel;
	public boolean key;
	public boolean entered;
	int progress=0;
	
	public IVDFrame(){
			

		setTitle("IVD Tool");
		key = false;
		entered = false;
		JMenuBar menuBar = new JMenuBar();
		setJMenuBar(menuBar);
		
		JMenu mnNewMenu_1 = new JMenu("Help");
		menuBar.add(mnNewMenu_1);
		
		JMenuItem mntmHowToUse = new JMenuItem("How to Use");
		mnNewMenu_1.add(mntmHowToUse);
		
		JMenuItem mntmAboutUs = new JMenuItem("About us");
		mnNewMenu_1.add(mntmAboutUs);
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

			@Override
			public void actionPerformed(ActionEvent arg0) {
				// TODO Auto-generated method stub
				entered = true;
				start();

			}


		});
		

		btnAnalyze.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent arg0) {
				entered = true;
				start();

				
			}
		});
		
	
		
		btnAnalyze.setSize(50,50);
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
		lblNewLabel.setText("0%");
		this.setSize(600,241);
		this.setVisible(true);
		
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		
	}

	
	
	public void start(){
		String input = new String(textField.getText());
		if(!input.contains(".")){
			JOptionPane.showMessageDialog(null, "Invalid Input Format");
			return;
		}
		
		ivd.setHost(textField.getText());
	  
    	ivd.drownTest();

		JOptionPane.showMessageDialog(null, "Complete!");
	}
	
	public void run(){
		
		if(progressBar.getValue()<100){
			System.out.println("progressBar!!!!!!!!!!!!!!!!!!");
			progressBar.setValue(progress++);
			lblNewLabel.setText(progress + "%");
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
			// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
	}
	
	public void start1(){
		String input = new String(textField.getText());

		if(!input.contains(".")){
			JOptionPane.showMessageDialog(null, "Invalid Input Format");
			return;
		}
		
		ivd.setHost(textField.getText());
	
    	ivd.defaultHandshake();
    	while(true){
    		
    		if(ivd.socket.isBound()){

    			ivd.heartbleadTest();
    			break;
    		}
    	}

    	entered = false;
		JOptionPane.showMessageDialog(null, "Complete!");

	}
	
	
}
