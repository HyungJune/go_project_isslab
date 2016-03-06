package Frame;
import javax.swing.JFrame;
import javax.swing.JTextPane;
import java.awt.BorderLayout;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JMenu;
import javax.swing.JTextField;
import java.awt.GridLayout;

import VAtool.IVDTool;

import javax.swing.JButton;
import javax.swing.JFileChooser;

import java.awt.FlowLayout;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;

import javax.swing.JLabel;

public class IVDFrame extends JFrame{
	private final JTextField textField = new JTextField();
	private final JButton btnAnalyze = new JButton("analyze");
	IVDTool ivd = new IVDTool();
	
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
		
		JMenu mnNewMenu = new JMenu("File");
		menuBar.add(mnNewMenu);
		
		JMenuItem mntmNewMenuItem = new JMenuItem("Hi");
		mnNewMenu.add(mntmNewMenuItem);
		
		JMenuItem mntmNewMenuItem_1 = new JMenuItem("Hello");
		mnNewMenu.add(mntmNewMenuItem_1);
		
		JMenu mnNewMenu_1 = new JMenu("Help");
		menuBar.add(mnNewMenu_1);
		
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

		 
		    public void actionPerformed(ActionEvent e) {
		    	ivd.setHost(textField.getText());
				//ivd.defaultHandshake();
				ivd.heartbleadTest();
				JOptionPane.showMessageDialog(null, "Complete!");
		    }
		});
		
		
		
		btnAnalyze.addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent arg0) {
				ivd.setHost(textField.getText());
				//ivd.defaultHandshake();
				ivd.heartbleadTest();
				JOptionPane.showMessageDialog(null, "Complete!");
				
			}
		});
		btnAnalyze.setBounds(472, 44, 77, 31);
		getContentPane().add(btnAnalyze);
		
		JLabel lblTargetHost = new JLabel("Target Host");
		lblTargetHost.setBounds(12, 52, 77, 15);
		getContentPane().add(lblTargetHost);
		
		this.setSize(600,200);
		this.setVisible(true);
		
	}





	
}
