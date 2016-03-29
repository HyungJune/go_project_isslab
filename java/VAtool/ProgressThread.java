package VAtool;

import javax.swing.JLabel;
import javax.swing.JProgressBar;

public class ProgressThread extends Thread{
	
	JProgressBar jpb;
	JLabel label;
	
	public ProgressThread(JProgressBar jpb, JLabel label){
		this.jpb = jpb;
		this.label = label;
		
	}
		
	public void run(){
		for(int i=0;i<=100;i++){
			jpb.setValue(i);
			label.setText(i + "%");
			try {
				Thread.sleep(10);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println(i+"%");
		}
	}

}
