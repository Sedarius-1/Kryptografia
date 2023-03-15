package org.krypto;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

import java.io.IOException;


public class KryptoController {
    @FXML
    private MenuItem goto_des;

    @FXML
    private TextField klucz_text_field;
    private Stage stage;
    private Scene scene;

    public void switchToAES(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/aes.fxml"));
        stage =(Stage)((MenuItem)event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void switchToDSA(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/dsa.fxml"));
        stage =(Stage)((MenuItem)event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void createRandomValue(ActionEvent event){
        String s = "gwagawgawgawgawugwqgbnewigwgnwiew gjwe phiwe hpwehp";
        klucz_text_field = new TextField();
        klucz_text_field.setText(s);

    }


}

//    public void handleButtonPress(ActionEvent event) {
//        Stage stage;
//        Parent root;
//
//        if(event.getSource()==goto_des){
//            stage = (Stage) (((MenuItem)event.getTarget()).getParentPopup().getScene().getWindow());
//            try{
//                root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/dsa.fxml"));
//                Scene scene = new Scene(root);
//                stage.setScene(scene);
//                stage.show();
//            }catch (Exception e){
//                System.out.print(e.toString());
//            }
//        }
//    }
//    /*
//    @FXML
//    private Label welcomeText;
//
//    @FXML
//    protected void onHelloButtonClick() {
//        welcomeText.setText("Welcome to JavaFX Application!");
//    }*/
//}