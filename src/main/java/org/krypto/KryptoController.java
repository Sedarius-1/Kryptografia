package org.krypto;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.MenuItem;
import javafx.stage.Stage;


public class KryptoController {
    @FXML private MenuItem goto_des;
    public void handleButtonPress(ActionEvent event) {
        Stage stage;
        Parent root;

        if(event.getSource()==goto_des){
            stage = (Stage) (((MenuItem)event.getTarget()).getParentPopup().getScene().getWindow());
            try{
                root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/dsa.fxml"));
                Scene scene = new Scene(root);
                stage.setScene(scene);
                stage.show();
            }catch (Exception e){
                System.out.print(e.toString());
            }
        }
    }
    /*
    @FXML
    private Label welcomeText;

    @FXML
    protected void onHelloButtonClick() {
        welcomeText.setText("Welcome to JavaFX Application!");
    }*/
}