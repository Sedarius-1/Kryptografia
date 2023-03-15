package org.krypto;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class KryptoApplication extends Application {

    @Override
    public void start(Stage stage) {
        try {

            Parent root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/aes.fxml"));
            Scene scene = new Scene(root);
            stage.setScene(scene);
            stage.setTitle("NAPRAWIONE");
            stage.show();

        } catch(Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}