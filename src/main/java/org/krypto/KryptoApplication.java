package org.krypto;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.util.Objects;

// Key-yellow.png from https://freesvg.org/yellow-lock-key-vector-image (public domain)

public class KryptoApplication extends Application {

    @Override
    public void start(Stage stage) {
        try {
            Parent root = FXMLLoader.load(Objects.requireNonNull(KryptoApplication.class.getResource("/org.krypto/aes.fxml")));
            Scene scene = new Scene(root);
            stage.setScene(scene);
            stage.setTitle("Krypto");
            stage.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}