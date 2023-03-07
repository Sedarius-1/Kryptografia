package org.krypto;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class KryptoApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        KryptoController controller = new KryptoController();
        FXMLLoader fxmlLoader = new FXMLLoader(KryptoApplication.class.getResource("/org.krypto/aes.fxml"));
        fxmlLoader.setController(controller);
        Scene scene = new Scene(fxmlLoader.load(), 640, 400);
        stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}