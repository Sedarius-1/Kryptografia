package org.krypto;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import javafx.scene.image.Image;
import org.apache.commons.io.FilenameUtils;

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.ResourceBundle;


public class DSAKryptoController implements Initializable {

    private Stage stage;
    private Scene scene;


    // Initialize all "onClick" type events for UI elements
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

    }

    public void switchToAES(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(KryptoApplication.class.getResource("/org.krypto/aes.fxml")));
        stage = (Stage) ((MenuItem) event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void about(ActionEvent event) {
        String about_message = "App made as a university assignment by Jakub Kalinowski and Tomasz Kowalczyk";
        Alert a = new Alert(Alert.AlertType.INFORMATION, about_message, ButtonType.OK);
        a.setTitle("About");
        a.show();
    }

    // TODO: add "Quit" button handling


}