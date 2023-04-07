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

import javax.swing.*;
import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;


public class DSAKryptoController implements Initializable {

    @FXML
    private Button key_gen_button;
    @FXML
    private Button key_save_button;
    @FXML
    private Button key_read_button;

    @FXML
    private TextField key_p_text_field;
    @FXML
    private TextField key_q_text_field;
    @FXML
    private TextField key_h_text_field;
    @FXML
    private TextField key_private_text_field;
    @FXML
    private TextField key_public_text_field;

    @FXML
    private RadioButton radio_file;
    @FXML
    private RadioButton radio_text;

    @FXML
    private Button read_document_button;
    @FXML
    private TextArea document_textarea;

    @FXML
    private Button save_signature_button;
    @FXML
    private Button read_signature_button;
    @FXML
    private TextArea signature_textarea;

    @FXML
    private Button sign;
    @FXML
    private Button verify;

    @FXML
    private javafx.scene.image.ImageView file_indicator_read_document;
    @FXML
    private javafx.scene.image.ImageView file_indicator_read_signature;
    @FXML
    private javafx.scene.image.ImageView file_indicator_save_signature;
    @FXML
    private javafx.scene.image.ImageView file_indicator_sign;

    @FXML
    private Label verify_state_label;

    // TODO:
    // - key generation
    // - save key button must create two files:
    //      - filename.pub (p,q,h + public key)
    //      - filename.prv (p,q,h + private key)
    // - read key button must read in one file (pub or prv, depending on extension)
    // - to sign: we will use SHA512 of document (if you object, tell me why)
    // - signature_textarea must display signature in hex
    // - signatures must be readable and savable to .sig files
    // - verify_state_label is used to display state of verification ("Signature matches" or "INVALID SIGNATURE!")


    // Initialize all "onClick" type events for UI elements
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

    }

    public void switchToAES(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(KryptoApplication.class.getResource("/org.krypto/aes.fxml")));
        Stage stage = (Stage) ((MenuItem) event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void about(ActionEvent event) {
        String about_message = "App made as a university assignment by Jakub Kalinowski and Tomasz Kowalczyk";
        Alert a = new Alert(Alert.AlertType.INFORMATION, about_message, ButtonType.OK);
        a.setTitle("About");
        a.show();
    }

    // "Quit" button handling
    public void quit() {
        String quit_message = "Thank you for using our application!";
        Alert exitAlert = new Alert(Alert.AlertType.NONE, quit_message, ButtonType.OK);
        exitAlert.setTitle("Goodbye!");
        Optional<ButtonType> result = exitAlert.showAndWait();
        if (result.isEmpty() || result.get() == ButtonType.OK) {
            System.exit(0);
        }
    }

}