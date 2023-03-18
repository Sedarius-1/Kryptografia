package org.krypto;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import org.apache.commons.io.FilenameUtils;

import javax.swing.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;


public class AESKryptoController implements Initializable {

    @FXML
    private Button key_read_button;
    @FXML
    private TextField key_text_field;
    @FXML
    private Button key_gen_button;
    @FXML
    private Button key_save_button;
    @FXML
    private Slider key_length_slider;
    @FXML
    private Button read_plaintext_button;
    @FXML
    private TextArea plaintext_textarea;
    @FXML
    private Button save_plaintext_button;
    @FXML
    private Button read_ciphertext_button;
    @FXML
    private TextArea ciphertext_textarea;
    @FXML
    private Button save_ciphertext_button;


    @FXML
    private javafx.scene.image.ImageView key_length_display;
    private Stage stage;
    private Scene scene;

    private void setKeyLength(int value){
        File file;
        Image image;
        switch (value) {
            case 128 -> {
                file = new File("src/main/resources/org.krypto/Key-short.png");
                image = new Image(file.toURI().toString());
                key_length_display.setImage(image);
                key_length_display.setFitWidth(230);
            }
            case 192 -> {
                file = new File("src/main/resources/org.krypto/Key-medium.png");
                image = new Image(file.toURI().toString());
                key_length_display.setImage(image);
                key_length_display.setFitWidth(350);
            }
            case 256 -> {
                file = new File("src/main/resources/org.krypto/Key-long.png");
                image = new Image(file.toURI().toString());
                key_length_display.setImage(image);
                key_length_display.setFitWidth(460);
            }
        }
    }
    // Initialize all "onClick" type events for UI elements
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        //TODO: validate user input in text file

        // Generate new key
        key_gen_button.setOnAction(ActionEvent -> {
            byte[] secureRandomKeyBytes = new byte[((int) key_length_slider.getValue()) / 8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(secureRandomKeyBytes);
            HexFormat hex = HexFormat.of();
            key_text_field.setText(hex.formatHex(secureRandomKeyBytes));
        });

        // Change key length
        key_length_slider.valueProperty().addListener((observableValue, number, t1) ->
                setKeyLength((int)key_length_slider.getValue()));

        // Save key to file
        key_save_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();

                if (!FilenameUtils.getExtension(fileToSave.getName()).equalsIgnoreCase("aeskey")) {
                    fileToSave = new File(fileToSave + ".aeskey");
                    fileToSave = new File(fileToSave.getParentFile(), FilenameUtils.getBaseName(fileToSave.getName()) + ".aeskey");
                }
                byte[] key_bytes = HexFormat.of().parseHex(key_text_field.getText());

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(key_bytes);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                      "KEY FILE SAVED CORRECTLY", ButtonType.APPLY);
                        alert.show();
                    }
                } catch (IOException e) {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                 "ERROR DURING FILE SAVING", ButtonType.APPLY);
                    alert.show();
                    throw new RuntimeException(e);

                }
                System.out.println("Save as file: " + fileToSave.getAbsolutePath());
            }
        });

        // Read key from file
        key_read_button.setOnAction(ActionEvent -> {

            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to load");

            int userSelection = fileChooser.showOpenDialog(parentFrame);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("aeskey")) {
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        HexFormat hex = HexFormat.of();
                        key_text_field.setText(hex.formatHex(readData));
                        key_length_slider.setValue(hex.formatHex(readData).length()*4.0);
                        setKeyLength((int)key_length_slider.getValue());
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                      "KEY FILE LOADED PROPERLY", ButtonType.APPLY);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                 "THIS IS NOT A VALID KEY FILE (.aeskey)", ButtonType.APPLY);
                    alert.show();
                }
            }
        });

        // Save plaintext to file
        save_plaintext_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();

                if (!FilenameUtils.getExtension(fileToSave.getName()).equalsIgnoreCase("txt")) {
                    fileToSave = new File(fileToSave + ".txt");
                    fileToSave = new File(fileToSave.getParentFile(), FilenameUtils.getBaseName(fileToSave.getName()) + ".txt");
                }
                byte[] plaintext_bytes = plaintext_textarea.getText().getBytes();

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(plaintext_bytes);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "PLAINTEXT FILE SAVED CORRECTLY", ButtonType.APPLY);
                        alert.show();
                    }
                } catch (IOException e) {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                            "ERROR DURING FILE SAVING", ButtonType.APPLY);
                    alert.show();
                    throw new RuntimeException(e);

                }
                System.out.println("Save as file: " + fileToSave.getAbsolutePath());
            }
        });

        //Read plaintext from file
        read_plaintext_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to load");

            int userSelection = fileChooser.showOpenDialog(parentFrame);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                // TODO: unnecessary check (we can handle any file type)
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("txt")) {
                    try {
                        String readData = Files.readString(selectedFile.toPath());
                        // TODO: textareas should contain hex encoded data
                        plaintext_textarea.setText(readData);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                     "FILE LOADED PROPERLY", ButtonType.APPLY);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID TEXT FILE (.txt)", ButtonType.APPLY);
                    alert.show();
                }
            }
        });

        // Save encrypted text to file
        save_ciphertext_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();

                if (!FilenameUtils.getExtension(fileToSave.getName()).equalsIgnoreCase("aesciphered")) {
                    fileToSave = new File(fileToSave + ".aesciphered");
                    fileToSave = new File(fileToSave.getParentFile(), FilenameUtils.getBaseName(fileToSave.getName()) + ".aesciphered");
                }
                byte[] encrypted_bytes = HexFormat.of().parseHex(ciphertext_textarea.getText());

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(encrypted_bytes);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "ENCRYPTED FILE SAVED CORRECTLY", ButtonType.APPLY);
                        alert.show();
                    }
                } catch (IOException e) {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                            "ERROR DURING FILE SAVING", ButtonType.APPLY);
                    alert.show();
                    throw new RuntimeException(e);

                }
                System.out.println("File saved as: " + fileToSave.getAbsolutePath());
            }
        });

        // Read encrypted text from file
        read_ciphertext_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to load");

            int userSelection = fileChooser.showOpenDialog(parentFrame);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("aesciphered")) {
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        HexFormat hex = HexFormat.of();
                        ciphertext_textarea.setText(hex.formatHex(readData));
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "ENCRYPTED FILE LOADED PROPERLY", ButtonType.APPLY);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID AES ENCRYPTED FILE (.aesciphered)", ButtonType.APPLY);
                    alert.show();
                }
            }
        });
    }

    //Switch to DSA button handling
    public void switchToDSA(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(KryptoApplication.class.getResource("/org.krypto/dsa.fxml")));
        stage = (Stage) ((MenuItem) event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    // "About" button handling
    public void about() {
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
        if(result.isEmpty() || result.get() == ButtonType.OK){
            System.exit(0);
        }
    }


}