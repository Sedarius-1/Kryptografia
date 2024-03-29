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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;


public class AESKryptoController implements Initializable {

    private static final String ENCRYPTED_FILE_EXT = "aescrypt";
    private String FILE_EXTENSION = "";
    private byte[] plaintext_file_content;
    private byte[] ciphertext_file_content;

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
    private Button encrypt;
    @FXML
    private Button decrypt;

    @FXML
    private RadioButton radio_file;
    @FXML
    private RadioButton radio_text;

    @FXML
    private javafx.scene.image.ImageView key_length_display;
    @FXML
    private javafx.scene.image.ImageView file_indicator_read_plaintext;
    @FXML
    private javafx.scene.image.ImageView file_indicator_save_plaintext;
    @FXML
    private javafx.scene.image.ImageView file_indicator_read_ciphertext;
    @FXML
    private javafx.scene.image.ImageView file_indicator_save_ciphertext;
    @FXML
    private javafx.scene.image.ImageView file_indicator_crypt;


    private void setKeyLength(int value) {
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

    private void setIcon(String place, String icon) {
        File file = new File("src/main/resources/org.krypto/file_" + icon + ".png");
        Image image = new Image(file.toURI().toString());
        switch (place) {
            case "plain_read" -> file_indicator_read_plaintext.setImage(image);
            case "plain_save" -> file_indicator_save_plaintext.setImage(image);
            case "cipher_read" -> file_indicator_read_ciphertext.setImage(image);
            case "cipher_save" -> file_indicator_save_ciphertext.setImage(image);
            case "crypt" -> file_indicator_crypt.setImage(image);
        }
    }

    // Initialize all "onClick" type events for UI elements
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {


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
                setKeyLength((int) key_length_slider.getValue()));

        // Save key to file
        key_save_button.setOnAction(ActionEvent -> {
            if (key_text_field.getText().length() < 1) {
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CANNOT SAVE EMPTY KEY", ButtonType.OK);
                alert.show();
            } else {
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
                                    "KEY FILE SAVED CORRECTLY", ButtonType.OK);
                            alert.show();
                        }
                    } catch (IOException e) {
                        Alert alert = new Alert(Alert.AlertType.WARNING,
                                "ERROR DURING FILE SAVING", ButtonType.OK);
                        alert.show();
                        throw new RuntimeException(e);

                    }
                    System.out.println("Save as file: " + fileToSave.getAbsolutePath());
                }
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
                        key_length_slider.setValue(hex.formatHex(readData).length() * 4.0);
                        setKeyLength((int) key_length_slider.getValue());
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "KEY FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID KEY FILE (.aeskey)", ButtonType.OK);
                    alert.show();
                    setIcon("crypt", "x");
                }
            }
        });

        radio_text.selectedProperty().addListener((obs, old, niu) -> {
            FILE_EXTENSION = "txt";
            setIcon("plain_read", "empty");
            setIcon("plain_save", "empty");
            setIcon("cipher_read", "empty");
            setIcon("cipher_save", "empty");
            setIcon("crypt", "empty");
        });

        // Save plaintext to file
        save_plaintext_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();

                fileToSave = new File(fileToSave.getParentFile(), fileToSave.getName() + "." + FILE_EXTENSION);
                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(plaintext_file_content);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "PLAINTEXT FILE SAVED CORRECTLY", ButtonType.OK);
                        alert.show();
                    }
                } catch (IOException e) {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                            "ERROR DURING FILE SAVING", ButtonType.OK);
                    alert.show();
                    throw new RuntimeException(e);

                }
                setIcon("cipher_read", "empty");
                setIcon("plain_read", "empty");
                setIcon("plain_save", "empty");
                plaintext_textarea.setText("");
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
                try {
                    FILE_EXTENSION = FilenameUtils.getExtension(selectedFile.getName());
                    plaintext_file_content = Files.readAllBytes(selectedFile.toPath());
                    plaintext_textarea.setText("Loaded text from file " + selectedFile);
                    setIcon("plain_read", "upload");
                    setIcon("plain_save", "empty");
                    setIcon("cipher_read", "empty");
                    setIcon("cipher_save", "empty");
                    setIcon("crypt", "empty");

                    Alert alert = new Alert(Alert.AlertType.INFORMATION,
                            "FILE LOADED PROPERLY", ButtonType.OK);
                    alert.show();
                } catch (IOException e) {
                    throw new RuntimeException(e);
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

                if (!FilenameUtils.getExtension(fileToSave.getName()).equalsIgnoreCase(ENCRYPTED_FILE_EXT)) {
                    fileToSave = new File(fileToSave.getParentFile(), fileToSave.getName() + "." + FILE_EXTENSION + "." + ENCRYPTED_FILE_EXT);
                }

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(ciphertext_file_content);

                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "ENCRYPTED FILE SAVED CORRECTLY", ButtonType.OK);
                        alert.show();
                    }
                } catch (IOException e) {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                            "ERROR DURING FILE SAVING", ButtonType.OK);
                    alert.show();
                    throw new RuntimeException(e);

                }
                setIcon("plain_read", "empty");
                setIcon("cipher_read", "empty");
                setIcon("cipher_save", "empty");
                ciphertext_textarea.setText("");
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
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase(ENCRYPTED_FILE_EXT)) {
                    try {
                        String[] filename = selectedFile.getName().split("\\.");
                        ciphertext_file_content = Files.readAllBytes(selectedFile.toPath());
                        ciphertext_textarea.setText("Loaded text from file " + selectedFile);
                        FILE_EXTENSION = filename[filename.length - 2];
                        System.out.println("File extension: " + FILE_EXTENSION);
                        setIcon("plain_read", "empty");
                        setIcon("plain_save", "empty");
                        setIcon("cipher_read", "upload");
                        setIcon("cipher_save", "empty");
                        setIcon("crypt", "empty");

                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "ENCRYPTED FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID AES ENCRYPTED FILE (." + ENCRYPTED_FILE_EXT + ")", ButtonType.OK);
                    alert.show();
                }
            }
        });

        encrypt.setOnAction(ActionEvent -> {
            if (key_text_field.getText().length() != 128 / 4 && key_text_field.getText().length() != 192 / 4 && key_text_field.getText().length() != 256 / 4) {
                setIcon("crypt", "x");
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CANNOT ENCRYPT FILE WITH INVALID KEY", ButtonType.OK);
                alert.show();
            } else {
                setIcon("crypt", "scan");
                AES aes = new AES(HexFormat.of().parseHex(key_text_field.getText()));
                if (radio_file.isSelected()) {
                    ciphertext_file_content = aes.encryptData(plaintext_file_content);
                    ciphertext_textarea.setText("Encrypted file");
                } else {
                    if (plaintext_textarea.getText().length() < 1) {
                        setIcon("crypt", "x");
                        Alert alert = new Alert(Alert.AlertType.ERROR,
                                "CANNOT ENCRYPT EMPTY PLAINTEXT", ButtonType.OK);
                        alert.show();
                    } else {
                        plaintext_file_content = plaintext_textarea.getText().getBytes(StandardCharsets.UTF_8);
                        plaintext_textarea.clear();
                        ciphertext_file_content = aes.encryptData(plaintext_file_content);
                        ciphertext_textarea.setText(HexFormat.of().formatHex(ciphertext_file_content));
                    }
                }
                setIcon("cipher_save", "download");
                setIcon("crypt", "checked");
            }

        });

        decrypt.setOnAction(ActionEvent -> {
            if (key_text_field.getText().length() != 128 / 4 && key_text_field.getText().length() != 192 / 4 && key_text_field.getText().length() != 256 / 4) {
                setIcon("crypt", "x");
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CANNOT DECRYPT FILE WITH INVALID KEY", ButtonType.OK);
                alert.show();
            } else {
                setIcon("crypt", "scan");
                AES aes = new AES(HexFormat.of().parseHex(key_text_field.getText()));
                if (radio_file.isSelected()) {
                    plaintext_file_content = aes.decryptData(ciphertext_file_content);
                    plaintext_textarea.setText("Decrypted file");
                } else {
                    if (ciphertext_textarea.getText().length() < 1) {
                        setIcon("crypt", "x");
                        Alert alert = new Alert(Alert.AlertType.ERROR,
                                "CANNOT DECRYPT EMPTY CIPHERTEXT", ButtonType.OK);
                        alert.show();
                    } else {
                        ciphertext_file_content = HexFormat.of().parseHex(ciphertext_textarea.getText());
                        ciphertext_textarea.clear();
                        plaintext_file_content = aes.decryptData(ciphertext_file_content);
                        plaintext_textarea.setText(new String(plaintext_file_content, StandardCharsets.UTF_8));
                    }
                }

                setIcon("plain_save", "download");
                setIcon("crypt", "checked");
            }
        });
    }

    //Switch to DSA button handling
    public void switchToDSA(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(KryptoApplication.class.getResource("/org.krypto/dsa.fxml")));
        Stage stage = (Stage) ((MenuItem) event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        Scene scene = new Scene(root);
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
        if (result.isEmpty() || result.get() == ButtonType.OK) {
            System.exit(0);
        }
    }


}