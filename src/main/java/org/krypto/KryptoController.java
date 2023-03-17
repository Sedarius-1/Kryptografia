package org.krypto;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import javafx.scene.image.Image;
import org.apache.commons.io.FilenameUtils;

import javax.swing.*;
import javax.swing.text.html.ImageView;
import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.HexFormat;


public class KryptoController {

    @FXML
    private Button klucz_odczyt_button;

    @FXML
    private TextField key_text_field;

    @FXML
    private Button klucz_text_button;

    @FXML
    private Button klucz_zapis_button;

    @FXML
    private Slider key_length_slider;

    @FXML
    private javafx.scene.image.ImageView key_length_display;
    private Stage stage;
    private Scene scene;


    public void switchToAES(ActionEvent event) throws IOException {
        // TODO: fix "might be null warning"
        Parent root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/aes.fxml"));
        stage = (Stage) ((MenuItem) event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

    public void switchToDSA(ActionEvent event) throws IOException {
        // TODO: fix "might be null warning"
        Parent root = FXMLLoader.load(KryptoApplication.class.getResource("/org.krypto/dsa.fxml"));
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

    public void createRandomValue() {
        klucz_text_button.setOnAction(ActionEvent -> {
            byte[] secureRandomKeyBytes = new byte[((int) key_length_slider.getValue()) / 8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(secureRandomKeyBytes);
            HexFormat hex = HexFormat.of();
            key_text_field.setText(hex.formatHex(secureRandomKeyBytes));
        });

    }

    // TODO: fix
    public void setKeyLength() {
        key_length_slider.valueProperty().addListener(new ChangeListener<Number>() {
            @Override
            public void changed(ObservableValue<? extends Number> observableValue, Number number, Number t1) {
                File file;
                // src/main/resources/org/krypto/
                Image image;
                switch ((int) key_length_slider.getValue()) {
                    case 128:
                        file = new File("src/main/resources/org.krypto/Key-short.png");
                        image = new Image(file.toURI().toString());
                        key_length_display.setImage(image);
                        key_length_display.setFitWidth(230);
                        break;
                    case 192:
                        file = new File("src/main/resources/org.krypto/Key-medium.png");
                        image = new Image(file.toURI().toString());
                        key_length_display.setImage(image);
                        key_length_display.setFitWidth(350);
                        break;
                    case 256:
                        file = new File("src/main/resources/org.krypto/Key-long.png");
                        image = new Image(file.toURI().toString());
                        key_length_display.setImage(image);
                        key_length_display.setFitWidth(460);
                        break;
                }
            }
        });
    }

    public void saveKeyToFile() {
        klucz_zapis_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                // TODO: co to kurwa jest?
                if (FilenameUtils.getExtension(fileToSave.getName()).equalsIgnoreCase("aeskey")) {
                } else {
                    fileToSave = new File(fileToSave + ".aeskey");
                    fileToSave = new File(fileToSave.getParentFile(), FilenameUtils.getBaseName(fileToSave.getName()) + ".aeskey");
                }
                byte[] key_bytes = HexFormat.of().parseHex(key_text_field.getText());

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(key_bytes);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                System.out.println("Save as file: " + fileToSave.getAbsolutePath());
            }
        });
    }

    public void loadKeyFromFile() {
        klucz_odczyt_button.setOnAction(ActionEvent -> {
            Alert a = new Alert(Alert.AlertType.ERROR, "TO NIE JEST PLIK KLUCZA! (.aeskey)", ButtonType.APPLY);
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

                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    a.setAlertType(Alert.AlertType.ERROR);
                    a.show();
                }
            }
        });
    }


}