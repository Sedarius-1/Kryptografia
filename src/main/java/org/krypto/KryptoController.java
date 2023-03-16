package org.krypto;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.Stage;
import org.apache.commons.io.FilenameUtils;

import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.ThreadLocalRandom;


public class KryptoController {

    @FXML
    private Button klucz_odczyt_button;

    @FXML
    private MenuItem goto_des;

    @FXML
    private TextField klucz_text_field;

    @FXML
    private Button klucz_text_button;

    @FXML
    private Button klucz_zapis_button;
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

    public void createRandomValue(){
        klucz_text_button.setOnAction(ActionEvent-> {
            byte[] secureRandomKeyBytes = new byte[256/8];
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(secureRandomKeyBytes);
            HexFormat hex = HexFormat.of();
            klucz_text_field.setText(hex.formatHex(secureRandomKeyBytes));
        });

    }

    public void saveKeyToFile(){
        klucz_zapis_button.setOnAction(ActionEvent ->{
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File fileToSave = fileChooser.getSelectedFile();
                if (FilenameUtils.getExtension(fileToSave.getName()).equalsIgnoreCase("aeskey")) {
                } else {
                    fileToSave = new File(fileToSave + ".aeskey");
                    fileToSave = new File(fileToSave.getParentFile(), FilenameUtils.getBaseName(fileToSave.getName())+".aeskey");
                }
                 byte[] key_bytes = HexFormat.of().parseHex(klucz_text_field.getText());

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(fileToSave)) {
                        outputStream.write(key_bytes);
                    }
//                    BufferedWriter writer = new BufferedWriter(new FileWriter(fileToSave.getAbsolutePath()));
//                    writer.write(key_bytes);
//                    writer.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                System.out.println("Save as file: " + fileToSave.getAbsolutePath());
            }
        });
    }

    public void loadKeyFromFile(){
        klucz_odczyt_button.setOnAction(ActionEvent -> {
            Alert a = new Alert(Alert.AlertType.ERROR, "TO NIE JEST PLIK KLUCZA! (.aeskey)", ButtonType.APPLY);
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("Specify a file to load");

            int userSelection = fileChooser.showOpenDialog(parentFrame);
            if(userSelection == JFileChooser.APPROVE_OPTION){
                File selectedFile = fileChooser.getSelectedFile();
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("aeskey")){
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        HexFormat hex = HexFormat.of();
                        klucz_text_field.setText(hex.formatHex(readData));

                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                else{
                    a.setAlertType(Alert.AlertType.ERROR);
                    a.show();
                }
            }
        });
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