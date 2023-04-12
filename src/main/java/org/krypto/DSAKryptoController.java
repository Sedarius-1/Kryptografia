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
import org.apache.commons.io.FilenameUtils;

import javax.swing.*;
import java.io.*;
import java.math.BigInteger;
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
    // - parameters generation                                                                                      Done
    // - key generation                                                                                             Done
    // - save key button must create two files:                                                                     Done
    //      - filename.pbl (p,q,h + public key)
    //      - filename.prv (p,q,h + private key)
    // - read key button must read in one file (pub or prv, depending on extension)                                 Done

    // IMPORTANT: DATA IN FILES IS SAVED AS A PLAINTEXT FOR TESTING PURPOSES,
    // WILL BE REFACTORED AFTER CONSULTATION WITH YOU

    // - to sign: we will use SHA512 of document (if you object, tell me why)
    // - signature_textarea must display signature in hex
    // - signatures must be readable and savable to .sig files
    // - verify_state_label is used to display state of verification ("Signature matches" or "INVALID SIGNATURE!")


    // Initialize all "onClick" type events for UI elements
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {
        DSA dsa = new DSA();

        key_gen_button.setOnAction(ActionEvent -> {
                BigInteger q = BigInteger.probablePrime(160, new SecureRandom());
                int additional_bits_multipier = ((new SecureRandom().nextInt() & Integer.MAX_VALUE )% 9);
//                System.out.println("Multiplier: "+additional_bits_multipier);
                int bitLength = 512 + 64 * additional_bits_multipier;
                BigInteger pm1;
                do {
                    System.out.println("Generating new pm1!");
                    BigInteger pMul = new BigInteger(bitLength-160, new SecureRandom());
                    pm1 = q.multiply(pMul);
                    System.out.println("Bit length: "+pm1.bitLength());
                    System.out.println("Division result: "+pm1.mod(q));
                }while(pm1.bitLength()!=bitLength);
                BigInteger p = pm1.add(BigInteger.valueOf(1));
//                System.out.println("Q: "+q);
                BigInteger h;
                do{
                    h = new BigInteger(160, new SecureRandom());

                }while(h.equals(BigInteger.valueOf(0)) || h.compareTo(pm1)>0 ||  h.toString().length()!= q.toString().length());



                dsa.setParams(p,q,h);

                BigInteger privateKey;
                do{
                    privateKey = new BigInteger(160, new SecureRandom());

                }while(privateKey.equals(BigInteger.valueOf(1)) || privateKey.compareTo(q)>=0);

                BigInteger publicKey = h.modPow(privateKey,p);

                dsa.setPrivateKey(privateKey);
                dsa.setPublicKey(publicKey);

                key_p_text_field.setText(p.toString());
                key_q_text_field.setText(q.toString());
                key_h_text_field.setText(h.toString());
                key_private_text_field.setText(privateKey.toString());
                key_public_text_field.setText(publicKey.toString());
        });

        key_save_button.setOnAction(ActionEvent -> {
            if (key_private_text_field.getText().length() < 1 || key_public_text_field.getText().length() <1) {
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CANNOT SAVE PAIR OF KEYS IF EITHER OF THEM IS EMPTY", ButtonType.OK);
                alert.show();
            } else {
                JFrame parentFrame = new JFrame();

                JFileChooser fileChooser = new JFileChooser("C:\\DSA");
                fileChooser.setDialogTitle("Specify a file to save");

                int userSelection = fileChooser.showSaveDialog(parentFrame);


                if (userSelection == JFileChooser.APPROVE_OPTION) {

                    String directory =  fileChooser.getCurrentDirectory().getAbsolutePath();
                    String filename = fileChooser.getSelectedFile().getName();
//                    System.out.println( fileChooser.getCurrentDirectory().getAbsolutePath());
//                    System.out.println(fileChooser.getSelectedFile().getName());
                    byte[] lineseparator = "\n".getBytes();
                    byte[] p_bytes = key_p_text_field.getText().getBytes();
                    byte[] q_bytes = key_q_text_field.getText().getBytes();
                    byte[] h_bytes = key_h_text_field.getText().getBytes();
                    byte[] private_key_bytes =  key_private_text_field.getText().getBytes();
                    byte[] public_key_bytes =  key_public_text_field.getText().getBytes();
                    File privateKeyFile = new File(directory+"/"+filename+".prv");
                    File publicKeyFile = new File(directory+"/"+filename+".pbl");
                    try {
                        try (FileOutputStream outputStream = new FileOutputStream(privateKeyFile)) {
                            outputStream.write(p_bytes);
                            outputStream.write(lineseparator);
                            outputStream.write(q_bytes);
                            outputStream.write(lineseparator);
                            outputStream.write(h_bytes);
                            outputStream.write(lineseparator);
                            outputStream.write(private_key_bytes);

                        }
                        try (FileOutputStream outputStream = new FileOutputStream(publicKeyFile)) {
                            outputStream.write(p_bytes);
                            outputStream.write(lineseparator);
                            outputStream.write(q_bytes);
                            outputStream.write(lineseparator);
                            outputStream.write(h_bytes);
                            outputStream.write(lineseparator);
                            outputStream.write(public_key_bytes);

                        }
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "KEY FILES SAVED CORRECTLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        Alert alert = new Alert(Alert.AlertType.WARNING,
                                "ERROR DURING FILES SAVING", ButtonType.OK);
                        alert.show();
                        throw new RuntimeException(e);

                    }
                    System.out.println("Private Key saved as file: " + privateKeyFile.getAbsolutePath());
                    System.out.println("Public Key saved as file: " + publicKeyFile.getAbsolutePath());
                }
            }
        });

        key_read_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser("C:\\DSA");
            fileChooser.setDialogTitle("Specify a file to load");

            int userSelection = fileChooser.showOpenDialog(parentFrame);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("prv")) {
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        String readString = new String(readData);
                        String[] formatedString = readString.split("\n");
                        key_p_text_field.setText(formatedString[0]);
                        key_q_text_field.setText(formatedString[1]);
                        key_h_text_field.setText(formatedString[2]);
                        key_private_text_field.setText(formatedString[3]);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "PRIVATE KEY FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                }
                else if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("pbl")) {
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        String readString = new String(readData);
                        String[] formatedString = readString.split("\n");
                        key_p_text_field.setText(formatedString[0]);
                        key_q_text_field.setText(formatedString[1]);
                        key_h_text_field.setText(formatedString[2]);
                        key_public_text_field.setText(formatedString[3]);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "PUBLIC KEY FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID KEY FILE (.prv or .pbl)", ButtonType.OK);
                    alert.show();
                }
            }
        });

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