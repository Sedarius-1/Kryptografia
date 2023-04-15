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
import java.math.BigInteger;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.ResourceBundle;


public class DSAKryptoController implements Initializable {

    DSA dsa = new DSA();
    byte[] document_file_content;

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
//    private RadioButton radio_text;

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

    public DSAKryptoController() {
    }

    private void setIcon(String place, String icon) {
        File file = new File("src/main/resources/org.krypto/file_" + icon + ".png");
        Image image = new Image(file.toURI().toString());
        switch (place) {
            case "doc_read" -> file_indicator_read_document.setImage(image);
            case "sig_read" -> file_indicator_read_signature.setImage(image);
            case "sig_save" -> file_indicator_save_signature.setImage(image);
            case "verify" -> file_indicator_sign.setImage(image);
        }
    }

    private void setParamsFromString(String readString, boolean isPrivate) {
        String[] formatedString = readString.split("\n");
        key_p_text_field.setText(formatedString[0]);
        key_q_text_field.setText(formatedString[1]);
        key_h_text_field.setText(formatedString[2]);
        dsa.setParams(new BigInteger(formatedString[0]), new BigInteger(formatedString[1]), new BigInteger(formatedString[2]));
        if (isPrivate) {
            key_private_text_field.setText(formatedString[3]);
            dsa.setPrivateKey(new BigInteger(formatedString[3]));
        } else {
            key_public_text_field.setText(formatedString[3]);
            dsa.setPublicKey(new BigInteger(formatedString[3]));
        }

    }

//    public void generateKey()
//    {   //tworzymy losową liczbę bitów dla p
//        BigInteger p,q,h,g,x,y,pm1;
//        MessageDigest digest;
//        int keyLen=512; //ta wartość daje długość p=512
//        int ilZnHex=keyLen/4;//ilość znaków hex wyświetlanych w polu klucza
//        Random random=new Random();
//        int rand=512+(int)random.nextFloat()*512;
//        //następnie musimy ją dobić tak aby była wielokrotnością 64
//        while (true)
//            if (rand%64==0) break;
//            else rand++;
//        keyLen=rand;
//        q=BigInteger.probablePrime(160,new Random());
//        BigInteger pom1, pom2;
//        do
//        {
//            pom1 = BigInteger.probablePrime(keyLen,new Random());
//            pom2 = pom1.subtract(BigInteger.ONE);
//            pom1 = pom1.subtract(pom2.remainder(q));
//        } while (!pom1.isProbablePrime(2));
//        p=pom1;
//        pm1=p.subtract(BigInteger.ONE);
//        h=new BigInteger(keyLen-2,random);
//        while(true)
//            if (h.modPow(pm1.divide(q),p).compareTo(BigInteger.ONE)==1)break;
//            else h=new BigInteger(keyLen-2,random);
//        g=h.modPow(pm1.divide(q),p);
//        do
//            x=new BigInteger(160-2,random);
//        while (x.compareTo(BigInteger.ZERO) != 1);
//        y=g.modPow(x,p);
//    }

    // Initialize all "onClick" type events for UI elements
    @Override
    public void initialize(URL url, ResourceBundle resourceBundle) {

        key_gen_button.setOnAction(ActionEvent -> {
            List<List<BigInteger>> keyList;
            try {
                keyList = dsa.generateKeys();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            key_p_text_field.setText(keyList.get(0).get(0).toString());
            key_q_text_field.setText(keyList.get(0).get(1).toString());
            key_h_text_field.setText(keyList.get(0).get(2).toString());
            key_private_text_field.setText(keyList.get(0).get(3).toString());
            key_public_text_field.setText(keyList.get(1).get(3).toString());
        });

        key_save_button.setOnAction(ActionEvent -> {
            if (key_private_text_field.getText().length() < 1 || key_public_text_field.getText().length() < 1) {
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CANNOT SAVE PAIR OF KEYS IF EITHER OF THEM IS EMPTY", ButtonType.OK);
                alert.show();
            } else if (key_p_text_field.getText().length() < 1
                    || key_q_text_field.getText().length() < 1
                    || key_h_text_field.getText().length() < 1) {
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CANNOT SAVE PAIR OF KEYS IF ANY OF PARAMETERS IS EMPTY", ButtonType.OK);
                alert.show();
            } else {
                JFrame parentFrame = new JFrame();

                JFileChooser fileChooser = new JFileChooser("C:\\DSA");
                fileChooser.setDialogTitle("Specify a file to save");

                int userSelection = fileChooser.showSaveDialog(parentFrame);


                if (userSelection == JFileChooser.APPROVE_OPTION) {

                    String directory = fileChooser.getCurrentDirectory().getAbsolutePath();
                    String filename = fileChooser.getSelectedFile().getName();
                    byte[] lineSeparator = "\n".getBytes();
                    byte[] p_bytes = key_p_text_field.getText().getBytes();
                    byte[] q_bytes = key_q_text_field.getText().getBytes();
                    byte[] h_bytes = key_h_text_field.getText().getBytes();
                    byte[] private_key_bytes = key_private_text_field.getText().getBytes();
                    byte[] public_key_bytes = key_public_text_field.getText().getBytes();
                    File privateKeyFile = new File(directory + "/" + filename + ".prv");
                    File publicKeyFile = new File(directory + "/" + filename + ".pbl");
                    try {
                        try (FileOutputStream outputStream = new FileOutputStream(privateKeyFile)) {
                            outputStream.write(p_bytes);
                            outputStream.write(lineSeparator);
                            outputStream.write(q_bytes);
                            outputStream.write(lineSeparator);
                            outputStream.write(h_bytes);
                            outputStream.write(lineSeparator);
                            outputStream.write(private_key_bytes);

                        }
                        try (FileOutputStream outputStream = new FileOutputStream(publicKeyFile)) {
                            outputStream.write(p_bytes);
                            outputStream.write(lineSeparator);
                            outputStream.write(q_bytes);
                            outputStream.write(lineSeparator);
                            outputStream.write(h_bytes);
                            outputStream.write(lineSeparator);
                            outputStream.write(public_key_bytes);

                        }
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "Private Key saved as file: " + privateKeyFile.getAbsolutePath() +
                                        "\nPublic Key saved as file: " + publicKeyFile.getAbsolutePath(), ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        Alert alert = new Alert(Alert.AlertType.WARNING,
                                "ERROR DURING FILES SAVING", ButtonType.OK);
                        alert.show();
                        throw new RuntimeException(e);

                    }

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
                        setParamsFromString(readString, true);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "PRIVATE KEY FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                } else if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("pbl")) {
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        String readString = new String(readData);
                        setParamsFromString(readString, false);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "PUBLIC KEY FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID KEY FILE (.prv or .pbl)", ButtonType.OK);
                    alert.show();
                }
            }
        });

        // TODO: verify label text handling
        sign.setOnAction(ActionEvent -> {
            Signature s;
            if (radio_file.isSelected()) {
                // TODO: add file reading & error checking
                s = dsa.signData(document_file_content);
                signature_textarea.setText(s.s1.toString() + "\n" + s.s2.toString());
                setIcon("verify", "checked");
                setIcon("sig_save", "download");
            } else {
                if (document_textarea.getText().length() < 1) {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "CANNOT SIGN EMPTY DOCUMENT", ButtonType.OK);
                    alert.show();
                } else {
                    document_file_content = document_textarea.getText().getBytes(StandardCharsets.UTF_8);
                    s = dsa.signData(document_file_content);
                    signature_textarea.setText(s.s1.toString() + "\n" + s.s2.toString());
                    setIcon("verify", "checked");
                    setIcon("sig_save", "download");
                }
            }


        });

        verify.setOnAction(ActionEvent -> {
            String[] formattedSignature = signature_textarea.getText().split("\n");
            Signature signature = new Signature();
            signature.s1 = new BigInteger(formattedSignature[0]);
            signature.s2 = new BigInteger(formattedSignature[1]);
            System.out.println("TEXT:"+document_textarea.getText());
            System.out.println("Sign1:"+formattedSignature[0]);
            System.out.println("Sign2:"+formattedSignature[1]);
            if (dsa.verifySignature(document_file_content, signature)) {
                verify_state_label.setText("SIGNATURE MATCHES");
                setIcon("verify", "checked");
            } else {
                verify_state_label.setText("SIGNATURE DOES NOT MATCH");
                setIcon("verify", "x");
            }
        });

        save_signature_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();
            if (signature_textarea.getText().length() < 1) {
                Alert alert = new Alert(Alert.AlertType.ERROR,
                        "CAN'T SAVE EMPTY SIGNATURE", ButtonType.OK);
                alert.show();
                return;
            }
            JFileChooser fileChooser = new JFileChooser("C:\\DSA");
            fileChooser.setDialogTitle("Specify a file to save");

            int userSelection = fileChooser.showSaveDialog(parentFrame);

            if (userSelection == JFileChooser.APPROVE_OPTION) {
                String directory = fileChooser.getCurrentDirectory().getAbsolutePath();
                String filename = fileChooser.getSelectedFile().getName();
                byte[] signatureData = signature_textarea.getText().getBytes();
                File signatureFile = new File(directory + "/" + filename + ".sig");

                try {
                    try (FileOutputStream outputStream = new FileOutputStream(signatureFile)) {
                        outputStream.write(signatureData);

                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "File saved as: " + signatureFile.getAbsolutePath(), ButtonType.OK);
                        alert.show();
                    }
                } catch (IOException e) {
                    Alert alert = new Alert(Alert.AlertType.WARNING,
                            "ERROR DURING FILE SAVING", ButtonType.OK);
                    alert.show();
                    throw new RuntimeException(e);

                }
            }
            setIcon("sig_save", "empty");
        });

        read_signature_button.setOnAction(ActionEvent -> {
            JFrame parentFrame = new JFrame();

            JFileChooser fileChooser = new JFileChooser("C:\\DSA");
            fileChooser.setDialogTitle("Specify a file to load");

            int userSelection = fileChooser.showOpenDialog(parentFrame);
            if (userSelection == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();
                if (FilenameUtils.getExtension(selectedFile.getName()).equalsIgnoreCase("sig")) {
                    try {
                        byte[] readData = Files.readAllBytes(selectedFile.toPath());
                        String readString = new String(readData);
                        signature_textarea.setText(readString);
                        Alert alert = new Alert(Alert.AlertType.INFORMATION,
                                "SIGNATURE FILE LOADED PROPERLY", ButtonType.OK);
                        alert.show();
                        setIcon("sig_read", "upload");
                        setIcon("verify", "empty");
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                } else {
                    Alert alert = new Alert(Alert.AlertType.ERROR,
                            "THIS IS NOT A VALID SIGNATURE FILE (.sig(ma))", ButtonType.OK);
                    alert.show();
                    setIcon("sig_read", "empty");
                    setIcon("verify", "empty");
                }
            }
        });

        // TODO: read_document
    }

    public void switchToAES(ActionEvent event) throws IOException {
        Parent root = FXMLLoader.load(Objects.requireNonNull(KryptoApplication.class.getResource("/org.krypto/aes.fxml")));
        Stage stage = (Stage) ((MenuItem) event.getSource()).getParentPopup().getOwnerWindow().getScene().getWindow();
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }

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