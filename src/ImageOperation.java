import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.*;
import java.util.List;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;

public class ImageOperation {
    static List<Map.Entry<File, byte[]>> encryptedImages = new ArrayList<>();
    static JTable encryptedImagesTable; // Declare as static
    static JLabel selectedFileLabel; // JLabel to display selected file path

    static final int AES_KEY_SIZE = 128;
    static String selectedFilePath = ""; // Store the selected file path

    static byte[] generateAESKey() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[AES_KEY_SIZE / 8];
        secureRandom.nextBytes(keyBytes);
        return keyBytes;
    }

    static void encryptDecrypt(byte[] key, int cipherMode, File inputFile) throws Exception {
        Key secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(cipherMode, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(inputFile);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();
    }

    static boolean isEncrypted(File inputFile) {
        for (Map.Entry<File, byte[]> entry : encryptedImages) {
            if (entry.getKey().equals(inputFile)) {
                return true;
            }
        }
        return false;
    }

    static void encryptImage(File inputFile) throws Exception {
        if (isEncrypted(inputFile)) {
            // File is already encrypted
            JOptionPane.showMessageDialog(null, "File is already encrypted.");
            return;
        }

        byte[] aesKey = generateAESKey();
        encryptDecrypt(aesKey, Cipher.ENCRYPT_MODE, inputFile);
        encryptedImages.add(new AbstractMap.SimpleEntry<>(inputFile, aesKey));
        // Display encrypted image and its key
        JOptionPane.showMessageDialog(null, "Image Encrypted successfully.\nKey: " + Base64.getEncoder().encodeToString(aesKey));
    }

    static void decryptImage(File selectedFile, String aesKeyString) throws Exception {
        byte[] aesKey = Base64.getDecoder().decode(aesKeyString);
        if (aesKey.length != AES_KEY_SIZE / 8) {
            JOptionPane.showMessageDialog(null, "Invalid key length!", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        encryptDecrypt(aesKey, Cipher.DECRYPT_MODE, selectedFile);
        JOptionPane.showMessageDialog(null, "Image Decrypted successfully.");
        // Remove the decrypted image and its key from the list
        Iterator<Map.Entry<File, byte[]>> iterator = encryptedImages.iterator();
        while (iterator.hasNext()) {
            Map.Entry<File, byte[]> entry = iterator.next();
            if (entry.getKey().equals(selectedFile)) {
                iterator.remove();
                break;
            }
        }
        updateEncryptedImagesTable(); // Update the table to reflect changes
        selectedFileLabel.setText("Selected File: " + selectedFilePath); // Restore selected file path
    }

    static void updateEncryptedImagesTable() {
        DefaultTableModel model = (DefaultTableModel) encryptedImagesTable.getModel();
        model.setRowCount(0);
        for (Map.Entry<File, byte[]> entry : encryptedImages) {
            File imageFile = entry.getKey();
            byte[] aesKey = entry.getValue();
            model.addRow(new Object[]{imageFile.getName(), Base64.getEncoder().encodeToString(aesKey)});
        }
    }

    public static void main(String[] args) {
        // creating a frame
        JFrame f = new JFrame();
        f.setTitle("Image Encryption/Decryption");
        f.setSize(600, 400);
        f.setLocationRelativeTo(null);

        // choose file button
        JButton cf = new JButton();
        cf.setText("Choose File");

        // Encryption button
        JButton enc = new JButton();
        enc.setText("Encrypt");

        // Decryption button
        JButton dec = new JButton();
        dec.setText("Decrypt");

        // Show encrypted images button
        JButton showEncrypted = new JButton();
        showEncrypted.setText("Show Encrypted Images");

        // Table to display encrypted images and their keys
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("Image");
        model.addColumn("Encrypted Key");
        encryptedImagesTable = new JTable(model); // Initialize encryptedImagesTable
        JScrollPane scrollPane = new JScrollPane(encryptedImagesTable);

        // JLabel to display selected file path
        selectedFileLabel = new JLabel("Selected File: ");

        // button listeners
        cf.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.addChoosableFileFilter(new FileNameExtensionFilter("Image Files", "jpg", "png"));
            fc.setAcceptAllFileFilterUsed(false);
            fc.showOpenDialog(null);
            File selectedFile = fc.getSelectedFile();
            if (selectedFile != null) {
                selectedFilePath = selectedFile.getAbsolutePath(); // Update selected file path
                selectedFileLabel.setText("Selected File: " + selectedFilePath);
            }
        });

        enc.addActionListener(e -> {
            String filePath = selectedFileLabel.getText().replace("Selected File: ", "");
            if (!filePath.isEmpty()) {
                try {
                    File selectedFile = new File(filePath);
                    encryptImage(selectedFile);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Encryption failed!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(null, "No file selected!", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        dec.addActionListener(e -> {
            int selectedRow = encryptedImagesTable.getSelectedRow();
            if (selectedRow == -1) {
                JOptionPane.showMessageDialog(null, "Please select an encrypted image to decrypt!", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String aesKeyString = (String) model.getValueAt(selectedRow, 1);
            String filename = (String) model.getValueAt(selectedRow, 0);
            if (aesKeyString == null || aesKeyString.isEmpty()) {
                JOptionPane.showMessageDialog(null, "Invalid AES key!", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            String input = JOptionPane.showInputDialog(null, "Enter decryption key for image " + filename + ":");
            if (input != null) {
                try {
                    decryptImage(encryptedImages.get(selectedRow).getKey(), input);
                } catch (Exception ex) {
                    ex.printStackTrace();
                    JOptionPane.showMessageDialog(null, "Decryption failed!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        showEncrypted.addActionListener(e -> {
            updateEncryptedImagesTable(); // Update the table before showing
            JOptionPane.showMessageDialog(null, scrollPane, "Encrypted Images", JOptionPane.PLAIN_MESSAGE);
        });

        // Panel for buttons
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(cf);
        buttonPanel.add(enc);
        buttonPanel.add(dec);
        buttonPanel.add(showEncrypted);

        // Panel to display selected file path
        JPanel selectedFilePanel = new JPanel();
        selectedFilePanel.add(selectedFileLabel);

        // Add button panel and selected file panel to frame
        f.add(selectedFilePanel, BorderLayout.NORTH);
        f.add(buttonPanel, BorderLayout.CENTER);
        f.setVisible(true);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
}

