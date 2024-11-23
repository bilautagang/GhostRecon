package main

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"time"
)

func main() {
	// Check and install required tools
	tools := []string{"subfinder", "assetfinder", "dnsrecon", "findomain", "aquatone"}
	for _, tool := range tools {
		checkAndInstall(tool)
	}

	// Get website URL
	website := getUserInput("Enter the website URL: ")

	// Determine output directory
	outputDir := fmt.Sprintf("/home/%s/ghostrecon-%s", getUsername(), strings.ReplaceAll(website, ".", "-"))

	// Create output directory
	createDirectory(outputDir)

	// Find subdomains
	findSubdomains(website, outputDir)

	// Remove duplicates and save to master file
	uniqueSubdomains := removeDuplicates(outputDir)
	saveToFile(uniqueSubdomains, outputDir+"/ghostrecon-uniq.txt")

	// Check for live and dead subdomains
	checkLiveDeadSubdomains(uniqueSubdomains, outputDir)

	// Take screenshots of live subdomains
	takeScreenshots(outputDir+"/ghostrecon-live.txt", outputDir+"/aquatone-live")

	// Take screenshots of 404 subdomains
	takeScreenshots(outputDir+"/ghostrecon-404.txt", outputDir+"/aquatone-404")

	fmt.Println("Reconnaissance completed.")
}

func checkAndInstall(tool string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("command -v %s", tool))
	if err := cmd.Run(); err != nil {
		fmt.Printf("Installing %s...\n", tool)
		var installCmd *exec.Cmd
		switch tool {
		case "aquatone":
			installCmd = exec.Command("sh", "-c", "go install github.com/michenriksen/aquatone@latest")
		default:
			installCmd = exec.Command("sh", "-c", fmt.Sprintf("sudo pacman -S --noconfirm %s", tool))
		}
		if err := installCmd.Run(); err != nil {
			fmt.Printf("Error installing %s: %v\n", tool, err)
			os.Exit(1)
		}
	}
}

func getUserInput(prompt string) string {
	var input string
	fmt.Print(prompt)
	fmt.Scanln(&input)
	return input
}

func getUsername() string {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("Error getting current user: %v\n", err)
		os.Exit(1)
	}
	return currentUser.Username
}

func createDirectory(dirPath string) {
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		fmt.Printf("Error creating output directory %s: %v\n", dirPath, err)
		os.Exit(1)
	}
}

func findSubdomains(website, outputDir string) {
	subdomainTools := []struct {
		name     string
		command  string
		filename string
	}{
		{"subfinder", fmt.Sprintf("subfinder -d %s -o %s/subfinder.txt", website, outputDir), "subfinder.txt"},
		{"assetfinder", fmt.Sprintf("assetfinder --subs-only %s | tee %s/assetfinder.txt", website, outputDir), "assetfinder.txt"},
		{"dnsrecon", fmt.Sprintf("dnsrecon -d %s -t std --xml %s/dnsrecon.xml", website, outputDir), "dnsrecon.xml"},
		{"findomain", fmt.Sprintf("findomain -t %s -u %s/findomain.txt", website, outputDir), "findomain.txt"},
	}

	var wg sync.WaitGroup
	wg.Add(len(subdomainTools))
	for _, tool := range subdomainTools {
		go func(tool struct {
			name     string
			command  string
			filename string
		}) {
			defer wg.Done()
			fmt.Printf("Running %s...\n", tool.name)
			cmd := exec.Command("sh", "-c", tool.command)
			if output, err := cmd.CombinedOutput(); err != nil {
				fmt.Printf("Error running %s: %v\nOutput: %s\n", tool.name, err, string(output))
			} else {
				fmt.Printf("%s completed successfully.\n", tool.name)
			}
		}(tool)
	}
	wg.Wait()
}

func removeDuplicates(outputDir string) []string {
	subdomainFiles := []string{
		outputDir + "/subfinder.txt",
		outputDir + "/assetfinder.txt",
		outputDir + "/findomain.txt",
	}

	subdomainSet := make(map[string]struct{})
	for _, file := range subdomainFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fmt.Printf("Warning: File %s does not exist.\n", file)
			continue
		}
		f, err := os.Open(file)
		if err != nil {
			fmt.Printf("Error opening file %s: %v\n", file, err)
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			subdomain := scanner.Text()
			subdomainSet[subdomain] = struct{}{}
		}
		f.Close()
	}

	var uniqueSubdomains []string
	for subdomain := range subdomainSet {
		uniqueSubdomains = append(uniqueSubdomains, subdomain)
	}

	return uniqueSubdomains
}

func saveToFile(data []string, filepath string) {
	f, err := os.Create(filepath)
	if err != nil {
		fmt.Printf("Error creating file %s: %v\n", filepath, err)
		return
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range data {
		writer.WriteString(line + "\n")
	}
	writer.Flush()
}

func checkLiveDeadSubdomains(subdomains []string, outputDir string) {
	var wg sync.WaitGroup
	liveSubdomains := make(chan string, len(subdomains))
	deadSubdomains := make(chan string, len(subdomains))
	errorSubdomains := make(chan string, len(subdomains))

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			statusCode := getStatusCode(subdomain)
			if statusCode == 200 || statusCode == 301 || statusCode == 302 {
				liveSubdomains <- subdomain
			} else if statusCode == 404 {
				errorSubdomains <- subdomain
			} else {
				deadSubdomains <- subdomain
			}
		}(subdomain)
	}

	wg.Wait()
	close(liveSubdomains)
	close(deadSubdomains)
	close(errorSubdomains)

	var live, dead, errors []string
	for sub := range liveSubdomains {
		live = append(live, sub)
	}
	for sub := range deadSubdomains {
		dead = append(dead, sub)
	}
	for sub := range errorSubdomains {
		errors = append(errors, sub)
	}

	saveToFile(live, outputDir+"/ghostrecon-live.txt")
	saveToFile(dead, outputDir+"/ghostrecon-dead.txt")
	saveToFile(errors, outputDir+"/ghostrecon-404.txt")
}

func getStatusCode(subdomain string) int {
	httpClient := http.Client{Timeout: 5 * time.Second}
	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s", scheme, subdomain)
		resp, err := httpClient.Get(url)
		if err == nil {
			return resp.StatusCode
		}
	}
	return 0
}

func takeScreenshots(inputFile, outputDir string) {
	fmt.Printf("Taking screenshots of subdomains listed in %s...\n", inputFile)
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cat %s | aquatone -out %s", inputFile, outputDir))
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error running aquatone: %v\nOutput: %s\n", err, string(output))
	} else {
		fmt.Printf("Aquatone completed successfully. Screenshots saved in %s.\n", outputDir)
	}
}
