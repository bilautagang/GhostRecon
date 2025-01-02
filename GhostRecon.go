package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

func main() {
	fmt.Print("Enter the target domain: ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	domain := scanner.Text()

	if domain == "" {
		fmt.Println("Domain cannot be empty.")
		return
	}

	// Create output folder in /home
	baseFolder := filepath.Join("/home", fmt.Sprintf("ghostrecon_%s", domain))
	err := os.MkdirAll(baseFolder, 0755)
	if err != nil {
		log.Fatalf("Error creating folder: %v", err)
	}

	// Run all tools concurrently
	results := runAllToolsConcurrently(domain, baseFolder)

	// Consolidate and clean subdomains
	cleanedSubdomains := consolidateAndCleanSubdomains(domain, baseFolder, results)

	// Check for live subdomains
	saveLiveSubdomains(domain, baseFolder, cleanedSubdomains)
}

// Run all tools concurrently
func runAllToolsConcurrently(domain, folder string) map[string]string {
	fmt.Println("Running all tools concurrently...")
	var wg sync.WaitGroup
	results := make(map[string]string)
	mu := sync.Mutex{}

	tools := map[string]func(string, string) string{
		"Sublist3r":   runSublist3r,
		"Assetfinder": runAssetfinder,
		"Subfinder":   runSubfinder,
	}

	for toolName, toolFunc := range tools {
		wg.Add(1)
		go func(name string, tool func(string, string) string) {
			defer wg.Done()
			output := tool(domain, folder)
			mu.Lock()
			results[name] = output
			mu.Unlock()
		}(toolName, toolFunc)
	}

	wg.Wait()
	return results
}

// Run Sublist3r
func runSublist3r(domain, folder string) string {
	fmt.Printf("Running Sublist3r for %s\n", domain)
	outputFile := filepath.Join(folder, fmt.Sprintf("%s_sublist3r_%s.txt", "Sublist3r", domain))
	cmd := exec.Command("sublist3r", "-d", domain, "-o", outputFile)
	err := cmd.Run()
	if err != nil {
		log.Printf("Error running Sublist3r: %v", err)
	}
	fmt.Printf("Subdomains saved to %s\n", outputFile)
	return outputFile
}

// Run Assetfinder
func runAssetfinder(domain, folder string) string {
	fmt.Printf("Running Assetfinder for %s\n", domain)
	outputFile := filepath.Join(folder, fmt.Sprintf("%s_assetfinder_%s.txt", "Assetfinder", domain))
	cmd := exec.Command("assetfinder", "--subs-only", domain)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Printf("Error running Assetfinder: %v", err)
	}
	err = os.WriteFile(outputFile, out.Bytes(), 0644)
	if err != nil {
		log.Printf("Error saving Assetfinder output: %v", err)
	}
	fmt.Printf("Subdomains saved to %s\n", outputFile)
	return outputFile
}

// Run Subfinder
func runSubfinder(domain, folder string) string {
	fmt.Printf("Running Subfinder for %s\n", domain)
	outputFile := filepath.Join(folder, fmt.Sprintf("%s_subfinder_%s.txt", "Subfinder", domain))
	cmd := exec.Command("subfinder", "-d", domain, "-o", outputFile)
	err := cmd.Run()
	if err != nil {
		log.Printf("Error running Subfinder: %v", err)
	}
	fmt.Printf("Subdomains saved to %s\n", outputFile)
	return outputFile
}

// Check domain status using httprobe
func checkDomainStatus(domain string) string {
	cmd := exec.Command("httprobe", domain)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Error running httprobe: %v", err)
		return "dead"
	}
	output := string(out)
	if strings.Contains(output, domain) {
		return "live"
	}
	return "dead"
}

// Consolidate and clean subdomains
func consolidateAndCleanSubdomains(domain, folder string, results map[string]string) []string {
	fmt.Println("Consolidating and cleaning subdomains...")
	subdomainSet := make(map[string]struct{})
	for _, file := range results {
		fileContent, err := os.ReadFile(file)
		if err != nil {
			log.Printf("Error reading file %s: %v", file, err)
			continue
		}
		lines := strings.Split(string(fileContent), "\n")
		for _, line := range lines {
			cleaned := strings.TrimSpace(line)
			if cleaned != "" {
				subdomainSet[cleaned] = struct{}{}
			}
		}
	}

	cleanedSubdomains := make([]string, 0, len(subdomainSet))
	for subdomain := range subdomainSet {
		cleanedSubdomains = append(cleanedSubdomains, subdomain)
	}

	cleanedFile := filepath.Join(folder, fmt.Sprintf("%s_cleaned_subdomains.txt", domain))
	err := os.WriteFile(cleanedFile, []byte(strings.Join(cleanedSubdomains, "\n")), 0644)
	if err != nil {
		log.Fatalf("Error saving cleaned subdomains: %v", err)
	}
	fmt.Printf("Cleaned subdomains saved to %s\n", cleanedFile)

	return cleanedSubdomains
}

// Save live subdomains using httprobe
func saveLiveSubdomains(domain, folder string, subdomains []string) {
	const workerCount = 10 // Adjust the number of workers based on system capacity
	liveSubdomains := make([]string, 0)
	var mu sync.Mutex
	wg := sync.WaitGroup{}
	tasks := make(chan string, len(subdomains))

	// Worker function
	worker := func() {
		defer wg.Done()
		for sub := range tasks {
			status := checkDomainStatus(sub)
			mu.Lock()
			if status == "live" {
				liveSubdomains = append(liveSubdomains, sub)
			}
			mu.Unlock()
		}
	}

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

	// Distribute tasks
	for _, subdomain := range subdomains {
		tasks <- subdomain
	}
	close(tasks)

	// Wait for all workers to finish
	wg.Wait()

	// Save live subdomains
	liveFilePath := filepath.Join(folder, fmt.Sprintf("%s_live_subdomains.txt", domain))
	err := os.WriteFile(liveFilePath, []byte(strings.Join(liveSubdomains, "\n")), 0644)
	if err != nil {
		log.Fatalf("Error saving live subdomains: %v", err)
	}
	fmt.Printf("Live subdomains saved to %s\n", liveFilePath)
}
