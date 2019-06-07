package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

const (
	baseURI = `https://snyk.io/api/v1`
)

func main() {
	var endpoint string

	nArgs := len(os.Args[1:])
	if nArgs > 1 {
		fmt.Println("Usage: go run get.go [endpoint]")
		fmt.Println("       go run get.go")
		fmt.Println("          => GET https://snyk.io/api/v1")
		fmt.Println()
		fmt.Println("       go run get.go org/:orgID/projects")
		fmt.Println("          => GET https://snyk.io/api/v1/org/:orgID/projects")
		return
	} else if nArgs == 1 {
		endpoint = os.Args[1]
	}
	fmt.Println("called with", os.Args[1:])

	if err := godotenv.Load(); err != nil {
		fmt.Println(err)
		return
	}

	uri := fmt.Sprintf("%s/%s", baseURI, endpoint)

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "token "+os.Getenv("API_KEY"))

	fmt.Println("GET ", uri)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	fmt.Println(resp.Status)

	if err := writePrettyJson(os.Stdout, resp); err != nil {
		fmt.Println(err)
		return
	}
}

func writePrettyJson(w io.Writer, r *http.Response) error {
	var j interface{}

	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		return fmt.Errorf("writePrettyJson: %s", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(j); err != nil {
		return fmt.Errorf("writePrettyJson: %s", err)
	}

	return nil
}
