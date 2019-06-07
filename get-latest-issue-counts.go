package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

const (
	baseURI  = `https://snyk.io/api/v1`
	endpoint = `reporting/counts/issues/latest`
)

func main() {
	nArgs := len(os.Args[1:])
	if nArgs != 1 {
		fmt.Println("Usage: go run get-latest-issue-counts.go <orgId>")
		return
	}
	orgId := os.Args[1]

	fmt.Println("called with", os.Args[1:])

	if err := godotenv.Load(); err != nil {
		fmt.Println(err)
		return
	}

	uri := fmt.Sprintf("%s/%s", baseURI, endpoint)

	body := []byte(`{"filters": {"orgs": ["` + orgId + `"]}}`)

	req, err := http.NewRequest("POST", uri, bytes.NewBuffer(body))
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Authorization", "token "+os.Getenv("API_KEY"))
	req.Header.Add("Content-Type", "application/json")

	fmt.Println("POST ", uri)

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
