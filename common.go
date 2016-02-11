package cuckoo

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

// -----------------------------------------------------------------------------

// ClientError is a generic error specific to the `govt` package.
type ClientError struct {
	msg string
}

// Error returns a string representation of the error condition.
func (self ClientError) Error() string {
	return self.msg
}

// makeApiGetRequest fetches a URL with querystring via HTTP GET and
//  returns the response if the status code is HTTP 200
// `parameters` should not include the apikey.
// The caller must call `resp.Body.Close()`.
func (c *client) makeApiGetRequest(fullurl string, parameters map[string]string) (resp *http.Response, err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// prepare http client
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest("GET", fullurl, nil)
	if err != nil {
		return resp, err
	}

	if c.BasicAuthUsername != "" {
		req.SetBasicAuth(c.BasicAuthUsername, c.BasicAuthPassword)
	}

	resp, err = client.Do(req)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != 200 {
		var msg string = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		resp.Write(os.Stdout)
		return resp, ClientError{msg: msg}
	}

	return resp, nil
}

// makeApiPostRequest fetches a URL with querystring via HTTP POST and
//  returns the response if the status code is HTTP 200
// `parameters` should not include the apikey.
// The caller must call `resp.Body.Close()`.
func (c *client) makeApiPostRequest(fullurl string, parameters map[string]string) (resp *http.Response, err error) {
	values := url.Values{}
	for k, v := range parameters {
		values.Add(k, v)
	}

	resp, err = http.PostForm(fullurl, values)
	if err != nil {
		return resp, err
	}

	if resp.StatusCode != 200 {
		var msg string = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		resp.Write(os.Stdout)
		return resp, ClientError{msg: msg}
	}

	return resp, nil
}

// makeApiUploadRequest uploads a file via multipart/mime POST and
//  returns the response if the status code is HTTP 200
// `parameters` should not include the apikey.
// The caller must call `resp.Body.Close()`.
func (c *client) makeApiUploadRequest(fullurl string, parameters map[string]string, paramName, path string) (resp *http.Response, err error) {
	// open the file
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// prepare and create a multipart/mime body
	// create a buffer to hold the body of our HTTP Request
	body := &bytes.Buffer{}
	// create a multipat/mime writer
	writer := multipart.NewWriter(body)
	// get the Content-Type of our form data
	fdct := writer.FormDataContentType()
	// create a part for our file
	part, err := writer.CreateFormFile(paramName, filepath.Base(path))
	if err != nil {
		return nil, err
	}
	// copy our file into the file part of our multipart/mime message
	_, err = io.Copy(part, file)
	// write parameters into the request
	for key, val := range parameters {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	// create a HTTP request with our body, that contains our file
	postReq, err := http.NewRequest("POST", fullurl, body)

	if err != nil {
		return resp, err
	}

	if c.BasicAuthUsername != "" {
		postReq.SetBasicAuth(c.BasicAuthUsername, c.BasicAuthPassword)
	}

	// add the Content-Type we got earlier to the request header.
	//  some implementations fail if this is not present. (malwr.com, virustotal.com, probably others too)
	//  this could also be a bug in go actually.
	postReq.Header.Add("Content-Type", fdct)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	// prepare http client
	client := &http.Client{Transport: tr}
	// send our request off, get response and/or error
	resp, err = client.Do(postReq)
	if err != nil {
		return resp, err
	}
	// oops something went wrong
	if resp.StatusCode != 200 {
		var msg string = fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
		resp.Write(os.Stdout)
		return resp, ClientError{msg: msg}
	}
	// we made it, let's return
	return resp, nil
}

type Parameters map[string]string

// fetchApiJson makes a request to the API and decodes the response.
// `method` is one of "GET", "POST", or "FILE"
// `actionurl` is the final path component that specifies the API call
// `parameters` does not include the API key
// `result` is modified as an output parameter. It must be a pointer to a VT JSON structure.
func (c *client) fetchApiJson(method string, actionurl string, parameters Parameters, result interface{}) (err error) {
	theurl := fmt.Sprintf("%s%s", c.BaseURL, actionurl)
	var resp *http.Response
	switch method {
	case "GET":
		resp, err = c.makeApiGetRequest(theurl, parameters)
	case "POST":
		resp, err = c.makeApiPostRequest(theurl, parameters)
	case "FILE":
		// get the path to our file from parameters["filename"]
		path := parameters["filename"]
		// call makeApiUploadRequest with fresh/empty Parameters
		resp, err = c.makeApiUploadRequest(theurl, Parameters{}, "file", path)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)
	if err = dec.Decode(result); err != nil {
		return err
	}

	return nil
}

// fetchApiFile makes a get request to the API and returns the file content
func (c *client) fetchApiFile(actionurl string, parameters Parameters) (data []byte, err error) {
	theurl := fmt.Sprintf("%s%s", c.BaseURL, actionurl)
	var resp *http.Response
	resp, err = c.makeApiGetRequest(theurl, parameters)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// -----------------------------------------------------------------------------
