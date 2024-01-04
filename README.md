# SmartClient.py - Web Server Information Collection Tool

## Description

SmartClient.py is a Python tool designed to collect information regarding a web server by utilizing socket programming. The primary goals of this project are to provide students with hands-on experience in socket programming and to enhance their understanding of HTTP/HTTPS application-layer protocols.

## Features

1. **HTTP/HTTPS Information Retrieval**: The tool sends HTTP requests to a given web server and collects information from the corresponding HTTP responses.

2. **URI Parsing**: SmartClient.py accepts a Uniform Resource Identifier (URI) from standard input, parses it, and establishes a connection to the specified web server.

3. **HTTP/HTTPS Protocol Analysis**: The tool analyzes the HTTP/HTTPS protocol by examining the headers and bodies of both requests and responses. It focuses on key elements such as method, URL, HTTP version, status code, and more.

4. **Web Server Information Extraction**:
   - Determines whether the web server supports HTTP2.
   - Retrieves cookie information, including cookie name, expiration time (if any), and domain name.
   - Identifies if the requested web page is password-protected.

5. **Handling HTTP Status Codes**:
   - Handles common HTTP status codes like 200 (OK), 404 (Not Found), 505 (HTTP Version Not Supported), and 302 (Found for URL redirection).

## Usage

1. **Clone the repository:**

   ```bash
   git clone https://github.com/your-username/SmartClient.git
   cd SmartClient
   ```

2. **Run SmartClient.py:**

   ```bash
   python SmartClient.py [web server URI]
   ```

   Example:
   ```bash
   python SmartClient.py www.uvic.ca
   ```

## Output

After running SmartClient.py, the tool will output information about the web server, including its support for HTTP2, cookie details, and whether the requested web page is password-protected.

**Example Output:**

```plaintext
    ---Request begin--- 
    GET / HTTP/1.1
    Host: uvic.ca
    Connection: close

    ---Request end---

    HTTP request sent, awaiting response...

    ---Response header---
    HTTP/1.0 302 Moved Temporarily
    Location: https://www.uvic.ca/
    Server: BigIP
    Connection: close
    Content-Length: 0
    ---Response header end---

    300 code found: Redirecting

    ---Request begin--- 
    GET / HTTP/1.1
    Host: www.uvic.ca
    Connection: close

    ---Request end---

    HTTP request sent, awaiting response...

    ---Response header---
    HTTP/1.1 200 OK
    Date: Tue, 26 Sep 2023 00:22:17 GMT
    Expires: Thu, 19 Nov 1981 08:52:00 GMT
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
    Set-Cookie: PHPSESSID=97f3e2kaucqq94e1tia763cc8e; path=/; secure; HttpOnly; SameSite=Lax
    Set-Cookie: uvic_bar=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT; Max-Age=0; path=/; domain=.uvic.ca; secure; HttpOnly
    X-XSS-Protection: 1; mode=block
    X-Content-Type-Options: nosniff
    Referrer-Policy: strict-origin-when-cross-origin
    Vary: Accept-Encoding,User-Agent
    Feature-Policy: accelerometer 'none'; camera 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'
    Connection: close
    Content-Type: text/html; charset=UTF-8
    Set-Cookie: www_def=!3y4RDdQUi0AmAUcWefXdu+huOdHSMdRl07OgmQk50nNjPp10IQ07UEOAyHNw+DZMV3kjQzMb9mzQ3+w=; path=/; Httponly; Secure
    Strict-Transport-Security: max-age=16070400
    Set-Cookie: TS018b3cbd=0183e07534a873ad398befd3e35f1758bfc6252945ca06aa3fb76d93526613f9a88cfcc4ce44e648a715b23c22c2bb14a9fd245d4c0c565818665cbe3b69caf859daf88397f16fa98d97e0d509ab00e898f52ee92f; Path=/; Secure; HTTPOnly
    Set-Cookie: TS0165a077=0183e075344b049472d986150e08c1f25e266508fdca06aa3fb76d93526613f9a88cfcc4ceca3b9e8e41f7fc3adf31d052e3f6687d3f0b5abad7b081763f55e587d9522a0f; path=/; domain=.uvic.ca; HTTPonly; Secure
    ---Response header end---




    ---Summary---
    website: www.uvic.ca
    1. Supports http2: False
    2. List of Cookies:
    cookie name: PHPSESSID, expiry time: None, domain: None 
    cookie name: uvic_bar, expiry time: Thu, 01-Jan-1970 00:00:01 GMT, domain: .uvic.ca 
    cookie name: www_def, expiry time: None, domain: None 
    cookie name: TS018b3cbd, expiry time: None, domain: None 
    cookie name: TS0165a077, expiry time: None, domain: .uvic.ca 
    3. Password-protected: False
```

## Notes

- **Ensure that Python is installed on your system before running SmartClient.py.**

## Disclaimer

The output provided by SmartClient.py may be outdated and does not necessarily reflect the current configuration of the specified web server.
