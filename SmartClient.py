import sys
import socket as s
import ssl
import re


#global variables, where G indiciates global
G_HOST = "" #global host name
G_FILEPATH = "" #global filepath
G_H2 = False #boolean flag for h2 support
G_COOKIES_LI = []  #list of cookies
G_PASSWORD_FLAG = False #boolean flag for password protection
G_401_FLAG = False #boolean flag for 401 error code
G_400_FLAG = False #boolean flag for 400 error code


#1. read input from stdin and return uri
def getStdin():
    if len(sys.argv) != 2:
        print("Please enter arguments in the form: python3 SmartClient.py URL_name")
    else:
        uri = sys.argv[1].strip()
        return uri


#2. given a uri, parse to identify the protocol, host, port, and filepath. 
#Store the host and filepath in G_HOST and G_FILEPATH   
def parseURI(uri):
    https_flag = False
    protocol_passed = True

    #find the protocol
    protocol_end_char = uri.find("://")
    if protocol_end_char == -1:
        protocol_passed = False
        url_rest = uri 
    else:
        #set protocol
        if protocol_end_char == 5:
            protocol = uri[:protocol_end_char]  
            https_flag = True
            port = 443
        else:
            protocol = uri[:protocol_end_char]  
            port = 80
        uri_split = uri.split("://", 1)
        protocol = uri_split[0]
        url_rest = uri_split[1]
        

    filepath = ""
   
    
    host = url_rest
    #isolate filepath and port if given
    if "/" in host:
        host_filepath_split = host.split("/", 1)
        host = host_filepath_split[0]
        filepath = host_filepath_split[1]
        if ":" in host:
            host_port_split = host.split(":", 1)
            host = host_port_split[0]
            port = host_port_split[1]
    else:
        if ":" in host:
            host_port_split = host.split(":", 1)
            host = host_port_split[0]
            port = host_port_split[1]
    
    
    #find protocol using server connection if not passed
    if not protocol_passed:
        try:
            context = ssl.create_default_context()
            with s.create_connection((url_rest, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as secure_socket:
                    https_flag = True
                    protocol = 'https'
                    port = 443
        except (s.error, ssl.SSLError):
            https_flag = False
            protocol = "http"
            port = 80
            
    global G_HOST, G_FILEPATH
    G_HOST = host
    G_FILEPATH = filepath
    return port, url_rest
    

#check if h2 is supported and store the boolean result in G_H2
def checkH2():
    global G_HOST, G_FILEPATH, G_H2 
    
    #connect to the server using SSL and check if h2 is supported using alpn_protocols
    try:
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2', 'http/1.1'])
        sock = s.socket(s.AF_INET, s.SOCK_STREAM)
        connection = context.wrap_socket(sock, server_hostname=G_HOST)
        connection.connect((G_HOST, 443))
        ret_protocols = connection.selected_alpn_protocol()
        if ret_protocols == "h2":
            G_H2 = True
    except s.error as socket_error:
        print("Socket error occurred:", socket_error)
    except ssl.SSLError as ssl_error:
        print("SSL error occurred:", ssl_error)
    except Exception as e:
        print("An unexpected error occurred:", e)
  
  
#find list of cookies by sending an http request
#store the list of cookies in G_COOKIES_LI trimmed as per assignment guidelines
def getCookies(response_lines):
    global G_COOKIES_LI, G_HOST, G_FILEPATH

    for line in response_lines:       
        if b"Set-Cookie:" in line or b"set-cookie:" in line:
                cookie_pattern = r'Set-Cookie:\s*([^=]+)'
                expiry_pattern = r'Expires=([^;]+)'
                domain_pattern = r'domain=([^;]+)'

                cookie_name_matches = re.search(cookie_pattern, line.decode(), re.IGNORECASE)
                expiry_match = re.search(expiry_pattern, line.decode(), re.IGNORECASE)
                domain_match = re.search(domain_pattern, line.decode(), re.IGNORECASE)
                if cookie_name_matches:
                    cookie_name = cookie_name_matches.group(1).strip()
                else:
                    cookie_name = None

                if expiry_match:
                    expiry_date = expiry_match.group(1).strip()
                else:
                    expiry_date = None

                if domain_match:
                    domain = domain_match.group(1)
                else:
                    domain = None
                    
                G_COOKIES_LI.append(f"{cookie_name}, expiry time: {expiry_date}, domain: {domain} ")
                
                
        
        
        
        
            # regex_pattern1 = r'Set-Cookie:\s*([^=]+)(?:.*?expires=([^;]+);)?(?:.*?domain=([^;]+);)?(?:.*?path=([^;]+);)?'
            # matches1 = re.search(regex_pattern1, line.decode(), re.IGNORECASE)
            # if matches1:
            #     for match1 in matches1:
            #         cookie_name = match1[0].strip()
            #         # expiry_date = match1[1].strip() if match1[1] else None
            #         # domain = match1[2].strip() if match1[2] else None
            #         expiry_date = match1[1].strip() if match1[1] else None
            #         domain = match1[2].strip() if match1[2] else None
            #         path = match1[3].strip() if match1[3] else None
            #         G_COOKIES_LI.append(f"{cookie_name}, expiry time: {expiry_date}, domain: {domain}, path: {path} ")
            #         # G_COOKIES_LI.append(f"{cookie_name}, expiry time: {expiry_date}, domain: {domain} ")
            # else:
            #     print("no cookies to match regex1")


#send an http request and return the response header
def sendRequest():
    global G_HOST, G_FILEPATH, G_401_FLAG, G_400_FLAG
    
    # Construct the HTTP GET request
    if (G_HOST != None):
        request = f"GET /{G_FILEPATH} HTTP/1.1\r\nHost: {G_HOST}\r\nConnection: close\r\n\r\n"
    else:
        request = f"GET / HTTP/1.1\r\nHost: {G_HOST}\r\nConnection: close\r\n\r\n"
        
    print("\n---Request begin---\n" + request + "---Request end---\n\n HTTP request sent, awaiting response...\n")
    
    #connect to server using SSL
    context = ssl.create_default_context()
    sock = s.socket(s.AF_INET, s.SOCK_STREAM)
    connection = context.wrap_socket(sock, server_hostname=G_HOST)
    connection.connect((G_HOST, 443))
    
    #send request
    connection.sendall(request.encode())

    # Receive and process the response
    response = b""
    while True:
        data = connection.recv(4096)
        if not data:
            break
        response += data
    
    
    resp_split = response.split(b"\r\n\r\n")
    headers = resp_split[0] #split the response header
    response_lines = headers.split(b"\r\n")
    
    #print header
    print("---Response header---")
    for line in response_lines:
        print(line.decode())
    print("---Response header end---\n")
        
    first_line = response_lines[0]
    second_line = response_lines[1]
    
    http_code = int(re.findall(r'\d{3}', first_line.decode())[0])
    #REDIRECT IF NECESSARY
    while not (200<=http_code<=299):
        if http_code == 401:
            G_401_FLAG = True
            break
        elif (400<=http_code<=499):
            G_400_FLAG = True
            break
        elif (300<=http_code<=308):
            print("300 code found: Redirecting\n")
            for line in response_lines:   
                if b"Location:" in line or b"location:" in line:
                    location_string = line[len("Location: "):].decode()
                    #if location string does not contain :// meaning no host was passed and only a filepath was given
                    #add the old host to the filepath and then call parseURI
                    if "/" == location_string[0]:
                        location_string = f"{G_HOST}{location_string}"
                    #given a new redirection location, we want to parse the uri again
                    parseURI(location_string)
                    #call the redirection function to get the new response header
                    response_lines = redirection()                    
                    first_line = response_lines[0]
                    http_code = int(re.findall(r'\d{3}', first_line.decode())[0])
    return response_lines

#if redirection code found, send new http request to a new location using G_HOST
def redirection():
    global G_HOST, G_FILEPATH
    
    if (G_FILEPATH != None):
        request = f"GET /{G_FILEPATH} HTTP/1.1\r\nHost: {G_HOST}\r\nConnection: close\r\n\r\n"
    else:
        request = f"GET / HTTP/1.1\r\nHost: {G_HOST}\r\nConnection: close\r\n\r\n"
        
    print("\n---Request begin---\n" + request + "---Request end---\n\n HTTP request sent, awaiting response...\n")
    
    #connect to server using SSL
    context = ssl.create_default_context()
    sock = s.socket(s.AF_INET, s.SOCK_STREAM)
    connection = context.wrap_socket(sock, server_hostname=G_HOST)
    connection.connect((G_HOST, 443))
    
    #send request
    connection.sendall(request.encode())

    # Receive and process the response
    response = b""
    while True:
        data = connection.recv(4096)
        if not data:
            break
        response += data
    
    
    resp_split = response.split(b"\r\n\r\n")
    headers = resp_split[0]
    response_lines = headers.split(b"\r\n")
    
    #print new header from redirected response
    print("---Response header---")
    for line in response_lines:
        print(line.decode())
    print("---Response header end---\n")
    
    #return new response header 
    return response_lines
    

#find password protection and change G_PASSWORD_FLAG to True if secure
def checkPasswordProtection(http_response):
    global G_PASSWORD_FLAG
    for line in http_response: 
        if b"401 Unauthorized" in line:
            G_PASSWORD_FLAG = True # password protected
            break
    

#end: print final answer using global variables  
def printAnswer():
    print("\n\n\n---Summary---\n")
    global G_HOST
    global G_H2
    global G_COOKIES_LI
    global G_PASSWORD_FLAG
    print(f"website: {G_HOST}")
    print(f"1. Supports http2: {G_H2}")
    print("2. List of Cookies:")
    for line in G_COOKIES_LI:
        print("cookie name: " + line)
    print(f"3. Password-protected: {G_PASSWORD_FLAG}")
    
          
def main():
    uri = getStdin()
    global G_HOST, G_FILEPATH, G_401_FLAG, G_400_FLAG
    #parse the initial uri to set global host and filepath
    port, url = parseURI(uri)
    #now try to send request so we can check if our host works
    response_lines = sendRequest()
    if G_401_FLAG == True:
        print ("401 Unauthorized error code: Try running Smart Client again with a different URL.")
    elif G_400_FLAG == True:
        print ("A 400 error code: bad request. Try running Smart Client again with a different URL.")
    
    checkH2()
    getCookies(response_lines)
    checkPasswordProtection(response_lines)
    printAnswer()
 
    
if __name__ == "__main__":
    main() 
