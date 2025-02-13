import requests

def get_headers(url):
    try:
        # Send a GET request to the target URL
        response = requests.get(url)

        # Grab all headers from the response
        headers = response.headers

        # Check if CSP header exists
        csp_header = headers.get('Content-Security-Policy', 'No CSP header found')

        # Print the response headers with nice formatting
        print(f"\n{'='*50}")
        print(f"Headers for {url}:")
        print(f"{'='*50}")

        # Output each header
        for header, value in headers.items():
            print(f"{header}: {value}")

        print(f"\n{'='*50}")
        # Output the CSP header (if it exists)
        print(f"Content-Security-Policy Header:\n{'='*50}")
        print(csp_header)
        print(f"{'='*50}\n")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")

# Main function to input the URL
if __name__ == "__main__":
    target_url = input("Enter the URL to scan (https:// + target): ").strip()
    if target_url:
        get_headers(target_url)
    else:
        print("Please provide a valid URL.")
