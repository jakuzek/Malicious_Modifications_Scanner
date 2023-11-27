# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# This Python script is a simple web scraping tool that saves the content of a specified URL into a text file.

# Script Structure:
# - 'install_requests': Function installing libraries to avoid errors during running the code.
# - Command Line Argument Processing: The script checks if the '--input' flag is present in the command line arguments.
# - Timestamp Generation: Calculates a timestamp representing one hour ago and formats it as a string.
# - HTTP Request and File Writing: Sends an HTTP GET request to the specified URL. It writes the content of the webpage to a text file.

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

from datetime import datetime, timedelta
import sys
import subprocess


# A function install_requests is defined to install the bs4 and requests modules using the subprocess module.
def install_requests():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "bs4"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])


# The script attempts to import bs4 and requests.
# If there is an ImportError, it prints a message, installs the required modules using the install_requests function, and then imports them again.
try:
    import bs4
    import requests
except ImportError:
    print("Installing requests module...")
    install_requests()
    import bs4
    import requests


# The script checks if the --input flag is present in the command line arguments.
# If found, it retrieves the URL provided after the flag. If the URL is not provided, an error message is printed.
if "--input" in sys.argv:
    input_index = sys.argv.index("--input")
    if input_index + 1 < len(sys.argv):
        url = sys.argv[input_index + 1]
    else:
        print("Error")
else:
    print("Error")


# The script calculates a timestamp representing one hour ago and formats it as a string in the format "YYYY-MM-DD_HH-MM-SS".
one_hour_ago = datetime.now() - timedelta(hours=1)
timestamp = one_hour_ago.strftime("%Y-%m-%d_%H-%M-%S")
response = requests.get(url)


# The script sends an HTTP GET request to the specified URL. If the response status code is 200 (OK),
# it writes the content of the webpage to a text file named "old_website_content.txt" along with the timestamp.
# If the response status code is not 200, an error message is printed.
if response.status_code == 200:
    page_content = response.text

    with open("old_website_content.txt", "w", encoding="utf-8") as file:
        file.write(f"Snapshot from {timestamp}:\n")
        file.write(page_content)

    print(f"Old website content saved to 'old_website_content.txt'")
else:
    print(f"Download error: {response.status_code}")
