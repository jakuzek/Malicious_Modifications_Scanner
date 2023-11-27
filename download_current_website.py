# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# The provided Python script is a simplified version of a web scraping tool that saves the content of a specified URL into a text file.

# Script Structure:
# - Command Line Argument Processing: The script checks if the '--input' flag is present in the command line arguments.
# - HTTP Request and File Writing: Sends an HTTP GET request to the specified URL. It writes the content of the webpage to a text file.

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

import requests
from datetime import datetime, timedelta
import sys


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


# The script sends an HTTP GET request to the specified URL, retrieves the content of the webpage, and stores it in the variable website_content.
# It then gets the current timestamp, formats it as a string in the format "YYYY-MM-DD_HH-MM-SS".
response = requests.get(url)
website_content = response.text

time = datetime.now()
timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")


# Writes the webpage content to a text file named "current_website_content.txt" along with the timestamp.
with open("current_website_content.txt", "w", encoding="utf-8") as file:
    file.write(f"Snapshot from {timestamp}:\n")
    file.write(website_content)


# Finally, it prints a message indicating that the current website content has been saved to the file.
print(f"Current website content saved to 'current_website_content.txt'")
