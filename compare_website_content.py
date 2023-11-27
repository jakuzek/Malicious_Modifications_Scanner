# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# This Python script copares the content of two text files ("current_website_content.txt" and "old_website_content.txt")
# and extract the lines that are present in the current content but not in the old content.
# It then generates a result file with the added lines and includes a timestamp in the filename.

# Script Structure:
# - Command Line Argument Processing: The script checks if the '--input' flag is present in the command line arguments.
# - Reading Current and Old Website Content Files: Reads the content of the "current_website_content.txt" and "old_website_content.txt" files into lists.
# - Timestamp Generation: Gets a current timestamp and formats it as a string.
# - URL Parsing: Checks if the provided URL contains 'www.' and parses the domain accordingly.

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

from datetime import datetime, timedelta
import sys


# # The script checks if the --input flag is present in the command line arguments.
# If found, it retrieves the URL provided after the flag. If the URL is not provided, an error message is printed.
if "--input" in sys.argv:
    input_index = sys.argv.index("--input")
    if input_index + 1 < len(sys.argv):
        url = sys.argv[input_index + 1]
    else:
        print("Error")
else:
    print("Error")


# The script reads the content of the "current_website_content.txt" and "old_website_content.txt" files into lists (current_content and old_content, respectively).
with open("current_website_content.txt", "r", encoding="utf-8") as current_file:
    current_content = current_file.readlines()
with open("old_website_content.txt", "r", encoding="utf-8") as old_file:
    old_content = old_file.readlines()


# The script creates a list of lines that are present in current_content but not in old_content.
added_lines = [line for line in current_content[1:] if line not in old_content[1:]]


# The script gets the current timestamp and formats it as a string in the format "YYYY-MM-DD_HH-MM-SS".
time = datetime.now()
timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")


# The script checks if the provided URL contains 'www.' or 'http://' and parses the domain accordingly.
if url.find("www.") != -1:
    start_index = url.find("www.") + 4
    end_index = url.find("/", start_index)
    if end_index != -1:
        result = url[start_index:end_index]
    else:
        result = url[start_index:]
else:
    start_index = url.find("http://") + 7
    result = url[start_index:[i for i, char in enumerate(url) if char == "/"][2]] if url.count("/") >= 3 else url


# The script writes the added lines to a file in a folder named "Compared_website," with a filename based on the parsed URL and the timestamp.
with open(f"Compared_website\\{result}_{timestamp}.txt", "w", encoding="utf-8") as compared_file:
    compared_file.writelines(added_lines)


# The script writes the added lines to a temporary file named "temp.txt" in the "Compared_website" folder.
with open(f"Compared_website\\temp.txt", "w", encoding="utf-8") as temp:
    temp.writelines(added_lines)


# The script prints a message indicating that the compared website content has been saved to a file with the current timestamp.
print(f"Compared website content was saved to '{timestamp}.txt'")