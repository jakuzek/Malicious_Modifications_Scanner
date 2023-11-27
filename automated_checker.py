# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# This script is designed to run a sequence of Python scripts located in the specified 'script_folder'. It dynamically adds
# the folder to the system path to access the scripts. The main function checks for command-line arguments, specifically
# the presence of "--input" and an associated input text. It then sequentially runs three scripts: "download_old_website.py",
# "download_current_website.py", and "compare_website_content.py", passing the input text to each. Any errors encountered
# during script execution are caught and printed.

# Script Structure:
# - 'script_folder': The directory containing the Python scripts to be executed.
# - 'run_script': Function to run a specified script with a given input text and handle exceptions.
# - 'main': Entry point of the script. Checks command-line arguments and runs the sequence of scripts.

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

import os
import sys

script_folder = "SCRIPT_FOLDER_PATH" # Paste your script folder here


# The script checks if the --input flag is present in the command line arguments.
# If found, it retrieves the URL provided after the flag. If the URL is not provided, an error message is printed.
if script_folder not in sys.path:
    sys.path.append(script_folder)


# The function run_script takes a script name and input text as parameters, then attempts to execute the specified script using exec.
# It prints messages indicating the start and completion of script execution and handles any exceptions that may occur during execution.
def run_script(script_name, input_text):
    try:
        print(f"Running {script_name}...")
        exec(open(os.path.join(script_folder, script_name)).read(), {"input_text": input_text})
        print(f"{script_name} finished.\n")
    except Exception as e:
        print(f"Error with running {script_name}: {str(e)}")


# The main function checks if the script is run with command line arguments, specifically if the --input flag is present.
# If so, it retrieves the input text from the command line and runs three scripts
# ("download_old_website.py," "download_current_website.py," and "compare_website_content.py") using the run_script function.
def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--input":
        input_text = sys.argv[2]
        run_script("download_old_website.py", input_text)
        run_script("download_current_website.py", input_text)
        run_script("compare_website_content.py", input_text)
    else:
        pass


if __name__ == "__main__":
    main()