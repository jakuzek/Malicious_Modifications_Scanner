# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# This Python script is a graphical user interface (GUI) application built using the Tkinter library.
# The application serves as a scanner for detecting malicious modifications in website files.
# Here's a breakdown of the script structure:

# Constants:
# - TEMP_INPUT_FILE: Temporary file to store input text.
# - COMPARED_WEBSITE_FOLDER: Folder containing website comparison files.
# - API_KEY: API key for VirusTotal.
# - FILE_PATH: Path to the temporary file for VirusTotal scanning results.

# VirusTotalScanner Class:
# - Handles submission and retrieval of file scan reports from the VirusTotal API.
# - Methods include scan_file, get_scan_report, count_malicious_detections, and scan_and_report.

# Functions:
# - execute_script: Retrieves input text, writes it to a temporary file, executes an external Python script (automated_checker.py), and performs a file scan operation.
# - scan_file: Scans a file for malicious content using VirusTotalScanner and displays results.
# - show_lines: Displays modified lines in a new Tkinter window with a ScrolledText widget.
# - open_file: Opens and displays the content of a specified file.
# - on_select: Retrieves the selected file from the history_text widget and opens it, opens and displays its content using open_file function.
# - apply_filter: Updates the file history based on the filter text.
# - update_history: Updates the history_text widget with a list of files.

# Tkinter GUI:
# - Three tabs - "Scan", "History" and "Filter".
# - Scan Tab: Allows the user to input a website URL, scan it for modifications, and displays the results.
# - History Tab: Displays a history of scanned files with the ability to view details by double click files.
# - Filter Tab: Enables filtering of file history based on user input.

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import os
import requests
import time


# Constants
TEMP_INPUT_FILE = "temp_input.txt"
COMPARED_WEBSITE_FOLDER = "Compared_website"  # Paste your path to the "Compared_website" folder
API_KEY = "API_KEY" # Paste your api key from VirusTotal website (create account if you don't have one)
FILE_PATH = "Compared_website\\temp.txt"


# ---------------- VirusTotalScanner Class ----------------

# This class facilitates the submission and retrieval of file scan reports from the VirusTotal API.
class VirusTotalScanner:
    # Initializes the VirusTotalScanner object with the provided API key and sets the base URL for API requests.
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://www.virustotal.com/vtapi/v2/file/'

    # Submits the specified file to VirusTotal for scanning and returns the scan resources.
    def scan_file(self, file_path):
        url = self.base_url + 'scan'
        params = {'apikey': self.api_key}

        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url, files=files, params=params)

        scan_result = response.json()
        resource = scan_result.get('resource')

        return resource

    # Retrieves the scan report for a given resource identifier from VirusTotal
    def get_scan_report(self, resource):
        url = self.base_url + 'report'
        params = {'apikey': self.api_key, 'resource': resource}

        response = requests.get(url, params=params)
        report = response.json()

        return report

    # Counts the number of malicious detections from the given scan report.
    @staticmethod
    def count_malicious_detections(report):
        if 'scans' in report:
            detections = [scan for scan, result in report['scans'].items() if result.get('detected')]
            return len(detections)
        else:
            return 0

    # Submits a file for scanning, waits for results, and prints the number of malicious detections.
    # Writes the result to a temporary text file.
    def scan_and_report(self, file_path):
        resource = self.scan_file(file_path)

        if resource:
            print(f"File submitted to VirusTotal. Scan resource: {resource}")
            print("Waiting for scan results...")

            # Wait a bit to allow VirusTotal to process the file
            time.sleep(20)

            report = self.get_scan_report(resource)
            malicious_detections = self.count_malicious_detections(report)

            print(f"Number of malicious detections: {malicious_detections}")

            with open("temp_result.txt", "w") as file:
                file.write(f"Number of malicious detections: {malicious_detections}")
        else:
            print("Failed to submit file to VirusTotal.")




# --------------------- GUI Functions ---------------------

# Retrieves input text from a text entry widget, saves it to a temporary file, executes an external Python scripts
# with provided input, and performs a file scan operation.
# Deletes the temporary input file after execution.
def execute_script():
    input_text = text_entry.get("1.0", "end-1c")

    with open(TEMP_INPUT_FILE, "w") as temp_file:
        temp_file.write(input_text)

    script_path = "automated_checker.py"
    subprocess.run(["python", script_path, "--input", input_text])
    subprocess.run(["del", TEMP_INPUT_FILE], shell=True)
    scan_file()



# Scans a file located at 'COMPARED_WEBSITE_FOLDER/temp.txt' for malicious content using VirusTotalScanner.
# Displays the number of new modified lines and additional information in result_label and result_label2.
# Shows the modified lines using the show_lines function.
# Updates the file history and deletes temporary files.
def scan_file():
    try:
        file_path = os.path.join(COMPARED_WEBSITE_FOLDER, "temp.txt")

        with open(file_path, "r") as file:
            lines = file.readlines()
            if not lines:
                result_label.config(text="New modified lines: 0", pady=15)
            else:
                scanner = VirusTotalScanner(API_KEY)
                scanner.scan_and_report(FILE_PATH)
                with open("temp_result.txt", "r") as file:
                    result = file.readlines()
                result_label.config(text=f"New modified lines: {len(lines)}", pady=15)
                result_label2.config(text=f"{str(result[0])}")
                show_lines(lines)
        
        subprocess.run(["del", "Compared_website\\temp.txt"], shell=True)
        subprocess.run(["del", "temp_result.txt"], shell=True)

    except FileNotFoundError:
        result_label.config(text="File not found")
    
    txt_files = [f for f in os.listdir(COMPARED_WEBSITE_FOLDER) if f.endswith('.txt')]
    update_history(txt_files)



# This function displays the modified lines in a new tkinter window with a ScrolledText widget.
def show_lines(lines):
    new_window = tk.Toplevel(root)
    new_window.title("New modifications")

    text_widget = scrolledtext.ScrolledText(new_window, wrap=tk.NONE, width=110, height=20)
    text_widget.pack()

    x_scrollbar = tk.Scrollbar(new_window, orient=tk.HORIZONTAL, command=text_widget.xview)
    x_scrollbar.pack(fill=tk.X)

    text_widget.configure(xscrollcommand=x_scrollbar.set)

    for line in lines:
        text_widget.insert(tk.END, line)



# Opens the specified file in the COMPARED_WEBSITE_FOLDER directory and displays its content using the show_lines function.
def open_file(file_name):
    file_path = os.path.join(COMPARED_WEBSITE_FOLDER, file_name)
    with open(file_path, 'r') as file:
        content = file.read()
        show_lines(content)



# Retrieves the selected file from the history_text widget, opens and displays its content using open_file function.
def on_select(event):
    index = history_text.index(history_text.tag_ranges(tk.SEL)[0])
    selected_file = history_text.get(index.split('.')[0] + '.0', index.split('.')[0] + '.end')
    open_file(selected_file.strip())



# Updates the file history based on the filter text entered in the filter_entry widget.
def apply_filter():
    txt_files = [f for f in os.listdir(COMPARED_WEBSITE_FOLDER) if f.endswith('.txt')]
    update_history(txt_files)
    filter_text = filter_entry.get()
    filtered_files = [file for file in txt_files if filter_text.lower() in file.lower()]
    update_history(filtered_files)



# Updates the history_text widget with the list of files provided.
def update_history(file_list):
    history_text.delete(1.0, tk.END)
    for file_name in file_list:
        history_text.insert(tk.END, file_name + '\n')



# Create the main window
root = tk.Tk()
root.title("Malicious Modifications Scanner")
root.geometry("800x365")



# Custom style
style = ttk.Style()
style.configure("TNotebook", background="lightgray")
style.configure("TNotebook.Tab", background="gray", foreground="black", padding=[10, 5])



# Add tabs using a notebook
notebook = ttk.Notebook(root)



# Scan Tab
scan_tab = ttk.Frame(notebook)

name_text = tk.Label(scan_tab, text="Malicious Modifications Scanner", font=("Arial", 24), fg="#333333")
name_text.pack(side=tk.TOP, pady=20)

instruction = tk.Label(scan_tab, text="--- Enter the website url below ---", font=("Arial", 10), fg="#333333")
instruction.pack(side=tk.TOP)

text_entry = tk.Text(scan_tab, height=5, width=40)
text_entry.pack(pady=10, padx=10)

scan_button = tk.Button(scan_tab, text="Scan", command=execute_script, padx=10, pady=5, bg="#e6e6e6")
scan_button.pack()

result_label = tk.Label(scan_tab, text="", font=("Arial", 12), fg="green")
result_label.pack()

result_label2 = tk.Label(scan_tab, text="", font=("Arial", 12), fg="green")
result_label2.pack()

notebook.add(scan_tab, text="Scan")



# History Tab
history_tab = ttk.Frame(notebook)

name_history_text = tk.Label(history_tab, text="History", font=("Arial", 18), fg="#333333")
name_history_text.pack(side=tk.TOP, pady=10)

history_text = scrolledtext.ScrolledText(history_tab, wrap=tk.NONE, width=90, height=15, padx=10, pady=10)
history_text.pack()

x_scrollbar = tk.Scrollbar(history_tab, orient=tk.HORIZONTAL, command=history_text.xview)
x_scrollbar.pack(fill=tk.X)

history_text.configure(xscrollcommand=x_scrollbar.set)

txt_files = [f for f in os.listdir(COMPARED_WEBSITE_FOLDER) if f.endswith('.txt')]

update_history(txt_files)

history_text.bind("<ButtonRelease-1>", on_select)

notebook.add(history_tab, text="History")



# Filter Tab
filter_tab = ttk.Frame(notebook)

name_filter_text = tk.Label(filter_tab, text="Filter by name", font=("Arial", 18), fg="#333333")
name_filter_text.pack(side=tk.TOP, pady=10)

instruction = tk.Label(filter_tab, text="--- Enter filter below ---", font=("Arial", 10), fg="#333333")
instruction.pack(side=tk.TOP)

filter_entry = tk.Entry(filter_tab, width=40)
filter_entry.pack(pady=10, padx=10)

filter_button = tk.Button(filter_tab, text="Filter", command=apply_filter, padx=10, pady=5, bg="#e6e6e6")
filter_button.pack(pady=10)

notebook.add(filter_tab, text="Filter")

notebook.pack(expand=True, fill="both")

root.mainloop()
