import tkinter as tk
from tkinter import messagebox
from ipwhois import IPWhois

# Function to get the country of a given IP address
def get_country(ip_address):
    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()
        country = result.get('network', {}).get('country', 'Unknown Country')
        return country
    except Exception as e:
        return f"Error: {str(e)}"

# Function to handle the button click event
def fetch_country():
    ip_address = ip_entry.get().strip()
    if not ip_address:
        messagebox.showerror("Input Error", "Please enter a valid IP address.")
        return
    
    country = get_country(ip_address)
    result_label.config(text=f"Country: {country}")

# Creating the main application window
root = tk.Tk()
root.title("IP Country Fetcher")
root.geometry("400x200")

# IP Entry Frame
ip_frame = tk.Frame(root)
ip_frame.pack(pady=20)

# Label and Entry for IP address
ip_label = tk.Label(ip_frame, text="Enter IP Address:")
ip_label.pack(side=tk.LEFT, padx=5)
ip_entry = tk.Entry(ip_frame, width=30)
ip_entry.pack(side=tk.LEFT)

# Fetch Country Button
fetch_button = tk.Button(root, text="Fetch Country", command=fetch_country)
fetch_button.pack(pady=10)

# Label to display the result
result_label = tk.Label(root, text="Country: ", font=("Arial", 12))
result_label.pack(pady=20)

# Start the Tkinter main loop
root.mainloop()
