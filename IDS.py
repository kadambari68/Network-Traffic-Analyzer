import tkinter as tk
from tkinter import ttk, filedialog
import pyshark

class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")

        self.status_label = ttk.Label(root, text="Status: Ready")
        self.status_label.grid(row=0, column=0, padx=10, pady=10)

        self.start_button = ttk.Button(root, text="Start", command=self.start_capture)
        self.start_button.grid(row=0, column=1, padx=10, pady=10)

        self.stop_button = ttk.Button(root, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=2, padx=10, pady=10)

        self.select_button = ttk.Button(root, text="Select PCAP", command=self.select_pcap)
        self.select_button.grid(row=0, column=3, padx=10, pady=10)

        self.packet_text = tk.Text(root, width=100, height=20)
        self.packet_text.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

        self.packet_capture = None
        self.pcap_file = None

    def start_capture(self):
        if not self.pcap_file:
            self.status_label.config(text="Status: Please select a PCAP file")
            return

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Capturing packets...")

        self.packet_text.delete(1.0, tk.END)  # Clear previous packet details
        self.packet_capture = pyshark.FileCapture(self.pcap_file, keep_packets=False, tshark_path="C:/Program Files/Wireshark/tshark.exe")
        self.packet_capture.apply_on_packets(self.analyze_packet, timeout=10)

    def stop_capture(self):
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped")

        if self.packet_capture:
            self.packet_capture.close()

    def analyze_packet(self, packet):
        # Display packet details in the text widget
        self.packet_text.insert(tk.END, str(packet) + "\n")
        self.packet_text.see(tk.END)  # Scroll to the end of the text widget

        # Perform intrusion detection here
        # You can implement your IDS logic to analyze the packet and raise alerts

    def select_pcap(self):
        self.pcap_file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if self.pcap_file:
            self.status_label.config(text=f"Status: PCAP file selected: {self.pcap_file}")
        else:
            self.status_label.config(text="Status: No PCAP file selected")

def main():
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
