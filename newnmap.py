import nmap
import tkinter as tk
from tkinter import ttk


class App(ttk.Frame):
    def __init__(self, parent):
        ttk.Frame.__init__(self)

        self.scanner = nmap.PortScanner()

        # Make the app responsive
        for index in [0, 1, 2]:
            self.columnconfigure(index=index, weight=1)
            self.rowconfigure(index=index, weight=1)

        # Create widgets :)
        self.setup_widgets()

    def setup_widgets(self):
        # Create a Frame for input
        self.input_frame = ttk.Frame(self, padding=(0, 0, 0, 10))
        self.input_frame.grid(row=1, column=0, padx=5, pady=(30, 10), sticky="nsew")
        self.input_frame.columnconfigure(index=0, weight=1)

        # IP Label
        self.ipLabel = ttk.Label(self.input_frame, text='IP address', font=("-size", 9))
        self.ipLabel.grid(row=0, column=0, padx=5, pady=(0, 10), sticky="ew")

        # IP Entry
        self.ipEntry = ttk.Entry(self.input_frame, width=15)
        self.ipEntry.grid(row=1, column=0, padx=5, pady=(0, 10), sticky="ew")

        # Port Label
        self.portLabel = ttk.Label(self.input_frame, text='Port (optional)', font=("-size", 9), justify="center")
        self.portLabel.grid(row=0, column=1, padx=5, pady=(0, 10), sticky="ew")

        # Port Entry
        self.portEntry = ttk.Entry(self.input_frame, width=10)
        self.portEntry.grid(row=1, column=1, padx=5, pady=(0, 10), sticky="ew")

        # Buttons
        self.buttons = ttk.Frame(self.input_frame, padding=(0,0,0,10))
        self.buttons.grid(row=2, column=0, sticky="nsew")

        # Scan Button
        self.scanButton = ttk.Button(self.buttons, text="Scan", style="Accent.TButton", command=self.startScan)
        self.scanButton.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # Stop Button
        self.stopButton = ttk.Button(self.buttons, text="Stop")
        self.stopButton.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Panedwindow
        self.result = ttk.PanedWindow(self)
        self.result.grid(row=0, column=1, padx=10, pady=10, sticky="nsew", rowspan=3)

        self.hostListTextBox = tk.Text(self.result, height=15, width=50)
        self.hostListTextBox.grid(row=1, column=0)

    def startScan(self):
        address = self.ipEntry.get()
        if len(self.portEntry.get()) != 0:                                                  #Port range was provided
            thePorts = self.portEntry.get()
            print('With ports' + thePorts)
            self.scanner.scan(hosts=address,ports=thePorts)
            hostList= self.scanner.all_hosts()
            for host in hostList:
                hostInfo = host + " Name: " + self.scanner[host].hostname()
                for protocol in self.scanner[host].all_protocols():
                    hostInfo += " Protocol: " + protocol + " Ports:"
                    for key in self.scanner[host][protocol].keys():
                        hostInfo += str(key) + ", "
                self.hostListTextBox.insert(tk.INSERT, hostInfo + "\n")
        else:                                                                               
            self.scanner.scan(address)
            hostList = self.scanner.all_hosts()
            for host in hostList:
                hostInfo = host + " Name: " + self.scanner[host].hostname()
                for protocol in self.scanner[host].all_protocols():
                    hostInfo += " Protocol: " + protocol + " Ports:"
                    for key in self.scanner[host][protocol].keys():
                        hostInfo += str(key) + ", "
                self.hostListTextBox.insert(tk.INSERT, hostInfo + "\n")

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Nmap Scanner")

    # Set the theme
    root.tk.call("source", "sunvalley/sun-valley.tcl")
    root.tk.call("set_theme", "light")

    app = App(root)
    app.pack(fill="both", expand=True)

    # Set a minsize for the window
    root.update()
    root.minsize(root.winfo_width(), root.winfo_height())
    root.mainloop()
