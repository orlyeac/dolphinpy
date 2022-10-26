import tkinter as tk
import customtkinter as ctk
from tkinter import ttk
import scapy.all as scapy
import threading


# global var
thread = None
must_stop_it = True
iface = ''


def start_clicked():
    global iface
    iface = iface_entry.get()
    global thread
    global must_stop_it
    if (thread is None) or (not thread.is_alive()):
        must_stop_it = False
        thread = threading.Thread(target=do_sniff)
        thread.start()


def stop_clicked():
    global must_stop_it
    must_stop_it = True


def do_sniff():
    global iface
    scapy.sniff(iface=iface, prn=identify_known_protocol, stop_filter=quit_sniffing)


def quit_sniffing(packet):
    global must_stop_it
    return must_stop_it


def identify_known_protocol(packet):
    print(packet.show())
    src = ''
    dst = ''
    if 'Ethernet' in packet:
        row00 = treev.insert('', index=tk.END, text='Ethernet')
        src = f"src: {packet['Ethernet'].src}"
        dst = f"dst: {packet['Ethernet'].dst}"
        treev.insert(row00, index=tk.END, text=src)
        treev.insert(row00, index=tk.END, text=dst)
        type0 = f"protocol: {packet.get_field('type').i2s[packet.type]}"
        row01 = treev.insert(row00, index=tk.END, text=type0)
        if 'IP' in packet:
            src = f"src: {packet['IP'].src}"
            dst = f"dst: {packet['IP'].dst}"
            treev.insert(row01, index=tk.END, text=src)
            treev.insert(row01, index=tk.END, text=dst)
            proto = f"protocol: {packet.payload.get_field('proto').i2s[packet.proto]}"
            row10 = treev.insert(row01, index=tk.END, text=proto)
            if 'TCP' in packet:
                try:
                    proto = f"protocol: {packet.payload.payload.get_field('dport').i2s[packet.dport]}"
                    treev.insert(row10, index=tk.END, text=proto)
                except:
                    dport = f"dport: {packet['TCP'].dport}"
                    treev.insert(row10, index=tk.END, text=dport)
                try:
                    proto = f"protocol: {packet.payload.payload.get_field('sport').i2s[packet.sport]}"
                    treev.insert(row10, index=tk.END, text=proto)
                except:
                    sport = f"sport: {packet['TCP'].sport}"
                    treev.insert(row10, index=tk.END, text=sport)
        treev.pack(fill=tk.X)


# gui begin

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.geometry('500x500')
root.title('dolphin')

ctk.CTkLabel(root, text='dolphin').pack()
ctk.CTkLabel(root, text='enter the interface identifier').pack()

iface_entry = ctk.CTkEntry(root)
iface_entry.pack(ipady=5, ipadx=5, pady=10)

treev = ttk.Treeview(root, height=400)
treev.column('#0')

button_frame = ctk.CTkFrame(root)

ctk.CTkButton(button_frame, text="start", command=start_clicked, width=15).pack(side=tk.LEFT, padx=10)
ctk.CTkButton(button_frame, text="stop", command=stop_clicked, width=15).pack(side=tk.LEFT, padx=10)

button_frame.pack(side=tk.BOTTOM, padx=10, pady=10)

root.mainloop()
