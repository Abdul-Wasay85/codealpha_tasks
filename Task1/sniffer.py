import csv
import threading
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import customtkinter as ctk

from scapy.all import (
    AsyncSniffer,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    DNSQR,
    get_if_list,
)


# ============================================================
# APPLICATION SETTINGS
# ============================================================

APP_NAME = "NETSCOPE"
APP_SUBTITLE = "Network Security Monitor"

# Professional dark cybersecurity palette
BG_COLOR = "#0B1120"
SIDEBAR_COLOR = "#111827"
CARD_COLOR = "#151F32"
CARD_HOVER = "#1B2940"
BORDER_COLOR = "#263449"

TEXT_PRIMARY = "#F1F5F9"
TEXT_SECONDARY = "#94A3B8"
TEXT_MUTED = "#64748B"

ACCENT = "#8B5CF6"
ACCENT_HOVER = "#7C3AED"

SUCCESS = "#22C55E"
DANGER = "#EF4444"
WARNING = "#F59E0B"

TABLE_BG = "#101827"
TABLE_HEADER = "#1A2638"
TABLE_SELECTED = "#292044"


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class NetScopeApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("NETSCOPE | Network Security Monitor")
        self.geometry("1450x850")
        self.minsize(1100, 650)

        self.configure(fg_color=BG_COLOR)

        # Capture state
        self.sniffer = None
        self.capturing = False
        self.packets = []
        self.packet_count = 0

        # Statistics
        self.protocol_counts = {}

        # Variables
        self.interface_var = tk.StringVar(value="Default")
        self.filter_var = tk.StringVar(value="All")
        self.status_var = tk.StringVar(value="SYSTEM READY")

        self.build_ui()
        self.load_interfaces()

        self.protocol_filter.bind(
            "<<ComboboxSelected>>",
            self.apply_filter
        )

        self.protocol_filter.set("All")

        self.protocol_filter.bind(
            "<<ComboboxSelected>>",
            self.apply_filter
        )

        self.protocol_filter.set("All")

        self.protocol_filter.bind(
            "<<ComboboxSelected>>",
            self.apply_filter
        )

    # ========================================================
    # MAIN UI
    # ========================================================

    def build_ui(self):

        # Main grid
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ----------------------------------------------------
        # SIDEBAR
        # ----------------------------------------------------

        self.sidebar = ctk.CTkFrame(
            self,
            width=235,
            corner_radius=0,
            fg_color=SIDEBAR_COLOR
        )
        self.sidebar.grid(
            row=0,
            column=0,
            sticky="nsew"
        )
        self.sidebar.grid_propagate(False)

        # Logo
        logo_frame = ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        )
        logo_frame.pack(
            fill="x",
            padx=24,
            pady=(30, 35)
        )

        ctk.CTkLabel(
            logo_frame,
            text="◈",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=30,
                weight="bold"
            ),
            text_color=ACCENT
        ).pack(anchor="w")

        ctk.CTkLabel(
            logo_frame,
            text=APP_NAME,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=24,
                weight="bold"
            ),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            logo_frame,
            text=APP_SUBTITLE,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=11
            ),
            text_color=TEXT_SECONDARY
        ).pack(anchor="w", pady=(3, 0))

        # Navigation label
        ctk.CTkLabel(
            self.sidebar,
            text="MONITORING",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=10,
                weight="bold"
            ),
            text_color=TEXT_MUTED
        ).pack(
            anchor="w",
            padx=25,
            pady=(0, 10)
        )

        self.nav_button(
            "▦   Dashboard",
            active=True
        )

        self.nav_button("⌁   Live Packets")
        self.nav_button("◫   Analytics")

        ctk.CTkLabel(
            self.sidebar,
            text="SYSTEM",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=10,
                weight="bold"
            ),
            text_color=TEXT_MUTED
        ).pack(
            anchor="w",
            padx=25,
            pady=(35, 10)
        )

        self.nav_button("⚙   Settings")

        # Bottom sidebar
        sidebar_bottom = ctk.CTkFrame(
            self.sidebar,
            fg_color="transparent"
        )
        sidebar_bottom.pack(
            side="bottom",
            fill="x",
            padx=24,
            pady=25
        )

        ctk.CTkFrame(
            sidebar_bottom,
            height=1,
            fg_color=BORDER_COLOR
        ).pack(fill="x", pady=(0, 18))

        ctk.CTkLabel(
            sidebar_bottom,
            text="CodeAlpha Cyber Security",
            font=ctk.CTkFont(size=10),
            text_color=TEXT_MUTED
        ).pack(anchor="w")

        ctk.CTkLabel(
            sidebar_bottom,
            text="Internship Project",
            font=ctk.CTkFont(size=10),
            text_color=TEXT_MUTED
        ).pack(anchor="w", pady=(3, 0))

        # ----------------------------------------------------
        # MAIN CONTENT
        # ----------------------------------------------------

        self.main = ctk.CTkFrame(
            self,
            fg_color=BG_COLOR,
            corner_radius=0
        )
        self.main.grid(
            row=0,
            column=1,
            sticky="nsew"
        )

        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(3, weight=1)

        self.build_header()
        self.build_statistics()
        self.build_controls()
        self.build_packet_area()

    # ========================================================
    # SIDEBAR BUTTON
    # ========================================================

    def nav_button(self, text, active=False):

        button = ctk.CTkButton(
            self.sidebar,
            text=text,
            anchor="w",
            height=42,
            corner_radius=8,
            fg_color=ACCENT if active else "transparent",
            hover_color=ACCENT_HOVER if active else CARD_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=13,
                weight="bold" if active else "normal"
            ),
            command=lambda: None
        )

        button.pack(
            fill="x",
            padx=15,
            pady=3
        )

        return button

    # ========================================================
    # HEADER
    # ========================================================

    def build_header(self):

        header = ctk.CTkFrame(
            self.main,
            fg_color="transparent"
        )
        header.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=30,
            pady=(25, 20)
        )

        header.grid_columnconfigure(0, weight=1)

        # Left
        title_frame = ctk.CTkFrame(
            header,
            fg_color="transparent"
        )
        title_frame.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            title_frame,
            text="Network Overview",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=25,
                weight="bold"
            ),
            text_color=TEXT_PRIMARY
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame,
            text="Monitor and analyze network traffic in real time",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=12
            ),
            text_color=TEXT_SECONDARY
        ).pack(anchor="w", pady=(5, 0))

        # Right status
        status_frame = ctk.CTkFrame(
            header,
            fg_color=CARD_COLOR,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR
        )
        status_frame.grid(row=0, column=1, sticky="e")

        self.status_dot = ctk.CTkLabel(
            status_frame,
            text="●",
            font=ctk.CTkFont(size=14),
            text_color=SUCCESS
        )
        self.status_dot.pack(
            side="left",
            padx=(14, 7),
            pady=10
        )

        self.status_label = ctk.CTkLabel(
            status_frame,
            textvariable=self.status_var,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=11,
                weight="bold"
            ),
            text_color=TEXT_PRIMARY
        )
        self.status_label.pack(
            side="left",
            padx=(0, 14)
        )

    # ========================================================
    # STATISTICS CARDS
    # ========================================================

    def build_statistics(self):

        stats_frame = ctk.CTkFrame(
            self.main,
            fg_color="transparent"
        )
        stats_frame.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=30,
            pady=(0, 20)
        )

        for i in range(4):
            stats_frame.grid_columnconfigure(i, weight=1)

        self.total_card = self.create_stat_card(
            stats_frame,
            0,
            "TOTAL PACKETS",
            "0",
            "Captured traffic",
            ACCENT
        )

        self.tcp_card = self.create_stat_card(
            stats_frame,
            1,
            "TCP PACKETS",
            "0",
            "Transmission Control",
            "#60A5FA"
        )

        self.udp_card = self.create_stat_card(
            stats_frame,
            2,
            "UDP PACKETS",
            "0",
            "User Datagram",
            "#34D399"
        )

        self.other_card = self.create_stat_card(
            stats_frame,
            3,
            "OTHER TRAFFIC",
            "0",
            "ARP / ICMP / DNS",
            WARNING
        )

    def create_stat_card(
        self,
        parent,
        column,
        title,
        value,
        subtitle,
        accent
    ):

        card = ctk.CTkFrame(
            parent,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR
        )
        card.grid(
            row=0,
            column=column,
            sticky="ew",
            padx=(0 if column == 0 else 7, 7 if column < 3 else 0)
        )

        card.grid_columnconfigure(0, weight=1)

        ctk.CTkFrame(
            card,
            width=4,
            height=55,
            fg_color=accent,
            corner_radius=2
        ).grid(
            row=0,
            column=0,
            rowspan=2,
            sticky="w",
            padx=(16, 14),
            pady=18
        )

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=10,
                weight="bold"
            ),
            text_color=TEXT_SECONDARY
        ).grid(
            row=0,
            column=1,
            sticky="w",
            pady=(18, 0)
        )

        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=25,
                weight="bold"
            ),
            text_color=TEXT_PRIMARY
        )
        value_label.grid(
            row=1,
            column=1,
            sticky="w"
        )

        ctk.CTkLabel(
            card,
            text=subtitle,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=10
            ),
            text_color=TEXT_MUTED
        ).grid(
            row=2,
            column=1,
            sticky="w",
            pady=(0, 16)
        )

        return value_label

    # ========================================================
    # CAPTURE CONTROLS
    # ========================================================

    def build_controls(self):

        controls = ctk.CTkFrame(
            self.main,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR
        )
        controls.grid(
            row=2,
            column=0,
            sticky="ew",
            padx=30,
            pady=(0, 20)
        )

        controls.grid_columnconfigure(3, weight=1)

        # Section title
        ctk.CTkLabel(
            controls,
            text="CAPTURE CONTROLS",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=11,
                weight="bold"
            ),
            text_color=TEXT_SECONDARY
        ).grid(
            row=0,
            column=0,
            columnspan=6,
            sticky="w",
            padx=20,
            pady=(16, 10)
        )

        # Interface
        ctk.CTkLabel(
            controls,
            text="Interface",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY
        ).grid(
            row=1,
            column=0,
            sticky="w",
            padx=(20, 8),
            pady=(0, 18)
        )

        self.interface_combo = ctk.CTkComboBox(
            controls,
            variable=self.interface_var,
            width=240,
            height=36,
            corner_radius=8,
            fg_color=TABLE_BG,
            border_color=BORDER_COLOR,
            button_color=ACCENT,
            button_hover_color=ACCENT_HOVER,
            dropdown_fg_color=CARD_COLOR,
            dropdown_hover_color=CARD_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(size=11),
            values=["Default"]
        )
        self.interface_combo.grid(
            row=1,
            column=1,
            sticky="w",
            padx=(0, 25),
            pady=(0, 18)
        )

        # Filter
        ctk.CTkLabel(
            controls,
            text="Protocol",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_SECONDARY
        ).grid(
            row=1,
            column=2,
            sticky="w",
            padx=(0, 8),
            pady=(0, 18)
        )

        self.protocol_filter = ttk.Combobox(
            controls,
            textvariable=self.filter_var,
            values=[
                "All",
                "TCP",
                "UDP",
                "ICMP",
                "ARP",
                "DNS",
                "IP",
                "IPv6",
                "Other"
            ],
            width=14,
            state="readonly"
        )
        self.protocol_filter.grid(
            row=1,
            column=3,
            sticky="w",
            padx=(0, 25),
            pady=(0, 18)
        )

        # Buttons
        self.start_button = ctk.CTkButton(
            controls,
            text="▶  Start Capture",
            width=145,
            height=36,
            corner_radius=8,
            fg_color=ACCENT,
            hover_color=ACCENT_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(
                family="Segoe UI",
                size=11,
                weight="bold"
            ),
            command=self.start_capture
        )
        self.start_button.grid(
            row=1,
            column=4,
            padx=(0, 8),
            pady=(0, 18)
        )

        self.stop_button = ctk.CTkButton(
            controls,
            text="■  Stop",
            width=85,
            height=36,
            corner_radius=8,
            fg_color="#3A2028",
            hover_color="#542631",
            text_color="#FCA5A5",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=11,
                weight="bold"
            ),
            command=self.stop_capture,
            state="disabled"
        )
        self.stop_button.grid(
            row=1,
            column=5,
            padx=(0, 20),
            pady=(0, 18)
        )

    # ========================================================
    # PACKET AREA
    # ========================================================

    def build_packet_area(self):

        packet_area = ctk.CTkFrame(
            self.main,
            fg_color="transparent"
        )
        packet_area.grid(
            row=3,
            column=0,
            sticky="nsew",
            padx=30,
            pady=(0, 25)
        )

        packet_area.grid_columnconfigure(0, weight=1)
        packet_area.grid_rowconfigure(1, weight=1)
        packet_area.grid_rowconfigure(2, weight=0)

        # Title row
        title_row = ctk.CTkFrame(
            packet_area,
            fg_color="transparent"
        )
        title_row.grid(
            row=0,
            column=0,
            sticky="ew",
            pady=(0, 10)
        )

        ctk.CTkLabel(
            title_row,
            text="Live Traffic",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=16,
                weight="bold"
            ),
            text_color=TEXT_PRIMARY
        ).pack(side="left")

        self.packet_count_label = ctk.CTkLabel(
            title_row,
            text="0 packets",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_MUTED
        )
        self.packet_count_label.pack(
            side="left",
            padx=12
        )

        ctk.CTkButton(
            title_row,
            text="Clear",
            width=70,
            height=30,
            corner_radius=7,
            fg_color="transparent",
            hover_color=CARD_HOVER,
            border_width=1,
            border_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(size=11),
            command=self.clear_packets
        ).pack(side="right")

        ctk.CTkButton(
            title_row,
            text="Export CSV",
            width=100,
            height=30,
            corner_radius=7,
            fg_color="transparent",
            hover_color=CARD_HOVER,
            border_width=1,
            border_color=BORDER_COLOR,
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(size=11),
            command=self.export_csv
        ).pack(side="right", padx=(0, 8))

        # Table card
        table_card = ctk.CTkFrame(
            packet_area,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR
        )
        table_card.grid(
            row=1,
            column=0,
            sticky="nsew"
        )

        table_card.grid_columnconfigure(0, weight=1)
        table_card.grid_rowconfigure(0, weight=1)

        # Treeview styling
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "NetScope.Treeview",
            background=TABLE_BG,
            foreground=TEXT_PRIMARY,
            fieldbackground=TABLE_BG,
            borderwidth=0,
            rowheight=34,
            font=("Segoe UI", 10)
        )

        style.configure(
            "NetScope.Treeview.Heading",
            background=TABLE_HEADER,
            foreground=TEXT_SECONDARY,
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 10, "bold")
        )

        style.map(
            "NetScope.Treeview",
            background=[
                ("selected", TABLE_SELECTED)
            ],
            foreground=[
                ("selected", TEXT_PRIMARY)
            ]
        )

        columns = (
            "number",
            "time",
            "source",
            "destination",
            "protocol",
            "length",
            "info"
        )

        self.tree = ttk.Treeview(
            table_card,
            columns=columns,
            show="headings",
            style="NetScope.Treeview",
            selectmode="browse"
        )

        headings = {
            "number": "#",
            "time": "TIME",
            "source": "SOURCE",
            "destination": "DESTINATION",
            "protocol": "PROTOCOL",
            "length": "LENGTH",
            "info": "PACKET INFORMATION"
        }

        widths = {
            "number": 55,
            "time": 90,
            "source": 170,
            "destination": 170,
            "protocol": 100,
            "length": 85,
            "info": 450
        }

        for column in columns:
            self.tree.heading(
                column,
                text=headings[column]
            )
            self.tree.column(
                column,
                width=widths[column],
                anchor="w",
                stretch=column == "info"
            )

        self.tree.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(12, 0),
            pady=12
        )

        scrollbar = ttk.Scrollbar(
            table_card,
            orient="vertical",
            command=self.tree.yview
        )
        scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
            padx=(0, 10),
            pady=12
        )

        self.tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.tree.bind(
            "<<TreeviewSelect>>",
            self.show_packet_details
        )

        # Details section
        details_card = ctk.CTkFrame(
            packet_area,
            fg_color=CARD_COLOR,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR
        )
        details_card.grid(
            row=2,
            column=0,
            sticky="ew",
            pady=(15, 0)
        )

        details_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            details_card,
            text="SELECTED PACKET DETAILS",
            font=ctk.CTkFont(
                family="Segoe UI",
                size=10,
                weight="bold"
            ),
            text_color=TEXT_SECONDARY
        ).grid(
            row=0,
            column=0,
            sticky="w",
            padx=18,
            pady=(14, 8)
        )

        self.details_text = ctk.CTkTextbox(
            details_card,
            height=125,
            corner_radius=8,
            fg_color=TABLE_BG,
            border_width=0,
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(
                family="Consolas",
                size=10
            ),
            wrap="none"
        )
        self.details_text.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=12,
            pady=(0, 12)
        )

        self.details_text.insert(
            "1.0",
            "Select a packet from the table to inspect its details."
        )
        self.details_text.configure(state="disabled")

    # ========================================================
    # INTERFACES
    # ========================================================

    def load_interfaces(self):

        try:
            interfaces = get_if_list()

            values = ["Default"] + interfaces

            self.interface_combo.configure(
                values=values
            )

            self.interface_combo.set("Default")

        except Exception:
            self.interface_combo.configure(
                values=["Default"]
            )
            self.interface_combo.set("Default")

    # ========================================================
    # CAPTURE
    # ========================================================

    def start_capture(self):

        if self.capturing:
            return

        self.capturing = True

        self.start_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="normal"
        )

        self.status_var.set("CAPTURING TRAFFIC")

        self.status_dot.configure(
            text_color=SUCCESS
        )

        selected_interface = self.interface_combo.get()

        interface = (
            None
            if selected_interface == "Default"
            else selected_interface
        )

        try:

            self.sniffer = AsyncSniffer(
                iface=interface,
                prn=self.process_packet,
                store=False
            )

            self.sniffer.start()

        except Exception as error:

            self.capturing = False

            self.start_button.configure(
                state="normal"
            )

            self.stop_button.configure(
                state="disabled"
            )

            self.status_var.set("CAPTURE ERROR")

            messagebox.showerror(
                "Capture Error",
                f"{error}\n\n"
                "Make sure Npcap is installed and try running "
                "Command Prompt as Administrator."
            )

    def stop_capture(self):

        if not self.capturing:
            return

        self.capturing = False

        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception:
            pass

        self.start_button.configure(
            state="normal"
        )

        self.stop_button.configure(
            state="disabled"
        )

        self.status_var.set("SYSTEM READY")

        self.status_dot.configure(
            text_color=SUCCESS
        )

    # ========================================================
    # PACKET PROCESSING
    # ========================================================

    def process_packet(self, packet):

        if not self.capturing:
            return

        protocol = self.get_protocol(packet)

        data = {
            "number": self.packet_count + 1,
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": self.get_source(packet),
            "destination": self.get_destination(packet),
            "protocol": protocol,
            "length": len(packet),
            "info": self.get_info(packet),
            "raw": packet
        }

        self.packet_count += 1
        self.packets.append(data)

        self.protocol_counts[protocol] = (
            self.protocol_counts.get(protocol, 0) + 1
        )

        self.after(
            0,
            lambda d=data: self.add_packet_to_table(d)
        )

    def add_packet_to_table(self, data):

        selected_filter = self.filter_var.get()

        if (
            selected_filter != "All"
            and data["protocol"] != selected_filter
        ):
            return

        self.tree.insert(
            "",
            "end",
            iid=str(data["number"]),
            values=(
                data["number"],
                data["time"],
                data["source"],
                data["destination"],
                data["protocol"],
                data["length"],
                data["info"]
            )
        )

        self.tree.yview_moveto(1)

        self.update_statistics()

    # ========================================================
    # PACKET INFORMATION
    # ========================================================

    def get_source(self, packet):

        if IP in packet:
            return packet[IP].src

        if IPv6 in packet:
            return packet[IPv6].src

        if ARP in packet:
            return packet[ARP].psrc

        return "-"

    def get_destination(self, packet):

        if IP in packet:
            return packet[IP].dst

        if IPv6 in packet:
            return packet[IPv6].dst

        if ARP in packet:
            return packet[ARP].pdst

        return "-"

    def get_protocol(self, packet):

        if DNS in packet:
            return "DNS"

        if ARP in packet:
            return "ARP"

        if TCP in packet:
            return "TCP"

        if UDP in packet:
            return "UDP"

        if ICMP in packet:
            return "ICMP"

        if IPv6 in packet:
            return "IPv6"

        if IP in packet:
            return "IP"

        return "Other"

    def get_info(self, packet):

        if DNS in packet:

            try:
                if packet.haslayer(DNSQR):
                    query = packet[DNSQR].qname.decode(
                        errors="ignore"
                    )

                    return f"DNS Query: {query}"

                return "DNS Query / Response"

            except Exception:
                return "DNS Traffic"

        if TCP in packet:

            return (
                f"TCP {packet[TCP].sport} "
                f"→ {packet[TCP].dport}"
            )

        if UDP in packet:

            return (
                f"UDP {packet[UDP].sport} "
                f"→ {packet[UDP].dport}"
            )

        if ICMP in packet:

            return (
                f"ICMP Type: "
                f"{packet[ICMP].type}"
            )

        if ARP in packet:

            return (
                f"ARP {packet[ARP].psrc} "
                f"→ {packet[ARP].pdst}"
            )

        return packet.summary()[:120]

    # ========================================================
    # STATISTICS
    # ========================================================

    def update_statistics(self):

        tcp_count = self.protocol_counts.get("TCP", 0)
        udp_count = self.protocol_counts.get("UDP", 0)

        other_count = (
            self.packet_count
            - tcp_count
            - udp_count
        )

        self.total_card.configure(
            text=f"{self.packet_count:,}"
        )

        self.tcp_card.configure(
            text=f"{tcp_count:,}"
        )

        self.udp_card.configure(
            text=f"{udp_count:,}"
        )

        self.other_card.configure(
            text=f"{other_count:,}"
        )

        self.packet_count_label.configure(
            text=f"{self.packet_count:,} packets"
        )

    # ========================================================
    # FILTER
    # ========================================================

    def apply_filter(self, event=None):

        selected_filter = self.filter_var.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        for data in self.packets:

            if (
                selected_filter == "All"
                or data["protocol"] == selected_filter
            ):

                self.tree.insert(
                    "",
                    "end",
                    iid=str(data["number"]),
                    values=(
                        data["number"],
                        data["time"],
                        data["source"],
                        data["destination"],
                        data["protocol"],
                        data["length"],
                        data["info"]
                    )
                )

    # ========================================================
    # PACKET DETAILS
    # ========================================================

    def show_packet_details(self, event=None):

        selected = self.tree.selection()

        if not selected:
            return

        packet_number = int(selected[0])

        packet_data = next(
            (
                data for data in self.packets
                if data["number"] == packet_number
            ),
            None
        )

        if packet_data:

            details = packet_data["raw"].show(
                dump=True
            )

            self.details_text.configure(
                state="normal"
            )

            self.details_text.delete(
                "1.0",
                "end"
            )

            self.details_text.insert(
                "1.0",
                details
            )

            self.details_text.configure(
                state="disabled"
            )

    # ========================================================
    # CLEAR
    # ========================================================

    def clear_packets(self):

        self.packets.clear()
        self.packet_count = 0
        self.protocol_counts.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.details_text.configure(
            state="normal"
        )

        self.details_text.delete(
            "1.0",
            "end"
        )

        self.details_text.insert(
            "1.0",
            "Select a packet from the table to inspect its details."
        )

        self.details_text.configure(
            state="disabled"
        )

        self.update_statistics()

        self.status_var.set("PACKET LIST CLEARED")

    # ========================================================
    # EXPORT
    # ========================================================

    def export_csv(self):

        if not self.packets:

            messagebox.showinfo(
                "Export",
                "There are no captured packets to export."
            )

            return

        file_path = filedialog.asksaveasfilename(
            title="Export Captured Packets",
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )

        if not file_path:
            return

        try:

            with open(
                file_path,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.writer(file)

                writer.writerow([
                    "No.",
                    "Time",
                    "Source",
                    "Destination",
                    "Protocol",
                    "Length",
                    "Info"
                ])

                for data in self.packets:

                    writer.writerow([
                        data["number"],
                        data["time"],
                        data["source"],
                        data["destination"],
                        data["protocol"],
                        data["length"],
                        data["info"]
                    ])

            messagebox.showinfo(
                "Export Successful",
                f"Packets exported successfully:\n\n{file_path}"
            )

        except Exception as error:

            messagebox.showerror(
                "Export Error",
                str(error)
            )


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    app = NetScopeApp()

    app.mainloop()
