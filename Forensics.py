import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import hashlib
import re
import json
import base64
import socket
import threading
import time
from datetime import datetime
import urllib.parse
from collections import defaultdict
import subprocess
import sys
import os


try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    Fernet = None

class DarkWebForensicsTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🕵️ Dark Web Forensics Tool - Educational Edition")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0a')
        self.root.minsize(1200, 800)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_dark_theme()
        
        # Data storage
        self.analysis_results = {}
        self.tor_nodes = []
        self.onion_patterns = []
        
        self.create_widgets()
        self.load_educational_content()
        
    def configure_dark_theme(self):
        """Configure advanced dark theme for the application"""
        # Main notebook styling
        self.style.configure('TNotebook', 
                           background='#1a1a1a', 
                           borderwidth=0,
                           tabmargins=[2, 5, 2, 0])
        
        self.style.configure('TNotebook.Tab', 
                           background='#2d2d30', 
                           foreground='#cccccc',
                           padding=[20, 10],
                           borderwidth=1,
                           focuscolor='none')
        
        self.style.map('TNotebook.Tab', 
                      background=[('selected', '#007acc'), ('active', '#3d3d40')],
                      foreground=[('selected', 'white'), ('active', 'white')],
                      expand=[('selected', [1, 1, 1, 0])])
        
        # Frame styling
        self.style.configure('TFrame', 
                           background='#1a1a1a', 
                           borderwidth=1, 
                           relief='flat')
        
        self.style.configure('Card.TFrame', 
                           background='#252526', 
                           borderwidth=1, 
                           relief='solid',
                           bd=1)
        
        # Label styling
        self.style.configure('TLabel', 
                           background='#1a1a1a', 
                           foreground='#cccccc',
                           font=('Segoe UI', 10))
        
        self.style.configure('Title.TLabel', 
                           background='#1a1a1a', 
                           foreground='#ffffff',
                           font=('Segoe UI', 12, 'bold'))
        
        self.style.configure('Header.TLabel', 
                           background='#252526', 
                           foreground='#007acc',
                           font=('Segoe UI', 11, 'bold'))
        
        # Button styling
        self.style.configure('TButton', 
                           background='#0e639c', 
                           foreground='white',
                           font=('Segoe UI', 9),
                           borderwidth=1,
                           focuscolor='none',
                           padding=[10, 8])
        
        self.style.map('TButton', 
                      background=[('active', '#1177bb'), ('pressed', '#005a9e')],
                      relief=[('pressed', 'flat'), ('!pressed', 'flat')])
        
        # Danger button style
        self.style.configure('Danger.TButton', 
                           background='#dc3545', 
                           foreground='white',
                           font=('Segoe UI', 9),
                           borderwidth=1,
                           focuscolor='none',
                           padding=[10, 8])
        
        self.style.map('Danger.TButton', 
                      background=[('active', '#c82333'), ('pressed', '#bd2130')])
        
        # Success button style
        self.style.configure('Success.TButton', 
                           background='#28a745', 
                           foreground='white',
                           font=('Segoe UI', 9),
                           borderwidth=1,
                           focuscolor='none',
                           padding=[10, 8])
        
        self.style.map('Success.TButton', 
                      background=[('active', '#218838'), ('pressed', '#1e7e34')])
        
        # LabelFrame styling
        self.style.configure('TLabelframe', 
                           background='#252526',
                           borderwidth=1,
                           relief='solid')
        
        self.style.configure('TLabelframe.Label', 
                           background='#252526', 
                           foreground='#007acc',
                           font=('Segoe UI', 10, 'bold'))
        
    def create_widgets(self):
        """Create the main GUI components with enhanced styling"""
        # Create header section
        self.create_header()
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=15, pady=(10, 15))
        
        # Create tabs with improved styling
        self.create_analysis_tab()
        self.create_educational_tab()
        self.create_tools_tab()
        self.create_reporting_tab()
        
    def create_header(self):
        """Create application header with branding"""
        header_frame = tk.Frame(self.root, bg='#0a0a0a', height=80)
        header_frame.pack(fill='x', padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Title section
        title_frame = tk.Frame(header_frame, bg='#0a0a0a')
        title_frame.pack(side='left', fill='y', padx=20, pady=15)
        
        title_label = tk.Label(title_frame, 
                              text="🕵️ Dark Web Forensics Tool", 
                              bg='#0a0a0a', 
                              fg='#ffffff',
                              font=('Segoe UI', 18, 'bold'))
        title_label.pack(anchor='w')
        
        subtitle_label = tk.Label(title_frame, 
                                 text="Professional Digital Forensics & Cybersecurity Education Platform", 
                                 bg='#0a0a0a', 
                                 fg='#007acc',
                                 font=('Segoe UI', 10))
        subtitle_label.pack(anchor='w')
        
        # Status indicators
        status_frame = tk.Frame(header_frame, bg='#0a0a0a')
        status_frame.pack(side='right', fill='y', padx=20, pady=15)
        
        # Educational badge
        edu_badge = tk.Label(status_frame, 
                            text="🎓 EDUCATIONAL", 
                            bg='#28a745', 
                            fg='white',
                            font=('Segoe UI', 9, 'bold'),
                            padx=10, pady=5)
        edu_badge.pack(anchor='e', pady=(0, 5))
        
        # Security badge
        sec_badge = tk.Label(status_frame, 
                            text="🔒 SECURE ANALYSIS", 
                            bg='#007acc', 
                            fg='white',
                            font=('Segoe UI', 9, 'bold'),
                            padx=10, pady=5)
        sec_badge.pack(anchor='e')
        
        # Separator line
        separator = tk.Frame(self.root, bg='#007acc', height=2)
        separator.pack(fill='x')
        
    def create_analysis_tab(self):
        """Create the main analysis tab with enhanced UI"""
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="🔍 Forensic Analysis")
        
        # Main container with padding
        main_container = tk.Frame(analysis_frame, bg='#1a1a1a')
        main_container.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Input section with card-like appearance
        input_card = ttk.Frame(main_container, style='Card.TFrame')
        input_card.pack(fill='x', pady=(0, 20))
        
        input_inner = tk.Frame(input_card, bg='#252526')
        input_inner.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Header for input section
        input_header = ttk.Label(input_inner, text="🎯 Target Analysis", style='Header.TLabel')
        input_header.pack(anchor='w', pady=(0, 15))
        
        # Input field with label
        input_label = ttk.Label(input_inner, text="Enter URL, Domain, or Hash for Analysis:")
        input_label.pack(anchor='w', pady=(0, 8))
        
        # Styled input field
        input_field_frame = tk.Frame(input_inner, bg='#252526')
        input_field_frame.pack(fill='x', pady=(0, 15))
        
        self.input_entry = tk.Entry(input_field_frame, 
                                   bg='#3c3c3c', 
                                   fg='#ffffff', 
                                   insertbackground='#007acc',
                                   font=('Consolas', 11),
                                   bd=1,
                                   relief='solid',
                                   highlightthickness=2,
                                   highlightcolor='#007acc',
                                   highlightbackground='#555555')
        self.input_entry.pack(fill='x', ipady=8)
        
        # Button section with improved layout
        button_frame = tk.Frame(input_inner, bg='#252526')
        button_frame.pack(fill='x', pady=(10, 0))
        
        # Analysis buttons with different styles
        ttk.Button(button_frame, text="🔗 Analyze URL", 
                  command=self.analyze_url).pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="🔐 Check Hash", 
                  command=self.analyze_hash).pack(side='left', padx=(0, 10))
        ttk.Button(button_frame, text="🌐 Domain Info", 
                  command=self.analyze_domain).pack(side='left', padx=(0, 10))
        
        # Clear button
        ttk.Button(button_frame, text="🗑️ Clear", 
                  command=self.clear_results, 
                  style='Danger.TButton').pack(side='right')
        
        # Results section with enhanced styling
        results_card = ttk.Frame(main_container, style='Card.TFrame')
        results_card.pack(expand=True, fill='both')
        
        results_inner = tk.Frame(results_card, bg='#252526')
        results_inner.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Results header
        results_header_frame = tk.Frame(results_inner, bg='#252526')
        results_header_frame.pack(fill='x', pady=(0, 15))
        
        results_header = ttk.Label(results_header_frame, text="📊 Analysis Results", style='Header.TLabel')
        results_header.pack(side='left')
        
        # Export button in header
        ttk.Button(results_header_frame, text="💾 Export", 
                  command=self.export_json,
                  style='Success.TButton').pack(side='right')
        
        # Terminal-style results area
        terminal_frame = tk.Frame(results_inner, bg='#0d1117', bd=1, relief='solid')
        terminal_frame.pack(expand=True, fill='both')
        
        # Terminal header
        terminal_header = tk.Frame(terminal_frame, bg='#21262d', height=30)
        terminal_header.pack(fill='x')
        terminal_header.pack_propagate(False)
        
        # Terminal dots (like macOS)
        dots_frame = tk.Frame(terminal_header, bg='#21262d')
        dots_frame.pack(side='left', padx=10, pady=8)
        
        for color in ['#ff5f56', '#ffbd2e', '#27ca3f']:
            dot = tk.Label(dots_frame, text="●", fg=color, bg='#21262d', font=('Arial', 8))
            dot.pack(side='left', padx=2)
        
        terminal_title = tk.Label(terminal_header, text="Forensic Analysis Terminal", 
                                 bg='#21262d', fg='#8b949e', font=('Consolas', 9))
        terminal_title.pack(side='left', padx=10)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(terminal_frame, 
                                                     bg='#0d1117', 
                                                     fg='#58a6ff', 
                                                     insertbackground='#58a6ff',
                                                     font=('Consolas', 10),
                                                     wrap='word',
                                                     bd=0,
                                                     selectbackground='#264f78',
                                                     selectforeground='#ffffff')
        self.results_text.pack(expand=True, fill='both', padx=10, pady=10)
    
    def clear_results(self):
        """Clear analysis results"""
        self.results_text.delete('1.0', tk.END)
        self.input_entry.delete(0, tk.END)
        
    def create_educational_tab(self):
        """Create the educational content tab with enhanced UI"""
        edu_frame = ttk.Frame(self.notebook)
        self.notebook.add(edu_frame, text="🎓 Dark Web Education")
        
        # Main container
        main_container = tk.Frame(edu_frame, bg='#1a1a1a')
        main_container.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Education header
        edu_header_frame = tk.Frame(main_container, bg='#1a1a1a')
        edu_header_frame.pack(fill='x', pady=(0, 20))
        
        edu_title = tk.Label(edu_header_frame, 
                            text="🎓 Comprehensive Dark Web Education Center", 
                            bg='#1a1a1a', 
                            fg='#ffffff',
                            font=('Segoe UI', 16, 'bold'))
        edu_title.pack(side='left')
        
        # Education badge
        edu_badge = tk.Label(edu_header_frame, 
                           text="📚 LEARNING MODE", 
                           bg='#7c3aed', 
                           fg='white',
                           font=('Segoe UI', 9, 'bold'),
                           padx=15, pady=5)
        edu_badge.pack(side='right')
        
        # Create sub-tabs for different educational topics
        edu_notebook = ttk.Notebook(main_container)
        edu_notebook.pack(expand=True, fill='both')
        
        # Enhanced educational tabs
        self.create_edu_subtab(edu_notebook, "🌍 Overview", "overview")
        self.create_edu_subtab(edu_notebook, "🧅 TOR Network", "tor")
        self.create_edu_subtab(edu_notebook, "🔬 Forensic Techniques", "forensics")
        
    def create_edu_subtab(self, parent_notebook, tab_text, content_key):
        """Create an educational sub-tab with enhanced styling"""
        frame = ttk.Frame(parent_notebook)
        parent_notebook.add(frame, text=tab_text)
        
        # Content container
        content_container = tk.Frame(frame, bg='#1a1a1a')
        content_container.pack(expand=True, fill='both', padx=15, pady=15)
        
        # Content card
        content_card = ttk.Frame(content_container, style='Card.TFrame')
        content_card.pack(expand=True, fill='both')
        
        content_inner = tk.Frame(content_card, bg='#252526')
        content_inner.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Reading mode styling (like an e-book)
        reading_frame = tk.Frame(content_inner, bg='#fefefe', bd=1, relief='solid')
        reading_frame.pack(expand=True, fill='both')
        
        # Content header
        content_header = tk.Frame(reading_frame, bg='#f8f9fa', height=50)
        content_header.pack(fill='x')
        content_header.pack_propagate(False)
        
        header_title = tk.Label(content_header, 
                               text=tab_text, 
                               bg='#f8f9fa', 
                               fg='#1f2937',
                               font=('Segoe UI', 14, 'bold'))
        header_title.pack(expand=True)
        
        # Scrolled text for content
        text_widget = scrolledtext.ScrolledText(reading_frame, 
                                               bg='#fefefe', 
                                               fg='#374151', 
                                               font=('Georgia', 11),
                                               wrap='word',
                                               bd=0,
                                               selectbackground='#dbeafe',
                                               selectforeground='#1f2937',
                                               padx=40,
                                               pady=30,
                                               spacing1=2,
                                               spacing2=1,
                                               spacing3=2)
        text_widget.pack(expand=True, fill='both')
        
        # Store reference for content loading
        if not hasattr(self, 'edu_texts'):
            self.edu_texts = {}
        self.edu_texts[content_key] = text_widget
        
    def create_tools_tab(self):
        """Create the forensic tools tab with enhanced UI"""
        tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(tools_frame, text="🛠️ Forensic Tools")
        
        # Main container
        main_container = tk.Frame(tools_frame, bg='#1a1a1a')
        main_container.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Tool selection card
        tools_card = ttk.Frame(main_container, style='Card.TFrame')
        tools_card.pack(fill='x', pady=(0, 20))
        
        tools_inner = tk.Frame(tools_card, bg='#252526')
        tools_inner.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Tools header
        tools_header = ttk.Label(tools_inner, text="🔧 Available Forensic Tools", style='Header.TLabel')
        tools_header.pack(anchor='w', pady=(0, 15))
        
        # Tool buttons grid
        tools_grid = tk.Frame(tools_inner, bg='#252526')
        tools_grid.pack(fill='x')
        
        tools_info = [
            ("🔍 Onion URL Validator", "Validate .onion addresses", "Onion URL Validator"),
            ("🔐 Hash Generator", "Generate cryptographic hashes", "Hash Generator"),
            ("🌐 Network Tracer", "Trace network connections", "Network Tracer"),
            ("📋 Metadata Extractor", "Extract file metadata", "Metadata Extractor"),
            ("🎯 Pattern Analyzer", "Analyze suspicious patterns", "Pattern Analyzer")
        ]
        
        for i, (icon_text, description, command) in enumerate(tools_info):
            # Tool button container
            tool_container = tk.Frame(tools_grid, bg='#2d2d30', bd=1, relief='solid')
            tool_container.grid(row=i//3, column=i%3, padx=10, pady=10, sticky='ew')
            
            # Configure grid weights
            tools_grid.grid_columnconfigure(i%3, weight=1)
            
            # Tool button
            tool_btn = tk.Button(tool_container,
                               text=icon_text,
                               bg='#0e639c',
                               fg='white',
                               font=('Segoe UI', 11, 'bold'),
                               bd=0,
                               relief='flat',
                               pady=15,
                               command=lambda t=command: self.run_tool(t))
            tool_btn.pack(fill='x', padx=1, pady=(1, 0))
            
            # Tool description
            desc_label = tk.Label(tool_container,
                                text=description,
                                bg='#2d2d30',
                                fg='#cccccc',
                                font=('Segoe UI', 9),
                                pady=10)
            desc_label.pack(fill='x')
            
            # Hover effects
            def on_enter(e, btn=tool_btn):
                btn.config(bg='#1177bb')
            
            def on_leave(e, btn=tool_btn):
                btn.config(bg='#0e639c')
            
            tool_btn.bind("<Enter>", on_enter)
            tool_btn.bind("<Leave>", on_leave)
        
        # Tool output card
        output_card = ttk.Frame(main_container, style='Card.TFrame')
        output_card.pack(expand=True, fill='both')
        
        output_inner = tk.Frame(output_card, bg='#252526')
        output_inner.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Output header
        output_header_frame = tk.Frame(output_inner, bg='#252526')
        output_header_frame.pack(fill='x', pady=(0, 15))
        
        output_header = ttk.Label(output_header_frame, text="⚡ Tool Output", style='Header.TLabel')
        output_header.pack(side='left')
        
        # Clear output button
        ttk.Button(output_header_frame, text="🗑️ Clear Output", 
                  command=self.clear_tool_output,
                  style='Danger.TButton').pack(side='right')
        
        # Terminal-style output area
        output_terminal_frame = tk.Frame(output_inner, bg='#0d1117', bd=1, relief='solid')
        output_terminal_frame.pack(expand=True, fill='both')
        
        # Terminal header for output
        output_terminal_header = tk.Frame(output_terminal_frame, bg='#21262d', height=30)
        output_terminal_header.pack(fill='x')
        output_terminal_header.pack_propagate(False)
        
        # Terminal dots
        output_dots_frame = tk.Frame(output_terminal_header, bg='#21262d')
        output_dots_frame.pack(side='left', padx=10, pady=8)
        
        for color in ['#ff5f56', '#ffbd2e', '#27ca3f']:
            dot = tk.Label(output_dots_frame, text="●", fg=color, bg='#21262d', font=('Arial', 8))
            dot.pack(side='left', padx=2)
        
        output_terminal_title = tk.Label(output_terminal_header, text="Forensic Tools Output", 
                                       bg='#21262d', fg='#8b949e', font=('Consolas', 9))
        output_terminal_title.pack(side='left', padx=10)
        
        # Tool output text area
        self.tool_output = scrolledtext.ScrolledText(output_terminal_frame, 
                                                    bg='#0d1117', 
                                                    fg='#7dd3fc', 
                                                    insertbackground='#7dd3fc',
                                                    font=('Consolas', 10),
                                                    wrap='word',
                                                    bd=0,
                                                    selectbackground='#264f78',
                                                    selectforeground='#ffffff')
        self.tool_output.pack(expand=True, fill='both', padx=10, pady=10)
    
    def clear_tool_output(self):
        """Clear tool output"""
        self.tool_output.delete('1.0', tk.END)
        
    def create_reporting_tab(self):
        """Create the reporting tab"""
        report_frame = ttk.Frame(self.notebook)
        self.notebook.add(report_frame, text="Reporting")
        
        # Report generation
        report_gen_frame = ttk.LabelFrame(report_frame, text="Generate Report", padding="10")
        report_gen_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(report_gen_frame, text="Generate Forensic Report", 
                  command=self.generate_report).pack(side='left', padx=5)
        ttk.Button(report_gen_frame, text="Export to JSON", 
                  command=self.export_json).pack(side='left', padx=5)
        ttk.Button(report_gen_frame, text="Save Log", 
                  command=self.save_log).pack(side='left', padx=5)
        
        # Report preview
        report_preview_frame = ttk.LabelFrame(report_frame, text="Report Preview", padding="10")
        report_preview_frame.pack(expand=True, fill='both', padx=10, pady=5)
        
        self.report_text = scrolledtext.ScrolledText(report_preview_frame, bg='#1e1e1e', fg='white', 
                                                    insertbackground='white', wrap='word')
        self.report_text.pack(expand=True, fill='both')
        
    def load_educational_content(self):
        """Load educational content into the text widgets"""
        
        overview_content = """
DARK WEB FORENSICS - EDUCATIONAL OVERVIEW

The Dark Web represents a portion of the internet that requires special software, configurations, or authorization to access. Understanding its structure and forensic implications is crucial for cybersecurity professionals.

KEY CONCEPTS:

1. NETWORK LAYERS:
   - Surface Web: Publicly accessible websites indexed by search engines
   - Deep Web: Content not indexed by search engines (private databases, etc.)
   - Dark Web: Encrypted networks requiring special software (TOR, I2P, Freenet)

2. FORENSIC CHALLENGES:
   - Anonymity technologies make attribution difficult
   - Encrypted communications hide content and metadata
   - Volatile nature of hidden services
   - Legal and jurisdictional complexities

3. COMMON ARTIFACTS:
   - .onion URLs (TOR hidden services)
   - Bitcoin/cryptocurrency transactions
   - Encrypted communication logs
   - Specialized software installations

4. INVESTIGATIVE APPROACH:
   - Passive reconnaissance techniques
   - Traffic analysis and correlation
   - Metadata extraction and analysis
   - Timeline reconstruction
   - Attribution through operational security failures

LEGAL CONSIDERATIONS:
- Always operate within legal boundaries
- Obtain proper authorization before investigations
- Maintain chain of custody for digital evidence
- Document all investigative steps thoroughly

This tool is designed for educational purposes and legitimate forensic analysis only.
        """
        
        tor_content = """
TOR NETWORK ARCHITECTURE AND FORENSICS

The Onion Router (TOR) is a free and open-source software that enables anonymous communication by directing internet traffic through a worldwide volunteer network.

TECHNICAL ARCHITECTURE:

1. ONION ROUTING:
   - Messages are encapsulated in multiple layers of encryption
   - Each relay knows only the previous and next hop
   - Final destination is hidden from entry nodes
   - Entry nodes are hidden from exit nodes

2. NETWORK COMPONENTS:
   - Directory Authorities: Maintain network consensus
   - Guard Nodes: First hop in the circuit
   - Middle Relays: Intermediate hops
   - Exit Nodes: Final hop to destination
   - Hidden Services: .onion addresses

3. HIDDEN SERVICES (.onion):
   - Use 16-character (v2) or 56-character (v3) addresses
   - Provide server anonymity
   - No exit node required for .onion-to-.onion communication
   - Use introduction points and rendezvous points

FORENSIC CONSIDERATIONS:

1. TRAFFIC ANALYSIS:
   - Timing correlation attacks
   - Entry/exit node monitoring
   - Circuit fingerprinting
   - Website fingerprinting

2. OPERATIONAL SECURITY FAILURES:
   - Application-level information leaks
   - Time zone correlation
   - Writing style analysis
   - Social engineering

3. NETWORK MONITORING:
   - Relay node compromise
   - BGP hijacking
   - SSL/TLS certificate analysis
   - DNS leaks

4. METADATA COLLECTION:
   - Connection patterns
   - Usage statistics
   - Circuit construction timing
   - Bandwidth patterns

DETECTION TECHNIQUES:
- Deep Packet Inspection (DPI) for TOR traffic
- Statistical traffic analysis
- Behavioral pattern recognition
- Cross-correlation with other data sources

Remember: TOR has legitimate uses including privacy protection, circumventing censorship, and protecting vulnerable populations.
        """
        
        forensics_content = """
DARK WEB FORENSIC TECHNIQUES AND METHODOLOGIES

Digital forensics in the context of the dark web requires specialized techniques and understanding of anonymity technologies.

INVESTIGATION METHODOLOGY:

1. PREPARATION PHASE:
   - Legal authorization and scope definition
   - Tool selection and environment setup
   - Risk assessment and safety measures
   - Evidence handling procedures

2. COLLECTION PHASE:
   - Network traffic capture
   - System memory acquisition
   - File system analysis
   - Application data extraction

3. EXAMINATION PHASE:
   - Artifact identification and extraction
   - Timeline reconstruction
   - Pattern recognition and correlation
   - Cryptographic analysis

4. ANALYSIS PHASE:
   - Behavioral pattern analysis
   - Attribution techniques
   - Network topology mapping
   - Communication pattern analysis

KEY FORENSIC ARTIFACTS:

1. NETWORK ARTIFACTS:
   - TOR client configurations
   - Browser history and bookmarks
   - Cached .onion addresses
   - Network connection logs

2. APPLICATION ARTIFACTS:
   - Chat application databases
   - Cryptocurrency wallet files
   - Encrypted container files
   - Browser session data

3. SYSTEM ARTIFACTS:
   - Registry entries (Windows)
   - Log files and system events
   - Temporary files and swap data
   - Process memory dumps

ANALYTICAL TECHNIQUES:

1. TRAFFIC ANALYSIS:
   - Flow correlation
   - Timing analysis
   - Volume correlation
   - Protocol analysis

2. CRYPTOCURRENCY ANALYSIS:
   - Transaction graph analysis
   - Address clustering
   - Mixing service detection
   - Exchange interaction tracking

3. LINGUISTIC ANALYSIS:
   - Writing style fingerprinting
   - Language detection
   - Slang and terminology analysis
   - Social network analysis

4. OPERATIONAL SECURITY ANALYSIS:
   - OPSEC failure identification
   - Cross-platform correlation
   - Identity linkage
   - Behavioral pattern matching

ADVANCED TECHNIQUES:

1. MACHINE LEARNING APPLICATIONS:
   - Anomaly detection
   - Classification algorithms
   - Clustering analysis
   - Predictive modeling

2. CRYPTOGRAPHIC ANALYSIS:
   - Encryption strength assessment
   - Key recovery techniques
   - Protocol vulnerability analysis
   - Side-channel attacks

CHALLENGES AND LIMITATIONS:

1. TECHNICAL CHALLENGES:
   - Strong encryption implementations
   - Anonymity network design
   - Volatile evidence
   - Large data volumes

2. LEGAL CHALLENGES:
   - Jurisdictional issues
   - Privacy expectations
   - Evidence admissibility
   - International cooperation

3. ETHICAL CONSIDERATIONS:
   - Proportionality principle
   - Collateral impact
   - Privacy rights
   - Investigative methods disclosure

Remember: Forensic analysis must always be conducted within legal and ethical boundaries with proper authorization.
        """
        
        # Load content into text widgets
        self.edu_texts['overview'].insert('1.0', overview_content)
        self.edu_texts['tor'].insert('1.0', tor_content)
        self.edu_texts['forensics'].insert('1.0', forensics_content)
        
        # Make text widgets read-only
        for text_widget in self.edu_texts.values():
            text_widget.config(state='disabled')
    
    def analyze_url(self):
        """Analyze a URL for dark web characteristics"""
        url = self.input_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL to analyze")
            return
            
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, f"[{datetime.now()}] Starting URL Analysis...\n\n")
        
        # Basic URL validation and analysis
        analysis = self.perform_url_analysis(url)
        
        # Display results
        for key, value in analysis.items():
            self.results_text.insert(tk.END, f"{key}: {value}\n")
        
        self.results_text.insert(tk.END, "\n" + "="*50 + "\n")
        self.analysis_results['url_analysis'] = analysis
    
    def perform_url_analysis(self, url):
        """Perform comprehensive URL analysis"""
        analysis = {}
        
        # Basic URL parsing
        try:
            parsed = urllib.parse.urlparse(url)
            analysis['Scheme'] = parsed.scheme
            analysis['Domain'] = parsed.netloc
            analysis['Path'] = parsed.path
            analysis['Query'] = parsed.query
        except Exception as e:
            analysis['URL Parse Error'] = str(e)
        
        # Check for .onion domain
        if '.onion' in url.lower():
            analysis['Type'] = 'TOR Hidden Service'
            onion_address = self.extract_onion_address(url)
            if onion_address:
                analysis['Onion Address'] = onion_address
                analysis['Onion Version'] = self.identify_onion_version(onion_address)
                analysis['Address Validation'] = self.validate_onion_address(onion_address)
        else:
            analysis['Type'] = 'Surface/Deep Web'
            
        # Security analysis
        analysis['HTTPS'] = 'Yes' if url.startswith('https://') else 'No'
        
        # Pattern matching
        suspicious_patterns = self.check_suspicious_patterns(url)
        if suspicious_patterns:
            analysis['Suspicious Patterns'] = ', '.join(suspicious_patterns)
        
        # URL entropy analysis
        analysis['URL Entropy'] = self.calculate_entropy(url)
        
        return analysis
    
    def extract_onion_address(self, url):
        """Extract .onion address from URL"""
        onion_pattern = r'([a-z2-7]{16}|[a-z2-7]{56})\.onion'
        match = re.search(onion_pattern, url.lower())
        return match.group(0) if match else None
    
    def identify_onion_version(self, onion_address):
        """Identify version of .onion address"""
        base_address = onion_address.replace('.onion', '')
        if len(base_address) == 16:
            return 'v2 (Deprecated)'
        elif len(base_address) == 56:
            return 'v3 (Current)'
        else:
            return 'Unknown/Invalid'
    
    def validate_onion_address(self, onion_address):
        """Validate .onion address format"""
        base_address = onion_address.replace('.onion', '')
        
        # Check character set (base32)
        valid_chars = set('abcdefghijklmnopqrstuvwxyz234567')
        if not set(base_address.lower()).issubset(valid_chars):
            return 'Invalid - Contains invalid characters'
        
        # Check length
        if len(base_address) == 16:
            return 'Valid v2 format (deprecated)'
        elif len(base_address) == 56:
            return 'Valid v3 format'
        else:
            return 'Invalid - Incorrect length'
    
    def check_suspicious_patterns(self, url):
        """Check for suspicious patterns in URL"""
        patterns = []
        
        # Common suspicious keywords
        suspicious_keywords = ['admin', 'login', 'secure', 'private', 'hidden', 'secret']
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                patterns.append(f'Contains "{keyword}"')
        
        # Check for encoded content
        if '%' in url:
            patterns.append('URL encoded content')
        
        # Check for unusual ports
        if ':' in url and not url.startswith('http'):
            patterns.append('Non-standard port')
        
        return patterns
    
    def calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        from collections import Counter
        import math
        
        if not text:
            return 0
        
        counts = Counter(text)
        length = len(text)
        entropy = -sum(count/length * math.log2(count/length) for count in counts.values())
        return round(entropy, 2)
    
    def analyze_hash(self):
        """Analyze hash values"""
        hash_input = self.input_entry.get().strip()
        if not hash_input:
            messagebox.showwarning("Warning", "Please enter a hash to analyze")
            return
        
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, f"[{datetime.now()}] Starting Hash Analysis...\n\n")
        
        analysis = self.perform_hash_analysis(hash_input)
        
        for key, value in analysis.items():
            self.results_text.insert(tk.END, f"{key}: {value}\n")
        
        self.analysis_results['hash_analysis'] = analysis
    
    def perform_hash_analysis(self, hash_value):
        """Perform hash analysis"""
        analysis = {}
        
        # Determine hash type by length and character set
        hash_clean = hash_value.strip().lower()
        analysis['Input Hash'] = hash_clean
        analysis['Length'] = len(hash_clean)
        
        # Identify hash type
        if len(hash_clean) == 32 and all(c in '0123456789abcdef' for c in hash_clean):
            analysis['Likely Type'] = 'MD5'
        elif len(hash_clean) == 40 and all(c in '0123456789abcdef' for c in hash_clean):
            analysis['Likely Type'] = 'SHA-1'
        elif len(hash_clean) == 64 and all(c in '0123456789abcdef' for c in hash_clean):
            analysis['Likely Type'] = 'SHA-256'
        elif len(hash_clean) == 128 and all(c in '0123456789abcdef' for c in hash_clean):
            analysis['Likely Type'] = 'SHA-512'
        else:
            analysis['Likely Type'] = 'Unknown or Custom'
        
        # Generate test hashes for comparison
        test_strings = ['password', '123456', 'admin', 'test', 'hello']
        analysis['Common Hash Matches'] = self.check_common_hashes(hash_clean, test_strings)
        
        return analysis
    
    def check_common_hashes(self, target_hash, test_strings):
        """Check hash against common strings"""
        matches = []
        
        for test_string in test_strings:
            # Generate various hash types
            md5_hash = hashlib.md5(test_string.encode()).hexdigest()
            sha1_hash = hashlib.sha1(test_string.encode()).hexdigest()
            sha256_hash = hashlib.sha256(test_string.encode()).hexdigest()
            
            if target_hash == md5_hash:
                matches.append(f'MD5("{test_string}")')
            elif target_hash == sha1_hash:
                matches.append(f'SHA-1("{test_string}")')
            elif target_hash == sha256_hash:
                matches.append(f'SHA-256("{test_string}")')
        
        return matches if matches else ['No common matches found']
    
    def analyze_domain(self):
        """Analyze domain information with progress tracking"""
        domain = self.input_entry.get().strip()
        if not domain:
            messagebox.showwarning("Warning", "Please enter a domain to analyze")
            return
        
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, f"[{datetime.now()}] Starting Domain Analysis...\n")
        self.results_text.insert(tk.END, f"Target: {domain}\n")
        self.results_text.insert(tk.END, "="*50 + "\n\n")
        
        # Update GUI
        self.root.update()
        
        # Run analysis in steps with progress updates
        try:
            analysis = self.perform_domain_analysis(domain)
            
            # Display results
            self.results_text.insert(tk.END, "\nANALYSIS RESULTS:\n")
            self.results_text.insert(tk.END, "-"*20 + "\n")
            
            for key, value in analysis.items():
                # Format long values
                if isinstance(value, str) and len(value) > 100:
                    value = value[:100] + "..."
                self.results_text.insert(tk.END, f"{key}: {value}\n")
            
            self.results_text.insert(tk.END, "\n" + "="*50 + "\n")
            self.results_text.insert(tk.END, f"Analysis completed at {datetime.now()}\n")
            
            self.analysis_results['domain_analysis'] = analysis
            
        except Exception as e:
            self.results_text.insert(tk.END, f"\nERROR: Analysis failed - {str(e)}\n")
            messagebox.showerror("Analysis Error", f"Domain analysis failed: {str(e)}")
        
        # Scroll to bottom
        self.results_text.see(tk.END)
    
    def perform_domain_analysis(self, domain):
        """Perform domain analysis"""
        analysis = {}
        
        # Clean domain - remove protocol and path
        original_domain = domain
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0]
        
        # Remove port if present
        if ':' in domain and not domain.endswith('.onion'):
            domain = domain.split(':')[0]
        
        analysis['Original Input'] = original_domain
        analysis['Cleaned Domain'] = domain
        
        # Check if it's an .onion domain
        if domain.endswith('.onion'):
            analysis['Type'] = 'TOR Hidden Service'
            analysis['Onion Analysis'] = self.validate_onion_address(domain)
            analysis['DNS Resolution'] = 'N/A (Hidden Service)'
            analysis['WHOIS'] = 'N/A (Anonymous Service)'
        else:
            analysis['Type'] = 'Regular Domain'
            
            # Try DNS resolution with timeout
            try:
                self.results_text.insert(tk.END, f"Resolving DNS for {domain}...\n")
                self.root.update()
                
                ip = socket.gethostbyname(domain)
                analysis['IP Address'] = ip
                analysis['IP Type'] = self.classify_ip(ip)
                
                # Try reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip)
                    analysis['Reverse DNS'] = hostname[0]
                except:
                    analysis['Reverse DNS'] = 'Not available'
                
            except socket.gaierror as e:
                analysis['DNS Resolution'] = f'Failed: {str(e)}'
                analysis['IP Address'] = 'Not resolved'
            
            # Enhanced WHOIS lookup with better error handling
            self.results_text.insert(tk.END, f"Performing WHOIS lookup for {domain}...\n")
            self.root.update()
            
            whois_result = self.perform_whois_lookup(domain)
            analysis.update(whois_result)
            
            # Additional domain checks
            analysis['Domain Length'] = len(domain)
            analysis['Subdomain Count'] = len(domain.split('.')) - 1
            analysis['TLD'] = domain.split('.')[-1] if '.' in domain else 'None'
            
            # Check for suspicious patterns
            suspicious_checks = self.check_domain_suspicious_patterns(domain)
            if suspicious_checks:
                analysis['Suspicious Indicators'] = suspicious_checks
        
        return analysis
    
    def perform_whois_lookup(self, domain):
        """Perform WHOIS lookup with multiple methods"""
        whois_data = {}
        
        # Method 1: Try python-whois library
        if whois:
            try:
                self.results_text.insert(tk.END, "Using python-whois library...\n")
                self.root.update()
                
                w = whois.whois(domain)
                
                if w:
                    whois_data['Registrar'] = str(w.registrar) if hasattr(w, 'registrar') and w.registrar else 'Not available'
                    whois_data['Creation Date'] = str(w.creation_date) if hasattr(w, 'creation_date') and w.creation_date else 'Not available'
                    whois_data['Expiration Date'] = str(w.expiration_date) if hasattr(w, 'expiration_date') and w.expiration_date else 'Not available'
                    whois_data['Updated Date'] = str(w.updated_date) if hasattr(w, 'updated_date') and w.updated_date else 'Not available'
                    whois_data['Name Servers'] = ', '.join(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else 'Not available'
                    whois_data['Status'] = ', '.join(w.status) if hasattr(w, 'status') and w.status else 'Not available'
                    whois_data['WHOIS Server'] = str(w.whois_server) if hasattr(w, 'whois_server') and w.whois_server else 'Not available'
                    
                    # Organization info
                    if hasattr(w, 'org') and w.org:
                        whois_data['Organization'] = str(w.org)
                    
                    # Country info
                    if hasattr(w, 'country') and w.country:
                        whois_data['Country'] = str(w.country)
                        
                    whois_data['WHOIS Status'] = 'Success'
                else:
                    whois_data['WHOIS Status'] = 'No data returned'
                    
            except Exception as e:
                whois_data['WHOIS Status'] = f'Library lookup failed: {str(e)}'
                
                # Method 2: Try manual WHOIS query
                try:
                    self.results_text.insert(tk.END, "Trying manual WHOIS query...\n")
                    self.root.update()
                    
                    manual_whois = self.manual_whois_lookup(domain)
                    whois_data.update(manual_whois)
                except Exception as e2:
                    whois_data['Manual WHOIS'] = f'Also failed: {str(e2)}'
        else:
            whois_data['WHOIS Status'] = 'python-whois library not installed'
            
            # Try manual method as fallback
            try:
                self.results_text.insert(tk.END, "Using manual WHOIS method...\n")
                self.root.update()
                
                manual_whois = self.manual_whois_lookup(domain)
                whois_data.update(manual_whois)
            except Exception as e:
                whois_data['Manual WHOIS'] = f'Failed: {str(e)}'
        
        return whois_data
    
    def manual_whois_lookup(self, domain):
        """Manual WHOIS lookup using socket connection"""
        whois_data = {}
        
        try:
            # Determine WHOIS server
            tld = domain.split('.')[-1].lower()
            whois_servers = {
                'com': 'whois.verisign-grs.com',
                'net': 'whois.verisign-grs.com',
                'org': 'whois.pir.org',
                'edu': 'whois.educause.edu',
                'gov': 'whois.dotgov.gov',
                'mil': 'whois.nic.mil',
                'int': 'whois.iana.org',
                'uk': 'whois.nic.uk',
                'de': 'whois.denic.de',
                'fr': 'whois.afnic.fr',
                'it': 'whois.nic.it',
                'jp': 'whois.jprs.jp',
                'au': 'whois.auda.org.au',
                'ca': 'whois.cira.ca',
                'ru': 'whois.tcinet.ru',
                'cn': 'whois.cnnic.cn',
                'in': 'whois.registry.in'
            }
            
            whois_server = whois_servers.get(tld, 'whois.iana.org')
            whois_data['WHOIS Server Used'] = whois_server
            
            # Connect to WHOIS server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)  # 10 second timeout
            s.connect((whois_server, 43))
            s.send(f"{domain}\r\n".encode())
            
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            # Parse key information from response
            whois_data['Manual WHOIS Status'] = 'Success'
            whois_data['Response Length'] = f"{len(response_text)} characters"
            
            # Extract key fields using regex
            patterns = {
                'Registrar': r'Registrar:\s*(.+)',
                'Creation Date': r'Creation Date:\s*(.+)',
                'Registry Expiry Date': r'Registry Expiry Date:\s*(.+)',
                'Updated Date': r'Updated Date:\s*(.+)',
                'Name Server': r'Name Server:\s*(.+)',
                'Status': r'Domain Status:\s*(.+)'
            }
            
            for field, pattern in patterns.items():
                matches = re.findall(pattern, response_text, re.IGNORECASE)
                if matches:
                    whois_data[f'Manual {field}'] = matches[0].strip()
            
            # Store raw response (first 500 chars)
            whois_data['Raw Response Preview'] = response_text[:500] + "..." if len(response_text) > 500 else response_text
            
        except socket.timeout:
            whois_data['Manual WHOIS Status'] = 'Timeout - Server not responding'
        except socket.gaierror:
            whois_data['Manual WHOIS Status'] = 'DNS resolution failed for WHOIS server'
        except ConnectionRefusedError:
            whois_data['Manual WHOIS Status'] = 'Connection refused by WHOIS server'
        except Exception as e:
            whois_data['Manual WHOIS Status'] = f'Error: {str(e)}'
        
        return whois_data
    
    def check_domain_suspicious_patterns(self, domain):
        """Check domain for suspicious patterns"""
        suspicious = []
        
        # Length checks
        if len(domain) > 50:
            suspicious.append("Unusually long domain name")
        
        # Character patterns
        if re.search(r'\d{3,}', domain):
            suspicious.append("Contains multiple consecutive numbers")
        
        if re.search(r'[0-9]+[a-z]+[0-9]+', domain):
            suspicious.append("Mixed numbers and letters pattern")
        
        # Hyphen patterns
        if domain.count('-') > 3:
            suspicious.append("Excessive hyphens")
        
        # Double letters
        if re.search(r'(.)\1{2,}', domain):
            suspicious.append("Contains repeated characters")
        
        # Common suspicious keywords
        suspicious_keywords = ['secure', 'login', 'bank', 'paypal', 'amazon', 'google', 'facebook']
        for keyword in suspicious_keywords:
            if keyword in domain.lower() and keyword not in domain.lower().split('.')[0]:
                suspicious.append(f"Contains suspicious keyword: {keyword}")
        
        return suspicious
    
    def classify_ip(self, ip):
        """Classify IP address type"""
        octets = ip.split('.')
        first_octet = int(octets[0])
        second_octet = int(octets[1])
        
        if first_octet == 10:
            return 'Private (RFC 1918)'
        elif first_octet == 172 and 16 <= second_octet <= 31:
            return 'Private (RFC 1918)'
        elif first_octet == 192 and second_octet == 168:
            return 'Private (RFC 1918)'
        elif first_octet == 127:
            return 'Loopback'
        else:
            return 'Public'
    
    def run_tool(self, tool_name):
        """Run selected forensic tool"""
        self.tool_output.delete('1.0', tk.END)
        self.tool_output.insert(tk.END, f"Running {tool_name}...\n\n")
        
        if tool_name == "Onion URL Validator":
            self.run_onion_validator()
        elif tool_name == "Hash Generator":
            self.run_hash_generator()
        elif tool_name == "Network Tracer":
            self.run_network_tracer()
        elif tool_name == "Metadata Extractor":
            self.run_metadata_extractor()
        elif tool_name == "Pattern Analyzer":
            self.run_pattern_analyzer()
    
    def run_onion_validator(self):
        """Run onion URL validator tool"""
        test_urls = [
            "facebookcorewwwi.onion",  # Facebook v2 (example)
            "duckduckgogg42ts72.onion",  # DuckDuckGo v2 (example)
            "invalid_onion.onion",
            "3g2upl4pq6kufc4m.onion"
        ]
        
        self.tool_output.insert(tk.END, "ONION URL VALIDATOR\n")
        self.tool_output.insert(tk.END, "="*30 + "\n\n")
        
        for url in test_urls:
            validation = self.validate_onion_address(url)
            self.tool_output.insert(tk.END, f"URL: {url}\n")
            self.tool_output.insert(tk.END, f"Status: {validation}\n")
            self.tool_output.insert(tk.END, "-" * 20 + "\n")
    
    def run_hash_generator(self):
        """Run hash generator tool"""
        input_text = "example_password"
        
        self.tool_output.insert(tk.END, "HASH GENERATOR\n")
        self.tool_output.insert(tk.END, "="*20 + "\n\n")
        self.tool_output.insert(tk.END, f"Input: {input_text}\n\n")
        
        # Generate various hashes
        md5_hash = hashlib.md5(input_text.encode()).hexdigest()
        sha1_hash = hashlib.sha1(input_text.encode()).hexdigest()
        sha256_hash = hashlib.sha256(input_text.encode()).hexdigest()
        sha512_hash = hashlib.sha512(input_text.encode()).hexdigest()
        
        self.tool_output.insert(tk.END, f"MD5:    {md5_hash}\n")
        self.tool_output.insert(tk.END, f"SHA-1:  {sha1_hash}\n")
        self.tool_output.insert(tk.END, f"SHA-256: {sha256_hash}\n")
        self.tool_output.insert(tk.END, f"SHA-512: {sha512_hash}\n")
    
    def run_network_tracer(self):
        """Run network tracer tool"""
        self.tool_output.insert(tk.END, "NETWORK TRACER\n")
        self.tool_output.insert(tk.END, "="*20 + "\n\n")
        
        # Simulate network trace information
        trace_info = [
            "Hop 1: Local Gateway (192.168.1.1)",
            "Hop 2: ISP Router (10.x.x.x)",
            "Hop 3: Regional Hub",
            "Hop 4: TOR Entry Node (Simulated)",
            "Hop 5: TOR Middle Relay (Encrypted)",
            "Hop 6: TOR Exit Node (Encrypted)",
            "Destination: Hidden Service"
        ]
        
        for i, hop in enumerate(trace_info, 1):
            self.tool_output.insert(tk.END, f"{hop}\n")
            self.root.update()
            time.sleep(0.5)  # Simulate trace delay
    
    def run_metadata_extractor(self):
        """Run metadata extractor tool"""
        self.tool_output.insert(tk.END, "METADATA EXTRACTOR\n")
        self.tool_output.insert(tk.END, "="*25 + "\n\n")
        
        # Sample metadata extraction
        metadata = {
            "File Type": "Web Page",
            "Server": "nginx/1.18.0",
            "Last-Modified": "2024-01-15 10:30:00",
            "Content-Length": "4,567 bytes",
            "Language": "en-US",
            "Charset": "UTF-8",
            "Security Headers": "X-Frame-Options, CSP",
            "Cookies": "2 session cookies detected"
        }
        
        for key, value in metadata.items():
            self.tool_output.insert(tk.END, f"{key}: {value}\n")
    
    def run_pattern_analyzer(self):
        """Run pattern analyzer tool"""
        self.tool_output.insert(tk.END, "PATTERN ANALYZER\n")
        self.tool_output.insert(tk.END, "="*20 + "\n\n")
        
        # Sample patterns commonly found in dark web investigations
        patterns = {
            "Bitcoin Addresses": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
            "Ethereum Addresses": r"0x[a-fA-F0-9]{40}",
            "Email Addresses": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "Phone Numbers": r"\+?1?-?\.?\s?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
            "Credit Card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "Social Security": r"\b\d{3}-\d{2}-\d{4}\b",
            "Onion URLs": r"[a-z2-7]{16,56}\.onion",
            "IP Addresses": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        }
        
        sample_text = """
        Sample text for analysis:
        Contact: darkuser@protonmail.com
        Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        Phone: +1-555-123-4567
        Hidden service: 3g2upl4pq6kufc4m236i.onion
        IP: 192.168.1.100
        """
        
        self.tool_output.insert(tk.END, "Analyzing sample text for patterns...\n\n")
        
        for pattern_name, pattern_regex in patterns.items():
            matches = re.findall(pattern_regex, sample_text)
            if matches:
                self.tool_output.insert(tk.END, f"{pattern_name}: {len(matches)} match(es)\n")
                for match in matches:
                    self.tool_output.insert(tk.END, f"  - {match}\n")
            else:
                self.tool_output.insert(tk.END, f"{pattern_name}: No matches\n")
        
        self.tool_output.insert(tk.END, "\nPattern analysis complete.\n")
    
    def generate_report(self):
        """Generate comprehensive forensic report"""
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis data available for report generation")
            return
        
        report = self.create_forensic_report()
        self.report_text.delete('1.0', tk.END)
        self.report_text.insert('1.0', report)
    
    def create_forensic_report(self):
        """Create a comprehensive forensic report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
DARK WEB FORENSIC ANALYSIS REPORT
{"="*50}

Report Generated: {timestamp}
Tool Version: Dark Web Forensics Tool v1.0
Analysis Type: Educational/Training Exercise

EXECUTIVE SUMMARY
{"-"*20}
This report contains the results of dark web forensic analysis conducted for educational purposes.
All analysis was performed using legitimate forensic techniques and tools.

INVESTIGATION DETAILS
{"-"*25}
Investigation ID: DWFT-{int(time.time())}
Analyst: Training User
Scope: Educational Analysis
Authorization: Training Exercise

TECHNICAL ANALYSIS RESULTS
{"-"*30}
"""
        
        # Add analysis results
        for analysis_type, results in self.analysis_results.items():
            report += f"\n{analysis_type.upper().replace('_', ' ')}:\n"
            report += "-" * (len(analysis_type) + 1) + "\n"
            
            for key, value in results.items():
                report += f"{key}: {value}\n"
            report += "\n"
        
        report += f"""
FORENSIC METHODOLOGY
{"-"*25}
1. Evidence Collection: Passive analysis techniques
2. Data Processing: Automated pattern recognition
3. Analysis Framework: Multi-layer investigation approach
4. Validation: Cross-reference with known indicators
5. Documentation: Comprehensive logging and reporting

FINDINGS SUMMARY
{"-"*20}
- Total Analyses Performed: {len(self.analysis_results)}
- Analysis Types: {', '.join(self.analysis_results.keys())}
- Timestamp: {timestamp}

RECOMMENDATIONS
{"-"*15}
1. Continue monitoring for additional indicators
2. Correlate findings with other intelligence sources
3. Maintain detailed documentation of all activities
4. Follow proper legal and ethical guidelines

DISCLAIMER
{"-"*10}
This analysis was conducted for educational purposes only. All techniques and tools
used are publicly available and employed for legitimate cybersecurity research.
Any real-world application should be conducted only with proper legal authorization.

END OF REPORT
{"="*50}
        """
        
        return report
    
    def export_json(self):
        """Export analysis results to JSON"""
        if not self.analysis_results:
            messagebox.showwarning("Warning", "No analysis data to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Analysis Results"
        )
        
        if filename:
            export_data = {
                "timestamp": datetime.now().isoformat(),
                "tool_version": "Dark Web Forensics Tool v1.0",
                "analysis_results": self.analysis_results,
                "metadata": {
                    "export_time": datetime.now().isoformat(),
                    "total_analyses": len(self.analysis_results)
                }
            }
            
            try:
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Success", f"Analysis results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def save_log(self):
        """Save current analysis log"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Analysis Log"
        )
        
        if filename:
            try:
                log_content = self.results_text.get('1.0', tk.END)
                with open(filename, 'w') as f:
                    f.write(f"Dark Web Forensics Tool - Analysis Log\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    f.write("="*50 + "\n\n")
                    f.write(log_content)
                messagebox.showinfo("Success", f"Log saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
Dark Web Forensics Tool v1.0
Educational Edition

This tool is designed for educational purposes and legitimate 
cybersecurity research only. It provides:

• Comprehensive dark web education
• Forensic analysis capabilities  
• Pattern recognition tools
• Professional reporting features

Developer: Cybersecurity Research Team
Purpose: Education and Training
License: Educational Use Only

Remember: Always operate within legal boundaries
and obtain proper authorization for investigations.
        """
        messagebox.showinfo("About", about_text)

def main():
    """Main function to run the application"""
    root = tk.Tk()
    
    # Set application icon and additional properties
    root.resizable(True, True)
    root.minsize(800, 600)
    
    # Create menu bar
    menubar = tk.Menu(root)
    root.config(menu=menubar)
    
    # Create the application
    app = DarkWebForensicsTool(root)
    
    # File menu
    file_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Export Results", command=app.export_json)
    file_menu.add_command(label="Save Log", command=app.save_log)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=root.quit)
    
    # Tools menu
    tools_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Tools", menu=tools_menu)
    tools_menu.add_command(label="Onion Validator", command=lambda: app.run_tool("Onion URL Validator"))
    tools_menu.add_command(label="Hash Generator", command=lambda: app.run_tool("Hash Generator"))
    tools_menu.add_command(label="Pattern Analyzer", command=lambda: app.run_tool("Pattern Analyzer"))
    
    # Help menu
    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=app.show_about)
    
    # Add status bar
    status_frame = tk.Frame(root, bg='#2d2d2d')
    status_frame.pack(side='bottom', fill='x')
    
    status_label = tk.Label(status_frame, text="Ready for analysis | Educational Tool - Use Responsibly", 
                           bg='#2d2d2d', fg='white', anchor='w')
    status_label.pack(side='left', padx=10, pady=2)
    
    # Add warning label
    warning_label = tk.Label(status_frame, text="⚠ Educational Use Only", 
                            bg='#2d2d2d', fg='yellow', anchor='e')
    warning_label.pack(side='right', padx=10, pady=2)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    print("Dark Web Forensics Tool - Educational Edition")
    print("=" * 50)
    print("Starting application...")
    print("Remember: This tool is for educational purposes only!")
    print("Always operate within legal and ethical boundaries.")
    print("=" * 50)
    
    # Check for required libraries
    missing_libs = []
    
    try:
        import requests
    except ImportError:
        missing_libs.append("requests")
    
    if missing_libs:
        print("Warning: Some optional libraries are missing:")
        for lib in missing_libs:
            print(f"  - {lib}")
        print("Install with: pip install " + " ".join(missing_libs))
        print("The tool will work with reduced functionality.")
        print()
    
    main()