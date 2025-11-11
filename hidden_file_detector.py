#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Hidden File Detector - Legacy Compatible Version
Works with Python 2.7+ and Python 3.x
Compatible with older Windows, Linux, and macOS systems
"""

import os
import sys
import stat

# Python 2/3 compatibility
try:
    input = raw_input  # Python 2
except NameError:
    pass  # Python 3

def get_system():
    """Get operating system name (compatible way)"""
    import platform
    return platform.system()

def is_hidden_file(file_path):
    """Check if file is hidden (cross-platform, legacy compatible)"""
    try:
        system = get_system()
        
        if system == "Windows":
            try:
                # Try modern Windows method first
                attrs = os.stat(file_path).st_file_attributes
                return bool(attrs & 0x02)  # FILE_ATTRIBUTE_HIDDEN = 0x02
            except AttributeError:
                # Fallback for older Windows/Python
                return os.path.basename(file_path).startswith('.')
        else:
            # Unix/Linux/macOS: Files starting with '.' are hidden
            return os.path.basename(file_path).startswith('.')
            
    except (OSError, AttributeError):
        # Ultimate fallback for all systems
        return os.path.basename(file_path).startswith('.')

def is_potential_flag(filename):
    """Check if filename suggests it might contain a flag"""
    flag_keywords = [
        'flag', 'secret', 'password', 'key', 'hint', 
        'token', 'admin', 'config', 'backup', 'hidden'
    ]
    
    suspicious_extensions = ['.bak', '.old', '.tmp', '.swp', '.orig']
    
    filename_lower = filename.lower()
    
    # Check for flag keywords
    for keyword in flag_keywords:
        if keyword in filename_lower:
            return True
    
    # Check for suspicious extensions
    for ext in suspicious_extensions:
        if filename_lower.endswith(ext):
            return True
    
    return False

def get_file_size(file_path):
    """Get file size safely"""
    try:
        return os.path.getsize(file_path)
    except (OSError, IOError):
        return 0

def scan_directory(directory_path):
    """Scan directory for hidden files (compatible with old Python)"""
    hidden_items = []
    system = get_system()
    
    print("=" * 50)
    print("Hidden File Detector - Legacy Compatible")
    print("Directory: " + directory_path)
    print("System: " + system)
    print("=" * 50)
    
    if not os.path.exists(directory_path):
        print("ERROR: Directory not found - " + directory_path)
        return hidden_items
    
    try:
        # Walk through directory tree
        for root, dirs, files in os.walk(directory_path):
            
            # Check directories
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                if is_hidden_file(dir_path):
                    hidden_items.append(('Hidden Directory', dir_path, 0))
            
            # Check files
            for file_name in files:
                file_path = os.path.join(root, file_name)
                file_size = get_file_size(file_path)
                
                # Check if hidden
                if is_hidden_file(file_path):
                    hidden_items.append(('Hidden File', file_path, file_size))
                
                # Check if potential flag
                elif is_potential_flag(file_name):
                    hidden_items.append(('Potential Flag', file_path, file_size))
    
    except OSError as e:
        print("ERROR: Permission denied or access error")
        print("Details: " + str(e))
    
    return hidden_items

def display_results(hidden_items):
    """Display found items"""
    if not hidden_items:
        print("\nNo hidden files or suspicious items found!")
        return
    
    print("\nFound " + str(len(hidden_items)) + " suspicious items:")
    print("-" * 70)
    
    for item_type, file_path, file_size in hidden_items:
        size_kb = file_size / 1024.0 if file_size > 0 else 0
        
        if item_type == 'Hidden Directory':
            print("[DIR]  " + file_path)
        elif item_type == 'Hidden File':
            print("[HIDDEN] " + file_path + " (" + str(round(size_kb, 1)) + " KB)")
        elif item_type == 'Potential Flag':
            print("[FLAG?] " + file_path + " (" + str(round(size_kb, 1)) + " KB)")

def preview_small_files(hidden_items):
    """Show content preview for small text files"""
    print("\nContent Preview (small files only):")
    print("-" * 40)
    
    for item_type, file_path, file_size in hidden_items:
        if file_size > 0 and file_size < 500:  # Only small files
            try:
                with open(file_path, 'r') as f:
                    content = f.read(100).strip()
                    if content and len(content) > 5:
                        filename = os.path.basename(file_path)
                        print(filename + ": " + content[:80] + "...")
            except (IOError, UnicodeDecodeError):
                pass  # Skip binary or unreadable files

def save_report(hidden_items, output_file):
    """Save results to text file"""
    try:
        with open(output_file, 'w') as f:
            f.write("Hidden File Detection Report\n")
            f.write("System: " + get_system() + "\n")
            f.write("Total Items Found: " + str(len(hidden_items)) + "\n")
            f.write("-" * 50 + "\n\n")
            
            for item_type, file_path, file_size in hidden_items:
                f.write("[" + item_type + "] " + file_path + " (" + str(file_size) + " bytes)\n")
        
        print("Report saved to: " + output_file)
        return True
    except IOError:
        print("ERROR: Could not save report file")
        return False

def get_common_paths():
    """Get common paths where flags/secrets are hidden"""
    system = get_system()
    paths = []
    
    if system == "Windows":
        # Windows common paths
        username = os.environ.get('USERNAME', 'user')
        paths = [
            'C:\\Users\\' + username,
            'C:\\Users\\' + username + '\\Desktop',
            'C:\\Users\\' + username + '\\Documents',
            'C:\\Temp',
            'C:\\Windows\\Temp',
            'C:\\ProgramData'
        ]
    else:
        # Linux/macOS common paths
        username = os.environ.get('USER', 'user')
        home = os.environ.get('HOME', '/home/' + username)
        paths = [
            home,
            '/tmp',
            '/var/tmp',
            '/var/log',
            '/etc',
            '/opt',
            '/usr/local'
        ]
    
    # Filter to existing paths only
    existing_paths = []
    for path in paths:
        if os.path.exists(path):
            existing_paths.append(path)
    
    return existing_paths

def main():
    """Main function - legacy compatible"""
    print("Hidden File Detector v2.0 (Legacy Compatible)")
    print("Works with Python 2.7+ and Python 3.x")
    
    # Get directory to scan
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
        
        # Special shortcuts
        if scan_path.lower() in ['auto', 'common', 'smart']:
            print("\nScanning common hiding locations...")
            common_paths = get_common_paths()
            all_items = []
            
            for path in common_paths:
                print("Checking: " + path)
                items = scan_directory(path)
                all_items.extend(items)
            
            display_results(all_items)
            if all_items:
                preview_small_files(all_items)
            return
            
    else:
        try:
            print("\nOptions:")
            print("1. Enter specific path")
            print("2. Type 'auto' for smart scanning")
            print("3. Type '.' for current directory")
            scan_path = input("Choose option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting...")
            return
        
        if scan_path.lower() in ['auto', 'common', 'smart']:
            print("\nScanning common hiding locations...")
            common_paths = get_common_paths()
            all_items = []
            
            for path in common_paths:
                print("Checking: " + path)
                items = scan_directory(path)
                all_items.extend(items)
            
            display_results(all_items)
            if all_items:
                preview_small_files(all_items)
            return
        
        if not scan_path:
            scan_path = "."
    
    # Scan for hidden files
    hidden_items = scan_directory(scan_path)
    
    # Display results
    display_results(hidden_items)
    
    # Show content preview
    if hidden_items:
        preview_small_files(hidden_items)
        
        # Ask about saving report
        try:
            save_choice = input("\nSave report to file? (y/n): ").lower().strip()
            if save_choice == 'y' or save_choice == 'yes':
                save_report(hidden_items, "hidden_files_report.txt")
        except (EOFError, KeyboardInterrupt):
            print("\nExiting without saving...")

if __name__ == "__main__":
    main()