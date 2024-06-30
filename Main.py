import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pyodbc
import logging
import os
import schedule
import time
import threading
import datetime

class BackupRestoreApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SQL Server Backup and Restore")
        self.geometry("1000x600")

        self.create_widgets()
        self.setup_logging()
        self.scheduled_backup_running = False
        self.scheduled_log_shipping_running = False
        self.schedule_thread = None
    
    def setup_logging(self):
        # Get the directory of the current Python file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_directory = os.path.join(script_dir, 'logs')
    
        # Create the log directory if it does not exist
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)
    
        log_file = os.path.join(log_directory, 'backup_restore.log')
    
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s %(levelname)s:%(message)s'
        )
    
    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create a horizontal paned window
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        # Left frame for main function
        left_frame = ttk.Frame(paned_window, width=500)
        left_frame.pack(fill=tk.BOTH, expand=True)
        left_frame.pack_propagate(False)

        # Right frame for error report
        right_frame = ttk.Frame(paned_window, width=500)
        right_frame.pack(fill=tk.BOTH, expand=True)

        paned_window.add(left_frame)
        paned_window.add(right_frame)

        # Server Section
        server_frame = ttk.LabelFrame(left_frame, text="Server Details")
        server_frame.pack(fill=tk.X, padx=10, pady=10)

        self.server_label = ttk.Label(server_frame, text="Server:")
        self.server_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.server_entry = ttk.Entry(server_frame)
        self.server_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        self.user_label = ttk.Label(server_frame, text="Username:")
        self.user_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.user_entry = ttk.Entry(server_frame)
        self.user_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        self.password_label = ttk.Label(server_frame, text="Password:")
        self.password_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(server_frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

        self.browse_button = ttk.Button(server_frame, text="Connect", command=self.load_databases)
        self.browse_button.grid(row=3, column=1, padx=5, pady=5)

        self.database_label = ttk.Label(server_frame, text="Database:")
        self.database_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.database_combobox = ttk.Combobox(server_frame, state="disabled")
        self.database_combobox.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)

        # Backup and Restore Section
        self.backup_restore_frame = ttk.LabelFrame(left_frame, text="Backup and Restore")
        self.backup_restore_frame.pack(fill=tk.X, padx=10, pady=10)

        backup_section_frame = ttk.LabelFrame(self.backup_restore_frame, text="Backup Section")
        backup_section_frame.pack(fill=tk.X, padx=10, pady=10)

        self.backup_path_label = ttk.Label(backup_section_frame, text="Backup Path:")
        self.backup_path_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.backup_path_entry = ttk.Entry(backup_section_frame)
        self.backup_path_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.browse_button = ttk.Button(backup_section_frame, text="Browse", command=self.browse_backup_path)
        self.browse_button.grid(row=1, column=2, padx=5, pady=5)
        self.full_backup_button = ttk.Button(backup_section_frame, text="Full Backup", command=self.backup_full)
        self.full_backup_button.grid(row=2, column=0, padx=5, pady=5)
        self.diff_backup_button = ttk.Button(backup_section_frame, text="Differential Backup", command=self.differential_backup)
        self.diff_backup_button.grid(row=2, column=1, padx=5, pady=5)
        self.log_backup_button = ttk.Button(backup_section_frame, text="Transaction Log Backup", command=self.transaction_log_backup)
        self.log_backup_button.grid(row=2, column=2, padx=5, pady=5)

        #Restore Section
        restore_section_frame = ttk.LabelFrame(self.backup_restore_frame, text="Restore Section")
        restore_section_frame.pack(fill=tk.X, padx=10, pady=10)

        self.restore_button = ttk.Button(restore_section_frame, text="Restore Database Full", command=self.restore_database)
        self.restore_button.grid(row=1, column=0, padx=5, pady=5)

        self.restore_diff_button = ttk.Button(restore_section_frame, text="Restore Differential", command=self.restore_differential)
        self.restore_diff_button.grid(row=1, column=1, padx=5, pady=5)
        
        self.restore_log_button = ttk.Button(restore_section_frame, text="Restore Transaction Log", command=self.restore_log)
        self.restore_log_button.grid(row=1, column=2, padx=5, pady=5)

        #Log Shipping Section
        sched_section_frame = ttk.LabelFrame(self.backup_restore_frame, text="Log Shipping Schedule")
        sched_section_frame.pack(fill=tk.X, padx=10, pady=10)

        self.logship_sched_button = ttk.Button(sched_section_frame, text="Set Log Shipping Schedule", command=self.open_logship_schedule_popup)
        self.logship_sched_button.grid(row=0, column=0, padx=5, pady=5)

        self.toggle_logship_button_style = ttk.Style()
        self.toggle_logship_button_style.configure("Toggle.TButton", background="red", foreground="red")

        self.toggle_logship_button = ttk.Button(sched_section_frame, text="Log Shipping is OFF", style="Toggle.TButton", command=self.toggle_log_shipping)
        self.toggle_logship_button.grid(row=0, column=1, padx=5, pady=5)


        #Scheduled backup Section
        sched_section_frame = ttk.LabelFrame(self.backup_restore_frame, text="Scheduled Backup")
        sched_section_frame.pack(fill=tk.X, padx=10, pady=10)

        self.sched_button = ttk.Button(sched_section_frame, text="Set Scheduled Backup", command=self.open_schedule_popup)
        self.sched_button.grid(row=1, column=0, padx=5, pady=5)

        self.toggle_button_style = ttk.Style()
        self.toggle_button_style.configure("ToggleSchd.TButton", background="red", foreground="red")

        self.toggle_button = ttk.Button(sched_section_frame, text="Scheduled Backup is OFF", style="ToggleSchd.TButton", command=self.toggle_scheduled_backup)
        self.toggle_button.grid(row=1, column=1, padx=5, pady=5)

        self.set_widget_states(self.backup_restore_frame, 'disabled')

        # Error Report Section
        error_frame = ttk.LabelFrame(right_frame, text="Error Report")
        error_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.error_report_text = tk.Text(error_frame, wrap=tk.WORD)
        self.error_report_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.error_report_scrollbar = ttk.Scrollbar(error_frame, command=self.error_report_text.yview)
        self.error_report_text.configure(yscrollcommand=self.error_report_scrollbar.set)
        self.error_report_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind event untuk menyimpan posisi scroll
        self.error_report_text.bind("<MouseWheel>", self.on_error_report_scroll)

        # Add a method to update the error report
        self.update_error_report()
    
    def on_error_report_scroll(self, event):
        # Menyimpan posisi scroll saat ini
        self.last_error_report_position = self.error_report_text.yview()[0]
    
    def convert_path_format(self, path):
        return path.replace('/', '\\')
    
    def set_widget_states(self, parent, state):
        for child in parent.winfo_children():
            if isinstance(child, (ttk.Button, ttk.Entry, ttk.Combobox)):
                child.configure(state=state)
            elif isinstance(child, ttk.Frame) or isinstance(child, ttk.LabelFrame):
                self.set_widget_states(child, state)
    
    def load_databases(self):
        server = self.server_entry.get()
        username = self.user_entry.get()
        password = self.password_entry.get()
        
        try:
            databases = self.fetch_databases(server, username, password)
            if databases:
                self.database_combobox['values'] = databases
                self.database_combobox.set(databases[0] if databases else '')
                self.database_combobox.configure(state="readonly")

                # Aktifkan hanya backup path entry dan browse button
                self.backup_path_entry.configure(state='normal')
                self.browse_button.configure(state='normal')

                messagebox.showinfo("Info", f"Connection successful. Databases loaded.")
            else:
                messagebox.showwarning("Warning", f"No databases found or connection failed.")
        except Exception as e:
            messagebox.showerror("Error", f"Error during connecting to server: {str(e)}")


    def fetch_databases(self, server, username, password):
        try:
            connection_string = f'DRIVER={{SQL Server}};SERVER={server};UID={username};PWD={password}'
            connection = pyodbc.connect(connection_string)
            cursor = connection.cursor()
            cursor.execute("SELECT name FROM sys.databases")
            databases = [row.name for row in cursor.fetchall()]
            connection.close()
            return databases
        except Exception as e:
            logging.error(f"Error during connecting to server: {e}")
            raise  # Re-raise the exception to be caught in load_databases

    
    def browse_backup_path(self):
        backup_path = filedialog.askdirectory()
        if backup_path:
            self.backup_path_entry.delete(0, tk.END)
            self.backup_path_entry.insert(0, backup_path)
            
            # Mengaktifkan semua widget yang bisa diaktifkan di backup_restore_frame
            self.set_widget_states(self.backup_restore_frame, 'normal')
    
    def backup_full(self):
        path = self.backup_path_entry.get()
        converted_path = self.convert_path_format(path)
        dbname = self.database_combobox.get()
        logging.info(f"Performing Full Database Backup for database: {dbname} to path: {path}")
        try:
            self.execute(f"BACKUP DATABASE [{dbname}] TO DISK = '{converted_path}\\{dbname}_{self.get_datetime()}.bak';", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
            logging.info("Full Database Backup completed successfully")
            recent_backup_id = self.get_recent_backup_set_id(self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()), dbname)
            self.save_backup_set_id(recent_backup_id)
        except Exception as e:
            logging.error(f"Error during full backup: {e}")
            messagebox.showerror("Error", f"Error during full backup: {e}")

    def differential_backup(self):
        path = self.backup_path_entry.get()
        converted_path = self.convert_path_format(path)
        dbname = self.database_combobox.get()
        logging.info("Performing Differential Backup")
        try:
            self.execute(f"BACKUP DATABASE [{dbname}] TO DISK = '{converted_path}\\{dbname}_diff_{self.get_datetime()}.bak' WITH DIFFERENTIAL;", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
            logging.info("Differential Backup completed successfully")
            recent_backup_id = self.get_recent_backup_set_id(self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()), dbname)
            self.save_backup_set_id(recent_backup_id)
        except Exception as e:
            logging.error(f"Error during differential backup: {e}")
    
    def transaction_log_backup(self):
        path = self.backup_path_entry.get()
        converted_path = self.convert_path_format(path)
        dbname = self.database_combobox.get()
        logging.info("Performing Transaction Log Backup")
        try:
            self.execute(f"BACKUP LOG [{dbname}] TO DISK = '{converted_path}\\{dbname}_log_{self.get_datetime()}.trn';", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
            logging.info("Transaction Log Backup completed successfully")
            recent_backup_id = self.get_recent_backup_set_id(self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()), dbname)
            self.save_backup_set_id(recent_backup_id)
        except Exception as e:
            logging.error(f"Error during transaction log backup: {e}")

    def restore_database(self):
        dbname = self.database_combobox.get()
        restore_from_file = filedialog.askopenfilename(filetypes=[('Backup Files', '*.bak')])
        if restore_from_file:
                logging.info("Restoring Database from Full Backup")
                try:
                    connection = self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get())
                    self.execute(f"RESTORE DATABASE [{dbname}] FROM DISK = '{restore_from_file}' WITH REPLACE", connection)
                    logging.info("Database restored successfully")
                    messagebox.showinfo("Success", "Database restored successfully")
                except Exception as e:
                    logging.error(f"Error during database restore: {e}")
                    messagebox.showerror("Error", f"Error during database restore: {e}")
    
    def restore_differential(self):
        try:
            dbname = self.database_combobox.get()
            full_backup_path = filedialog.askopenfilename(title="Select Full Backup File", filetypes=[("Backup Files", "*.bak")])
            diff_backup_path = filedialog.askopenfilename(title="Select Differential Backup File", filetypes=[("Backup Files", "*.bak")])
            
            if full_backup_path and diff_backup_path:
                full_converted_path = self.convert_path_format(full_backup_path)
                diff_converted_path = self.convert_path_format(diff_backup_path)
                logging.info(f"Restoring Full Backup for Database {dbname} from backup: {full_backup_path}")
                self.execute(f"RESTORE DATABASE [{dbname}] FROM DISK = '{full_converted_path}' WITH NORECOVERY, REPLACE;", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
                logging.info(f"Restoring Differential Backup for Database {dbname} from backup: {diff_backup_path}")
                self.execute(f"RESTORE DATABASE [{dbname}] FROM DISK = '{diff_converted_path}' WITH RECOVERY;", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
                messagebox.showinfo("Restore Completed", "Differential backup restored successfully.")
        except Exception as e:
            logging.error(f"Error during database restore: {e}")
            messagebox.showerror("Restore Error", str(e))

    def restore_log(self):
        try:
            dbname = self.database_combobox.get()
            full_backup_path = filedialog.askopenfilename(title="Select Full Backup File", filetypes=[("Backup Files", "*.bak")])
            log_backup_path = filedialog.askopenfilename(title="Select Transaction Log Backup File", filetypes=[("Transaction Log Files", "*.trn")])
            
            if full_backup_path and log_backup_path:
                full_converted_path = self.convert_path_format(full_backup_path)
                log_converted_path = self.convert_path_format(log_backup_path)
                logging.info(f"Restoring Full Backup for Database {dbname} from backup: {full_backup_path}")
                self.execute(f"RESTORE DATABASE [{dbname}] FROM DISK = '{full_converted_path}' WITH NORECOVERY, REPLACE;", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
                logging.info(f"Restoring Transaction Log for Database {dbname} from backup: {log_backup_path}")
                self.execute(f"RESTORE LOG [{dbname}] FROM DISK = '{log_converted_path}' WITH RECOVERY;", self.connectionpyodbc(self.server_entry.get(), self.user_entry.get(), self.password_entry.get()))
                messagebox.showinfo("Restore Completed", "Transaction log restored successfully.")
        except Exception as e:
            logging.error(f"Error during log restore: {e}")
            messagebox.showerror("Restore Error", str(e))


    def open_schedule_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Set Scheduled Backup")

        backup_type_frame = ttk.LabelFrame(popup, text="Select Backup Types and Schedule")
        backup_type_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.full_backup_var = tk.BooleanVar()
        self.diff_backup_var = tk.BooleanVar()
        self.trans_log_backup_var = tk.BooleanVar()

        self.full_backup_check = tk.Checkbutton(backup_type_frame, text="Full Backup", variable=self.full_backup_var)
        self.full_backup_check.grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)

        self.full_backup_hour = tk.Spinbox(backup_type_frame, from_=0, to=23, width=5)
        self.full_backup_hour.grid(row=0, column=1, padx=5)
        self.full_backup_minute = tk.Spinbox(backup_type_frame, from_=0, to=59, width=5)
        self.full_backup_minute.grid(row=0, column=2, padx=5)
        tk.Label(backup_type_frame, text="HH").grid(row=0, column=3)
        tk.Label(backup_type_frame, text="MM").grid(row=0, column=4)

        self.diff_backup_check = tk.Checkbutton(backup_type_frame, text="Differential Backup", variable=self.diff_backup_var)
        self.diff_backup_check.grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)

        self.diff_backup_hour = tk.Spinbox(backup_type_frame, from_=0, to=23, width=5)
        self.diff_backup_hour.grid(row=1, column=1, padx=5)
        self.diff_backup_minute = tk.Spinbox(backup_type_frame, from_=0, to=59, width=5)
        self.diff_backup_minute.grid(row=1, column=2, padx=5)
        tk.Label(backup_type_frame, text="HH").grid(row=1, column=3)
        tk.Label(backup_type_frame, text="MM").grid(row=1, column=4)

        self.trans_log_backup_check = tk.Checkbutton(backup_type_frame, text="Transaction Log Backup", variable=self.trans_log_backup_var)
        self.trans_log_backup_check.grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)

        self.trans_log_backup_hour = tk.Spinbox(backup_type_frame, from_=0, to=23, width=5)
        self.trans_log_backup_hour.grid(row=2, column=1, padx=5)
        self.trans_log_backup_minute = tk.Spinbox(backup_type_frame, from_=0, to=59, width=5)
        self.trans_log_backup_minute.grid(row=2, column=2, padx=5)
        tk.Label(backup_type_frame, text="HH").grid(row=2, column=3)
        tk.Label(backup_type_frame, text="MM").grid(row=2, column=4)

        confirm_button = ttk.Button(popup, text="Confirm", command=lambda: self.set_schedule(popup))
        confirm_button.pack(pady=5)

    def set_schedule(self, popup):
        if self.full_backup_var.get():
            hoursfull = int(self.full_backup_hour.get())
            minutesfull = int(self.full_backup_minute.get())
            if (hoursfull == 0):
                schedule.every(minutesfull).minutes.do(self.backup_full)
            else:
                schedule.every(hoursfull).hours.at(f":{minutesfull:02d}").do(self.backup_full)
            
        if self.diff_backup_var.get():
            hoursdiff = int(self.diff_backup_hour.get())
            minutesdiff = int(self.diff_backup_minute.get())
            if (hoursdiff == 0):
                schedule.every(minutesdiff).minutes.do(self.differential_backup)
            else:
                schedule.every(hoursdiff).hours.at(f":{minutesdiff:02d}").do(self.differential_backup)
            
        if self.trans_log_backup_var.get():
            hourslog = int(self.trans_log_backup_hour.get())
            minuteslog = int(self.trans_log_backup_minute.get())
            if (hourslog == 0):
                schedule.every(minuteslog).minutes.do(self.transaction_log_backup)
            else:
                schedule.every(hourslog).hours.at(f":{minuteslog:02d}").do(self.transaction_log_backup)
            
        popup.destroy()
        messagebox.showinfo("Scheduled Backup", "Backups have been scheduled successfully")

    def run_schedule(self):
        while self.scheduled_backup_running:
            schedule.run_pending()
            time.sleep(1)

    def toggle_scheduled_backup(self):
        if self.scheduled_backup_running:
            self.scheduled_backup_running = False
            self.toggle_button.config(text="Scheduled Backup is OFF")
            self.toggle_button_style.configure("ToggleSchd.TButton", background="red", foreground="red")
            if self.schedule_thread and self.schedule_thread.is_alive():
                self.schedule_thread.join()
        else:
            self.scheduled_backup_running = True
            self.schedule_thread = threading.Thread(target=self.run_schedule)
            self.schedule_thread.start()
            self.toggle_button.config(text="Scheduled Backup is ON")
            self.toggle_button_style.configure("ToggleSchd.TButton", background="green", foreground="green")
    
    def open_logship_schedule_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Set Log Shipping Schedule")

        # Connection details for secondary server
        connection_frame = ttk.LabelFrame(popup, text="Secondary Server Connection")
        connection_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.secondary_server_label = ttk.Label(connection_frame, text="Secondary Server:")
        self.secondary_server_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.secondary_server_entry = ttk.Entry(connection_frame)
        self.secondary_server_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        self.secondary_user_label = ttk.Label(connection_frame, text="Username:")
        self.secondary_user_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.secondary_user_entry = ttk.Entry(connection_frame)
        self.secondary_user_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)

        self.secondary_password_label = ttk.Label(connection_frame, text="Password:")
        self.secondary_password_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.secondary_password_entry = ttk.Entry(connection_frame, show="*")
        self.secondary_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

        self.secondary_db_label = ttk.Label(connection_frame, text="Database:")
        self.secondary_db_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.secondary_db_entry = ttk.Entry(connection_frame)
        self.secondary_db_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)

        # Schedule details
        schedule_frame = ttk.LabelFrame(popup, text="Schedule Details")
        schedule_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.logship_hour_label = ttk.Label(schedule_frame, text="Hour Interval:")
        self.logship_hour_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.logship_hour_spinbox = tk.Spinbox(schedule_frame, from_=0, to=23, width=5)
        self.logship_hour_spinbox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        self.logship_minute_label = ttk.Label(schedule_frame, text="Minute Interval:")
        self.logship_minute_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.logship_minute_spinbox = tk.Spinbox(schedule_frame, from_=0, to=59, width=5)
        self.logship_minute_spinbox.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        confirm_button = ttk.Button(popup, text="Confirm", command=lambda: self.set_logship_schedule(popup))
        confirm_button.pack(pady=5)


    def set_logship_schedule(self, popup):
        secondary_server = self.secondary_server_entry.get()
        secondary_user = self.secondary_user_entry.get()
        secondary_password = self.secondary_password_entry.get()
        secondary_db = self.secondary_db_entry.get()
        logship_hours = int(self.logship_hour_spinbox.get())
        logship_minutes = int(self.logship_minute_spinbox.get())

        def log_ship_task():
            self.log_shipping(secondary_server, secondary_user, secondary_password, secondary_db)

        if logship_hours == 0:
            schedule.every(logship_minutes).minutes.do(log_ship_task)
        else:
            schedule.every(logship_hours).hours.at(f":{logship_minutes:02d}").do(log_ship_task)

        popup.destroy()
        messagebox.showinfo("Log Shipping Schedule", "Log Shipping has been scheduled successfully")


    def toggle_log_shipping(self):
        if self.scheduled_log_shipping_running:
            self.scheduled_log_shipping_running = False
            self.toggle_logship_button.config(text="Log Shipping is OFF")
            self.toggle_logship_button_style.configure("Toggle.TButton", background="red", foreground="red")
            if self.log_shipping_thread and self.log_shipping_thread.is_alive():
                self.log_shipping_thread.join()
        else:
            self.scheduled_log_shipping_running = True
            self.log_shipping_thread = threading.Thread(target=self.run_log_shipping_schedule)
            self.log_shipping_thread.start()
            self.toggle_logship_button.config(text="Log Shipping is ON")
            self.toggle_logship_button_style.configure("Toggle.TButton", background="green", foreground="green")


    def run_log_shipping_schedule(self):
        while self.scheduled_log_shipping_running:
            schedule.run_pending()
            time.sleep(1)
    
    def log_shipping(self, secondary_server, secondary_user, secondary_password, secondary_db):
        server = self.server_entry.get()
        username = self.user_entry.get()
        password = self.password_entry.get()
        primary_db = self.database_combobox.get()
        backup_path = self.backup_path_entry.get()
        converted_backup_path = self.convert_path_format(backup_path)
        logging.info(f"Performing Log Shipping from {primary_db} to {secondary_db}")

        try:
            # Backup transaction log on primary server
            self.transaction_log_backup()
            
            primary_connection = self.connectionpyodbc(server, username, password)
            
            # Get the recent backup set ID after the new transaction log backup
            recent_backup_id = self.get_recent_backup_set_id(primary_connection, primary_db)
            self.save_backup_set_id(recent_backup_id)

            # Get the last logged backup set ID
            last_logged_backup_id = self.load_backup_set_id()

            # Connect to secondary server
            secondary_connection = pyodbc.connect(
                f'DRIVER={{ODBC Driver 17 for SQL Server}};SERVER={secondary_server};DATABASE=master;UID={secondary_user};PWD={secondary_password}',
                autocommit=True
            )
            
            # Check if we need to perform a full backup and restore
            if last_logged_backup_id is None or recent_backup_id - last_logged_backup_id > 100:  # Arbitrary threshold
                logging.info("Performing full backup and restore")
                self.backup_full()
                
                self.execute(f"RESTORE FILELISTONLY FROM DISK = '{converted_backup_path}\\{primary_db}_{self.get_datetime()}.bak'", secondary_connection)
                self.execute(
                    f"RESTORE DATABASE [{secondary_db}] FROM DISK = '{converted_backup_path}\\{primary_db}_{self.get_datetime()}.bak' WITH REPLACE, NORECOVERY, "
                    f"MOVE '{primary_db}' TO '{converted_backup_path}\\{secondary_db}.mdf', "
                    f"MOVE '{primary_db}_log' TO '{converted_backup_path}\\{secondary_db}_log.ldf';",
                    secondary_connection
                )
                last_logged_backup_id = recent_backup_id

            # Find all transaction log backups that need to be applied
            cursor = primary_connection.cursor()
            cursor.execute(f"""
                SELECT bmf.physical_device_name
                FROM msdb.dbo.backupset bs
                JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
                WHERE bs.database_name = '{primary_db}'
                AND bs.type = 'L'
                AND bs.backup_set_id > {last_logged_backup_id}
                ORDER BY bs.backup_start_date
            """)
            log_backups = cursor.fetchall()
            
            # Apply each log backup in sequence
            for log_backup in log_backups:
                try:
                    self.execute(f"RESTORE LOG [{secondary_db}] FROM DISK = '{log_backup[0]}' WITH NORECOVERY;", secondary_connection)
                except Exception as e:
                    logging.error(f"Error applying log backup {log_backup[0]}: {e}")
                    raise

            # Update the last logged backup ID
            self.save_backup_set_id(recent_backup_id)

            logging.info(f"Log Shipping from {primary_db} to {secondary_db} completed successfully")
        except Exception as e:
            logging.error(f"Error during log shipping: {e}")
            messagebox.showerror("Error", f"Error during log shipping: {e}")
        finally:
            if 'primary_connection' in locals():
                primary_connection.close()
            if 'secondary_connection' in locals():
                secondary_connection.close()

    def connectionpyodbc(self, server, username, password):
        connectionpyodbc = pyodbc.connect(
            'DRIVER={ODBC Driver 17 for SQL Server};'
            f'SERVER={server};'
            f'DATABASE=master;'
            f'UID={username};'
            f'PWD={password}',
            autocommit=True
        )
        return connectionpyodbc
    
    def execute(self, query, connection):
        cursor = connection.cursor()
        try:
            cursor.execute(query)
            while cursor.nextset():
                pass
        except Exception as e:
            logging.error(f"Error executing query: {query}, Error: {e}")
            raise  # Re-raise the exception after logging
        finally:
            cursor.close()
    
    def get_datetime(self):
        current_time = datetime.datetime.now()
        year = current_time.year
        month = f"{current_time.month:02d}"
        day = f"{current_time.day:02d}"
        hour = f"{current_time.hour:02d}"
        minute = f"{current_time.minute:02d}"
    
        return f"{year}{month}{day}{hour}{minute}"
    
    def get_recent_backup_set_id(self, connection, database_name):
        query = f"""
        SELECT TOP 1 backup_set_id
        FROM msdb.dbo.backupset
        WHERE database_name = ?
        ORDER BY backup_start_date DESC;
        """
        cursor = connection.cursor()
        cursor.execute(query, (database_name,))
        result = cursor.fetchone()
        return result[0] if result else None

    def save_backup_set_id(self, backup_set_id, filename="backup_set_id.txt"):
        with open(filename, "w") as file:
            file.write(str(backup_set_id))
    
    def load_backup_set_id(self, filename="backup_set_id.txt"):
        if os.path.exists(filename):
            with open(filename, "r") as file:
                return int(file.read().strip())
        return None
    
    def save_backup_set_id_logship(self, backup_set_id, filename="backup_set_id_logship.txt"):
        with open(filename, "w") as file:
            file.write(str(backup_set_id))
    
    def load_backup_set_id_logship(self, filename="backup_set_id_logship.txt"):
        if os.path.exists(filename):
            with open(filename, "r") as file:
                return int(file.read().strip())
        return None
    
    def update_error_report(self):
        # Get the directory of the current Python file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_file = os.path.join(script_dir, 'logs', 'backup_restore.log')
        current_position = self.error_report_text.yview()[0]

        try:
            with open(log_file, 'r') as file:
                log_content = file.read()
            self.error_report_text.delete('1.0', tk.END)
            self.error_report_text.insert(tk.END, log_content)
        except FileNotFoundError:
            self.error_report_text.insert(tk.END, "Log file not found.")
        except Exception as e:
            self.error_report_text.insert(tk.END, f"Error reading log file: {str(e)}")
        
        self.error_report_text.yview_moveto(current_position)

        # Schedule the next update
        self.after(5000, self.update_error_report)  # Update every 1 seconds


if __name__ == "__main__":
    app = BackupRestoreApp()
    app.mainloop()
