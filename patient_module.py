import pymysql 
import boto3
from botocore.client import Config
import variables
from tkinter import messagebox, filedialog
import os
from prettytable import PrettyTable

temp_data = {"report": "", "prescription": ""}

class Patients:

    def report_upload(self, report_entry):

        report_file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        report_file_path_name = os.path.basename(report_file_path)

        vultr_access_key = '3432RKVCCHUN6LV2QSHO'
        vultr_secret_key = 'Gi1Z70L5Pofc5jSUH1gPaqWL5Q5jkEolCeGvD8OK'
        endpoint_url = 'https://del1.vultrobjects.com'  # Use your endpoint here if different
        bucket_name = 'patient-files'

        # Initialize Vultr Object Storage session
        s3 = boto3.resource(
            's3',
            aws_access_key_id=vultr_access_key,
            aws_secret_access_key=vultr_secret_key,
            endpoint_url=endpoint_url,
            config=Config(signature_version='s3v4')
        )

        try:
            s3.Bucket(bucket_name).upload_file(report_file_path, report_file_path_name)
        except:
            messagebox.showerror("Error", "failed to upload file")
        else:
            messagebox.showinfo("Success", "File Successfully uploaded")
            report_entry.insert(0, report_file_path_name)
            temp_data["report"] = report_file_path_name
    
    def prescription_upload(self, prescription_entry):

        prescription_file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        prescription_file_path_name = os.path.basename(prescription_file_path)

        vultr_access_key = '3432RKVCCHUN6LV2QSHO'
        vultr_secret_key = 'Gi1Z70L5Pofc5jSUH1gPaqWL5Q5jkEolCeGvD8OK'
        endpoint_url = 'https://del1.vultrobjects.com'  # Use your endpoint here if different
        bucket_name = 'patient-files'

        # Initialize Vultr Object Storage session
        s3 = boto3.resource(
            's3',
            aws_access_key_id=vultr_access_key,
            aws_secret_access_key=vultr_secret_key,
            endpoint_url=endpoint_url,
            config=Config(signature_version='s3v4')
        )

        try:
            s3.Bucket(bucket_name).upload_file(prescription_file_path, prescription_file_path_name)
        except:
            messagebox.showerror("Error", "failed to upload file")
        else:
            messagebox.showinfo("Success", "File Successfully uploaded")
            prescription_entry.insert(0, prescription_file_path_name)
            temp_data["prescription"] = prescription_file_path_name
        
    
    def add_file_data(self, hospital_name_, diagnose_name_, prescription_entry, report_entry):
        
        variables.obj_var["sqlbase"].execute("use Patient")
        variables.obj_var["sqlbase"].execute(f"insert into {variables.patient_credentials['username']}(report, prescription, diagnose, hospital_name) values('{temp_data['report']}', '{temp_data['prescription']}', '{diagnose_name_.get()}', '{hospital_name_.get()}')")
        variables.obj_var["sql"].commit()
        messagebox.showinfo("Success", "Uploaded Successfully")
        prescription_entry.delete(0, "end")
        report_entry.delete(0, "end")
        diagnose_name_.set("")
        hospital_name_.set("")

    def download_files(self):
        
        self.selected_file = variables.obj_var["filedata_listbox"].get(variables.obj_var["filedata_listbox"].curselection())
        self.selected_file_split = self.selected_file.split("|")
        self.file_list = []

        file_path = filedialog.askdirectory()
        
        for file_index in range(1, 3):
            self.file_list.append(str(self.selected_file_split[file_index]).strip())

        vultr_access_key = '3432RKVCCHUN6LV2QSHO'
        vultr_secret_key = 'Gi1Z70L5Pofc5jSUH1gPaqWL5Q5jkEolCeGvD8OK'
        endpoint_url = 'https://del1.vultrobjects.com'  # Use your endpoint here if different
        bucket_name = 'patient-files'

        # Initialize Vultr Object Storage session
        s3 = boto3.resource(
            's3',
            aws_access_key_id=vultr_access_key,
            aws_secret_access_key=vultr_secret_key,
            endpoint_url=endpoint_url,
            config=Config(signature_version='s3v4')
        )

        try:
            for file_index in range(2):
                s3.Bucket(bucket_name).download_file(self.file_list[file_index], f"{file_path}/{self.file_list[file_index]}")
        except:
            messagebox.showerror("Error", "failed to download file")
        else:
            messagebox.showinfo("Success", "File Successfully downloaded")

    def active_prescription(self, patient_list):
        
        patient_list.delete(0, "end")
        patient_data_cols = {"Prescription": [], "Diagnose": [], "Hospital_name": [], "Activity": []}
    
        variables.obj_var["sqlbase"].execute("use Patient")
        for keys in patient_data_cols.keys():
            variables.obj_var["sqlbase"].execute(f"select {keys} from {variables.patient_credentials['username']} where Activity = 'Active'")
            for file_data in variables.obj_var["sqlbase"]:
                patient_data_cols[keys].append(str(file_data).strip("()',"))
        patient_data_table = PrettyTable()
        for key, value in patient_data_cols.items():
            patient_data_table.add_column(key, value)
        for each_col in patient_data_table.get_string().split("\n"):
            patient_list.insert("end", each_col)

    def all_prescription(self, patient_list):
        
        patient_list.delete(0, "end")
        patient_data_cols = {"Prescription": [], "Diagnose": [], "Hospital_name": [], "Activity": []}
    
        variables.obj_var["sqlbase"].execute("use Patient")
        for keys in patient_data_cols.keys():
            variables.obj_var["sqlbase"].execute(f"select {keys} from {variables.patient_credentials['username']}")
            for file_data in variables.obj_var["sqlbase"]:
                patient_data_cols[keys].append(str(file_data).strip("()',"))
        patient_data_table = PrettyTable()
        for key, value in patient_data_cols.items():
            patient_data_table.add_column(key, value)
        for each_col in patient_data_table.get_string().split("\n"):
            patient_list.insert("end", each_col)        






        

