import pymysql 
import boto3
from botocore.client import Config
import variables
from tkinter import messagebox, filedialog
import os
from prettytable import PrettyTable

temp_data = {"prescription": "", "report": ""}

class Doctors:

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


    def create_patientid(self, patient_username, case_no, diagnose, hospital_name, report, prescription):

        variables.obj_var["sqlbase"].execute("Use Doctor_data")
        variables.obj_var["sqlbase"].execute(f"insert into docpatients values('{variables.doctor_credentials["username"]}', '{patient_username.get()}', '{case_no.get()}', '{diagnose.get()}', '{hospital_name.get()}')")
        variables.obj_var["sql"].commit()

        variables.obj_var["sqlbase"].execute("Use Patient")
        variables.obj_var["sqlbase"].execute(f"insert into {patient_username.get()} values('{temp_data["report"]}', '{temp_data['prescription']}', '{diagnose.get()}', '{hospital_name.get()}', 'Active')")
        variables.obj_var["sql"].commit()

        messagebox.showinfo("Success", "Successfully created New Patient ID")
        patient_username.delete(0, "end")
        report.delete(0, "end")
        prescription.delete(0, "end")
        case_no.delete(0, "end")
        diagnose.set("")
        hospital_name.set("")

    def doctor_myprescription(self, patient_list):

        patient_list.delete(0, "end")
        patient_list.config(font=("Courier", 20, "bold"))
        variables.obj_var["sqlbase"].execute("Use Doctor_data")
        col_names = {"patient_username": [], "case_no": [], "diagnose": [], "hospital_name": []}

        for cols_name in col_names:
            variables.obj_var["sqlbase"].execute(f"select {cols_name} from docpatients where doctor_username = '{variables.doctor_credentials["username"]}'")
            for my_patient_index in variables.obj_var["sqlbase"]:
                col_names[f"{cols_name}"].append(str(my_patient_index).strip("(),'"))
        my_patient_table = PrettyTable()
        for key, value in col_names.items():
            my_patient_table.add_column(key, value)
        for each_col in my_patient_table.get_string().split("\n"):
            patient_list.insert("end", each_col)

    def download_files(self):
        
        self.selected_file = variables.doctor_credentials["filedata_listbox"].get(variables.doctor_credentials["filedata_listbox"].curselection())
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
            

        

        

