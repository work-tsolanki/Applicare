import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from PIL import Image,ImageTk
import pymysql 
import cryptography
import variables
import random
from prettytable import PrettyTable
import os
import boto3
from botocore.client import Config

class MYSQL:

    def __init__(self):

        self.sql = pymysql.connect(
            user = "vultradmin", 
            password = "AVNS_p8of8enxNpGGvOGL4Yd",
            host = "vultr-prod-a605f422-2a38-473e-8d01-d175c9151447-vultr-prod-8651.vultrdb.com",
            port = 16751
        )
        self.sqlbase = self.sql.cursor()
        variables.obj_var["sql"] = self.sql
        variables.obj_var["sqlbase"] = self.sqlbase
        
        

####################################################################################################################################################
legger = {("a"):"a"}

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Applicare")
        self.geometry("800x600")
        self.configure(bg="#e3f2fd")
        self.logged_in_user = None
        self.logged_password= None
        self.current_frame = None
        self.page_history = []
        self.frames={}
        self.show_dashboard()
        self.myconnection = MYSQL()

    def show_dashboard(self):                                                                                               #dashboard
        self.logged_in_user = "admin"
        self.page_history.clear()
        self.switch_frame(Dashboard)

    def show_signup_page(self):                                                                                             #doctor signup page
        self.switch_frame(Doctorssignup)

    def show_upload_page(self):                                                                                             #uploading page
        self.switch_frame(patuploadpage)

    def show_signupp_page(self):                                                                                            #patient signup page
        self.switch_frame(Patientssignup)

    def show_new_patient_page(self):                                                                                        #newpatient page
        self.switch_frame(NewPatientPage)

    def show_prescrip_page(self):                                                                                           # prescription page under patient portal
        self.switch_frame(patPrescriptionpage)

    def show_patientslogin_page(self):                                                                                      #patients login
        self.switch_frame(Patientslogin)
        
    def show_doctorslogin_page(self):                                                                                       #doctors login
        self.switch_frame(Doctorslogin)

    def show_patients_page(self,user,password): 
        self.logged_password = password
        self.logged_in_user = user                                                                                          #patients page
        self.switch_frame(PatientsPage)
        
    def show_doctors_page(self,username,password):
        self.logged_password = password                                                                                     #doctors page
        self.logged_in_user = username
        self.switch_frame(DoctorsPage)

    def show_pharmacists_page(self):                                                                                      #pharmacists login
        self.switch_frame(PharmacistsPage)

    def show_dprofile_page(self):                                                                                           #doctors profile
        self.switch_frame(DocProfilePage)
    
    def show_pprofile_page(self):                                                                                           #patient profile
        self.switch_frame(PatProfilePage)

    def show_docprescriptions(self):                                                                                        # prescription page under docs portal
        self.switch_frame(Prescriptionpage)

    def show_searchedpatientpage(self):                                                                                        # prescription page under docs portal
        self.switch_frame(SearchedPatientsPage)
    
    def show_searchedpprofile_page(self):                                                                                           #patient profile
        self.switch_frame(SearchedPatProfilePage)

    def  switch_frame(self, frame_class):                                                                                    # frame switching
        if frame_class not in self.frames:
            frame = frame_class(self)
            self.frames[frame_class] = frame
            frame.pack(expand=True, fill=tk.BOTH)

        if hasattr(self, 'current_frame') and self.current_frame:
            self.current_frame.pack_forget()

        if hasattr(self, 'current_frame'):
            self.page_history.append(self.current_frame)

        self.current_frame = self.frames[frame_class]
        self.current_frame.pack(expand=True, fill=tk.BOTH)

    def go_back(self):                                                                                                          # back button
        if self.page_history:
            self.current_frame.pack_forget()  
            self.current_frame = self.page_history.pop()  
            self.current_frame.pack(expand=True, fill=tk.BOTH)

######################################################################################################################################################

class Doctorssignup(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8", height=10)

        Tab_btn=tk.Label(self, text="D O C T O R    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="#ffffff", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        login_frame = tk.Frame(self, bd=0, relief="solid", padx=50, pady=80, bg="#ffffff")
        login_frame.pack(anchor="center")

        firstname_label = tk.Label(login_frame, text="First Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        firstname_label.grid(row=0, column=0, sticky="e", pady=5)
        self.firstname_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.firstname_entry.grid(row=0, column=1, pady=5)
        
        midname_label = tk.Label(login_frame, text="Middle Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        midname_label.grid(row=1, column=0, sticky="e", pady=5)
        self.midname_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.midname_entry.grid(row=1, column=1, pady=5)

        lstname_label = tk.Label(login_frame, text="Last Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        lstname_label.grid(row=3, column=0, sticky="e", pady=5)
        self.lstname_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.lstname_entry.grid(row=3, column=1, pady=5)

        eaddress_label = tk.Label(login_frame, text="E-mail Address:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        eaddress_label.grid(row=4, column=0, sticky="e", pady=5)
        self.eaddress_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.eaddress_entry.grid(row=4, column=1, pady=5)

        ph_label = tk.Label(login_frame, text="Phone No.:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        ph_label.grid(row=5, column=0, sticky="e", pady=5)
        self.ph_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.ph_entry.grid(row=5, column=1, pady=5)

        certi_label = tk.Label(login_frame, text="Dr. Certification:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        certi_label.grid(row=6, column=0, sticky="e", pady=5)
        self.certi_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.certi_entry.grid(row=6, column=1, pady=5)
        
        upload_img = Image.open("upload.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.upload_icon = ImageTk.PhotoImage(upload_img)

        up1_button = tk.Label(login_frame, image=self.upload_icon,borderwidth=0,bg="#ffffff",cursor="hand2")
        up1_button.grid(row=6,column=3,pady=5,sticky="e")
        up1_button.bind("<Button-1>", lambda event:self.certi_check())

        hospi_label = tk.Label(login_frame, text="Hospital Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        hospi_label.grid(row=7, column=0, sticky="e", pady=5)
        self.hospi_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.hospi_entry.grid(row=7, column=1, pady=5)

        password_label = tk.Label(login_frame, text="Password:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        password_label.grid(row=8, column=0, sticky="e", pady=5)
        self.password_entry = tk.Entry(login_frame, font=("Arial", 16), show="*", width=25,bd=4)
        self.password_entry.grid(row=8, column=1, pady=5)

        create_button = tk.Button(login_frame, text="Create", font=("Arial", 10,"italic"),command=self.signin,relief="raised",padx=10,pady=5,cursor="hand2")
        create_button.grid(row=9, column=1, columnspan=2, pady=10)

        txt_label = tk.Label(login_frame, text="Already have account?", font=("Arial", 12), bg="#ffffff",fg="black")
        txt_label.grid(row=10, column=0, sticky="e", pady=5)

        log_button = tk.Button(login_frame, text="LOGIN", font=("Arial", 10,"italic"),fg="navy blue",bg="#ffffff",command=self.login,relief="raised",padx=10,pady=5,cursor="hand2")
        log_button.grid(row=10, column=1,sticky="w", columnspan=25, pady=10)

    def certi_check(self):
        
        self.certification_file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        self.certification_file_path_name = os.path.basename(self.certification_file_path)


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

        self.certification = False
        try:
            s3.Bucket(bucket_name).upload_file(self.certification_file_path, self.certification_file_path_name)
        except:
            messagebox.showerror("Error", "failed to upload file")
        else:
            messagebox.showinfo("Success", "File Successfully uploaded")
            self.certification = True
            self.certi_entry.insert(0, self.certification_file_path_name)



    def login(self):
        self.master.show_doctorslogin_page()

    def signin(self):                                                                                           #doctor signup id and pass fn                 
        first_name = self.firstname_entry.get()
        middle_name = self.midname_entry.get()
        last_name = self.lstname_entry.get()
        phone_no = self.ph_entry.get()
        email = self.eaddress_entry.get()
        hospital_name = self.hospi_entry.get()
        password = self.password_entry.get()

        variables.obj_var["sqlbase"].execute("use Doctor")
        variables.obj_var["sqlbase"].execute(f"select if(exists (select email from doctor_info where email = '{email}'), 'Yes', 'No')")

        email_exists = False
        get_check = None
        for email_check in variables.obj_var["sqlbase"]:
            get_check = str(email_check).strip("(),'")
            if get_check == "Yes":
                email_exists = True
                
        if email_exists == False and self.certification == True:
            variables.obj_var["sqlbase"].execute("use Doctor")  
            variables.obj_var["sqlbase"].execute(f"insert into doctor_info values('{first_name}', '{middle_name}', '{last_name}', '{phone_no}', '{email}', '{hospital_name}', 'Approved', '{password}')")  
            variables.obj_var["sql"].commit()
            messagebox.showinfo("success","Account created successfully. Your username is your email")                    
            self.master.show_doctorslogin_page()
        else:
            messagebox.showerror("Error", "Please enter valid username and password!")
            self.certi_entry.delete(0, "end")
            self.firstname_entry.delete(0, "end")
            self.midname_entry.delete(0, "end")
            self.lstname_entry.delete(0, "end")
            self.ph_entry.delete(0, "end")
            self.eaddress_entry.delete(0, "end")
            self.hospi_entry.delete(0, "end")
                                                                                                                                                            
######################################################################################################################################################

class Patientssignup(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8", height=10)

        Tab_btn=tk.Label(self, text="P A T I E N T    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="#ffffff", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        login_frame = tk.Frame(self, bd=0, relief="ridge", padx=50, pady=80, bg="#ffffff")
        login_frame.pack(anchor="center")

        firstname_label = tk.Label(login_frame, text="First Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        firstname_label.grid(row=0, column=0, sticky="e", pady=5)
        self.firstname_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.firstname_entry.grid(row=0, column=1, pady=5)
        
        midname_label = tk.Label(login_frame, text="Middle Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        midname_label.grid(row=1, column=0, sticky="e", pady=5)
        self.midname_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.midname_entry.grid(row=1, column=1, pady=5)

        lstname_label = tk.Label(login_frame, text="Last Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        lstname_label.grid(row=3, column=0, sticky="e", pady=5)
        self.lstname_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.lstname_entry.grid(row=3, column=1, pady=5)

        address_label = tk.Label(login_frame, text="Address:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        address_label.grid(row=4, column=0, sticky="e", pady=5)
        self.address_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.address_entry.grid(row=4, column=1, pady=5)

        ph_label = tk.Label(login_frame, text="Phone No.:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        ph_label.grid(row=5, column=0, sticky="e", pady=5)
        self.ph_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.ph_entry.grid(row=5, column=1, pady=5)

        aph_label = tk.Label(login_frame, text="Alternate Phone No.:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        aph_label.grid(row=6, column=0, sticky="e", pady=5)
        self.aph_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.aph_entry.grid(row=6, column=1, pady=5)

        password_label = tk.Label(login_frame, text="Password:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        password_label.grid(row=7, column=0, sticky="e", pady=5)
        self.password_entry = tk.Entry(login_frame, font=("Arial", 16), show="*", width=25,bd=4)
        self.password_entry.grid(row=7, column=1, pady=5)

        create_button = tk.Button(login_frame, text="Create", font=("Arial", 10,"italic"),bg="#f8f8f8",fg="black",command=self.username_alloc,relief="raised",padx=10,pady=5,cursor="hand2")
        create_button.grid(row=8, column=1, columnspan=2, pady=10)

        txt_label = tk.Label(login_frame, text="Already have account?", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        txt_label.grid(row=9, column=0, sticky="e", pady=5)

        log_button = tk.Button(login_frame, text="LOGIN", font=("Arial", 10,"italic"),fg="black",bg="#f8f8f8", command=self.login,relief="raised",padx=10,pady=5,cursor="hand2")
        log_button.grid(row=9, column=1, columnspan=25, pady=10)
        
    def login(self):
        self.master.show_patientslogin_page()
    
    #username allocation
    def username_alloc(self):

        self.last_name = self.lstname_entry.get()
        self.first_name = self.firstname_entry.get()
        self.surname_suffle = []
        for letter in self.last_name:
            self.surname_suffle.append(letter)
        random.shuffle(self.surname_suffle)
        self.surname = ""
        for letters in self.surname_suffle:
            self.surname += letters
        self.random_bit = random.getrandbits(16)
        self.username = str(self.first_name).lower().strip()+str(self.random_bit)+str(self.surname).lower().strip()
        self.signin()

    def signin(self):                                                                                       #patient signup id and pass fn
        
        self.first_name = self.firstname_entry.get()
        self.middle_name = self.midname_entry.get()
        self.last_name = self.lstname_entry.get()
        self.address = self.address_entry.get()
        self.phone_no = self.ph_entry.get()
        self.alternate_phone_no = self.aph_entry.get()
        self.password = self.password_entry.get()

        variables.obj_var["sqlbase"].execute("use Patient_info")
        variables.obj_var["sqlbase"].execute(f"select if(exists (select username from patient_data where username = '{self.username}'), 'Yes', 'No')")

        self.username_exists = False

        for username_exists in variables.obj_var["sqlbase"]:
            if str(username_exists).strip("(),'") == "Yes":
                self.username_alloc()
                self.username_exists = True
            elif str(username_exists).strip("(),'") == "No":
                self.username_exists = False
            break

        if self.username_exists == False:
            try:
                variables.obj_var["sqlbase"].execute("Use Patient_info")
                variables.obj_var["sqlbase"].execute(f"insert into patient_data values('{self.username}','{self.first_name.strip()}', '{self.middle_name.strip()}', '{self.last_name.strip()}', '{self.address.strip()}', '{self.phone_no.strip()}', '{self.alternate_phone_no.strip()}', '{self.password.strip()}')")
                variables.obj_var["sql"].commit()
            except:
                messagebox.showerror("Signup Error", "Something went wrong")
            else:
                variables.obj_var["sqlbase"].execute("Use Patient_info")
                variables.obj_var["sqlbase"].execute(f"select if(exists (select username from patient_data where username = '{self.username}'), 'Yes', 'No')")
                self.signup_check = False
                for signup in variables.obj_var["sqlbase"]:
                    if str(signup).strip("()',") == "Yes":
                        self.signup_check = True
                    break
                if self.signup_check == True:
                    messagebox.showinfo("Signed up Sucessfully", f"Your username is {self.username}")
                    variables.obj_var["sqlbase"].execute("Use Patient")
                    variables.obj_var["sqlbase"].execute(f"create table {self.username}(Report varchar(300) primary key, prescription varchar(300), Diagnose varchar(200),hospital_name varchar(100), activity varchar(300) default 'Not Active')")
                    variables.obj_var["sql"].commit()
                    self.firstname_entry.delete(0, "end")
                    self.lstname_entry.delete(0, "end")
                    self.midname_entry.delete(0, "end")
                    self.address_entry.delete(0, "end")
                    self.ph_entry.delete(0, "end")
                    self.aph_entry.delete(0, "end")
                    self.password_entry.delete(0, "end")
                    self.login()


######################################################################################################################################################

class Doctorslogin(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8", height=10)

        Tab_btn=tk.Label(self, text="D O C T O R    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="#ffffff", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        login_frame = tk.Frame(self, bd=0, relief="solid", padx=50, pady=80, bg="#ffffff")
        login_frame.pack(anchor="center")

        username_label = tk.Label(login_frame, text="Username:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        username_label.grid(row=0, column=0, sticky="e", pady=5)
        self.username_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.username_entry.grid(row=0, column=2, pady=5)

        password_label = tk.Label(login_frame, text="Password:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        password_label.grid(row=1, column=0, sticky="e", pady=5)
        self.password_entry = tk.Entry(login_frame, font=("Arial", 16), show="*", width=25,bd=4)
        self.password_entry.grid(row=1, column=2, pady=5)

        login_button = tk.Button(login_frame, text="Login", font=("Arial", 10,"italic"), command=self.login,relief="raised",padx=10,pady=5,cursor="hand2")
        login_button.grid(row=2, column=1, columnspan=2, pady=10)

        create_account_label = tk.Label(login_frame,text="Don't have account?",font=("arial",10),bg="#ffffff",fg="black").grid(row=3,column=1,pady=5)

        create_account_button = tk.Button(login_frame, text="Create account", font=("Arial", 10,"italic"), command=self.signup,relief="raised",padx=10,pady=5,cursor="hand2")
        create_account_button.grid(row=3, column=1, columnspan=25, pady=5)

    def login(self):                                                                                              #doctor id and pass fn
        username = "tirthsolanki@proton.me" #self.username_entry.get()
        password = "Tirth" #self.password_entry.get()

        credential_ckeck = None

        variables.obj_var["sqlbase"].execute("Use Doctor")
        variables.obj_var["sqlbase"].execute(f"select if(exists (select email from doctor_info where email = '{username}' and password = '{password}'), 'Yes', 'No')")
        
        for credential in variables.obj_var["sqlbase"]:
            if str(credential).strip("(),'") == 'Yes':
                credential_ckeck = True
            elif str(credential).strip("(),'") == 'No':
                credential_ckeck = False

        if credential_ckeck == True:                      
            self.master.show_doctors_page(username,password)
            variables.doctor_credentials["username"] = username
            from doctor_module import Doctors
            doctor_instance = Doctors()
            variables.obj_var["doctor_instance"] = doctor_instance
        else:
            messagebox.showerror("Error", "Please enter valid username and password!")
             
    def signup(self):
        self.master.show_signup_page()

######################################################################################################################################################

class Patientslogin(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8", height=10)

        Tab_btn=tk.Label(self, text="P A T I E N T    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="#ffffff", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        login_frame = tk.Frame(self, bd=0, relief="ridge", padx=50, pady=80, bg="#ffffff")
        login_frame.pack(anchor="center")

        username_label = tk.Label(login_frame, text="Username:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        username_label.grid(row=0, column=0, sticky="e", pady=5)
        self.username_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.username_entry.grid(row=0, column=2, pady=5)

        password_label = tk.Label(login_frame, text="Password:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        password_label.grid(row=1, column=0, sticky="e", pady=5)
        self.password_entry = tk.Entry(login_frame, font=("Arial", 16), show="*", width=25,bd=4)
        self.password_entry.grid(row=1, column=2, pady=5)

        login_button = tk.Button(login_frame, text="Login", font=("Arial", 10,"italic"), command=self.login,relief="raised",padx=10,pady=5,cursor="hand2")
        login_button.grid(row=2, column=1, columnspan=2, pady=10)

        create_account_label = tk.Label(login_frame,text="Don't have account?",font=("arial",10),bg="#ffffff",fg="black",bd=2).grid(row=3,column=1,pady=5)

        create_account_button = tk.Button(login_frame, text="Create account", font=("Arial", 10,"italic"), command=self.signup,bd=2,relief="raised",padx=10,pady=5,cursor="hand2")
        create_account_button.grid(row=3, column=1, columnspan=25, pady=5)

    def login(self):                                                                                                # patient login id and pass fn
        username = "tirth15141sikolna" #self.username_entry.get()
        password = "Tirth" #self.password_entry.get()

        variables.obj_var["sqlbase"].execute("Use Patient_info")
        variables.obj_var["sqlbase"].execute(f"select if(exists (select username from patient_data where username = '{username}' and password = '{password}'), 'Yes', 'No')")

        user_exists = False

        for credentials in variables.obj_var["sqlbase"]:
            if str(credentials).strip("()',") == "Yes":
                user_exists = True
            break

        if user_exists == True:
                variables.patient_credentials["username"] = username  
                import patient_module
                patient_instance = patient_module.Patients()
                variables.obj_var["patient_instance"] = patient_instance                    
                self.master.show_patients_page(username,password)
        else:
            messagebox.showerror("Error", "Please enter valid username and password!")

    def signup(self):
        self.master.show_signupp_page()

######################################################################################################################################################

class Dashboard(tk.Frame):

    def __init__(self, parent):
        super().__init__(parent, bg="#e3f2fd")

        sidebar = Sidebar(self, app=parent)
        sidebar.pack(side="left", fill="y")

        topbar = Topbar(self, parent,app=parent)
        topbar.pack(side="top", fill="x")

        footer = tk.Label(self, text="Applicare © 2024 | All Rights Reserved", font=("Arial", 10, "italic"), bg="#ffffff", fg="#7a7a7a")
        footer.pack(side="bottom", pady=5)

        dashboard_area = DashboardArea(self)
        dashboard_area.pack(expand=True, fill=tk.BOTH)

######################################################################################################################################################

class Sidebar(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg="#9cd3ff",width=600)
        tk.Label(self, text="Applicare", font=("palatino linotype", 35, "italic bold"), 
                 fg="#083b66", bg="#9cd3ff").pack(pady=25)
        self.app = app  
        self.create_buttons()

    def create_buttons(self):
        button_names = [
            (" Dashboard", lambda: self.app.show_dashboard()),
            (" Patients", self.app.show_patientslogin_page),                                                        #redirects to patients login page
            (" Doctors", self.app.show_doctorslogin_page),                                                          #redirects to doctor login page
            (" Pharmacists", self.app.show_pharmacists_page),
        ]

        for name, command in button_names:
            btn = ttk.Button(self, text=name, command=command, style='Sidebar.TButton',cursor="hand2")
            btn.pack(pady=10, padx=10, fill=tk.X)

        style = ttk.Style()
        style.configure('Sidebar.TButton', font=("palatino linotype", 15,"italic"), background='#1976d2', foreground='black')
        style.map('Sidebar.TButton', background=[('active', '#0d47a1')])

######################################################################################################################################################

class Topbar(tk.Frame):
    def __init__(self, parent, username, app):
        super().__init__(parent, bg="#cce6ff", height=70)

        tk.Label(self, text="W E L C O M E   T O   A P P L I C A R E", font=("arial", 25, "italic"), bg="#cce6ff", fg="#1976d2",anchor="center").place(relx=0.5, rely=0.5, anchor="center")

        bell_image = Image.open("bell_icon.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.bell_icon = ImageTk.PhotoImage(bell_image)

        bell_button = tk.Label(self, image=self.bell_icon,borderwidth=0,bg="#cce6ff")
        bell_button.place(relx=0.98, rely=0.5, anchor="e")
        bell_button.bind("<Button-1>",self.show_notifications)

    def show_notifications(self,event):
        messagebox.showinfo("Notifications", "You have no new notifications.")

######################################################################################################################################################

class DashboardArea(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#e3f2fd")

        self.page_container = tk.Frame(self, bg="white", bd=2, relief="sunken")
        self.page_container.pack(expand=True, fill="both", padx=10, pady=10)

        self.find_doctor = tk.Label(self.page_container, text="Find A Doctor", font=("Baskerville Old Face", 30), bg="#e3f3ff")
        self.find_doctor.pack(anchor="n", pady=10, fill='x')
        
        self.doc_search = tk.Entry(self.page_container, bd=4, font=("Courier", 15), width=90)
        self.doc_search.pack(expand=True,anchor="nw", pady=20, padx=10)

        find_img = Image.open("search.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.find_icon = ImageTk.PhotoImage(find_img)

        find_btn = tk.Button(self.page_container, image=self.find_icon,borderwidth=0,bg="#ffffff",cursor="hand2",relief="raised",bd=4,command=lambda: messagebox.showwarning("No Data", "Currently their's no legit data for Doctors so this feature could not be used for now. The feature will be available after real world implimentation."))
        find_btn.place(relx=0.93,rely=0.14,anchor="w")

######################################################################################################################################################

class PatientsPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="P A T I E N T    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        profile_img = Image.open("profile.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.profile_icon = ImageTk.PhotoImage(profile_img)

        profile_btn = tk.Label(self, image=self.profile_icon,borderwidth=0,bg="#bcdfff",cursor="hand2")
        profile_btn.place(relx=0.98, rely=0.01, anchor="ne")
        profile_btn.bind("<Button-1>",lambda event :self.show_profile())

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")   

        prescription_button = tk.Button(self, text="📝", command=self.master.show_prescrip_page, font=("algerian", 21), bd=0, bg="#bcdfff")
        prescription_button.place(relx=0.90, rely=0.0001, anchor="ne")

        download_button = tk.Button(self, text="Download", bg="#e3f2fd", fg="navy blue",font=("algerian", 16), command=self.download,relief= 'raised', padx=5, pady=5,cursor="hand2",bd=4)
        download_button.pack(side="top",anchor="ne",padx=25, pady=25)
        
        upload_btn = tk.Button(self,text = "Upload",bg="#e3f2fd",relief="raised",fg= "navy blue",font=("algerian",16),bd=4,anchor="w",padx=5,pady=5,cursor="hand2",command=lambda: self.upload())
        upload_btn.place(relx=0.04,rely=0.225,anchor="w")

        listbox_frame = tk.Frame(self, bg="#f0f4f7",relief="ridge",bd=2)
        listbox_frame.pack(anchor="n", expand=True, padx=30, pady=25)

        scrollbar = tk.Scrollbar(listbox_frame)                                                                     # scrollbar code
        scrollbar.pack(side="right", fill="y")

        self.prescript_list = tk.Listbox(listbox_frame, width=200, height=40,                                 
                                            font=("Courier", 10, "bold"), yscrollcommand=scrollbar.set)
        self.prescript_list.pack(expand=True, fill="both")

        variables.obj_var["filedata_listbox"] = self.prescript_list

        scrollbar.config(command=self.prescript_list.yview)

        patient_data_cols = {"Report": [], "Prescription": [], "Diagnose": [], "Hospital_name": [], "Activity": []}
        
        variables.obj_var["sqlbase"].execute("use Patient")
        for keys in patient_data_cols.keys():
            variables.obj_var["sqlbase"].execute(f"select {keys} from {variables.patient_credentials['username']}")
            for file_data in variables.obj_var["sqlbase"]:
                patient_data_cols[keys].append(str(file_data).strip("()',"))
        
        patient_data_table = PrettyTable()

        for key, value in patient_data_cols.items():
            patient_data_table.add_column(key, value)

        for each_col in patient_data_table.get_string().split("\n"):
            self.prescript_list.insert("end", each_col)
           
        
    def show_profile(self):
        self.master.show_pprofile_page()

    def download(self):
        variables.obj_var["patient_instance"].download_files()


######################################################################################################################################################

class PharmacistsPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")
        
        Tab_btn=tk.Label(self, text="P H A R M A C I S T    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")
        
        patname_label = tk.Label(self, text="Patient's Username:", bg="#f8f8f8", fg="#1976d2",font=("arial",16,"italic"))
        patname_label.pack(anchor="w", padx=50)
        self.patname_entry = ttk.Entry(self)
        self.patname_entry.pack(anchor="w",pady=5, padx=100,fill=tk.X)

        find_img = Image.open("search.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.find_icon = ImageTk.PhotoImage(find_img)

        find_btn = tk.Button(self, image=self.find_icon,borderwidth=0,bg="#ffffff",cursor="hand2",relief="raised",bd=4,command= self.get_patient_prescription)
        find_btn.place(relx=0.93,rely=0.21,anchor="w")

        listbox_frame = tk.Frame(self, bg="#f0f4f7",relief="ridge",bd=2)
        listbox_frame.pack(anchor="n", expand=True, padx=30, pady=25)

        scrollbar = tk.Scrollbar(listbox_frame)                                                                     # scrollbar code
        scrollbar.pack(side="right", fill="y")

        self.patient_list = tk.Listbox(listbox_frame, width=160, height=30,                                 
                                            font=("Courier", 18, "bold"), yscrollcommand=scrollbar.set)
        self.patient_list.pack(expand=True, fill="both")

        scrollbar.config(command=self.patient_list.yview)
    
    def get_patient_prescription(self):

        col_names = {"prescription": [], "diagnose": [], "activity": []}
        variables.obj_var["sqlbase"].execute("use Patient")

        for col_index in col_names:
            variables.obj_var["sqlbase"].execute(f"select {col_index} from {self.patname_entry.get()} where activity = 'Active'")
            for col_data in variables.obj_var["sqlbase"]:
                col_names[col_index].append(str(col_data).strip("(),'"))
        
        prescription_table = PrettyTable()

        for key, value in col_names.items():
            prescription_table.add_column(key, value)
        for each_col in prescription_table.get_string().split("\n"):
            self.patient_list.insert("end", each_col)


######################################################################################################################################################

class NewPatientPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="D O C T O R   P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        login_frame = tk.Frame(self, bd=0, relief="ridge", padx=50, pady=80, bg="#ffffff")
        login_frame.pack(anchor="center")

        name_label = tk.Label(login_frame, text="Patient Username:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        name_label.grid(row=0, column=0, sticky="e", pady=5)
        self.name_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.name_entry.grid(row=0, column=1, pady=5)
        
        case_label = tk.Label(login_frame, text="Case No.:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        case_label.grid(row=1, column=0, sticky="e", pady=5)
        self.case_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.case_entry.grid(row=1, column=1, pady=5)

        report_label = tk.Label(login_frame, text="Report:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        report_label.grid(row=3, column=0, sticky="e", pady=5)
        self.report_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.report_entry.grid(row=3, column=1, pady=5)

        upload_img = Image.open("upload.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.upload_icon = ImageTk.PhotoImage(upload_img)

        up1_button = tk.Label(login_frame, image=self.upload_icon,borderwidth=0,bg="#ffffff",cursor="hand2")
        up1_button.grid(row=3,column=3,pady=5,sticky="e")
        up1_button.bind("<Button-1>", lambda event: variables.obj_var["doctor_instance"].report_upload(report_entry = self.report_entry))

        prescription_label = tk.Label(login_frame, text="Prescription:", font=("Arial", 16), bg="#ffffff",fg="navy blue")
        prescription_label.grid(row=4, column=0, sticky="e", pady=5)
        self.prescription_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.prescription_entry.grid(row=4, column=1, pady=5)

        up2_button = tk.Label(login_frame, image=self.upload_icon,borderwidth=0,bg="#ffffff",cursor="hand2")
        up2_button.grid(row=4,column=3,pady=5,sticky="e")
        up2_button.bind("<Button-1>", lambda event: variables.obj_var["doctor_instance"].prescription_upload(prescription_entry = self.prescription_entry))

        diag = tk.Label(login_frame, text="Diagnose:", font=("Arial", 16), bg="#ffffff",fg="navy blue").grid(row=5, column=0, pady=5)
        self.diag_combo = ttk.Combobox(login_frame, values=[""],cursor="hand2")
        self.diag_combo.grid(row=5, column=1, pady=5,padx=10)
        self.diag_combo.bind("<Button-1>", lambda event :self.get_diagnose())
        
        hospi = tk.Label(login_frame, text="Hospital's Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue").grid(row=6, column=0, pady=5)
        self.hosp_combo = ttk.Combobox(login_frame, values=[""],cursor="hand2")
        self.hosp_combo.grid(row=6, column=1, pady=5,padx=10)
        self.hosp_combo.bind("<Button-1>", lambda event :self.get_hospital_name())


        submit_button = tk.Button(self, text="UPLOAD", bg="#1976d2", fg="white",font=("algerian",16,"bold"),cursor="hand2", command= lambda: variables.obj_var["doctor_instance"].create_patientid(patient_username = self.name_entry, case_no = self.case_entry, diagnose = self.diag_combo, hospital_name = self.hosp_combo, report = self.report_entry, prescription = self.prescription_entry))
        submit_button.pack(pady=25)

    def get_diagnose(self):
        self.diagnose_values = []

        variables.obj_var["sqlbase"].execute("use Patient")
        variables.obj_var["sqlbase"].execute(f"select diagnose from {self.name_entry.get()} group by diagnose")

        for diagnose in variables.obj_var["sqlbase"]:
            self.diagnose_values.append(str(diagnose).strip("(),'"))
        self.diag_combo.config(values=self.diagnose_values)
    
    def get_hospital_name(self):
        self.hospital_name_values = []

        variables.obj_var["sqlbase"].execute("use Patient")
        variables.obj_var["sqlbase"].execute(f"select hospital_name from {self.name_entry.get()} group by hospital_name")

        for hospital_name in variables.obj_var["sqlbase"]:
            self.hospital_name_values.append(str(hospital_name).strip("(),'"))
        self.hosp_combo.config(values=self.hospital_name_values)

        


######################################################################################################################################################

class DoctorsPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="D O C T O R    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        profile_img = Image.open("profile.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.profile_icon = ImageTk.PhotoImage(profile_img)

        profile_btn = tk.Label(self, image=self.profile_icon,borderwidth=0,bg="#bcdfff",cursor="hand2")
        profile_btn.place(relx=0.98, rely=0.01, anchor="ne")
        profile_btn.bind("<Button-1>",self.show_profile)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="#ffffff", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        self.patname_entry = ttk.Entry(self,font=("arial",16,"italic"))
        self.patname_entry.insert(0, "Search...")
        self.patname_entry.pack(anchor="w",pady=5,padx=120,fill=tk.X)

        find_img = Image.open("search.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.find_icon = ImageTk.PhotoImage(find_img)

        find_btn = tk.Button(self, image=self.find_icon,borderwidth=0,bg="#ffffff",cursor="hand2",relief="raised",bd=4,command=self.get_patient_details)
        find_btn.place(relx=0.93,rely=0.16,anchor="w")

        new_patient_button = tk.Button(
            self, text="New Patient", bg="#ffffff", fg="#1976d2",
            font=("arial", 15, "bold"), command=app.show_new_patient_page,
            relief="groove", padx=5, pady=5,cursor="hand2",bd=4)
        new_patient_button.pack(side=tk.TOP,anchor="e",padx=25, pady=25)
        
        My_patients = tk.Button(self,text = "My Patients",bg="#ffffff",fg= "#1976d2",font=("algerian",16),bd=4,anchor="w",relief="groove",padx=7,pady=7,cursor="hand2", command= lambda:variables.obj_var["doctor_instance"].doctor_myprescription(patient_list = self.patient_list)).place(relx=0.04,rely=0.28,anchor="w")
        
        listbox_frame = tk.Frame(self, bg="#f0f4f7",relief="ridge",bd=2)
        listbox_frame.pack(anchor="n", expand=True, padx=30, pady=25)

        scrollbar = tk.Scrollbar(listbox_frame)                                                                     # scrollbar code
        scrollbar.pack(side="right", fill="y")

        self.patient_list = tk.Listbox(listbox_frame, width=160, height=30,                                 
                                            font=("Courier", 20, "bold"), yscrollcommand=scrollbar.set)
        self.patient_list.pack(expand=True, fill="both")

        scrollbar.config(command=self.patient_list.yview)
                
    def get_patient_details(self):

        variables.obj_var["sqlbase"].execute("use Patient_info")
        variables.obj_var["sqlbase"].execute(f"select if(exists (select username from patient_data where username = '{self.patname_entry.get()}'),'Yes', 'No')")
        
        patient_exists = False
        for patient_check in variables.obj_var["sqlbase"]:
            if str(patient_check).strip("(),'") == 'Yes':
                patient_exists = True
            break
        if patient_exists == True:    
            variables.doctor_credentials["patient_username"] = self.patname_entry
            app.show_searchedpatientpage()
        elif patient_exists == False:
            messagebox.showerror("Error", "Patient not found!")
        
                    

    def show_profile(self,event):
        self.master.show_dprofile_page()

######################################################################################################################################################

class patuploadpage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#e3f2fd")

        Tab_btn=tk.Label(self, text="P A T I E N T    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="#ffffff", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        login_frame = tk.Frame(self, bd=0, relief="ridge", padx=50, pady=80, bg="#ffffff")
        login_frame.pack(anchor="center")

        report_label = tk.Label(login_frame, text="Report:", font=("Arial", 16), bg="#ffffff",fg="navy blue").grid(row=0, column=0, sticky="e", pady=5)
        self.report_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.report_entry.grid(row=0, column=1, pady=5)

        upload_img = Image.open("upload.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.upload_icon = ImageTk.PhotoImage(upload_img)

        up1_button = tk.Label(login_frame, image=self.upload_icon,borderwidth=0,bg="#ffffff",cursor="hand2")
        up1_button.grid(row=0,column=3,pady=5,sticky="e")
        up1_button.bind("<Button-1>",lambda event :variables.obj_var["patient_instance"].report_upload(report_entry = self.report_entry))

        prescrip_label = tk.Label(login_frame, text="Prescription:", font=("Arial", 16), bg="#ffffff",fg="navy blue").grid(row=1, column=0, sticky="e", pady=5)
        self.prescrip_entry = tk.Entry(login_frame, font=("Arial", 16), width=25,bd=4)
        self.prescrip_entry.grid(row=1, column=1, pady=5)

        up2_button = tk.Label(login_frame, image=self.upload_icon,borderwidth=0,bg="#ffffff",cursor="hand2")
        up2_button.grid(row=1,column=3,pady=5,sticky="e")
        up2_button.bind("<Button-1>",lambda event :variables.obj_var["patient_instance"].prescription_upload(prescription_entry = self.prescrip_entry))

        variables.obj_var["sqlbase"].execute("use Patient")
        variables.obj_var["sqlbase"].execute(f"select diagnose from {variables.patient_credentials['username']} group by diagnose")

        diagnose_values = ["Add Diagnose"]
        for diagnose_name in variables.obj_var["sqlbase"]:
            diagnose_values.insert(0, str(diagnose_name).strip("()',"))

        diag = tk.Label(login_frame, text="Diagnose:", font=("Arial", 16), bg="#ffffff",fg="navy blue").grid(row=2, column=0,sticky="e", pady=5)
        diag_combo = ttk.Combobox(login_frame, values= diagnose_values, cursor="hand2")
        diag_combo.grid(row=2, column=1, pady=5,padx=10)
        diag_combo.bind("<<ComboboxSelected>>", lambda event: (diagnose_values.insert(0, [simpledialog.askstring("Diagnose", "Enter Diagnose name")]), diag_combo.config(values=diagnose_values)) if diag_combo.get() == "Add Diagnose" else None)
        
        variables.obj_var["sqlbase"].execute("use Patient")
        variables.obj_var["sqlbase"].execute(f"select hospital_name from {variables.patient_credentials['username']} group by hospital_name")

        hospital_name_values = ["Add Hospital"]
        for hospital_name in variables.obj_var["sqlbase"]:
            hospital_name_values.insert(0, str(hospital_name).strip("()',"))

        hospi = tk.Label(login_frame, text="Hospital's Name:", font=("Arial", 16), bg="#ffffff",fg="navy blue").grid(row=3, column=0, sticky="e",pady=5)
        hosp_combo = ttk.Combobox(login_frame, values=hospital_name_values,cursor="hand2")
        hosp_combo.grid(row=3, column=1, pady=5,padx=10)
        hosp_combo.bind("<<ComboboxSelected>>", lambda event: (hospital_name_values.insert(0, [simpledialog.askstring("Hospital name", "Enter Hospital name")]), hosp_combo.config(values=hospital_name_values)) if hosp_combo.get() == "Add Hospital" else None)

        Upload_btn = tk.Button(login_frame,text="UPLOAD",font=("Arial", 16), bg="#ffffff",fg="navy blue",relief="groove",bd=2, command=lambda:variables.obj_var["patient_instance"].add_file_data(hospital_name_ = hosp_combo, diagnose_name_ = diag_combo, prescription_entry = self.prescrip_entry, report_entry = self.report_entry)).grid(row=4,column=1,pady=10,padx=10)

    def patpres(self,event):
        self.master.show_prescrip_page()
######################################################################################################################################################

class DocProfilePage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="D O C T O R' S    P R O F I L E", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        form_frame = tk.Frame(self, bg="white")
        form_frame.pack(expand=True, fill="both", padx=40, pady=40)

        doctor_credential = {"first_name":[], "middle_name":[], "last_name":[], "phone_no":[], "email":[], "certificate":[], "hospital_name":[]}

        variables.obj_var["sqlbase"].execute("use Doctor")

        for col_index in doctor_credential.keys():
            variables.obj_var["sqlbase"].execute(f"select {col_index} from doctor_info where email = '{variables.doctor_credentials["username"]}'")
            for col_data in variables.obj_var["sqlbase"]:
                doctor_credential[col_index].append(str(col_data).strip("(),'"))

        doctor_name = f"{doctor_credential["first_name"][0]} {doctor_credential["middle_name"][0]} {doctor_credential["last_name"][0]}"
        doctor_phone_no = doctor_credential["phone_no"][0]
        doctor_email = doctor_credential["email"][0]
        doctor_certi = doctor_credential["certificate"][0]
        doctor_hospital_name = doctor_credential["hospital_name"][0]


        tk.Label(form_frame, text="Name:", font=("Arial", 18, "bold"), bg="white").grid(row=2, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=doctor_name).grid(row=2, column=3, padx=10, pady=10)

        tk.Label(form_frame, text="E-mail:", font=("Arial", 18, "bold"), bg="white").grid(row=5, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=doctor_email).grid(row=5, column=3, padx=10, pady=10)

        tk.Label(form_frame, text="Phone no.:", font=("Arial", 18, "bold"), bg="white").grid(row=2, column=5, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=doctor_phone_no).grid(row=2, column=6, padx=10, pady=10)

        tk.Label(form_frame, text="Hospital Name:", font=("Arial", 18, "bold"), bg="white").grid(row=5, column=5, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, height=3, width=30, text=doctor_hospital_name).grid(row=5, column=6, padx=10, pady=10)

        tk.Label(form_frame, text="Dr. Certification:", font=("Arial", 18, "bold"), bg="white").grid(row=7, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=doctor_certi).grid(row=7, column=3, padx=10, pady=10)

######################################################################################################################################################

class PatProfilePage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="P A T I E N T' S    P R O F I L E", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)
        
        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        form_frame = tk.Frame(self, bg="white")
        form_frame.pack(expand=True, fill="both", padx=40, pady=40)

        patient_credential = {"first_name":[], "middle_name":[], "last_name":[], "phone_no":[], "alternate_phone_no":[], "address":[]}

        variables.obj_var["sqlbase"].execute("use Patient_info")

        for col_index in patient_credential.keys():
            variables.obj_var["sqlbase"].execute(f"select {col_index} from patient_data where username = '{variables.patient_credentials["username"]}'")
            for col_data in variables.obj_var["sqlbase"]:
                patient_credential[col_index].append(str(col_data).strip("(),'"))

        patient_name = f"{patient_credential["first_name"][0]} {patient_credential["middle_name"][0]} {patient_credential["last_name"][0]}"
        patient_phone_no = patient_credential["phone_no"][0]
        patient_alternate_phone_no = patient_credential["alternate_phone_no"][0]
        patient_address = patient_credential["address"][0]

        tk.Label(form_frame, text="Name:", font=("Arial", 18, "bold"), bg="white").grid(row=2, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=patient_name).grid(row=2, column=3, padx=10, pady=10)

        tk.Label(form_frame, text="Phone no.:", font=("Arial", 18, "bold"), bg="white").grid(row=5, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=patient_phone_no).grid(row=5, column=3, padx=10, pady=10)

        tk.Label(form_frame, text="Alternate Phone no.:", font=("Arial", 18, "bold"), bg="white").grid(row=2, column=5, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=patient_alternate_phone_no).grid(row=2, column=6, padx=10, pady=10)

        tk.Label(form_frame, text="Address:", font=("Arial", 18, "bold"), bg="white").grid(row=5, column=5, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, height=3, width=80, text=patient_address).grid(row=5, column=6, padx=10, pady=10)

######################################################################################################################################################


class SearchedPatProfilePage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        self.searched_patient = variables.doctor_credentials["patient_username"].get()

        Tab_btn=tk.Label(self, text=f"{self.searched_patient.upper()}    P R O F I L E", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)
        
        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")

        form_frame = tk.Frame(self, bg="white")
        form_frame.pack(expand=True, fill="both", padx=40, pady=40)
        
        patient_info = {"first_name":[], "middle_name":[], "last_name":[], "address":[], "phone_no":[], "alternate_phone_no":[]}
        variables.obj_var["sqlbase"].execute("use Patient_info")
        
        for col_index in patient_info.keys():
            variables.obj_var["sqlbase"].execute(f"select {col_index} from patient_data where username = '{self.searched_patient}'")
            for col_data in variables.obj_var["sqlbase"]:
                patient_info[col_index].append(str(col_data).strip("(),'"))
        
        patient_name = f"{patient_info["first_name"][0]} {patient_info["middle_name"][0]} {patient_info["last_name"][0]}"
        patient_address = patient_info["address"][0]
        patient_phone_no = patient_info["phone_no"][0]
        patient_alternate_phone_no = patient_info["alternate_phone_no"][0]  
        tk.Label(form_frame, text="Name:", font=("Arial", 18, "bold"), bg="white").grid(row=2, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=f"{patient_name}").grid(row=2, column=3, padx=10, pady=10)

        tk.Label(form_frame, text="Phone no.:", font=("Arial", 18, "bold"), bg="white").grid(row=5, column=2, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=f"{patient_phone_no}").grid(row=5, column=3, padx=10, pady=10)

        tk.Label(form_frame, text="Alternate Phone no.:", font=("Arial", 18, "bold"), bg="white").grid(row=2, column=5, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, width=30, text=f"{patient_alternate_phone_no}").grid(row=2, column=6, padx=10, pady=10)

        tk.Label(form_frame, text="Address:", font=("Arial", 18, "bold"), bg="white").grid(row=5, column=5, sticky="w", padx=10, pady=10)
        tk.Label(form_frame, height=3, width=80, text=f"{patient_address}").grid(row=5, column=6, padx=10, pady=10)
     

######################################################################################################################################################

class Prescriptionpage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="P R E S C R I P T I O N' S   P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#cce6ff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")   
        
        self.create_widgets()

    def create_widgets(self):
        
        listbox_frame = tk.Frame(self, bg="#f0f4f7",relief="ridge",bd=2)
        listbox_frame.pack(anchor="n", expand=True, padx=30, pady=25)

        scrollbar = tk.Scrollbar(listbox_frame)                                                                     # scrollbar code
        scrollbar.pack(side="right", fill="y")

        self.prescription_list = tk.Listbox(listbox_frame, width=50, height=16,                                 
                                            font=("Arial", 16), yscrollcommand=scrollbar.set)
        self.prescription_list.pack(expand=True, fill="both")

        scrollbar.config(command=self.prescription_list.yview)

        options_frame = tk.Frame(self, bg="#f0f4f7")
        options_frame.place(relx=0.88, rely=0.45, anchor="e")

        time_label = tk.Label(options_frame, text="Time*", font=("Arial", 16), 
                              bg="#f0f4f7", anchor="w")
        time_label.grid(row=0, column=0, sticky="w", pady=10)

        self.time_vars = {
            "Day": tk.IntVar(),
            "Noon": tk.IntVar(),
            "Evening": tk.IntVar(),
            "Night": tk.IntVar()
        }
        for index, (time, var) in enumerate(self.time_vars.items()):
            tk.Checkbutton(
                options_frame, text=time, variable=var, font=("Arial", 16),
                bg="#f0f4f7", anchor="w"
            ).grid(row=index + 1, column=0, sticky="w")
        

        dosage_label = tk.Label(options_frame, text="Dosage*", font=("Arial", 16), bg="#f0f4f7", anchor="w")
        dosage_label.grid(row=5, column=0, sticky="w", pady=10)

        self.dosage_var = tk.StringVar(value="After")
        dosages = ["After", "Before"]
        for index, dosage in enumerate(dosages):
            tk.Radiobutton(
                options_frame, text=dosage, variable=self.dosage_var, value=dosage, font=("Arial", 16),
                bg="#f0f4f7", anchor="w"
            ).grid(row=6 + index, column=0, sticky="w")

        self.prescription_entry = tk.Entry(self, font=("Arial", 16), width=50,relief="sunken",bd=4)
        self.prescription_entry.place(relx=0.26,rely=0.77)

        add_button = tk.Button(self, text="ADD", font=("Arial", 16,"bold"), width=15,bg="#ffffff",command=self.add_prescription,relief="raised",bd=4)  #               
        add_button.place(relx=0.78,rely=0.75)                                                                               ############################          
                                                                                                                            ####################################
        prescript_button = tk.Button(self, text="Prescript", font=("Arial", 16), width=15,bg = "#ffffff",bd=4,relief="raised",command=self.prescript)          #
        prescript_button.place(relx=0.45,rely=0.83)                                                                         ####################################
                                                                                                                            #
        self.prescription_list.insert(tk.END, f"{"MED NAME"}                 {"TIME"}                 {"DOSAGE"}")          #                        
        self.prescription_entry.delete(0, tk.END)                                                                           #
                                                                                                                            #
    def add_prescription(self):                                                                                             #
        prescription = self.prescription_entry.get()                                                                        #
                                                                                                                            # refer this much section for conversion of containers to listbox
        selected_times = [time for time, var in self.time_vars.items() if var.get() == 1]                                   #
        time_str = ", ".join(selected_times) if selected_times else "No Time Selected"                                      #
                                                                                                                            #
        dosage = self.dosage_var.get()                                                                                      #
                                                                                                                            #
        if prescription:                                                                                                    #
            self.prescription_list.insert(tk.END, f"{prescription}                 {time_str}                 {dosage}")    #                        
            self.prescription_entry.delete(0, tk.END)                                                                       #
                                                                                                                        #####    
    def prescript(self):                                                                                                    
        prescriptions = self.prescription_list.get(1, tk.END)
        if prescriptions:
            print("Prescriptions:", prescriptions)
            self.master.go_back() 
        else:
            print("No prescriptions added.")

######################################################################################################################################################

class patPrescriptionpage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        Tab_btn=tk.Label(self, text="P A T I E N T    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")   

        active_prescript = tk.Button(self, text="Active Prescription", bg="#ffffff", fg="#1976d2",font=("arial", 15, "bold"),relief="groove", padx=5, pady=5,cursor="hand2",bd=4, command= lambda:variables.obj_var["patient_instance"].active_prescription(patient_list = self.patient_list))
        active_prescript.pack(side=tk.TOP,anchor="e",padx=25, pady=25)
        
        My_prescript = tk.Button(self,text = "My Prescriptions",bg="#ffffff",fg= "#1976d2",font=("arial", 15, "bold"),anchor="w",relief="groove",padx=7,pady=7,cursor="hand2", command= lambda:variables.obj_var["patient_instance"].all_prescription(patient_list = self.patient_list)).place(relx=0.04,rely=0.19,anchor="w")

        listbox_frame = tk.Frame(self, bg="#f0f4f7",relief="ridge",bd=2)
        listbox_frame.pack(anchor="n", expand=True, padx=30, pady=25)

        scrollbar = tk.Scrollbar(listbox_frame)                                                                     # scrollbar code
        scrollbar.pack(side="right", fill="y")

        self.patient_list = tk.Listbox(listbox_frame, width=100, height=30,                                 
                                            font=("Courier", 10, "bold"), yscrollcommand=scrollbar.set)
        self.patient_list.pack(expand=True, fill="both")

        scrollbar.config(command=self.patient_list.yview)

######################################################################################################################################################


class SearchedPatientsPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#f8f8f8")

        self.searched_patient = variables.doctor_credentials["patient_username"].get()

        Tab_btn=tk.Label(self, text=f"{self.searched_patient.upper()}    P O R T A L", font=("palatino linotype", 25, "italic bold"), bg="#bcdfff", fg="#1976d2")
        Tab_btn.pack(side="top",anchor="center",fill=tk.X)

        profile_img = Image.open("profile.jpeg").resize((35,32), Image.Resampling.LANCZOS)
        self.profile_icon = ImageTk.PhotoImage(profile_img)

        profile_btn = tk.Label(self, image=self.profile_icon,borderwidth=0,bg="#bcdfff",cursor="hand2")
        profile_btn.place(relx=0.98, rely=0.01, anchor="ne")
        profile_btn.bind("<Button-1>",self.show_profile)

        back_button = tk.Button(self, text="<--", command=lambda: parent.go_back(), bg="white", fg="navy blue",font=("algerian",16,"bold"),cursor="hand2")
        back_button.pack(pady=10,anchor="nw")   

        download_button = tk.Button(self, text="Download", bg="#e3f2fd", fg="navy blue",font=("algerian", 16), command=self.download,relief= 'raised', padx=5, pady=5,cursor="hand2",bd=4)
        download_button.pack(side="top",anchor="ne",padx=25, pady=25)
        
        listbox_frame = tk.Frame(self, bg="#f0f4f7",relief="ridge",bd=2)
        listbox_frame.pack(anchor="n", expand=True, padx=30, pady=25)

        scrollbar = tk.Scrollbar(listbox_frame)                                                                     # scrollbar code
        scrollbar.pack(side="right", fill="y")

        self.prescript_list = tk.Listbox(listbox_frame, width=200, height=40,                                 
                                            font=("Courier", 10, "bold"), yscrollcommand=scrollbar.set)
        self.prescript_list.pack(expand=True, fill="both")

        scrollbar.config(command=self.prescript_list.yview)

        patient_data_cols = {"Report": [], "Prescription": [], "Diagnose": [], "Hospital_name": [], "Activity": []}
        

        variables.obj_var["sqlbase"].execute("use Patient")
        for keys in patient_data_cols.keys():
            variables.obj_var["sqlbase"].execute(f"select {keys} from {self.searched_patient}")
            for file_data in variables.obj_var["sqlbase"]:
                patient_data_cols[keys].append(str(file_data).strip("()',"))
        
        patient_data_table = PrettyTable()

        for key, value in patient_data_cols.items():
            patient_data_table.add_column(key, value)

        for each_col in patient_data_table.get_string().split("\n"):
            self.prescript_list.insert("end", each_col)
           
        
    def show_profile(self, event):
        self.master.show_searchedpprofile_page()

    def download(self):
        variables.doctor_credentials["filedata_listbox"] = self.prescript_list
        variables.obj_var["doctor_instance"].download_files()
    

######################################################################################################################################################

if __name__ == "__main__":
    app = App()
    app.mainloop()

######################################################################################################################################################
