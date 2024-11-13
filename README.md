#Edit this lines:
427 - username = self.username_entry.get()
428 - password = self.password_entry.get()
487 - username = self.username_entry.get()
488 - password = self.password_entry.get() 

#Add this code 
def upload(self):
        app.show_upload_page()
to get patient upload module  in line 660 after def download(self):
