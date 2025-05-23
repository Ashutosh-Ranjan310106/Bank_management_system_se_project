from flask import Flask
from functions import recreate_database
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime
folder_path = "logs"

# Iterate through all files in the folder and remove them
if os.path.exists(folder_path):

    for file in os.listdir(folder_path):
        old_file_path = os.path.join(folder_path, file)
        if os.path.isfile(old_file_path):  # Ensure it's a file before deleting
            #name, ext = os.path.splitext(old_file_path)
            #new_file_path = f"old_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{name}{ext}"  # Append '_old' before extension
            #os.rename(old_file_path, new_file_path)
            os.remove(old_file_path)

    print("All files deleted successfully!")
else:
        os.mkdir(folder_path)


from app import app
with app.app_context():
    recreate_database()

