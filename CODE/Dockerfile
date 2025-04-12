# Use Python 3.11 base image
FROM python:3.11-slim


# Set working directory
WORKDIR /app 

# Copy project files
COPY . /app

# Install Python packages
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

#RUN python recreate_db.py
# Expose Flask port
EXPOSE 5000
# Load from .env
# Start everything via entrypoint
CMD ["python", "app.py"]
