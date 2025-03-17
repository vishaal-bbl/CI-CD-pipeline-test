#Using python 3.11 as base image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /ktproject

# Copy requirements file to the container
COPY requirements.txt .

# Install dependencies
RUN apt-get update && \
apt-get install -y --no-install-recommends \
    python3-pip build-essential libpq-dev libssl-dev && \
apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt
# Copy the rest of the application code to the container
COPY . .

# Expose port 8000
EXPOSE 8000

# Run the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]