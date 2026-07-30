# ---- Base image ----
# Python 3.13 slim — smaller than the full image, has everything
# we need. Matches your local Python version.
FROM python:3.13-slim

# Set working directory inside the container.
WORKDIR /app

# Copy requirements first — Docker caches layers. If requirements
# haven't changed, Docker skips the pip install step on rebuilds.
# This makes rebuilds fast when you only change Python code.
COPY requirements.txt .

# Install dependencies. --no-cache-dir keeps the image smaller.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the backend code.
COPY . .

# Tell Docker this container listens on port 8000.
EXPOSE 8000

# Start the server. 0.0.0.0 means "accept connections from outside
# the container" — without this, the app is unreachable.
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]