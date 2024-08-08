# Use an official image as a base
FROM node:14

# Create a non-root user
RUN useradd -m appuser

# Set the user to the non-root user
USER appuser

# Set the working directory
WORKDIR /app

# Copy the application code
COPY . .

# Install dependencies
RUN npm install

# Expose the application port
EXPOSE 3000

# Start the application
CMD ["node", "app.js"]
